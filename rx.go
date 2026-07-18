package hydra

import (
	"bytes"
	"errors"
	"time"
)

// rxInit processes a received INIT (hydra.c:1390-1445). The negotiation
// itself runs only while rxState == hrxInit; INITACK is sent
// unconditionally for every INIT, including duplicates in any later
// state. INIT never resets braindead.
func (b *batch) rxInit(pkt packet) error {
	if b.rxState == hrxInit {
		p, err := parseInit(pkt.payload)
		if err == nil {
			if nerr := b.negotiate(p); nerr != nil {
				return nerr
			}
			b.rxState = hrxFinfo
		}
		// Malformed INIT: stay in hrxInit; the peer's retry re-sends.
	}
	return b.write(pktINITACK, nil)
}

// negotiate computes the effective option set and window pair
// (hydra.c:1395-1442). The formula is a UNION of the two desire sets
// plus the always-nice extras, intersected with both supported sets —
// C32/DEV go active on mutual support alone. One effective set governs
// both directions.
func (b *batch) negotiate(p initPkt) error {
	localSup := b.cfg.localSupported()
	localDes := b.cfg.localDesired()

	eff := ((localDes | capUnion | p.desired) & p.supported) & localSup

	// Vital check: every escape flag we desired must have survived,
	// else the link cannot be made byte-safe.
	vital := localDes & capEscape
	if eff&vital != vital {
		return ErrIncompatible
	}

	// Window merge (hydra.c:1406-1415): field 1 is the peer's TX window
	// — our DATAACK duty; field 2 the peer's RX window — our unacked
	// limit. Per direction: a nonzero value beats zero, two nonzero
	// values take the minimum. Values with the sign bit set are junk.
	peerTx, peerRx := int64(p.txWindow), int64(p.rxWindow)
	if peerTx < 0 || peerTx > SafeMaxOffset {
		peerTx = 0
	}
	if peerRx < 0 || peerRx > SafeMaxOffset {
		peerRx = 0
	}
	b.rxWindow = mergeWindow(peerTx, int64(b.cfg.RxWindowBytes))
	b.txWindow = mergeWindow(peerRx, int64(b.cfg.TxWindowBytes))

	b.prefix = p.prefix
	if len(b.prefix) > prefixMax {
		b.prefix = b.prefix[:prefixMax]
	}

	b.opts = eff
	b.s.rxOpts.Store(eff)
	b.s.effOpts.Store(eff)
	b.s.negotiated.Store(true)
	return nil
}

func mergeWindow(peer, local int64) int64 {
	if local > 0 && (peer == 0 || local < peer) {
		return local
	}
	return peer
}

// rxFinfo processes a received FINFO (hydra.c:1458-1561). FINFOACK is
// always sent, whatever state we are in.
func (b *batch) rxFinfo(pkt packet) error {
	var ack int32
	switch b.rxState {
	case hrxFinfo:
		b.feedBraindead()
		switch {
		case isFinfoEOB(pkt.payload):
			ack = 0
			b.rxState = hrxDone
		case b.lastRefusedFinfo != nil && bytes.Equal(pkt.payload, b.lastRefusedFinfo):
			// Retransmit of a FINFO we already refused (our ack was
			// lost): re-ack without consulting the handler again —
			// AcceptFile/FileCompleted must not double-fire.
			ack = b.lastRefusedAck
		default:
			ack = b.acceptFinfo(pkt.payload)
			if ack < 0 {
				b.lastRefusedFinfo = append([]byte(nil), pkt.payload...)
				b.lastRefusedAck = ack
			} else {
				b.lastRefusedFinfo = nil
			}
		}
	case hrxData:
		// Duplicate FINFO after a lost FINFOACK: re-ack with the
		// current position — correct resume semantics (hydra.c:1556).
		ack = int32(b.rxPos)
	case hrxDone:
		// Late FINFO after our EOB ack: EOB dups re-ack 0, a real file
		// is deferred to the next batch.
		if isFinfoEOB(pkt.payload) {
			ack = 0
		} else {
			ack = ackDefer
		}
	default: // hrxInit — peer jumped the gun; static 0 (hydra.c edge)
		ack = 0
	}
	return b.write(pktFINFOACK, marshalOffset(ack))
}

// acceptFinfo parses a file announcement and asks the handler. Returns
// the FINFOACK value and, on acceptance, arms the RX per-file state.
func (b *batch) acceptFinfo(payload []byte) int32 {
	meta, err := parseFinfo(payload)
	if err != nil {
		return ackDefer
	}
	info := FileInfo{
		Name: meta.name,
		Path: meta.path,
		Size: meta.size,
	}
	if meta.mtime != 0 {
		info.ModTime = time.Unix(meta.mtime, 0)
	}
	if meta.count != 0 {
		// First file of the batch carries the total, later ones their
		// ordinal ≥2 (advisory; HydraCom sends 0 — SPEC §3.4).
		if b.filesRcvd == 0 {
			info.FileTotal = int(meta.count)
			info.FileNum = 1
		} else {
			info.FileNum = int(meta.count)
		}
	}

	// A size beyond the signed-offset range can never complete (the
	// 32-bit offsets would collide with the -1/-2 sentinels); refuse
	// before involving the handler, mirroring the TX-side check.
	if info.Size > SafeMaxOffset {
		b.s.handler.FileCompleted(info, 0, ErrFileTooLarge)
		return ackDefer
	}

	w, offset, herr := b.s.handler.AcceptFile(info)
	switch {
	case errors.Is(herr, ErrSkip):
		if w != nil {
			_ = w.Close()
		}
		b.s.handler.FileCompleted(info, 0, herr)
		return ackHaveFile
	case herr != nil:
		if w != nil {
			_ = w.Close()
		}
		b.s.handler.FileCompleted(info, 0, herr)
		return ackDefer
	case w == nil:
		b.s.handler.FileCompleted(info, 0, ErrHandlerContract)
		return ackDefer
	case offset < 0 || offset > SafeMaxOffset || (meta.size > 0 && offset > meta.size):
		_ = w.Close()
		b.s.handler.FileCompleted(info, 0, ErrResumeOutOfRange)
		return ackDefer
	}

	b.filesRcvd++
	b.rxWriter = w
	b.rxOpen = true
	b.rxInfo = info
	b.rxPos = offset
	b.rxRetries = 0
	b.rxSyncID = 0
	b.rxLastSync = 0
	b.rxTimer = time.Time{}
	b.rxState = hrxData
	return int32(offset)
}

// rxCloseFile closes the receive file exactly once, firing FileCompleted
// with the given error (nil = success).
func (b *batch) rxCloseFile(err error) {
	if !b.rxOpen {
		return
	}
	b.rxOpen = false
	if b.rxWriter != nil {
		_ = b.rxWriter.Close()
		b.rxWriter = nil
	}
	b.s.handler.FileCompleted(b.rxInfo, max(b.rxPos, 0), err)
}

// rxData processes a DATA packet (hydra.c:1615-1690). Only meaningful in
// hrxData; stale blocks in other states are dropped (the duplicate-EOF
// re-ack covers the lost-EOFACK case).
func (b *batch) rxData(pkt packet) error {
	if b.rxState != hrxData {
		return nil
	}
	offset, data, err := parseData(pkt.payload)
	if err != nil {
		return nil
	}
	if offset != b.rxPos || offset < 0 {
		return b.badPosition(offset, false)
	}

	b.feedBraindead()
	b.rxBlkLen = len(data)
	if b.rxWriter != nil {
		if _, werr := b.rxWriter.Write(data); werr != nil {
			// Destination write error: request a skip via RPOS(-2)
			// (hydra.c:1663-1673 — pos -2, blklen 0, fresh sync id).
			b.rxCloseFile(werr)
			b.rxPos = -2
			b.rxRetries = 1
			b.rxSyncID++
			b.rxTimer = time.Now().Add(b.cfg.Timeout)
			return b.write(pktRPOS, marshalRpos(rposPkt{
				offset: -2, blocksize: 0, id: b.rxSyncID,
			}))
		}
	}
	b.rxRetries = 0
	b.rxTimer = time.Time{}
	b.rxLastSync = b.rxPos
	b.rxPos += int64(len(data))
	if b.rxPos > SafeMaxOffset {
		// Wire offsets would wrap into sentinel territory — request a
		// skip exactly like a local write error.
		b.rxCloseFile(ErrFileTooLarge)
		b.rxPos = -2
		b.rxRetries = 1
		b.rxSyncID++
		b.rxTimer = time.Now().Add(b.cfg.Timeout)
		return b.write(pktRPOS, marshalRpos(rposPkt{
			offset: -2, blocksize: 0, id: b.rxSyncID,
		}))
	}
	b.s.handler.FileProgress(b.rxInfo, b.rxPos)
	if b.rxWindow > 0 {
		return b.write(pktDATAACK, marshalOffset(int32(b.rxPos)))
	}
	return nil
}

// badPosition is the shared out-of-sync machinery for DATA and EOF
// (hydra.c:1617-1655, 1786-1830). There are no dedicated states — an
// RPOS rate limiter (rxTimer), a burst counter (rxRetries), a per-burst
// sync id, and rxLastSync to detect that the sender rewound.
func (b *batch) badPosition(offset int64, isEOF bool) error {
	if offset <= b.rxLastSync {
		// The sender rewound (acted on our RPOS) or this is fresh
		// ground — treat as a new situation.
		b.rxTimer = time.Time{}
		b.rxRetries = 0
	}
	b.rxLastSync = offset

	now := time.Now()
	if !b.rxTimer.IsZero() && now.Before(b.rxTimer) {
		return nil // rate-limited: one RPOS per timeout
	}

	// One-way fallback: answerer only, DATA path only, only while our
	// TX is still busy (hydra.c:1627-1632).
	if !isEOF && b.rxRetries > 4 && b.txState < htxRend &&
		!b.cfg.Originator && !b.hdxlink {
		b.hdxlink = true
		b.rxRetries = 0
	}
	b.rxRetries++
	if b.rxRetries > b.cfg.MaxRetries {
		return ErrMaxRetries
	}
	if b.rxRetries == 1 {
		b.rxSyncID++
	}
	b.rxBlkLen /= 2
	proposal := ladder(b.rxBlkLen)
	b.rxTimer = now.Add(b.cfg.Timeout)
	return b.write(pktRPOS, marshalRpos(rposPkt{
		offset:    b.rxPos,
		blocksize: proposal,
		id:        b.rxSyncID,
	}))
}

// rxEOF processes an EOF packet (hydra.c:1773-1841).
func (b *batch) rxEOF(pkt packet) error {
	switch b.rxState {
	case hrxData:
		offset, err := parseOffset(pkt.payload)
		if err != nil {
			return nil
		}
		switch {
		case offset < 0:
			// Sender skipped the file (its own choice or honouring our
			// RPOS(-2)). rxCloseFile is a no-op if a write error
			// already closed it.
			b.rxCloseFile(ErrSenderSkip)
			b.rxPos = 0
			b.rxState = hrxFinfo
			b.feedBraindead()
		case int64(offset) != b.rxPos:
			return b.badPosition(int64(offset), true)
		default:
			b.rxCloseFile(nil)
			b.rxState = hrxFinfo
			b.feedBraindead()
		}
		return b.write(pktEOFACK, nil)
	case hrxFinfo:
		// Duplicate EOF — our EOFACK was lost; re-ack (hydra.c:1839).
		return b.write(pktEOFACK, nil)
	default:
		return nil
	}
}
