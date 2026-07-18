package hydra

import (
	"io"
	"strings"
	"time"
)

// txAction performs the current TX state's send duty (the C state-action
// switch, hydra.c:1181-1313). Sending states transition immediately to
// their ack-wait state; wait states no-op. htxXdata marks the loop
// productive so pump keeps the stream flowing without blocking.
func (b *batch) txAction() error {
	switch b.txState {
	case htxStart:
		if err := b.s.writer.writeRaw([]byte(autostart)); err != nil {
			return err
		}
		if err := b.write(pktSTART, nil); err != nil {
			return err
		}
		b.txTimer = time.Now().Add(startInterval)
		b.txState = htxSwait
	case htxInit:
		if err := b.sendInit(); err != nil {
			return err
		}
		// INIT always uses timeout/2, even on the first send
		// (hydra.c:1209).
		b.txTimer = time.Now().Add(b.cfg.Timeout / 2)
		b.txState = htxInitAck
	case htxFinfo:
		if err := b.sendFinfo(); err != nil {
			return err
		}
		b.finfoAckWait = true
		b.armTx()
		b.txState = htxFinfoAck
	case htxXdata:
		return b.sendData()
	case htxEOF:
		pos := b.txPos
		if b.txSkip {
			pos = int64(offsetSkip)
		}
		if err := b.write(pktEOF, marshalOffset(int32(pos))); err != nil {
			return err
		}
		b.eofAckWait = true
		b.armTx()
		b.txState = htxEOFAck
	case htxEnd:
		for range endInitialCount {
			if err := b.write(pktEND, nil); err != nil {
				return err
			}
		}
		b.txTimer = time.Now().Add(b.cfg.Timeout / 2)
		b.txState = htxEndAck
	}
	return nil
}

func (b *batch) sendInit() error {
	payload := marshalInit(initPkt{
		appID:     b.cfg.AppID,
		supported: b.cfg.localSupported(),
		desired:   b.cfg.localDesired(),
		txWindow:  uint32(b.cfg.TxWindowBytes),
		rxWindow:  uint32(b.cfg.RxWindowBytes),
		prefix:    "",
	})
	// INIT itself goes out with no negotiated escaping (txoptions swap,
	// hydra.c:1206-1208); its HEX format keeps it link-safe.
	return b.s.writer.writePacket(pktINIT, payload, b.opts&^capEscape, b.prefix)
}

// sendFinfo emits the FINFO for the current offer, pulling the next
// offer from the handler first when none is pending. Retries re-send the
// cached payload byte-identically.
func (b *batch) sendFinfo() error {
	if b.lastFinfo == nil {
		for b.txOffer == nil && !b.batchEnded {
			offer := b.s.send.NextFile()
			if offer == nil {
				b.batchEnded = true
				break
			}
			if offer.Size < 0 || offer.Size > SafeMaxOffset {
				closeOffer(offer)
				b.s.send.FileCompleted(offerInfo(offer), 0, ErrFileTooLarge)
				continue
			}
			if offer.Reader == nil {
				closeOffer(offer)
				b.s.send.FileCompleted(offerInfo(offer), 0, ErrHandlerContract)
				continue
			}
			b.txOffer = offer
		}
		if b.txOffer == nil {
			b.txEOB = true
			b.lastFinfo = finfoEOB
		} else {
			b.txEOB = false
			b.txInfo = offerInfo(b.txOffer)
			b.txReader = b.txOffer.Reader
			b.txSeeker, _ = b.txOffer.Reader.(io.Seeker)
			b.txPos = 0
			b.txSkip = false
			b.txErr = nil
			var mtime int64
			if !b.txOffer.ModTime.IsZero() {
				mtime = b.txOffer.ModTime.Unix()
			}
			b.lastFinfo = marshalFinfo(fileMeta{
				mtime: mtime,
				size:  b.txOffer.Size,
				name:  txWireName(b.txOffer.Name),
				path:  b.txOffer.Path,
			}, b.opts&capFPT != 0)
		}
	}
	return b.write(pktFINFO, b.lastFinfo)
}

// txWireName makes a filename safe for the wire: no path components and
// no spaces — HydraCom-lineage peers parse FINFO names with %s, which
// truncates at whitespace (hydra.c:1475).
func txWireName(name string) string {
	return strings.ReplaceAll(SanitizeFilename(name), " ", "_")
}

func offerInfo(o *FileOffer) FileInfo {
	return FileInfo{
		Name:    o.Name,
		Path:    o.Path,
		Size:    o.Size,
		ModTime: o.ModTime,
	}
}

// closeOffer runs the offer's Close hook exactly once, nilling it so
// the belt in finishTxFile and the teardown path cannot double-fire.
// Runs before the matching FileCompleted so the handler observes the
// file already released.
func closeOffer(o *FileOffer) {
	if o == nil || o.Close == nil {
		return
	}
	c := o.Close
	o.Close = nil
	_ = c()
}

// sendData transmits one DATA block (HTX_XDATA, hydra.c:1249-1290).
func (b *batch) sendData() error {
	if b.txSkip {
		b.txState = htxEOF
		b.productive = true
		return nil
	}

	if b.txDataBuf == nil {
		b.txDataBuf = make([]byte, DataBufMax)
	}
	blkLen := b.blk.size()
	n, err := io.ReadFull(b.txReader, b.txDataBuf[:blkLen])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		// Source read error: skip the file.
		b.txErr = err
		b.txSkip = true
		b.txState = htxEOF
		b.productive = true
		return nil
	}
	if n == 0 {
		b.txState = htxEOF
		b.productive = true
		return nil
	}

	if b.txPos+int64(n) > SafeMaxOffset {
		// The announced size is advisory and the source outgrew the
		// representable offset range — fail the file rather than wrap.
		b.txErr = ErrFileTooLarge
		b.txSkip = true
		b.txState = htxEOF
		b.productive = true
		return nil
	}
	if werr := b.write(pktDATA, marshalData(b.txPos, b.txDataBuf[:n])); werr != nil {
		return werr
	}
	b.txPos += int64(n)
	b.blk.good(n)
	b.s.send.FileProgress(b.txInfo, b.txPos)

	if b.txWindow > 0 && b.txPos >= b.txLastAck+b.txWindow {
		b.armTx()
		b.txState = htxDataAck
		return nil
	}
	// End-of-file is detected by the next read returning 0 bytes, like
	// the original — the announced size is advisory.
	b.productive = true
	return nil
}

// txFinfoAck handles FINFOACK (hydra.c:1564-1612).
func (b *batch) txFinfoAck(pkt packet) error {
	if !b.finfoAckWait || (b.txState != htxFinfo && b.txState != htxFinfoAck) {
		return nil // duplicate or unsolicited ack
	}

	// Parse before touching any state: a malformed (runt) ack must
	// leave the retry timer armed so the FINFO is retransmitted
	// (bforce ignores short FINFOACKs without touching send state).
	var offset int32
	if !b.txEOB {
		var err error
		offset, err = parseOffset(pkt.payload)
		if err != nil {
			return nil
		}
	}

	b.finfoAckWait = false
	b.feedBraindead()
	b.txRetries = 0
	b.txTimer = time.Time{}
	b.lastFinfo = nil

	if b.txEOB {
		// The ack value is ignored for EOB — bforce replies -2 to
		// re-sent EOBs and HydraCom advances regardless.
		b.txTimer = time.Now().Add(b.idle())
		b.txState = htxRend
		return nil
	}
	switch {
	case offset >= 0:
		if int64(offset) > b.txInfo.Size {
			// Resume beyond the announced size — a broken or hostile
			// receiver; never fabricate a "delivered" byte count.
			b.txErr = ErrResumeOutOfRange
			b.txSkip = true
			b.txState = htxEOF
			return nil
		}
		b.txPos = int64(offset)
		b.txLastAck = int64(offset)
		if offset > 0 {
			if b.txSeeker == nil {
				b.txErr = ErrResumeOutOfRange
				b.txSkip = true
				b.txState = htxEOF
				return nil
			}
			if _, serr := b.txSeeker.Seek(int64(offset), io.SeekStart); serr != nil {
				b.txErr = serr
				b.txSkip = true
				b.txState = htxEOF
				return nil
			}
		}
		b.txState = htxXdata
	case offset == ackHaveFile:
		// Receiver already has the file. The wire treats this as a
		// delivered outcome; ErrSkip lets the application distinguish
		// it from an actual transfer (go-zmodem semantics).
		closeOffer(b.txOffer)
		b.s.send.FileCompleted(b.txInfo, 0, ErrSkip)
		b.finishTxFile()
	default: // ≤ -2: defer to a later batch
		closeOffer(b.txOffer)
		b.s.send.FileCompleted(b.txInfo, 0, ErrDefer)
		b.finishTxFile()
	}
	return nil
}

func (b *batch) finishTxFile() {
	closeOffer(b.txOffer)
	b.txOffer = nil
	b.txReader = nil
	b.txSeeker = nil
	b.txSkip = false
	b.txErr = nil
	b.lastFinfo = nil
	b.txRetries = 0
	b.txTimer = time.Time{}
	b.finfoAckWait = false
	b.eofAckWait = false
	b.filesSent++
	b.txState = htxFinfo
}

// txDataAck handles DATAACK (hydra.c:1693-1707). Never resets braindead.
func (b *batch) txDataAck(pkt packet) {
	switch b.txState {
	case htxXdata, htxDataAck, htxXwait, htxEOF, htxEOFAck:
	default:
		return
	}
	ack, err := parseOffset(pkt.payload)
	if err != nil || b.txWindow == 0 {
		return
	}
	if int64(ack) > b.txLastAck {
		b.txLastAck = int64(ack)
	}
	if b.txState == htxDataAck && b.txPos < b.txLastAck+b.txWindow {
		b.txRetries = 0
		b.txTimer = time.Time{}
		b.txState = htxXdata
	}
}

// txRpos handles RPOS (hydra.c:1710-1770). Never resets braindead.
func (b *batch) txRpos(pkt packet) error {
	switch b.txState {
	case htxXdata, htxDataAck, htxXwait, htxEOF, htxEOFAck:
	default:
		return nil
	}
	rp, err := parseRpos(pkt.payload)
	if err != nil {
		return nil
	}

	if rp.id == b.txSyncID {
		// Duplicate of a resync we already acted on.
		b.txRetries++
		if b.txRetries > b.cfg.MaxRetries {
			return ErrMaxRetries
		}
		return nil
	}
	b.txSyncID = rp.id
	b.txRetries = 1
	b.txTimer = time.Time{}

	if rp.offset < 0 {
		// Receiver asks us to skip the rest of this file.
		if b.txErr == nil {
			b.txErr = ErrSkip
		}
		b.txSkip = true
		b.txState = htxEOF
		return nil
	}

	b.blk.rpos(rp.blocksize)
	if rp.offset > b.txInfo.Size {
		// Reposition beyond the announced size — bogus; skip the file
		// rather than fabricate data or a delivered count.
		b.txErr = ErrResumeOutOfRange
		b.txSkip = true
		b.txState = htxEOF
		return nil
	}
	if b.txSeeker == nil {
		b.txErr = ErrResumeOutOfRange
		b.txSkip = true
		b.txState = htxEOF
		return nil
	}
	if _, serr := b.txSeeker.Seek(rp.offset, io.SeekStart); serr != nil {
		b.txErr = serr
		b.txSkip = true
		b.txState = htxEOF
		return nil
	}
	b.txPos = rp.offset
	if b.txState != htxXwait {
		b.txState = htxXdata
	}
	return nil
}

// txEOFAck handles EOFACK (hydra.c:1844-1857). The eofAckWait guard
// rejects unsolicited acks that would otherwise complete a file whose
// EOF was never sent.
func (b *batch) txEOFAck() {
	if !b.eofAckWait || (b.txState != htxEOF && b.txState != htxEOFAck) {
		return
	}
	b.eofAckWait = false
	b.feedBraindead()
	closeOffer(b.txOffer)
	if b.txSkip {
		err := b.txErr
		if err == nil {
			err = ErrSkip
		}
		b.s.send.FileCompleted(b.txInfo, b.txPos, err)
	} else {
		b.s.send.FileCompleted(b.txInfo, b.txPos, nil)
	}
	b.finishTxFile()
}

// txIdle handles a received IDLE (hydra.c:1860-1869): wakes a one-way
// pause, or feeds braindead during active transfer states.
func (b *batch) txIdle() {
	if b.txState == htxXwait {
		b.hdxlink = false
		b.txTimer = time.Time{}
		b.txRetries = 0
		b.txState = htxXdata
		return
	}
	if b.txState >= htxFinfo && b.txState < htxRend {
		b.feedBraindead()
	}
}

// txEnd handles a received END (hydra.c:1872-1887): in the END states,
// respond with three more ENDs and finish. Ignored earlier — the peer
// retries until we catch up.
func (b *batch) txEnd() error {
	if b.txState != htxEnd && b.txState != htxEndAck {
		return nil
	}
	for range endResponseCount {
		if err := b.write(pktEND, nil); err != nil {
			return err
		}
	}
	b.txTimer = time.Time{}
	b.txState = htxDone
	return nil
}
