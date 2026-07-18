package hydra

import (
	"bufio"
	"io"
	"sync/atomic"
)

// transportReader implements the receive half of the wire format: the
// per-byte state machine of HydraCom's rxpkt() (hydra.c:540-821). It
// runs in its own goroutine, so the negotiated RX options arrive through
// an atomic the session updates after INIT (pre-negotiation the assumed
// set applies: high-bit strip plus control filtering).
type transportReader struct {
	r    *bufio.Reader
	opts *atomic.Uint32

	// Persistent per-byte state (survives across readPacket calls,
	// exactly like rxpkt's statics).
	dles     int  // consecutive-DLE cancel counter
	format   byte // current frame's format byte
	inPacket bool
	overflow bool
	body     []byte // collected, DLE-unescaped body bytes

	// garbage counts bytes discarded outside any frame, for diagnostics.
	garbage int
}

func newTransportReader(r io.Reader, opts *atomic.Uint32) *transportReader {
	return &transportReader{
		r:    bufio.NewReaderSize(r, 8192),
		opts: opts,
		body: make([]byte, 0, 4096),
	}
}

// readPacket blocks until one CRC-valid packet arrives, the peer's
// cancel sequence is detected (ErrPeerCancel), or the transport errors.
// Malformed frames, bad CRCs, and inter-frame garbage are consumed
// silently — recovery in Hydra is offset-driven, never framing-driven.
func (r *transportReader) readPacket() (packet, error) {
	for {
		c, err := r.r.ReadByte()
		if err != nil {
			return packet{}, err
		}
		opts := r.opts.Load()

		if opts&capHI8 != 0 {
			c &= 0x7f
		}
		n := c
		if opts&capHIC != 0 {
			n &= 0x7f
		}

		// Inbound noise filter (hydra.c:556-563): unescaped flow-control
		// and control bytes are eaten before the DLE machine sees them.
		// They touch neither the cancel counter nor the body. A byte
		// whose masked value is DLE is never eaten, and TLN needs no RX
		// handling.
		if n != DLE &&
			((opts&capXON != 0 && (n == charXON || n == charXOF)) ||
				(opts&capCTL != 0 && (n < 32 || n == 127))) {
			continue
		}

		if r.dles > 0 || c == DLE {
			switch c {
			case DLE:
				r.dles++
				if r.dles >= detectCancelCount {
					r.dles = 0
					return packet{}, ErrPeerCancel
				}
			case fmtBIN, fmtHEX, fmtASC, fmtUUE:
				// Packet start — abandons any half-collected frame.
				r.format = c
				r.body = r.body[:0]
				r.inPacket = true
				r.overflow = false
				r.dles = 0
			case fmtEnd:
				// NOTE: dles is deliberately NOT reset here — runs of
				// empty terminators accumulate toward cancel (c:568).
				pkt, ok := r.finishPacket()
				if ok {
					return pkt, nil
				}
			default:
				// DLE-escaped byte: recover the original.
				r.collect(c ^ 0x40)
				r.dles = 0
			}
			continue
		}

		// Ordinary byte.
		if r.inPacket {
			r.collect(c)
		} else {
			r.garbage++
		}
	}
}

func (r *transportReader) collect(c byte) {
	if !r.inPacket || r.overflow {
		return
	}
	if len(r.body) >= maxEncodedLen {
		r.overflow = true
		return
	}
	r.body = append(r.body, c)
}

// finishPacket runs the format decode and CRC check on the collected
// body (hydra.c:574-680). Returns ok=false for anything droppable: no
// packet in progress, overflow, decode error, runt, or bad CRC.
func (r *transportReader) finishPacket() (packet, bool) {
	if !r.inPacket {
		r.garbage++
		return packet{}, false
	}
	inPacket := r.inPacket
	overflow := r.overflow
	r.inPacket = false
	r.overflow = false
	if !inPacket || overflow {
		return packet{}, false
	}

	var decoded []byte
	var err error
	switch r.format {
	case fmtBIN:
		decoded = r.body
	case fmtHEX:
		decoded, err = hexDecodeBody(r.body)
	case fmtASC:
		decoded = ascDecodeBody(r.body)
	case fmtUUE:
		decoded, err = uueDecodeBody(r.body)
	}
	if err != nil || len(decoded) > maxDecodedLen {
		return packet{}, false
	}

	// HEX is always CRC-16; other formats use CRC-32 once C32 is active
	// (no per-packet flag — both sides flip at INIT, and the RINIT gate
	// guarantees no BIN packet crosses before that).
	crcLen := 2
	use32 := r.format != fmtHEX && r.opts.Load()&capC32 != 0
	if use32 {
		crcLen = 4
	}
	if len(decoded) < crcLen+1 {
		return packet{}, false // runt
	}
	if use32 {
		if crc32Compute(decoded) != crc32Test {
			return packet{}, false
		}
	} else {
		if crc16Compute(decoded) != crc16Test {
			return packet{}, false
		}
	}

	bodyEnd := len(decoded) - crcLen
	typ := decoded[bodyEnd-1]
	payload := append([]byte(nil), decoded[:bodyEnd-1]...)
	return packet{typ: typ, payload: payload}, true
}
