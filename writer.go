package hydra

import (
	"bufio"
	"io"
	"sync"
)

// transportWriter serialises frames onto the transport. It is
// mutex-guarded so Abort (cancel sequence) and the session event loop can
// share it; within a session all packets come from the single event-loop
// goroutine, so ordering is deterministic.
//
// The writer itself is stateless about negotiation — the caller passes
// the effective TX options and prefix with every packet, mirroring
// HydraCom's txpkt reading the txoptions global (hydra.c:335-536).
type transportWriter struct {
	mu  sync.Mutex
	w   *bufio.Writer
	esc binEscaper
}

func newTransportWriter(w io.Writer) *transportWriter {
	return &transportWriter{w: bufio.NewWriterSize(w, 8192)}
}

// selectFormat implements txpkt's format switch (hydra.c:345-367): the
// five supervisory types are always HEX; everything else is BIN unless
// HI8 bans 8-bit bodies, in which case the best negotiated 7-bit format
// wins (UUE needs CTL too, per the original's guard).
func selectFormat(typ byte, opts uint32) byte {
	switch typ {
	case pktSTART, pktINIT, pktINITACK, pktEND, pktIDLE:
		return fmtHEX
	}
	if opts&capHI8 != 0 {
		switch {
		case opts&capCTL != 0 && opts&capUUE != 0:
			return fmtUUE
		case opts&capASC != 0:
			return fmtASC
		default:
			return fmtHEX
		}
	}
	return fmtBIN
}

// writePacket frames one packet:
//
//	[prefix] DLE <format> encode(payload‖type‖crc) DLE 'a' [CR LF]
//
// crc32 applies when the format is not HEX and C32 is in the effective
// set; CR LF is appended only when type != DATA && format != BIN
// (hydra.c:514-517 — BIN supervisory packets carry no CRLF).
func (w *transportWriter) writePacket(typ byte, payload []byte, opts uint32, prefix string) error {
	// The mutex covers the whole encode+write: w.esc is per-writer
	// state, and Abort's cancel write may interleave from another
	// goroutine.
	w.mu.Lock()
	defer w.mu.Unlock()
	format := selectFormat(typ, opts)

	body := make([]byte, 0, len(payload)+5)
	body = append(body, payload...)
	body = append(body, typ)
	if format != fmtHEX && opts&capC32 != 0 {
		crc := ^crc32Compute(body)
		body = append(body, byte(crc), byte(crc>>8), byte(crc>>16), byte(crc>>24))
	} else {
		crc := ^crc16Compute(body)
		body = append(body, byte(crc), byte(crc>>8))
	}

	out := make([]byte, 0, len(body)*2+len(prefix)+8)
	for i := 0; i < len(prefix); i++ {
		switch prefix[i] {
		case 221, 222:
			// Break / delay magics — meaningless on an io.Writer
			// transport; skipped.
		case 223:
			out = append(out, 0)
		default:
			out = append(out, prefix[i])
		}
	}
	out = append(out, DLE, format)
	w.esc.reset(opts)
	switch format {
	case fmtBIN:
		out = w.esc.putAll(out, body)
	case fmtHEX:
		out = hexEncodeBody(out, body)
	case fmtASC:
		out = ascEncodeBody(out, body, &w.esc)
	case fmtUUE:
		out = uueEncodeBody(out, body)
	}
	out = append(out, DLE, fmtEnd)
	if typ != pktDATA && format != fmtBIN {
		out = append(out, charCR, charLF)
	}

	if _, err := w.w.Write(out); err != nil {
		return err
	}
	return w.w.Flush()
}

// writeRaw pushes literal bytes (autostart string) onto the transport.
func (w *transportWriter) writeRaw(p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.w.Write(p); err != nil {
		return err
	}
	return w.w.Flush()
}

// writeCancel emits the out-of-band abort sequence: 8×DLE then 10×BS
// (hydra.c abortstr — the C string's trailing NUL is not transmitted).
func (w *transportWriter) writeCancel() error {
	seq := make([]byte, 0, cancelCount+cancelPadCount)
	for range cancelCount {
		seq = append(seq, DLE)
	}
	for range cancelPadCount {
		seq = append(seq, charBS)
	}
	return w.writeRaw(seq)
}
