package hydra

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"
)

func newTestRW(rxOpts uint32) (*transportWriter, *transportReader, *bytes.Buffer) {
	var buf bytes.Buffer
	var opts atomic.Uint32
	opts.Store(rxOpts)
	return newTransportWriter(&buf), newTransportReader(&buf, &opts), &buf
}

// The spec's own golden vector: a framed START packet is exactly
// 18 63 41 5c 66 35 5c 61 33 18 61 0d 0a — this pins DLE framing, HEX
// encoding, CRC-16 (0x5C0A running / A3F5 complement), and byte order in
// one shot (fsc0072.md §9).
func TestGoldenStartFrame(t *testing.T) {
	w, _, buf := newTestRW(0)
	if err := w.writePacket(pktSTART, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x18, 0x63, 0x41, 0x5c, 0x66, 0x35, 0x5c, 0x61, 0x33, 0x18, 0x61, 0x0d, 0x0a}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("START frame = % x, want % x", buf.Bytes(), want)
	}
}

func TestFrameRoundTripFormats(t *testing.T) {
	var big []byte
	for i := range 2048 {
		big = append(big, byte(i))
	}
	payloads := [][]byte{nil, {0}, []byte("hello"), {DLE, DLE, DLE}, big}

	cases := []struct {
		name string
		opts uint32
	}{
		{"bin-crc16-noescape", 0},
		{"bin-crc16-assumed", capAssumed},
		{"bin-crc32", capAssumed | capC32},
		{"hex-forced-hi8", capHI8 | capXON | capTLN | capCTL | capHIC},
		{"asc", capHI8 | capASC | capXON | capCTL | capHIC},
		{"uue", capHI8 | capCTL | capUUE | capXON | capHIC},
		{"uue-crc32", capHI8 | capCTL | capUUE | capC32},
	}
	for _, tc := range cases {
		for _, payload := range payloads {
			w, r, _ := newTestRW(tc.opts)
			data := marshalData(0x1234, payload)
			if err := w.writePacket(pktDATA, data, tc.opts, ""); err != nil {
				t.Fatal(err)
			}
			pkt, err := r.readPacket()
			if err != nil {
				t.Fatalf("%s payload %d bytes: %v", tc.name, len(payload), err)
			}
			if pkt.typ != pktDATA || !bytes.Equal(pkt.payload, data) {
				t.Fatalf("%s payload %d bytes: round-trip mismatch (typ %c, %d bytes)",
					tc.name, len(payload), pkt.typ, len(pkt.payload))
			}
		}
	}
}

// HEX supervisory frames must survive a 7-bit-with-filtering receiver
// (the pre-INIT assumed state) even when the sender escapes nothing.
func TestFrameHexSurvivesAssumedFilter(t *testing.T) {
	w, r, _ := newTestRW(capAssumed)
	initPayload := marshalInit(initPkt{
		appID:     "2b1aab00gohydra,0.1",
		supported: capDefaultSupported,
		desired:   capDefaultSupported,
	})
	if err := w.writePacket(pktINIT, initPayload, 0, ""); err != nil {
		t.Fatal(err)
	}
	pkt, err := r.readPacket()
	if err != nil || pkt.typ != pktINIT {
		t.Fatalf("INIT through assumed filter: %v", err)
	}
	got, err := parseInit(pkt.payload)
	if err != nil || got.appID != "2b1aab00gohydra,0.1" {
		t.Fatalf("INIT payload corrupted: %+v %v", got, err)
	}
}

// CRLF only on non-DATA non-BIN frames (hydra.c:514-517).
func TestFrameCRLFRule(t *testing.T) {
	w, _, buf := newTestRW(0)

	// BIN FINFOACK: no CRLF.
	if err := w.writePacket(pktFINFOACK, marshalOffset(0), 0, ""); err != nil {
		t.Fatal(err)
	}
	if bytes.HasSuffix(buf.Bytes(), []byte{charCR, charLF}) {
		t.Error("BIN FINFOACK carries CRLF")
	}
	buf.Reset()

	// HEX END: CRLF.
	if err := w.writePacket(pktEND, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte{charCR, charLF}) {
		t.Error("HEX END missing CRLF")
	}
	buf.Reset()

	// HEX-format DATA under HI8: DATA never gets CRLF.
	opts := uint32(capHI8)
	if err := w.writePacket(pktDATA, marshalData(0, []byte("x")), opts, ""); err != nil {
		t.Fatal(err)
	}
	if bytes.HasSuffix(buf.Bytes(), []byte{charCR, charLF}) {
		t.Error("HEX DATA carries CRLF")
	}
}

func TestReaderCancelDetection(t *testing.T) {
	// 5 consecutive DLEs → ErrPeerCancel.
	_, r, buf := newTestRW(capAssumed)
	buf.Write(bytes.Repeat([]byte{DLE}, detectCancelCount))
	if _, err := r.readPacket(); err != ErrPeerCancel {
		t.Fatalf("5 DLEs: err = %v, want ErrPeerCancel", err)
	}

	// 4 DLEs then a valid frame: no cancel, frame parses.
	w, r2, buf2 := newTestRW(capAssumed)
	buf2.Write(bytes.Repeat([]byte{DLE}, detectCancelCount-1))
	buf2.WriteByte('x') // resets the run
	if err := w.writePacket(pktIDLE, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	pkt, err := r2.readPacket()
	if err != nil || pkt.typ != pktIDLE {
		t.Fatalf("4 DLEs + frame: %v (typ %c)", err, pkt.typ)
	}

	// Empty-terminator runs accumulate: DLE 'a' pairs never reset the
	// counter (hydra.c:568), so 5 pairs trigger cancel.
	_, r3, buf3 := newTestRW(capAssumed)
	for range detectCancelCount {
		buf3.Write([]byte{DLE, fmtEnd})
	}
	if _, err := r3.readPacket(); err != ErrPeerCancel {
		t.Fatalf("DLE-'a' run: err = %v, want ErrPeerCancel", err)
	}
}

func TestReaderGarbageAndBadCRC(t *testing.T) {
	w, r, buf := newTestRW(capAssumed)

	// Garbage, then a corrupted frame (bad CRC), then a good frame.
	buf.WriteString("prompt> hydra\r some line noise \xff\xfe")
	if err := w.writePacket(pktEOFACK, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	// Corrupt the EOFACK frame's CRC region (flip a bit mid-frame).
	b := buf.Bytes()
	b[len(b)-3] ^= 0x01
	if err := w.writePacket(pktIDLE, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	pkt, err := r.readPacket()
	if err != nil || pkt.typ != pktIDLE {
		t.Fatalf("after garbage+badCRC: %v (typ %c)", err, pkt.typ)
	}
	if r.garbage == 0 {
		t.Error("garbage counter not incremented")
	}
}

func TestReaderOversizeFrameDiscarded(t *testing.T) {
	w, r, buf := newTestRW(0)
	// A frame body exceeding maxEncodedLen must be discarded silently.
	buf.Write([]byte{DLE, fmtBIN})
	junk := bytes.Repeat([]byte{'j'}, maxEncodedLen+100)
	buf.Write(junk)
	buf.Write([]byte{DLE, fmtEnd})
	if err := w.writePacket(pktIDLE, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	pkt, err := r.readPacket()
	if err != nil || pkt.typ != pktIDLE {
		t.Fatalf("after oversize frame: %v", err)
	}
}

// A packet-start marker mid-frame abandons the old frame (hydra.c:571).
func TestReaderRestartMidFrame(t *testing.T) {
	w, r, buf := newTestRW(0)
	buf.Write([]byte{DLE, fmtBIN, 'p', 'a', 'r', 't', 'i', 'a', 'l'})
	if err := w.writePacket(pktEOFACK, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	pkt, err := r.readPacket()
	if err != nil || pkt.typ != pktEOFACK {
		t.Fatalf("restart mid-frame: %v", err)
	}
}

// HI8 strips bit 7 on receive; the writer avoids BIN under HI8, and HEX
// bodies are 7-bit clean, so a high-bit-mangling link still delivers.
func TestReaderHI8Strip(t *testing.T) {
	opts := uint32(capHI8 | capCTL | capXON | capHIC)
	w, r, buf := newTestRW(opts)
	data := marshalData(7, []byte{0x00, 0x7F, 0x80, 0xFF})
	if err := w.writePacket(pktDATA, data, opts, ""); err != nil {
		t.Fatal(err)
	}
	// Simulate a 7-bit link mangling bit 7 of every byte on the wire.
	b := buf.Bytes()
	for i := range b {
		b[i] |= 0x80
	}
	pkt, err := r.readPacket()
	if err != nil || pkt.typ != pktDATA || !bytes.Equal(pkt.payload, data) {
		t.Fatalf("HI8 through 7-bit link: %v", err)
	}
}

func TestWriterCancelSequence(t *testing.T) {
	w, _, buf := newTestRW(0)
	if err := w.writeCancel(); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte{DLE}, cancelCount), bytes.Repeat([]byte{charBS}, cancelPadCount)...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("cancel sequence = % x", buf.Bytes())
	}
}

func TestWriterPrefix(t *testing.T) {
	w, _, buf := newTestRW(0)
	// 223 → NUL, 221/222 → skipped, others literal.
	prefix := string([]byte{'A', 221, 222, 223, 'B'})
	if err := w.writePacket(pktIDLE, nil, 0, prefix); err != nil {
		t.Fatal(err)
	}
	want := []byte{'A', 0, 'B', DLE, fmtHEX}
	if !bytes.HasPrefix(buf.Bytes(), want) {
		t.Fatalf("prefix emission = % x", buf.Bytes()[:6])
	}
}

var _ io.Reader = (*bytes.Buffer)(nil)
