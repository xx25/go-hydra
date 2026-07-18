package hydra

import (
	"bytes"
	"testing"
)

func TestBinEscaper(t *testing.T) {
	cases := []struct {
		name string
		opts uint32
		in   []byte
		want []byte
	}{
		{"dle-always", 0, []byte{DLE}, []byte{DLE, DLE ^ 0x40}},
		{"plain-passthrough", 0, []byte{0x00, 0x1F, 0x41, 0xFF}, []byte{0x00, 0x1F, 0x41, 0xFF}},
		{"xon-xoff", capXON, []byte{charXON, charXOF, 0x12}, []byte{DLE, charXON ^ 0x40, DLE, charXOF ^ 0x40, 0x12}},
		{"ctl", capCTL, []byte{0x00, 0x1F, 0x20, 0x7E, 0x7F}, []byte{DLE, 0x40, DLE, 0x5F, 0x20, 0x7E, DLE, 0x7F ^ 0x40}},
		// TLN: CR escaped only immediately after '@'.
		{"tln", capTLN, []byte{'@', charCR, charCR, '@', 'x', charCR}, []byte{'@', DLE, charCR ^ 0x40, charCR, '@', 'x', charCR}},
		// HIC widens the *test* to the 7-bit twin; the emitted escape keeps bit 7.
		{"hic-dle-twin", capHIC, []byte{0x98}, []byte{DLE, 0x98 ^ 0x40}},
		{"hic-ctl-twin", capHIC | capCTL, []byte{0x85, 0xFF}, []byte{DLE, 0x85 ^ 0x40, DLE, 0xFF ^ 0x40}},
		// HI8 adds no BIN escapes (it forbids BIN at format selection).
		{"hi8-no-escape", capHI8, []byte{0x80, 0xFF}, []byte{0x80, 0xFF}},
	}
	for _, tc := range cases {
		var e binEscaper
		e.reset(tc.opts)
		got := e.putAll(nil, tc.in)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: putAll(% x) = % x, want % x", tc.name, tc.in, got, tc.want)
		}
	}
}

// The TLN tracker resets at each packet start: a trailing '@' must not
// leak into the next packet (hydra.c:451).
func TestBinEscaperTLNResetPerPacket(t *testing.T) {
	var e binEscaper
	e.reset(capTLN)
	e.putAll(nil, []byte{'@'})
	e.reset(capTLN)
	got := e.putAll(nil, []byte{charCR})
	if !bytes.Equal(got, []byte{charCR}) {
		t.Errorf("CR after packet-boundary '@' escaped: % x", got)
	}
}

// dleUnescape resolves DLE-escape pairs the way reader.collect does —
// encoder output is wire bytes, decoders expect the collected form.
func dleUnescape(t *testing.T, b []byte) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < len(b); i++ {
		if b[i] == DLE {
			i++
			if i >= len(b) {
				t.Fatal("dangling DLE in encoded stream")
			}
			out = append(out, b[i]^0x40)
			continue
		}
		out = append(out, b[i])
	}
	return out
}

func TestHexBodyRoundTrip(t *testing.T) {
	var all []byte
	for i := range 256 {
		all = append(all, byte(i))
	}
	enc := hexEncodeBody(nil, all)
	// Encoded form must be free of raw 8-bit and control bytes (except
	// the DLE escapes it introduces).
	for i := 0; i < len(enc); i++ {
		if enc[i] == DLE {
			i++ // escaped byte may be anything ≥ 0x40
			continue
		}
		if enc[i] >= 0x80 {
			t.Fatalf("raw high byte 0x%02x in HEX encoding", enc[i])
		}
	}
	dec, err := hexDecodeBody(dleUnescape(t, enc))
	if err != nil || !bytes.Equal(dec, all) {
		t.Fatalf("hex round-trip: err=%v", err)
	}
}

func TestHexDecodeErrors(t *testing.T) {
	if _, err := hexDecodeBody([]byte(`abc\`)); err == nil {
		t.Error("trailing lone backslash accepted")
	}
	if _, err := hexDecodeBody([]byte(`\F5`)); err == nil {
		t.Error("uppercase hex accepted (reference decoder is lowercase-only)")
	}
	if _, err := hexDecodeBody([]byte(`\f`)); err == nil {
		t.Error("truncated hex escape accepted")
	}
	got, err := hexDecodeBody([]byte(`\\`))
	if err != nil || !bytes.Equal(got, []byte{'\\'}) {
		t.Errorf("doubled backslash = %q, %v", got, err)
	}
}

func TestAscBodyRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 6, 7, 8, 100, 2048} {
		in := make([]byte, size)
		for i := range in {
			in[i] = byte(i*7 + 13)
		}
		var e binEscaper
		e.reset(0) // DLE-only escaping still applies to 0x18 units
		enc := ascEncodeBody(nil, in, &e)
		dec := ascDecodeBody(dleUnescape(t, enc))
		if !bytes.Equal(dec, in) {
			t.Fatalf("asc round-trip failed at size %d", size)
		}
	}
}

func TestUueBodyRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 4, 100, 2048} {
		in := make([]byte, size)
		for i := range in {
			in[i] = byte(i * 31)
		}
		enc := uueEncodeBody(nil, in)
		for _, c := range enc {
			if c < 0x21 || c > 0x60 {
				t.Fatalf("uue char 0x%02x outside '!'..'`'", c)
			}
		}
		dec, err := uueDecodeBody(enc)
		if err != nil || !bytes.Equal(dec, in) {
			t.Fatalf("uue round-trip failed at size %d: %v", size, err)
		}
	}
	if _, err := uueDecodeBody([]byte{0x1F, '!', '!', '!'}); err == nil {
		t.Error("uue char below range accepted")
	}
	// A single dangling char is tolerated as clean termination.
	if out, err := uueDecodeBody([]byte{'!'}); err != nil || len(out) != 0 {
		t.Errorf("dangling uue char: out=%q err=%v", out, err)
	}
}
