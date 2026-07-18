package hydra

import (
	"bytes"
	"testing"
)

func TestOffsetRoundTrip(t *testing.T) {
	for _, v := range []int32{0, 1, 0x7FFFFFFE, -1, -2} {
		got, err := parseOffset(marshalOffset(v))
		if err != nil || got != v {
			t.Errorf("offset %d round-trip = %d, %v", v, got, err)
		}
	}
	if _, err := parseOffset([]byte{1, 2, 3}); err == nil {
		t.Error("short offset payload accepted")
	}
}

func TestDataRoundTrip(t *testing.T) {
	payload := marshalData(0x12345678, []byte("abc"))
	want := []byte{0x78, 0x56, 0x34, 0x12, 'a', 'b', 'c'}
	if !bytes.Equal(payload, want) {
		t.Fatalf("marshalData = % x, want % x", payload, want)
	}
	off, data, err := parseData(payload)
	if err != nil || off != 0x12345678 || string(data) != "abc" {
		t.Fatalf("parseData = %d, %q, %v", off, data, err)
	}
}

// Emit must be the 12-byte LONG form (SPEC §13.1 / conformance
// EmitLongAcceptShort); parse must accept both 12- and 10-byte forms.
func TestRposEmitLongParseBoth(t *testing.T) {
	r := rposPkt{offset: 0x1000, blocksize: 512, id: 7}
	out := marshalRpos(r)
	if len(out) != 12 {
		t.Fatalf("marshalRpos length = %d, want 12 (LONG form)", len(out))
	}
	got, err := parseRpos(out)
	if err != nil || got != r {
		t.Fatalf("parseRpos(LONG) = %+v, %v", got, err)
	}

	// Hand-crafted 10-byte WORD form as bforce/FTNd emit it.
	word := []byte{
		0x00, 0x10, 0x00, 0x00, // offset 0x1000
		0x00, 0x02, // blocksize 512 as WORD
		0x07, 0x00, 0x00, 0x00, // id 7
	}
	got, err = parseRpos(word)
	if err != nil || got != r {
		t.Fatalf("parseRpos(WORD) = %+v, %v", got, err)
	}

	if _, err := parseRpos(out[:8]); err == nil {
		t.Error("8-byte RPOS accepted")
	}

	// Skip request round-trips the -2 sentinel.
	skip := marshalRpos(rposPkt{offset: -2, blocksize: 512, id: 8})
	got, err = parseRpos(skip)
	if err != nil || got.offset != -2 {
		t.Fatalf("parseRpos(skip) = %+v, %v", got, err)
	}
}

func TestInitRoundTrip(t *testing.T) {
	p := initPkt{
		appID:     "2b1aab00gohydra,0.1",
		supported: capDefaultSupported,
		desired:   capDefaultSupported,
		txWindow:  0,
		rxWindow:  4096,
		prefix:    "",
	}
	payload := marshalInit(p)

	// Conformance FiveFieldInit: exactly 5 NUL-terminated fields.
	if n := bytes.Count(payload, []byte{0}); n != 5 {
		t.Fatalf("INIT payload has %d NULs, want 5", n)
	}
	// Windows are one concatenated 16-hex-char field.
	fields := bytes.Split(payload, []byte{0})
	if string(fields[3]) != "0000000000001000" {
		t.Fatalf("windows field = %q", fields[3])
	}

	got, err := parseInit(payload)
	if err != nil || got != p {
		t.Fatalf("parseInit = %+v, %v", got, err)
	}
}

// Liberal receive: fewer than 5 fields defaults the rest (SPEC §13.1).
func TestInitParseShortForms(t *testing.T) {
	got, err := parseInit([]byte("someapp\x00XON,TLN,CTL\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if got.appID != "someapp" || got.supported != capXON|capTLN|capCTL ||
		got.desired != 0 || got.txWindow != 0 || got.prefix != "" {
		t.Fatalf("short INIT parse = %+v", got)
	}
	if _, err := parseInit([]byte("no-nul-at-all")); err == nil {
		t.Error("INIT without any NUL accepted")
	}
}

func TestDevDataRoundTrip(t *testing.T) {
	d := devDataPkt{id: 42, device: "CON", payload: []byte("hello")}
	got, err := parseDevData(marshalDevData(d))
	if err != nil || got.id != 42 || got.device != "CON" || string(got.payload) != "hello" {
		t.Fatalf("devdata round-trip = %+v, %v", got, err)
	}
	id, err := parseDevAck(marshalDevAck(42))
	if err != nil || id != 42 {
		t.Fatalf("devack round-trip = %d, %v", id, err)
	}
}
