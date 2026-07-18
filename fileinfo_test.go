package hydra

import (
	"bytes"
	"testing"
)

func TestFinfoRoundTrip(t *testing.T) {
	m := fileMeta{
		mtime: 0x66aabbcc,
		size:  123456,
		txid:  0,
		count: 3,
		name:  "file1.zip",
		path:  "outbound/file1.zip",
	}
	payload := marshalFinfo(m, true)
	if isFinfoEOB(payload) {
		t.Fatal("real FINFO detected as EOB")
	}
	got, err := parseFinfo(payload)
	if err != nil || got != m {
		t.Fatalf("parseFinfo = %+v, %v", got, err)
	}
}

// Without FPT the real filename must not go on the wire, and neither when
// the path adds nothing over the short name.
func TestFinfoNoFPT(t *testing.T) {
	m := fileMeta{size: 10, name: "a.txt", path: "dir/a.txt"}
	payload := marshalFinfo(m, false)
	if bytes.Contains(payload, []byte("dir/")) {
		t.Fatalf("real name leaked without FPT: %q", payload)
	}
	got, err := parseFinfo(payload)
	if err != nil || got.name != "a.txt" || got.path != "" {
		t.Fatalf("parseFinfo = %+v, %v", got, err)
	}

	same := marshalFinfo(fileMeta{size: 10, name: "a.txt", path: "a.txt"}, true)
	if !bytes.Equal(same, payload) {
		t.Fatalf("redundant path emitted: %q", same)
	}
}

// Conformance SingleNulEOB: end-of-batch is one NUL byte; detection is
// payload[0]==0 at any length (SPEC §3.4, §13.1).
func TestFinfoEOB(t *testing.T) {
	if len(finfoEOB) != 1 || finfoEOB[0] != 0 {
		t.Fatalf("finfoEOB = % x, want a single NUL", finfoEOB)
	}
	if !isFinfoEOB(finfoEOB) {
		t.Error("single NUL not detected as EOB")
	}
	// Defensive: 40 zero-hex chars + NUL from hypothetical spec-literal peers.
	legacy := append(bytes.Repeat([]byte{'0'}, 40), 0)
	if isFinfoEOB(legacy) {
		t.Error("40-zero-hex header misdetected: first byte is '0', not NUL")
	}
	// A header of all-zero VALUES with an empty filename is the other
	// legacy form: 8 hex zeros parse to zero fields and an empty name.
	if isFinfoEOB([]byte{}) != true {
		t.Error("empty payload should be treated as EOB")
	}
}

func TestFinfoMalformed(t *testing.T) {
	if _, err := parseFinfo([]byte("tooshort")); err == nil {
		t.Error("short FINFO accepted")
	}
	// Header present but filename missing its NUL terminator.
	bad := append([]byte("00000000000000010000000000000000000000ff"), "name-no-nul"...)
	if _, err := parseFinfo(bad); err == nil {
		t.Error("unterminated filename accepted")
	}
	// Non-hex header.
	bad2 := append([]byte("zzzzzzzz000000010000000000000000000000ff"), "n\x00"...)
	if _, err := parseFinfo(bad2); err == nil {
		t.Error("non-hex header accepted")
	}
}
