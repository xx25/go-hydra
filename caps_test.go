package hydra

import "testing"

func TestParseCapsRoundTrip(t *testing.T) {
	want := capXON | capTLN | capCTL | capHIC | capHI8 | capBRK | capC32
	s := capsString(want)
	if s != "XON,TLN,CTL,HIC,HI8,BRK,C32" {
		t.Fatalf("capsString = %q", s)
	}
	if got := parseCaps(s); got != want {
		t.Fatalf("parseCaps(%q) = %#x, want %#x", s, got, want)
	}
}

// FTNd advertises PLZ (zlib); future peers may add other codes. They must
// drop out silently (SPEC §3.2, §13.1).
func TestParseCapsUnknownCodes(t *testing.T) {
	got := parseCaps("XON,TLN,CTL,HIC,HI8,BRK,C32,PLZ,FOO,XYZ")
	want := capXON | capTLN | capCTL | capHIC | capHI8 | capBRK | capC32
	if got != want {
		t.Fatalf("parseCaps with unknowns = %#x, want %#x", got, want)
	}
}

func TestParseCapsWhitespaceAndCase(t *testing.T) {
	got := parseCaps(" xon , c32 ")
	if got != capXON|capC32 {
		t.Fatalf("parseCaps lenient = %#x", got)
	}
	if parseCaps("") != 0 {
		t.Fatalf("parseCaps(empty) != 0")
	}
}
