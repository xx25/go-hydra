package hydra

import "testing"

// crc16RefFirst16 are the first 16 entries of the static crc16tab in
// bforce/prot_hydra.c (poly 0x8408, reflected). Our generated table must
// match byte-for-byte.
var crc16RefFirst16 = [16]uint16{
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
}

func TestCRC16TableMatchesReference(t *testing.T) {
	for i, want := range crc16RefFirst16 {
		if got := crc16Table[i]; got != want {
			t.Errorf("crc16Table[%d] = 0x%04x, want 0x%04x", i, got, want)
		}
	}
}

// The X-25 check value: complementing the running state over "123456789"
// must give the well-known 0x906E (CRC-16/X-25 uses the same poly, init,
// and final inversion as Hydra's wire format).
func TestCRC16CheckValue(t *testing.T) {
	got := ^crc16Compute([]byte("123456789"))
	if got != 0x906e {
		t.Errorf("^crc16Compute(123456789) = 0x%04x, want 0x906e", got)
	}
}

// Magic-value property: data plus its complemented CRC, low byte first,
// runs through to the residual 0xF0B8.
func TestCRC16Magic(t *testing.T) {
	payloads := [][]byte{
		{},
		{0x00},
		{0xFF, 0x18, 0x18, 0x18},
		[]byte("hydra magic test payload \x00\x01\x02"),
	}
	for _, p := range payloads {
		crc := ^crc16Compute(p)
		full := append(append([]byte{}, p...), byte(crc), byte(crc>>8))
		if got := crc16Compute(full); got != crc16Test {
			t.Errorf("residual for %q = 0x%04x, want 0x%04x", p, got, crc16Test)
		}
	}
}

// CRC-32 check value: complementing the running state over "123456789"
// gives the standard IEEE check 0xCBF43926.
func TestCRC32CheckValue(t *testing.T) {
	got := ^crc32Compute([]byte("123456789"))
	if got != 0xcbf43926 {
		t.Errorf("^crc32Compute(123456789) = 0x%08x, want 0xcbf43926", got)
	}
}

func TestCRC32Magic(t *testing.T) {
	payloads := [][]byte{
		{},
		{0x00},
		{0xFF, 0x18, 0x18, 0x18},
		[]byte("hydra magic test payload \x00\x01\x02"),
	}
	for _, p := range payloads {
		crc := ^crc32Compute(p)
		full := append(append([]byte{}, p...),
			byte(crc), byte(crc>>8), byte(crc>>16), byte(crc>>24))
		if got := crc32Compute(full); got != crc32Test {
			t.Errorf("residual for %q = 0x%08x, want 0x%08x", p, got, crc32Test)
		}
	}
}
