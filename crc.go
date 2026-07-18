package hydra

import "hash/crc32"

// CRC-16: Hydra uses the bit-reflected CCITT polynomial 0x8408 (FSC-0072,
// HydraCom crc16tab) — NOT XMODEM's unreflected 0x1021 (Janus) and NOT the
// ZMODEM CRC-16. Init 0xFFFF. The wire carries the one's complement of the
// running state, low byte first.
//
// Magic-value test on receive: running payload || type || crc-bytes through
// the same update yields 0xF0B8 when the packet is good (HydraCom h_crc16test).
const (
	crc16Init uint16 = 0xFFFF
	crc16Test uint16 = 0xF0B8
	crc16Poly uint16 = 0x8408
)

// CRC-32: standard reflected IEEE polynomial 0xEDB88320, init 0xFFFFFFFF.
// Like CRC-16 the wire carries the one's complement of the running state,
// low byte first. Identical to ZMODEM's CRC-32.
//
// Magic-value test on receive: 0xDEBB20E3 (HydraCom h_crc32test).
const (
	crc32Init uint32 = 0xFFFFFFFF
	crc32Test uint32 = 0xDEBB20E3
)

// crc16Table is generated for poly 0x8408 in reflected (right-shift) form.
// crc_test.go cross-checks entries against the literal table in
// bforce/prot_hydra.c.
var crc16Table [256]uint16

// crc32Table is the standard IEEE table — byte-for-byte what HydraCom's
// crc32tab contains.
var crc32Table = crc32.MakeTable(crc32.IEEE)

func init() {
	for i := range 256 {
		c := uint16(i)
		for range 8 {
			if c&1 != 0 {
				c = (c >> 1) ^ crc16Poly
			} else {
				c >>= 1
			}
		}
		crc16Table[i] = c
	}
}

// crc16Update advances the running CRC-16 by one byte:
//
//	crc = tab[(crc ^ b) & 0xff] ^ (crc >> 8)
func crc16Update(crc uint16, b byte) uint16 {
	return crc16Table[byte(crc)^b] ^ (crc >> 8)
}

// crc16Compute runs crc16Update over p starting from init. Returns the raw
// running state — the caller complements it when marshalling to the wire.
func crc16Compute(p []byte) uint16 {
	crc := crc16Init
	for _, b := range p {
		crc = crc16Update(crc, b)
	}
	return crc
}

// crc32Update advances the running CRC-32 by one byte using the standard
// reflected formula, without any final inversion.
func crc32Update(crc uint32, b byte) uint32 {
	return crc32Table[byte(crc)^b] ^ (crc >> 8)
}

// crc32Compute runs crc32Update over p starting from init. Raw running
// state — complemented at marshal time, mirroring crc16Compute.
func crc32Compute(p []byte) uint32 {
	crc := crc32Init
	for _, b := range p {
		crc = crc32Update(crc, b)
	}
	return crc
}
