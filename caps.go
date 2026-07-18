package hydra

import "strings"

// capOrder fixes the canonical on-wire order of capability codes, matching
// HydraCom 1.00's flag table. Serialisation always follows this order.
var capOrder = []struct {
	bit  uint32
	code string
}{
	{capXON, "XON"},
	{capTLN, "TLN"},
	{capCTL, "CTL"},
	{capHIC, "HIC"},
	{capHI8, "HI8"},
	{capBRK, "BRK"},
	{capASC, "ASC"},
	{capUUE, "UUE"},
	{capC32, "C32"},
	{capDEV, "DEV"},
	{capFPT, "FPT"},
}

// capDefaultSupported is what go-hydra advertises in SupportedFlags: the
// five escape codes plus CRC-32, device channel, and full-path names.
// ASC and UUE are decode-only, so they are deliberately absent, and BRK
// is omitted because an io.Writer transport cannot transmit a break
// (HydraCom's own HCAN_OPTIONS also omits BRK, hydra.h:160).
const capDefaultSupported = capXON | capTLN | capCTL | capHIC | capHI8 |
	capC32 | capDEV | capFPT

// parseCaps converts a comma-separated 3-char code list into a bit set.
// Unknown codes (FTNd's PLZ, future extensions) are silently dropped —
// they fall out of the intersection naturally (SPEC §3.2).
func parseCaps(list string) uint32 {
	var caps uint32
	for code := range strings.SplitSeq(list, ",") {
		code = strings.TrimSpace(strings.ToUpper(code))
		for _, e := range capOrder {
			if e.code == code {
				caps |= e.bit
				break
			}
		}
	}
	return caps
}

// capsString serialises a bit set into the canonical comma-separated list.
func capsString(caps uint32) string {
	var b strings.Builder
	for _, e := range capOrder {
		if caps&e.bit == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(e.code)
	}
	return b.String()
}
