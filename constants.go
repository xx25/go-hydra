package hydra

import "time"

// DLE is Hydra's data-link-escape byte (FSC-0072 H_DLE). Note it is ASCII
// CAN (0x18), not ASCII DLE (0x10) — Hydra reuses ZMODEM's ZDLE value but
// applies it on the *outside* of the frame.
const DLE byte = 0x18

// Control bytes relevant to the escape rules negotiated via capability
// flags (SPEC §2.2, §3.2).
const (
	charXON byte = 0x11
	charXOF byte = 0x13
	charCR  byte = 0x0D
	charLF  byte = 0x0A
	charAT  byte = 0x40 // '@' — TLN escapes a CR that follows it
	charBS  byte = 0x08 // cancel sequence padding
)

// Frame format bytes. A frame is
//
//	[prefix] DLE <format> <encoded body> DLE fmtEnd [CR LF]
//
// where <format> selects the body encoding. fmtEnd terminates every frame
// regardless of encoding. (SPEC §2.1)
const (
	fmtEnd byte = 'a' // 0x61 — end-of-frame marker after DLE
	fmtBIN byte = 'b' // 0x62 — 8-bit, DLE-escaped
	fmtHEX byte = 'c' // 0x63 — 7-bit safe, \xx high bytes, always CRC-16
	fmtASC byte = 'd' // 0x64 — 7-bits-in-8 shift register (decode only)
	fmtUUE byte = 'e' // 0x65 — uuencode 3→4 (decode only)
)

// Packet type bytes (SPEC §3). The type byte travels at the end of the
// encoded body, before the CRC.
const (
	pktSTART    byte = 'A' // 0x41 HEX  empty
	pktINIT     byte = 'B' // 0x42 HEX  AppID/flags/windows/prefix
	pktINITACK  byte = 'C' // 0x43 HEX  empty
	pktFINFO    byte = 'D' // 0x44 BIN  5×8 hex header + filename(s)
	pktFINFOACK byte = 'E' // 0x45 BIN  4-byte LE signed offset / -1 / -2
	pktDATA     byte = 'F' // 0x46 BIN  4-byte LE offset + data
	pktDATAACK  byte = 'G' // 0x47 BIN  4-byte LE offset reached
	pktRPOS     byte = 'H' // 0x48 BIN  offset + blocksize + rpos id
	pktEOF      byte = 'I' // 0x49 BIN  4-byte LE final offset (or -2 skip)
	pktEOFACK   byte = 'J' // 0x4A BIN  empty
	pktEND      byte = 'K' // 0x4B HEX  empty
	pktIDLE     byte = 'L' // 0x4C HEX  empty
	pktDEVDATA  byte = 'M' // 0x4D BIN  id + device name + payload
	pktDEVDACK  byte = 'N' // 0x4E BIN  id
)

// Capability flags. On the wire these are comma-separated 3-char codes in
// the INIT packet (SPEC §3.2); internally we track them as a bit set. Bit
// values mirror HydraCom 1.00's HCAN_* constants for debuggability.
const (
	capXON uint32 = 1 << iota // escape XON/XOFF
	capTLN                    // escape CR-after-'@' (Telenet)
	capCTL                    // escape ASCII 0–31, 127
	capHIC                    // escape control chars with bit 7 set too
	capHI8                    // escape 128–255, strip high bit on receive
	capBRK                    // can transmit a break signal
	capASC                    // supports ASC encoding
	capUUE                    // supports UUE encoding
	capC32                    // supports CRC-32
	capDEV                    // supports DEVDATA packets
	capFPT                    // supports full-path filenames
)

// capAssumed is the RX option set assumed before INIT/INITACK completes:
// the receiver strips the high bit and filters control characters until
// negotiation lands (HydraCom HRXI_OPTIONS, hydra.c:1102). The TX side
// assumes nothing (HTXI_OPTIONS = 0) — HEX framing keeps START/INIT safe.
const capAssumed = capXON | capTLN | capCTL | capHIC | capHI8

// capUnion is HydraCom's HUNN set: capabilities folded into every
// negotiation regardless of either side's desired list, so C32/DEV (and
// ASC/UUE, which we don't support) activate on mutual support alone
// (hydra.c:1395-1398; knowledge: negotiation is a UNION of desires).
const capUnion = capASC | capUUE | capC32 | capDEV

// capEscape is the set of flags that alter the escape rules. The vital
// check after negotiation: every escape flag we desired must survive the
// merge, or the link cannot be made safe (HydraCom's HNEC compare,
// hydra.c:1399).
const capEscape = capXON | capTLN | capCTL | capHIC | capHI8

// hydraRevstamp is HydraCom 1.00's H_REVSTAMP, emitted as the 8-hex-char
// prefix of our AppID. No surveyed peer decisions on it, but matching the
// original maximises comfort (SPEC §13.1).
const hydraRevstamp = 0x2b1aab00

// autostart is the literal byte sequence emitted on the wire before the
// first START frame so interactive peers can trigger on it (SPEC §3.1).
const autostart = "hydra\r"

// DataBufMax is the maximum data bytes in one DATA packet (excluding the
// 4-byte offset prefix). FSC-0072 fixes this at 2048.
const DataBufMax = 2048

// dataOffsetPrefix is the 4-byte little-endian offset on every DATA packet.
const dataOffsetPrefix = 4

// maxPayloadSize is the largest decoded payload the reader accepts:
// 2048 data bytes plus H_OVERHEAD (8) header bytes — the worst case is
// a full DEVDATA (4-byte id + 3-char device + NUL + 2048 data). FSC-0072
// L1331-1341; bforce's HYDRA_MAXDATALEN is the same 2048+8(+5).
const maxPayloadSize = DataBufMax + 8

// maxDecodedLen caps the decoded packet buffer: payload + type byte +
// CRC-32 = 2061. Beyond this the packet is discarded and scanning
// continues.
const maxDecodedLen = maxPayloadSize + 1 + 4

// maxEncodedLen caps the raw encoded byte count of one frame body
// (HydraCom discards packets longer than 6183 encoded bytes, hydra.c).
const maxEncodedLen = 6183

// prefixMax is the longest packet-prefix string a peer may request in
// INIT field 5 (HydraCom H_PKTPREFIX = 31, hydra.h:69).
const prefixMax = 31

// Cancel sequence (SPEC §2.4): emitted on abort as cancelCount DLEs plus
// cancelPadCount backspaces; detected on receive as detectCancelCount
// consecutive DLEs with no intervening valid byte.
const (
	cancelCount       = 8
	cancelPadCount    = 10
	detectCancelCount = 5
)

// END handshake counts (SPEC §3.11): entering HTX_END sends endInitialCount
// packets; hearing any END in HTX_END/HTX_ENDACK sends endResponseCount
// more and exits.
const (
	endInitialCount  = 2
	endResponseCount = 3
)

// Timer and retry defaults (SPEC §7).
const (
	defaultBrainDead  = 120 * time.Second
	defaultTimeout    = 10 * time.Second // floor of max(10, min(60, 40960/baud))
	maxTimeout        = 60 * time.Second
	defaultMaxRetries = 10
	idleInterval      = 20 * time.Second
	startInterval     = 5 * time.Second
)

// Block size adaptation defaults (SPEC §6, HydraCom hydra.c:928-935,
// 1269-1277, 1732-1744).
const (
	defaultGoodNeeded = 1024 // good bytes before doubling the block size
	maxGoodNeeded     = 8192 // cap after repeated RPOS penalties
	minBlockSize      = 64   // floor of the RPOS block-size ladder
	rposMaxBlock      = 1024 // ladder cap — no RPOS proposal/adoption exceeds this
)

// FINFOACK sentinel offsets (SPEC §3.5) and the shared skip sentinel used
// by RPOS(-2)/EOF(-2) (SPEC §3.8, §3.9).
const (
	ackHaveFile int32 = -1 // receiver already has this file
	ackDefer    int32 = -2 // receiver defers to a later batch
	offsetSkip  int32 = -2 // skip-this-file sentinel in RPOS and EOF
)

// SafeMaxOffset is the largest file size or offset representable in the
// 4-byte signed wire fields without colliding with the -1/-2 sentinels.
const SafeMaxOffset int64 = 0x7FFFFFFE
