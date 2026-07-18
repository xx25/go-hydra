package hydra

import (
	"errors"
	"fmt"
	"strings"
)

// packet is one decoded frame off the wire: type byte plus raw payload.
type packet struct {
	typ     byte
	payload []byte
}

var (
	errBadPayload = errors.New("hydra: malformed packet payload")
	errBadInit    = errors.New("hydra: malformed INIT payload")
)

// le32 appends v as 4 little-endian bytes.
func le32(out []byte, v uint32) []byte {
	return append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// readLE32 reads 4 little-endian bytes at off.
func readLE32(p []byte, off int) uint32 {
	return uint32(p[off]) | uint32(p[off+1])<<8 |
		uint32(p[off+2])<<16 | uint32(p[off+3])<<24
}

// --- 4-byte signed offset payloads: FINFOACK, DATAACK, EOF -----------------

func marshalOffset(v int32) []byte {
	return le32(nil, uint32(v))
}

func parseOffset(payload []byte) (int32, error) {
	if len(payload) < 4 {
		return 0, errBadPayload
	}
	return int32(readLE32(payload, 0)), nil
}

// --- DATA -------------------------------------------------------------------

// marshalData prefixes data with its 4-byte LE file offset (SPEC §3.6).
func marshalData(offset int64, data []byte) []byte {
	out := make([]byte, 0, dataOffsetPrefix+len(data))
	out = le32(out, uint32(offset))
	return append(out, data...)
}

// parseData splits a DATA payload into offset and data. Empty data is
// tolerated (a peer may flush a zero-length tail block).
func parseData(payload []byte) (offset int64, data []byte, err error) {
	if len(payload) < dataOffsetPrefix {
		return 0, nil, errBadPayload
	}
	return int64(int32(readLE32(payload, 0))), payload[dataOffsetPrefix:], nil
}

// --- RPOS -------------------------------------------------------------------

// rposPkt is a receiver reposition request (SPEC §3.8). offset == -2 asks
// the sender to skip the file (answered with EOF(-2)).
type rposPkt struct {
	offset    int64
	blocksize int
	id        uint32
}

// marshalRpos emits the 12-byte LONG form — offset, blocksize, and id all
// 32-bit LE — matching HydraCom 1.00 and the majority of implementations
// (SPEC §13.1; the FSC-0072 text's 10-byte WORD form is the minority).
func marshalRpos(r rposPkt) []byte {
	out := le32(nil, uint32(int32(r.offset)))
	out = le32(out, uint32(r.blocksize))
	return le32(out, r.id)
}

// parseRpos accepts both wire forms by total length: 12 bytes (LONG
// blocksize, HydraCom/qico/xenia/BTXE) and 10 bytes (WORD blocksize,
// bforce/FTNd per the spec text). Anything else is malformed.
func parseRpos(payload []byte) (rposPkt, error) {
	var r rposPkt
	switch len(payload) {
	case 12:
		r.offset = int64(int32(readLE32(payload, 0)))
		r.blocksize = int(readLE32(payload, 4))
		r.id = readLE32(payload, 8)
	case 10:
		r.offset = int64(int32(readLE32(payload, 0)))
		r.blocksize = int(uint16(payload[4]) | uint16(payload[5])<<8)
		r.id = readLE32(payload, 6)
	default:
		return r, fmt.Errorf("%w: RPOS length %d", errBadPayload, len(payload))
	}
	return r, nil
}

// --- INIT -------------------------------------------------------------------

// initPkt carries the negotiation parameters (SPEC §3.2). Five
// NUL-terminated fields; the two window values share one 16-hex-char field.
type initPkt struct {
	appID     string
	supported uint32
	desired   uint32
	txWindow  uint32 // sender's TX window in bytes; 0 = full streaming
	rxWindow  uint32 // sender's RX window in bytes; 0 = full streaming
	prefix    string // ≤30 bytes prepended to each packet by the *receiver of this INIT*
}

// marshalInit assembles the five NUL-terminated INIT fields. The window
// field is a single "%08x%08x" concatenation — no separator — exactly as
// every surveyed implementation emits it (SPEC §3.2 format gotcha).
func marshalInit(p initPkt) []byte {
	var b []byte
	b = append(b, p.appID...)
	b = append(b, 0)
	b = append(b, capsString(p.supported)...)
	b = append(b, 0)
	b = append(b, capsString(p.desired)...)
	b = append(b, 0)
	b = fmt.Appendf(b, "%08x%08x", p.txWindow, p.rxWindow)
	b = append(b, 0)
	b = append(b, p.prefix...)
	b = append(b, 0)
	return b
}

// parseInit decodes an INIT payload. Liberal per SPEC §13.1: missing
// trailing fields default to zero/empty; unknown capability codes drop out
// in parseCaps.
func parseInit(payload []byte) (initPkt, error) {
	var p initPkt
	fields := strings.Split(string(payload), "\x00")
	if len(fields) < 2 {
		return p, errBadInit
	}
	get := func(i int) string {
		if i < len(fields) {
			return fields[i]
		}
		return ""
	}
	p.appID = get(0)
	p.supported = parseCaps(get(1))
	p.desired = parseCaps(get(2))
	if w := get(3); len(w) >= 16 {
		if _, err := fmt.Sscanf(w[:16], "%08x%08x", &p.txWindow, &p.rxWindow); err != nil {
			return p, fmt.Errorf("%w: windows: %w", errBadInit, err)
		}
	}
	p.prefix = get(4)
	return p, nil
}

// --- DEVDATA / DEVDACK -------------------------------------------------------

// devDataPkt is one device-channel datagram (SPEC §3.13).
type devDataPkt struct {
	id      uint32
	device  string // 3-char name, e.g. "CON" or "MSG"
	payload []byte
}

func marshalDevData(d devDataPkt) []byte {
	out := le32(nil, d.id)
	out = append(out, d.device...)
	out = append(out, 0)
	return append(out, d.payload...)
}

func parseDevData(payload []byte) (devDataPkt, error) {
	var d devDataPkt
	if len(payload) < 5 {
		return d, errBadPayload
	}
	d.id = readLE32(payload, 0)
	name, rest, ok := cutNul(payload[4:])
	if !ok {
		return d, fmt.Errorf("%w: DEVDATA device name unterminated", errBadPayload)
	}
	d.device = string(name)
	d.payload = rest
	return d, nil
}

func marshalDevAck(id uint32) []byte {
	return le32(nil, id)
}

func parseDevAck(payload []byte) (uint32, error) {
	if len(payload) < 4 {
		return 0, errBadPayload
	}
	return readLE32(payload, 0), nil
}
