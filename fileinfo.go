package hydra

import (
	"errors"
	"fmt"
)

// fileMeta is the decoded FINFO header plus filenames (SPEC §3.4). The
// on-wire header is 5×8 ASCII hex characters: timestamp, size, reserved,
// transaction id, file count.
type fileMeta struct {
	mtime int64  // Unix seconds; 0 if unknown
	size  int64  // bytes; 0 if unknown / streaming
	txid  uint32 // 0 unless the file answers a FREQ
	count uint32 // first file: batch total; later files: ordinal ≥2; 0 unknown
	name  string // short filename, no path
	path  string // real filename (may contain '/'); "" unless FPT active
}

const finfoHeaderLen = 40 // 5 fields × 8 hex chars

var errBadFinfo = errors.New("hydra: malformed FINFO payload")

// marshalFinfo encodes a FINFO payload. The real filename is appended only
// when fpt is negotiated and the path adds information beyond the short
// name (SPEC §13.1).
func marshalFinfo(m fileMeta, fpt bool) []byte {
	out := fmt.Appendf(nil, "%08x%08x%08x%08x%08x",
		uint32(m.mtime), uint32(m.size), uint32(0), m.txid, m.count)
	out = append(out, m.name...)
	out = append(out, 0)
	if fpt && m.path != "" && m.path != m.name {
		out = append(out, m.path...)
		out = append(out, 0)
	}
	return out
}

// finfoEOB is the end-of-batch FINFO payload: a single NUL byte. All four
// surveyed C implementations emit and detect exactly this (SPEC §3.4).
var finfoEOB = []byte{0}

// isFinfoEOB reports whether a FINFO payload signals end-of-batch. The
// check is payload[0] == 0 regardless of total length, tolerating the
// hypothetical 40-zero-hex variant from earlier spec drafts (SPEC §13.1).
func isFinfoEOB(payload []byte) bool {
	return len(payload) == 0 || payload[0] == 0
}

// parseFinfo decodes a non-EOB FINFO payload. Liberal per SPEC §13.1: the
// header must be present and hex-parsable; the real filename is optional.
func parseFinfo(payload []byte) (fileMeta, error) {
	var m fileMeta
	if len(payload) < finfoHeaderLen+1 {
		return m, errBadFinfo
	}
	var mtime, size, reserved uint32
	if _, err := fmt.Sscanf(string(payload[:finfoHeaderLen]),
		"%08x%08x%08x%08x%08x",
		&mtime, &size, &reserved, &m.txid, &m.count); err != nil {
		return m, fmt.Errorf("%w: header: %w", errBadFinfo, err)
	}
	m.mtime = int64(mtime)
	m.size = int64(size)

	rest := payload[finfoHeaderLen:]
	name, rest, ok := cutNul(rest)
	if !ok || len(name) == 0 {
		return m, fmt.Errorf("%w: missing filename", errBadFinfo)
	}
	m.name = string(name)

	// Optional real filename: present when FPT was negotiated and the
	// remainder holds a second non-empty NUL-terminated string. A single
	// stray NUL (the "terminating" byte some impls append) is not a name.
	if path, _, ok := cutNul(rest); ok && len(path) > 0 {
		m.path = string(path)
	}
	return m, nil
}

// cutNul splits b at the first NUL. ok is false when no NUL is present —
// callers treat the remainder as absent rather than trusting an
// unterminated string.
func cutNul(b []byte) (before, after []byte, ok bool) {
	for i, c := range b {
		if c == 0 {
			return b[:i], b[i+1:], true
		}
	}
	return b, nil, false
}
