package hydra

import "errors"

// This file implements the four Hydra body encodings, byte-exact to
// HydraCom 1.00 (hydra.c:311-508 on transmit, 574-649 on receive).
//
// On the wire a frame body is <payload><type><crc> passed through one of
// these encodings. DLE-escape *decoding* is not here — it happens at the
// byte-collection layer in reader.go (mirroring rxpkt), so the decoders
// below operate on already-unescaped buffers.

var (
	errHexEncoding = errors.New("hydra: malformed HEX body")
	errUueEncoding = errors.New("hydra: malformed UUE body")
)

// binEscaper implements put_binbyte (hydra.c:311-331): the DLE-escape
// pass applied to BIN bodies (and to ASC output units). The comparison
// copy is 7-bit masked under HIC so high-bit twins of the control set are
// escaped too; the emitted escape is always DLE + original^0x40 with the
// high bit preserved. lastc carries the masked previous byte for the
// Telenet CR-after-'@' rule and resets at every packet start (c:451) —
// unlike Janus, the state never spans packets.
//
// HI8 deliberately has no branch here: it never adds 0x80–0xFF to the
// BIN escape set. It is honoured by txpkt's format switch (HI8 forces a
// 7-bit format) and by the receive-side high-bit strip.
type binEscaper struct {
	opts  uint32
	lastc byte
}

func (e *binEscaper) reset(opts uint32) {
	e.opts = opts
	e.lastc = 0
}

func (e *binEscaper) put(out []byte, c byte) []byte {
	n := c
	if e.opts&capHIC != 0 {
		n &= 0x7f
	}
	escape := n == DLE ||
		(e.opts&capXON != 0 && (n == charXON || n == charXOF)) ||
		(e.opts&capTLN != 0 && n == charCR && e.lastc == charAT) ||
		(e.opts&capCTL != 0 && (n < 32 || n == 127))
	if escape {
		out = append(out, DLE, c^0x40)
	} else {
		out = append(out, c)
	}
	e.lastc = n
	return out
}

func (e *binEscaper) putAll(out, body []byte) []byte {
	for _, c := range body {
		out = e.put(out, c)
	}
	return out
}

// hexEncodeBody applies the HEX rules (hydra.c:456-474). Negotiated
// options are ignored — the rules are fixed: bytes ≥ 0x80 become '\' plus
// two lowercase hex digits, control bytes are DLE-escaped, backslash is
// doubled, everything else passes through.
func hexEncodeBody(out, body []byte) []byte {
	const hexdigit = "0123456789abcdef"
	for _, c := range body {
		switch {
		case c >= 0x80:
			out = append(out, '\\', hexdigit[c>>4], hexdigit[c&0x0f])
		case c < 32 || c == 127:
			out = append(out, DLE, c^0x40)
		case c == '\\':
			out = append(out, '\\', '\\')
		default:
			out = append(out, c)
		}
	}
	return out
}

// hexDecodeBody reverses hexEncodeBody on an already-DLE-unescaped
// buffer (hydra.c:579-597). Only lowercase hex digits are accepted — the
// original's decoder rejects uppercase (via CRC failure; we error
// directly). A trailing lone backslash is malformed.
func hexDecodeBody(body []byte) ([]byte, error) {
	out := body[:0:len(body)]
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(body) {
			return nil, errHexEncoding
		}
		if body[i] == '\\' {
			out = append(out, '\\')
			continue
		}
		if i+1 >= len(body) {
			return nil, errHexEncoding
		}
		hi, ok1 := hexNibble(body[i])
		lo, ok2 := hexNibble(body[i+1])
		if !ok1 || !ok2 {
			return nil, errHexEncoding
		}
		out = append(out, hi<<4|lo)
		i++
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

// ascEncodeBody packs 8-bit bytes into 7-bit units, LSB-first (hydra.c:
// 481-493): every 7 input bytes produce 8 output units. The caller feeds
// the units through a binEscaper exactly as HydraCom does. Emit support
// exists for tests and symmetry — go-hydra never advertises ASC.
func ascEncodeBody(out []byte, body []byte, esc *binEscaper) []byte {
	var acc uint32
	n := 0
	for _, b := range body {
		acc |= uint32(b) << n
		out = esc.put(out, byte(acc&0x7f))
		acc >>= 7
		n++
		if n >= 7 {
			out = esc.put(out, byte(acc&0x7f))
			acc = 0
			n = 0
		}
	}
	if n > 0 {
		out = esc.put(out, byte(acc&0x7f))
	}
	return out
}

// ascDecodeBody reverses ascEncodeBody on an already-DLE-unescaped
// buffer (hydra.c:599-609): accumulate 7 bits per unit, emit each full
// octet. Trailing bits that do not fill an octet are padding.
func ascDecodeBody(body []byte) []byte {
	out := make([]byte, 0, len(body)*7/8+1)
	var acc uint32
	n := 0
	for _, p := range body {
		acc |= uint32(p&0x7f) << n
		n += 7
		if n >= 8 {
			out = append(out, byte(acc))
			acc >>= 8
			n -= 8
		}
	}
	return out
}

const uueBase = '!' // h_uuenc(c) = ((c) & 0x3f) + '!'

func uueChar(c byte) byte { return (c & 0x3f) + uueBase }

// uueEncodeBody is HydraCom's uuencode variant (hydra.c:495-508): groups
// of 3 bytes become 4 chars in '!'..'`'; a 1-byte tail emits 2 chars and
// a 2-byte tail 3 chars. No line structure, no length prefix. Output is
// printable-safe and NOT escape-processed. Emit support exists for tests
// only — go-hydra never advertises UUE.
func uueEncodeBody(out, body []byte) []byte {
	for len(body) >= 3 {
		b0, b1, b2 := body[0], body[1], body[2]
		out = append(out,
			uueChar(b0>>2),
			uueChar(b0<<4|b1>>4),
			uueChar(b1<<2|b2>>6),
			uueChar(b2))
		body = body[3:]
	}
	switch len(body) {
	case 1:
		out = append(out, uueChar(body[0]>>2), uueChar(body[0]<<4))
	case 2:
		out = append(out,
			uueChar(body[0]>>2),
			uueChar(body[0]<<4|body[1]>>4),
			uueChar(body[1]<<2))
	}
	return out
}

// uueDecodeBody reverses uueEncodeBody (hydra.c:611-638). Every char
// must lie in 0x21..0x60; group tails of 2 and 3 chars decode to 1 and 2
// bytes; a single dangling char carries no whole byte and is silently
// ignored (the reference decoder treats it as clean termination).
func uueDecodeBody(body []byte) ([]byte, error) {
	dec := func(c byte) (byte, bool) {
		if c < 0x21 || c > 0x60 {
			return 0, false
		}
		return (c - uueBase) & 0x3f, true
	}
	out := make([]byte, 0, len(body)/4*3+2)
	for len(body) >= 4 {
		c0, ok0 := dec(body[0])
		c1, ok1 := dec(body[1])
		c2, ok2 := dec(body[2])
		c3, ok3 := dec(body[3])
		if !ok0 || !ok1 || !ok2 || !ok3 {
			return nil, errUueEncoding
		}
		out = append(out, c0<<2|c1>>4, c1<<4|c2>>2, c2<<6|c3)
		body = body[4:]
	}
	switch len(body) {
	case 0:
	case 2:
		c0, ok0 := dec(body[0])
		c1, ok1 := dec(body[1])
		if !ok0 || !ok1 {
			return nil, errUueEncoding
		}
		out = append(out, c0<<2|c1>>4)
	case 3:
		c0, ok0 := dec(body[0])
		c1, ok1 := dec(body[1])
		c2, ok2 := dec(body[2])
		if !ok0 || !ok1 || !ok2 {
			return nil, errUueEncoding
		}
		out = append(out, c0<<2|c1>>4, c1<<4|c2>>2)
	default: // 1 — dangling char, no whole byte: ignore
	}
	return out, nil
}
