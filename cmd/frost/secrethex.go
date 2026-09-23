package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// errSecretHexNotString is returned when a secret field in a JSON file is not
// a JSON string.
var errSecretHexNotString = errors.New("frost: secret must be a JSON string of hex digits")

// secretHex is secret material (a secret share or a signing nonce) that
// travels through a JSON file as a hex string but is held in memory as bytes
// this program allocated and owns. That ownership is what makes zero sound:
// the bytes are never a string literal's read-only backing array, never shared
// with a Go string, and never a map key, so overwriting them cannot fault and
// cannot corrupt anything else (go-frost#15).
//
// The slice holds the field's exact JSON wire form — the quoted hex string —
// so MarshalJSON hands encoding/json the owned buffer itself instead of a
// fresh copy this program could never reach. encoding/json still copies it
// into its own internal buffers, which are outside this program's control;
// callers scrub the marshaled document they get back.
type secretHex []byte

var (
	_ json.Marshaler   = secretHex(nil)
	_ json.Unmarshaler = (*secretHex)(nil)
)

// newSecretHex hex-encodes raw into a new owned buffer. raw is not retained;
// the caller remains responsible for scrubbing it.
func newSecretHex(raw []byte) secretHex {
	buf := make([]byte, hex.EncodedLen(len(raw))+2)
	buf[0] = '"'
	hex.Encode(buf[1:len(buf)-1], raw)
	buf[len(buf)-1] = '"'
	return buf
}

// MarshalJSON returns the owned wire form without copying it.
func (s secretHex) MarshalJSON() ([]byte, error) {
	if len(s) == 0 {
		return []byte(`""`), nil
	}
	return s, nil
}

// UnmarshalJSON unquotes a JSON string into a buffer the secretHex owns.
// data belongs to the caller's input, which the caller scrubs after
// json.Unmarshal returns, so it must not be retained. A JSON null leaves the
// value unchanged, as encoding/json expects of an Unmarshaler.
//
// Escapes are decoded exactly as encoding/json decodes them into a string, so
// every file the CLI accepted when these fields were strings still parses to
// the same hex text. The unquoting is done here, directly into the owned
// buffer, because letting encoding/json do it would leave the secret in a
// string that can never be scrubbed.
func (s *secretHex) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errSecretHexNotString
	}
	// Escapes only shrink, and an invalid UTF-8 byte grows to at most the
	// three bytes of U+FFFD, so this capacity is never exceeded and append
	// never reallocates — a reallocation would strand an unscrubbed copy.
	owned := make([]byte, 0, 3*len(data))
	owned = append(owned, '"')
	owned, ok := appendUnquoted(owned, data[1:len(data)-1])
	if !ok {
		secmem.ZeroBytes(owned[:cap(owned)])
		return errSecretHexNotString
	}
	owned = append(owned, '"')
	s.zero()
	*s = owned
	return nil
}

// appendUnquoted appends the unescaped contents of a JSON string body to dst,
// following encoding/json: simple escapes, \uXXXX with surrogate pairs
// combined, and U+FFFD for an unpaired surrogate or invalid UTF-8. It reports
// false for a malformed escape, which encoding/json rejects before calling
// UnmarshalJSON, so that path is only reachable by calling it directly.
func appendUnquoted(dst, body []byte) ([]byte, bool) {
	for i := 0; i < len(body); {
		c := body[i]
		switch {
		case c == '\\':
			if i+1 >= len(body) {
				return dst, false
			}
			switch body[i+1] {
			case '"', '\\', '/':
				dst = append(dst, body[i+1])
			case 'b':
				dst = append(dst, '\b')
			case 'f':
				dst = append(dst, '\f')
			case 'n':
				dst = append(dst, '\n')
			case 'r':
				dst = append(dst, '\r')
			case 't':
				dst = append(dst, '\t')
			case 'u':
				r, ok := hexRune(body[i+2:])
				if !ok {
					return dst, false
				}
				i += 6
				if utf16.IsSurrogate(r) {
					r2, ok2 := rune(-1), false
					if i+1 < len(body) && body[i] == '\\' && body[i+1] == 'u' {
						r2, ok2 = hexRune(body[i+2:])
					}
					if pair := utf16.DecodeRune(r, r2); ok2 && pair != utf8.RuneError {
						r = pair
						i += 6
					} else {
						r = utf8.RuneError
					}
				}
				dst = utf8.AppendRune(dst, r)
				continue
			default:
				return dst, false
			}
			i += 2
		case c < utf8.RuneSelf:
			dst = append(dst, c)
			i++
		default:
			r, size := utf8.DecodeRune(body[i:])
			dst = utf8.AppendRune(dst, r)
			i += size
		}
	}
	return dst, true
}

// hexRune parses the four hex digits that follow \u. It is written out
// rather than using strconv so the digits never pass through a string.
func hexRune(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// decode returns the raw secret in a new buffer the caller owns and must
// scrub with secmem.ZeroBytes. On error nothing is returned and the partial
// output has already been scrubbed.
func (s secretHex) decode() ([]byte, error) {
	var digits []byte
	if len(s) >= 2 {
		digits = s[1 : len(s)-1]
	}
	raw := make([]byte, hex.DecodedLen(len(digits)))
	n, err := hex.Decode(raw, digits)
	if err != nil {
		secmem.ZeroBytes(raw)
		return nil, err
	}
	return raw[:n], nil
}

// zero scrubs the owned buffer in place.
func (s secretHex) zero() {
	secmem.ZeroBytes(s)
}
