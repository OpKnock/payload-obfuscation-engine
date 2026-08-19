package engine

import (
	"errors"
)

// Hex escapes every byte of the payload as a \xNN sequence, defeating
// plain-text string signatures.
type Hex struct{}

func (Hex) Name() string { return "hex" }

func (Hex) Obfuscate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("hex: empty input")
	}
	out := make([]byte, 0, len(data)*4)
	for _, b := range data {
		out = append(out, '\\', 'x', hexDigit(b>>4), hexDigit(b&0x0F))
	}
	return out, nil
}

// Deobfuscate accepts \xNN escapes as well as bare hex strings (case
// insensitive), ignoring surrounding whitespace.
func (Hex) Deobfuscate(data []byte) ([]byte, error) {
	clean := make([]byte, 0, len(data))
	for _, c := range data {
		switch c {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			clean = append(clean, c)
		}
	}
	if len(clean) == 0 {
		return nil, errors.New("hex: empty input")
	}
	out := make([]byte, 0, len(clean)/2)
	for i := 0; i < len(clean); {
		if clean[i] == '\\' {
			if i+2 >= len(clean) || clean[i+1] != 'x' {
				return nil, errors.New("hex: dangling escape sequence")
			}
			hi, ok := hexVal(clean[i+2])
			if !ok {
				return nil, errors.New("hex: invalid escape digit")
			}
			lo := byte(0)
			if i+3 < len(clean) {
				if v, ok2 := hexVal(clean[i+3]); ok2 {
					lo = v
					out = append(out, hi<<4|lo)
					i += 4
					continue
				}
			}
			out = append(out, hi)
			i += 3
			continue
		}
		hi, ok1 := hexVal(clean[i])
		if !ok1 || i+1 >= len(clean) {
			return nil, errors.New("hex: invalid hex digit")
		}
		lo, ok2 := hexVal(clean[i+1])
		if !ok2 {
			return nil, errors.New("hex: invalid hex digit")
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, nil
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
