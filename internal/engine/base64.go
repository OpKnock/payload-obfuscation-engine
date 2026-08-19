package engine

import (
	"errors"
	"strings"
)

// CustomAlphabet is a non-standard base64 alphabet that defeats trivial
// signature matching on the standard A-Z a-z 0-9 + / table.
const CustomAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Base64 encodes data with a configurable 64-character alphabet.
type Base64 struct {
	Alphabet string
}

func (b *Base64) Name() string { return "base64" }

func (b *Base64) validate() error {
	if len(b.Alphabet) != 64 {
		return errors.New("base64: alphabet must contain exactly 64 characters")
	}
	seen := make(map[byte]bool, 64)
	for i := 0; i < len(b.Alphabet); i++ {
		if seen[b.Alphabet[i]] {
			return errors.New("base64: alphabet contains duplicate characters")
		}
		seen[b.Alphabet[i]] = true
	}
	return nil
}

func (b *Base64) Obfuscate(data []byte) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("base64: empty input")
	}
	out := make([]byte, ((len(data)+2)/3)*4)
	dst := out
	triplet := func(a, bb, c byte) {
		dst[0] = b.Alphabet[a>>2]
		dst[1] = b.Alphabet[(a&0x03)<<4|bb>>4]
		dst[2] = b.Alphabet[(bb&0x0F)<<2|c>>6]
		dst[3] = b.Alphabet[c&0x3F]
	}
	i := 0
	for ; i+3 <= len(data); i += 3 {
		triplet(data[i], data[i+1], data[i+2])
		dst = dst[4:]
	}
	rem := len(data) - i
	if rem == 1 {
		dst[0] = b.Alphabet[data[i]>>2]
		dst[1] = b.Alphabet[(data[i]&0x03)<<4]
		dst[2] = '='
		dst[3] = '='
	} else if rem == 2 {
		dst[0] = b.Alphabet[data[i]>>2]
		dst[1] = b.Alphabet[(data[i]&0x03)<<4|data[i+1]>>4]
		dst[2] = b.Alphabet[(data[i+1]&0x0F)<<2]
		dst[3] = '='
	}
	return out, nil
}

func (b *Base64) Deobfuscate(data []byte) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
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
		return nil, errors.New("base64: empty input")
	}
	if len(clean)%4 != 0 {
		return nil, errors.New("base64: invalid length")
	}
	pad := strings.IndexByte(string(clean), '=')
	if pad >= 0 && pad < len(clean)-2 {
		return nil, errors.New("base64: padding '=' in the middle of input")
	}
	value := func(c byte) (byte, error) {
		if c == '=' {
			return 0, nil
		}
		idx := strings.IndexByte(b.Alphabet, c)
		if idx < 0 {
			return 0, errors.New("base64: invalid character in input")
		}
		return byte(idx), nil
	}
	out := make([]byte, 0, (len(clean)/4)*3)
	for i := 0; i < len(clean); i += 4 {
		a, err := value(clean[i])
		if err != nil {
			return nil, err
		}
		bb, err := value(clean[i+1])
		if err != nil {
			return nil, err
		}
		c, err := value(clean[i+2])
		if err != nil {
			return nil, err
		}
		d, err := value(clean[i+3])
		if err != nil {
			return nil, err
		}
		if clean[i+2] == '=' {
			out = append(out, a<<2|bb>>4)
		} else if clean[i+3] == '=' {
			out = append(out, a<<2|bb>>4, (bb&0x0F)<<4|c>>2)
		} else {
			out = append(out, a<<2|bb>>4, (bb&0x0F)<<4|c>>2, (c&0x03)<<6|d)
		}
	}
	return out, nil
}
