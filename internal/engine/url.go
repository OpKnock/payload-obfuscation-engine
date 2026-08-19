package engine

import (
	"errors"
)

// URL percent-encodes every byte of the payload, producing output that
// resembles ordinary web request data.
type URL struct{}

func (URL) Name() string { return "url" }

func (URL) Obfuscate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("url: empty input")
	}
	out := make([]byte, 0, len(data)*3)
	for _, b := range data {
		out = append(out, '%', hexDigit(b>>4), hexDigit(b&0x0F))
	}
	return out, nil
}

func (URL) Deobfuscate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("url: empty input")
	}
	out := make([]byte, 0, len(data)/3)
	for i := 0; i < len(data); {
		if data[i] != '%' {
			return nil, errors.New("url: expected '%' escape")
		}
		if i+2 >= len(data) {
			return nil, errors.New("url: truncated escape")
		}
		hi, ok1 := hexVal(data[i+1])
		lo, ok2 := hexVal(data[i+2])
		if !ok1 || !ok2 {
			return nil, errors.New("url: invalid escape digits")
		}
		out = append(out, hi<<4|lo)
		i += 3
	}
	return out, nil
}
