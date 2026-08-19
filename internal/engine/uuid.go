package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// UUID renders the payload as a sequence of RFC 4122-looking UUID strings
// (one per 16-byte group), a format that blends in with legitimate
// identifiers and defeats naive byte-sequence signatures.
//
// Output layout: [original length (8 bytes LE)][UUID strings, one per line].
type UUID struct{}

func (UUID) Name() string { return "uuid" }

func (UUID) Obfuscate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("uuid: empty input")
	}
	out := make([]byte, 0, 8+((len(data)+15)/16)*37)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(data)))
	padding := (16 - len(data)%16) % 16
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := 0; i < len(padded); i += 16 {
		out = append(out, formatUUID(padded[i:i+16])...)
		out = append(out, '\n')
	}
	return out, nil
}

func (UUID) Deobfuscate(data []byte) ([]byte, error) {
	if len(data) < 9 {
		return nil, errors.New("uuid: input too short")
	}
	origLen := binary.LittleEndian.Uint64(data[:8])
	out := make([]byte, 0, len(data))
	for _, line := range bytes.Split(data[8:], []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(line) != 36 || line[8] != '-' || line[13] != '-' || line[18] != '-' || line[23] != '-' {
			return nil, errors.New("uuid: malformed uuid line")
		}
		nibbles := make([]byte, 0, 32)
		for _, c := range line {
			if c == '-' {
				continue
			}
			v, ok := hexVal(c)
			if !ok {
				return nil, errors.New("uuid: invalid hex digit")
			}
			nibbles = append(nibbles, v)
		}
		for i := 0; i+1 < len(nibbles); i += 2 {
			out = append(out, nibbles[i]<<4|nibbles[i+1])
		}
	}
	if uint64(len(out)) < origLen {
		return nil, errors.New("uuid: truncated payload")
	}
	return out[:origLen], nil
}

func formatUUID(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}
