package engine

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// XOR obfuscates data with a randomly generated key that is prepended to the
// output, so every run produces a different ciphertext.
//
// Output layout: [4-byte key length][key bytes][ciphertext].
type XOR struct{}

func (XOR) Name() string { return "xor" }

func (XOR) Obfuscate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("xor: empty input")
	}
	keyLen := 1 + len(data)%32
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	out := make([]byte, 4+keyLen+len(data))
	binary.LittleEndian.PutUint32(out, uint32(keyLen))
	copy(out[4:], key)
	for i, b := range data {
		out[4+keyLen+i] = b ^ key[i%keyLen]
	}
	return out, nil
}

func (XOR) Deobfuscate(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, errors.New("xor: input too short")
	}
	keyLen := int(binary.LittleEndian.Uint32(data))
	if keyLen < 1 || 4+keyLen > len(data) {
		return nil, errors.New("xor: invalid key length in header")
	}
	key := data[4 : 4+keyLen]
	cipher := data[4+keyLen:]
	out := make([]byte, len(cipher))
	for i, b := range cipher {
		out[i] = b ^ key[i%keyLen]
	}
	return out, nil
}
