package engine

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
)

// Split breaks the payload into fixed-size chunks, pads the final chunk,
// shuffles the chunks with a random permutation and stores the
// reconstruction header up front. The shuffled stream carries no detectable
// ordering, and the inverse permutation fully recovers the original bytes.
//
// Output layout: [chunk size (1 byte)][chunk count (4 bytes LE)]
//
//	[original length (8 bytes LE)]
//	[permutation (2 bytes LE each, chunk count entries)]
//	[padded chunks in permuted order].
type Split struct{}

func (Split) Name() string { return "split" }

func (Split) Obfuscate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("split: empty input")
	}
	var seedBytes [8]byte
	if _, err := cryptorand.Read(seedBytes[:]); err != nil {
		return nil, err
	}
	r := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:]))))
	chunkSize := 1 + r.Intn(8)
	if minSize := (len(data) + 65535) / 65536; chunkSize < minSize {
		chunkSize = minSize
	}
	numChunks := (len(data) + chunkSize - 1) / chunkSize
	perm := r.Perm(numChunks)

	out := make([]byte, 0, 13+2*numChunks+numChunks*chunkSize)
	out = append(out, byte(chunkSize))
	out = binary.LittleEndian.AppendUint32(out, uint32(numChunks))
	out = binary.LittleEndian.AppendUint64(out, uint64(len(data)))
	for _, p := range perm {
		out = binary.LittleEndian.AppendUint16(out, uint16(p))
	}
	padded := make([]byte, numChunks*chunkSize)
	copy(padded, data)
	for _, idx := range perm {
		out = append(out, padded[idx*chunkSize:(idx+1)*chunkSize]...)
	}
	return out, nil
}

func (Split) Deobfuscate(data []byte) ([]byte, error) {
	if len(data) < 14 {
		return nil, errors.New("split: input too short")
	}
	chunkSize := int(data[0])
	numChunks := int(binary.LittleEndian.Uint32(data[1:5]))
	origLen := int(binary.LittleEndian.Uint64(data[5:13]))
	if chunkSize < 1 || numChunks < 1 || numChunks > 65536 || 13+2*numChunks > len(data) {
		return nil, errors.New("split: invalid header")
	}
	perm := make([]int, numChunks)
	seen := make([]bool, numChunks)
	for i := 0; i < numChunks; i++ {
		p := int(binary.LittleEndian.Uint16(data[13+2*i : 15+2*i]))
		if p >= numChunks || seen[p] {
			return nil, errors.New("split: invalid permutation")
		}
		seen[p] = true
		perm[i] = p
	}
	body := data[13+2*numChunks:]
	if len(body) < numChunks*chunkSize {
		return nil, errors.New("split: truncated payload")
	}
	out := make([]byte, 0, numChunks*chunkSize)
	for i := 0; i < numChunks; i++ {
		pos := -1
		for j, p := range perm {
			if p == i {
				pos = j
				break
			}
		}
		out = append(out, body[pos*chunkSize:(pos+1)*chunkSize]...)
	}
	if origLen > len(out) {
		return nil, errors.New("split: original length exceeds payload")
	}
	return out[:origLen], nil
}
