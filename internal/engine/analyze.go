package engine

import "math"

// Entropy returns the Shannon entropy of data in bits per byte (0..8).
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(len(data))
		h -= p * math.Log2(p)
	}
	return h
}
