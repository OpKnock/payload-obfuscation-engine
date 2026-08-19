package engine

import (
	"bytes"
	"encoding/base64"
	"math"
	"strings"
	"testing"
)

var testPayload = []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" +
	"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00" +
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
	"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68" +
	"this is a string literal that should be hard to find\x00\x00\x00")

func roundTrip(t *testing.T, name string, tech Technique, payload []byte) {
	t.Helper()
	obf, err := tech.Obfuscate(payload)
	if err != nil {
		t.Fatalf("%s: obfuscate: %v", name, err)
	}
	if bytes.Equal(obf, payload) {
		t.Errorf("%s: obfuscated output equals input", name)
	}
	dec, err := tech.Deobfuscate(obf)
	if err != nil {
		t.Fatalf("%s: deobfuscate: %v", name, err)
	}
	if !bytes.Equal(dec, payload) {
		t.Errorf("%s: roundtrip mismatch: got %d bytes, want %d", name, len(dec), len(payload))
	}
}

func sizes() []int {
	return []int{1, 2, 3, 15, 16, 17, 31, 32, 33, 64, 100, 257, 1024, 4096}
}

func TestXORRoundTrip(t *testing.T) {
	tech := XOR{}
	for _, n := range sizes() {
		roundTrip(t, "xor", tech, bytes.Repeat([]byte{0x41}, n))
	}
	roundTrip(t, "xor", tech, testPayload)
}

func TestXORRandomizesKey(t *testing.T) {
	payload := []byte("repeating-repeating-repeating-payload")
	tech := XOR{}
	a, err := tech.Obfuscate(payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tech.Obfuscate(payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("xor output should differ between runs (random key)")
	}
}

func TestXORCorruptHeaderRejected(t *testing.T) {
	tech := XOR{}
	obf, err := tech.Obfuscate([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	obf[3] = 0x7F
	if _, err := tech.Deobfuscate(obf); err == nil {
		t.Error("expected error for invalid key length header")
	}
	if _, err := tech.Deobfuscate([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for truncated input")
	}
}

func TestBase64RoundTrip(t *testing.T) {
	tech := &Base64{Alphabet: CustomAlphabet}
	for _, n := range sizes() {
		roundTrip(t, "base64", tech, bytes.Repeat([]byte{0xFF}, n))
	}
	roundTrip(t, "base64", tech, testPayload)
}

func TestBase64CustomAlphabet(t *testing.T) {
	tech := &Base64{Alphabet: CustomAlphabet}
	obf, err := tech.Obfuscate(testPayload)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range obf {
		if !strings.ContainsRune(CustomAlphabet+"=", rune(c)) {
			t.Errorf("output contains char %q outside custom alphabet", rune(c))
		}
	}
	std := base64.StdEncoding.EncodeToString(testPayload)
	if string(obf) == std {
		t.Error("custom alphabet output must differ from standard base64")
	}
}

func TestBase64InvalidAlphabetRejected(t *testing.T) {
	if _, err := (&Base64{Alphabet: "short"}).Obfuscate([]byte("x")); err == nil {
		t.Error("expected error for short alphabet")
	}
	if _, err := (&Base64{Alphabet: strings.Repeat("A", 64)}).Obfuscate([]byte("x")); err == nil {
		t.Error("expected error for duplicate alphabet chars")
	}
}

func TestSplitRoundTrip(t *testing.T) {
	tech := Split{}
	for _, n := range sizes() {
		roundTrip(t, "split", tech, bytes.Repeat([]byte{0xAB, 0xCD}, n/2+n%2))
	}
	roundTrip(t, "split", tech, testPayload)
}

func TestSplitRejectsCorruptHeader(t *testing.T) {
	tech := Split{}
	obf, err := tech.Obfuscate([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	obf[0] = 0x40
	if _, err := tech.Deobfuscate(obf); err == nil {
		t.Error("expected error for oversized chunk size")
	}
}

func TestHexRoundTrip(t *testing.T) {
	tech := Hex{}
	for _, n := range sizes() {
		roundTrip(t, "hex", tech, bytes.Repeat([]byte{0x00, 0x1F, 0x80, 0xFF}, n/4+n%4))
	}
	roundTrip(t, "hex", tech, testPayload)
}

func TestHexAcceptsBareHex(t *testing.T) {
	dec, err := (Hex{}).Deobfuscate([]byte("\\x48\\x65 6c6c6f"))
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "Hello" {
		t.Errorf("got %q, want %q", dec, "Hello")
	}
}

func TestUUIDRoundTrip(t *testing.T) {
	tech := UUID{}
	for _, n := range sizes() {
		roundTrip(t, "uuid", tech, bytes.Repeat([]byte{0x01, 0x23, 0x45}, n/3+n%3))
	}
	roundTrip(t, "uuid", tech, testPayload)
}

func TestUUIDFormatIsCanonical(t *testing.T) {
	obf, err := (UUID{}).Obfuscate([]byte("hello world, this is a longer payload"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(obf[8:], []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(line) != 36 || line[8] != '-' || line[13] != '-' || line[18] != '-' || line[23] != '-' {
			t.Errorf("non-canonical uuid line: %q", line)
		}
	}
}

func TestUUIDRejectsMalformedLine(t *testing.T) {
	obf, err := (UUID{}).Obfuscate([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	obf[20] = 'X'
	if _, err := (UUID{}).Deobfuscate(obf); err == nil {
		t.Error("expected error for malformed uuid")
	}
}

func TestURLRoundTrip(t *testing.T) {
	tech := URL{}
	for _, n := range sizes() {
		roundTrip(t, "url", tech, bytes.Repeat([]byte("a %b&c"), n))
	}
	roundTrip(t, "url", tech, testPayload)
}

func TestURLRejectsBareBytes(t *testing.T) {
	if _, err := (URL{}).Deobfuscate([]byte("%4x!")); err == nil {
		t.Error("expected error for non-escaped character")
	}
}

func TestEmptyInputsRejected(t *testing.T) {
	techniques := []Technique{XOR{}, Split{}, Hex{}, UUID{}, URL{}, &Base64{Alphabet: CustomAlphabet}}
	for _, tech := range techniques {
		if _, err := tech.Obfuscate(nil); err == nil {
			t.Errorf("%s: expected error for empty obfuscate input", tech.Name())
		}
		if _, err := tech.Deobfuscate(nil); err == nil {
			t.Errorf("%s: expected error for empty deobfuscate input", tech.Name())
		}
	}
}

func TestRegistry(t *testing.T) {
	names := Names()
	if len(names) != 6 {
		t.Fatalf("expected 6 techniques, got %d: %v", len(names), names)
	}
	for _, name := range []string{"xor", "base64", "split", "hex", "uuid", "url"} {
		found := false
		for _, n := range names {
			if n == name {
				found = true
			}
		}
		if !found {
			t.Errorf("technique %q missing from registry", name)
		}
	}
	if _, err := New("not-a-technique"); err == nil {
		t.Error("expected error for unknown technique")
	}
}

func TestPipelineRoundTripEveryOrder(t *testing.T) {
	names := Names()
	var permutations func(prefix []string, rest []string)
	permutations = func(prefix, rest []string) {
		if len(rest) == 0 {
			builder, err := NewBuilder(prefix)
			if err != nil {
				t.Fatal(err)
			}
			obf, err := builder.Build(testPayload)
			if err != nil {
				t.Fatalf("build %v: %v", prefix, err)
			}
			dec, err := builder.Deobfuscate(obf)
			if err != nil {
				t.Fatalf("deobfuscate %v: %v", prefix, err)
			}
			if !bytes.Equal(dec, testPayload) {
				t.Errorf("pipeline %v failed roundtrip", prefix)
			}
			return
		}
		for i, name := range rest {
			next := append(append([]string{}, rest[:i]...), rest[i+1:]...)
			permutations(append(prefix, name), next)
		}
	}
	permutations(nil, names)
}

func TestPipelineMultiRound(t *testing.T) {
	builder, err := NewBuilder([]string{"xor", "base64", "uuid", "url", "split", "hex"})
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload
	for round := 0; round < 3; round++ {
		payload, err = builder.Build(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	for round := 0; round < 3; round++ {
		payload, err = builder.Deobfuscate(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(payload, testPayload) {
		t.Error("multi-round pipeline roundtrip failed")
	}
}

func TestPipelineUnknownStageRejected(t *testing.T) {
	if _, err := NewBuilder([]string{"xor", "bogus"}); err == nil {
		t.Error("expected error for unknown stage")
	}
}

func TestStagesOrdering(t *testing.T) {
	builder, err := NewBuilder([]string{"url", "uuid", "xor"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(builder.Stages(), ",")
	if got != "url,uuid,xor" {
		t.Errorf("stages = %q, want url,uuid,xor", got)
	}
}

func TestEntropy(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want float64
	}{
		{"zeros", bytes.Repeat([]byte{0}, 1024), 0},
		{"single", []byte{'A'}, 0},
		{"uniform", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(), 8},
		{"empty", nil, 0},
	}
	for _, tc := range cases {
		got := Entropy(tc.data)
		if math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: entropy = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func BenchmarkPipeline(b *testing.B) {
	builder, _ := NewBuilder([]string{"xor", "base64", "uuid"})
	payload := bytes.Repeat([]byte{0x90}, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		obf, err := builder.Build(payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := builder.Deobfuscate(obf); err != nil {
			b.Fatal(err)
		}
	}
}
