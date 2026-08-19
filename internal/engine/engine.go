package engine

import (
	"fmt"
	"sort"
	"strings"
)

// Technique is a reversible obfuscation stage. Every implementation must
// guarantee that Deobfuscate(Obfuscate(data)) == data.
type Technique interface {
	Name() string
	Obfuscate(data []byte) ([]byte, error)
	Deobfuscate(data []byte) ([]byte, error)
}

var registry = map[string]func() Technique{
	"xor":    func() Technique { return XOR{} },
	"base64": func() Technique { return &Base64{Alphabet: CustomAlphabet} },
	"split":  func() Technique { return Split{} },
	"hex":    func() Technique { return Hex{} },
	"uuid":   func() Technique { return UUID{} },
	"url":    func() Technique { return URL{} },
}

// New returns a technique registered under the given name.
func New(name string) (Technique, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown technique %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	return factory(), nil
}

// Names returns all registered technique names in sorted order.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Builder chains techniques into an obfuscation pipeline.
type Builder struct {
	stages []Technique
}

// NewBuilder validates the stage names and creates a pipeline.
func NewBuilder(names []string) (*Builder, error) {
	stages := make([]Technique, 0, len(names))
	for _, name := range names {
		t, err := New(name)
		if err != nil {
			return nil, err
		}
		stages = append(stages, t)
	}
	return &Builder{stages: stages}, nil
}

// Stages returns the ordered stage names of the pipeline.
func (b *Builder) Stages() []string {
	names := make([]string, 0, len(b.stages))
	for _, s := range b.stages {
		names = append(names, s.Name())
	}
	return names
}

// Build applies every stage in pipeline order.
func (b *Builder) Build(payload []byte) ([]byte, error) {
	return b.run(payload, false)
}

// Deobfuscate reverses every stage in reverse pipeline order.
func (b *Builder) Deobfuscate(data []byte) ([]byte, error) {
	return b.run(data, true)
}

func (b *Builder) run(data []byte, reverse bool) ([]byte, error) {
	cur := data
	for i, stage := range b.stages {
		if reverse {
			stage = b.stages[len(b.stages)-1-i]
		}
		op := stage.Obfuscate
		if reverse {
			op = stage.Deobfuscate
		}
		var err error
		cur, err = op(cur)
		if err != nil {
			return nil, fmt.Errorf("stage %d (%s): %w", i+1, stage.Name(), err)
		}
	}
	return cur, nil
}
