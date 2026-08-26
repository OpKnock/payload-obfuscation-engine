# Payload Obfuscation Engine

A defensive, educational payload obfuscation engine written in Go. It implements
six reversible obfuscation techniques as a composable library, chains them into
configurable pipelines, and ships a CLI to obfuscate and deobfuscate payloads.

> **Intended use only for education and defense.** This tool exists to teach
> how signature-based detection works and how static evasion techniques are
> defeated — the same concepts that drive behavioral analysis in modern
> antivirus. Only apply it to your own samples (e.g., malware you are analyzing
> in a lab, red-team exercises on infrastructure you own or are authorized to
> test). Never use it to evade security controls on systems you do not own or
> are not explicitly authorized to test.

## Features

- **Six reversible obfuscation techniques** (all `Obfuscate`/`Deobfuscate`
  round-trips are exact):
  - `xor` — XOR with a random key, prepended to the output (different output
    on every run)
  - `base64` — base64 with a custom 64-character alphabet (no standard `+/`)
  - `split` — chunk-and-shuffle with an embedded permutation header
  - `hex` — `\xNN` escape sequences
  - `uuid` — RFC-4122-lookalike UUID strings, one per 16-byte block
  - `url` — percent-encoding of every byte
- **Pipeline builder** — chain stages in any order; `Deobfuscate` reverses the
  exact inverse order.
- **CLI** with `list`, `analyze`, `obfuscate`, and `deobfuscate` commands,
  file/stdin/stdout I/O, and a `--rounds` flag to apply the pipeline multiple
  times.
- **Entropy analysis** — Shannon entropy (bits/byte) for payload reports.
- **Pure Go standard library** — zero external dependencies, fully offline.

## Project layout

```
cmd/payload-obfuscate/   CLI entry point
internal/engine/         Technique interface, registry, six techniques, entropy
internal/cli/            argument parsing and command execution
```

## Install / build

Requires Go 1.26+ (no external modules, works offline).

```sh
go build -o bin/payload-obfuscate ./cmd/payload-obfuscate
```

Or with `just`:

```sh
just build
```

## Usage

```sh
# List available techniques
payload-obfuscate list

# Obfuscate a payload through a pipeline (stdin/stdout)
payload-obfuscate obfuscate -i payload.bin -o payload.enc -s xor,base64,uuid,url,split,hex

# Undo it — pass the same stage list; the pipeline is reversed internally
payload-obfuscate deobfuscate -i payload.enc -o payload.bin -s xor,base64,uuid,url,split,hex

# Apply the whole pipeline 3 times
payload-obfuscate obfuscate -i payload.bin -s xor,base64 -r 3

# Pipe mode
cat payload.bin | payload-obfuscate obfuscate -s xor,hex | payload-obfuscate deobfuscate -s hex,xor

# Analyze entropy and size
payload-obfuscate analyze -i payload.bin
```

Default pipeline when `-s` is omitted: `xor,base64,hex`.

## Library usage

```go
builder, _ := engine.NewBuilder([]string{"xor", "base64", "uuid"})
obfuscated, _ := builder.Build(payload)
original, _ := builder.Deobfuscate(obfuscated)
```

## Testing

```sh
go test ./...
```

Coverage: round-trip (obfuscate → deobfuscate == original) for every technique
across many input sizes, pipeline round-trips for **every permutation** of all
six stages, multi-round pipelines, entropy math, malformed-input rejection, and
CLI behavior including a built-binary end-to-end test.

## Techniques at a glance

| Name | Output shape | Randomness |
|------|--------------|------------|
| `xor` | `[keylen][key][cipher]` binary | fresh key every run |
| `base64` | ASCII with custom alphabet | deterministic |
| `split` | `[size][count][perm][chunks]` binary | fresh permutation every run |
| `hex` | `\xHH` ASCII escapes | deterministic |
| `uuid` | `[len][uuid...\n]` ASCII | deterministic |
| `url` | `%HH` ASCII escapes | deterministic |

## Legal and ethical notes

- Obfuscation is a **dual-use** technique: it is the same method used by
  malware and by defensive researchers (evasion testing, detection
  engineering, malware analysis).
- Use this engine only on payloads you created, samples from sanctioned
  malware-analysis labs, or infrastructure you are authorized to test.
- The techniques here are trivial to reverse on purpose — the educational
  value is in understanding *why* signature-based detection fails and how
  behavioral detection takes over.