# Payload Obfuscation Engine

A defensive, educational payload obfuscation engine written in Go. It implements six reversible obfuscation techniques as a composable library, chains them into configurable pipelines, and ships a CLI to obfuscate and deobfuscate payloads.

## Overview

The Payload Obfuscation Engine is an educational tool designed to demonstrate how payload obfuscation works and how signature-based detection mechanisms can be evaded or bypassed. This knowledge is fundamental to understanding both offensive techniques and defensive countermeasures in modern cybersecurity. The engine is intentionally built with simple, reversible techniques to facilitate learning and analysis.

**Important:** This tool is intended solely for educational purposes and authorized security research. It should only be used on payloads you create, samples from sanctioned malware-analysis labs, or infrastructure you own or have explicit authorization to test.

## Techniques

The engine provides six reversible obfuscation techniques, all of which support exact round-trip deobfuscation:

| Technique | Output Shape | Randomness |
|-----------|--------------|------------|
| `xor` | `[keylen][key][cipher]` binary | Fresh key every run |
| `base64` | ASCII with custom alphabet | Deterministic |
| `split` | `[size][count][perm][chunks]` binary | Fresh permutation every run |
| `hex` | `\xHH` ASCII escapes | Deterministic |
| `uuid` | `[len][uuid...\n]` ASCII | Deterministic |
| `url` | `%HH` ASCII escapes | Deterministic |

Each technique is designed to be simple enough to understand fundamentally while demonstrating core concepts in payload transformation.

## Pipeline Builder

The engine features a composable pipeline system where techniques can be chained in any order:

- **Pipeline construction**: Select any combination of the six techniques in a desired sequence
- **Inverse operations**: `Deobfuscate` reverses the exact inverse order of the obfuscation pipeline
- **Round repetition**: Apply the entire pipeline multiple times using the `-r` or `--rounds` flag
- **Preset pipeline**: Default pipeline when no stages are specified: `xor,base64,hex`

## CLI Interface

The command-line tool provides comprehensive functionality:

### Available Commands

| Command | Description |
|---------|-------------|
| `list` | Display all available obfuscation techniques |
| `analyze` | Perform entropy and size analysis on a payload |
| `obfuscate` | Apply a pipeline of obfuscation techniques to a payload |
| `deobfuscate` | Reverse a previously applied obfuscation pipeline |

### CLI Options

- `-i, --input`: Input file path (defaults to stdin)
- `-o, --output`: Output file path (defaults to stdout)
- `-s, --stages`: Comma-separated list of obfuscation techniques to apply
- `-r, --rounds`: Number of times to apply the full pipeline (default: 1)
- `--help`: Display help information

### Example Usages

```bash
# List available techniques
payload-obfuscate list

# Obfuscate a payload through a pipeline (stdin/stdout)
payload-obfuscate obfuscate -i payload.bin -o payload.enc -s xor,base64,uuid,url,split,hex

# Undo it — pass the same stage list; the pipeline is reversed internally
payload-obfuscate deobfuscate -i payload.enc -o payload.bin -s xor,base64,uuid,url,split,hex

# Apply the whole pipeline 3 times
payload-obfuscate obfuscate -i payload.bin -s xor,base64 -r 3

# Pipe mode - obfuscate then deobfuscate in sequence
cat payload.bin | payload-obfuscate obfuscate -s xor,hex | payload-obfuscate deobfuscate -s hex,xor

# Analyze entropy and size
payload-obfuscate analyze -i payload.bin
```

## Library Usage

```go
import "github.com/OpKnock/payload-obfuscation-engine/engine"

builder, _ := engine.NewBuilder([]string{"xor", "base64", "uuid"})
obfuscated, _ := builder.Build(payload)
original, _ := builder.Deobfuscate(obfuscated)
```

The library provides a `Builder` type that handles technique registration, pipeline construction, and round-trip obfuscation/deobfuscation.

## Installation and Building

### Requirements

- Go 1.26+ (no external modules required, works fully offline)

### Build from Source

```bash
go build -o bin/payload-obfuscate ./cmd/payload-obfuscate
```

### Just Build Shortcut

```bash
just build
```

### Pre-built Binary

Binary releases are available in the GitHub Releases section for immediate use without building.

## Entropy Analysis

The engine includes Shannon entropy calculation (bits/byte) to help analyze payload complexity and detect potential obfuscation effects. The `analyze` command provides:

- Shannon entropy value per byte
- File size before and after obfuscation
- Comparison of entropy before/after each technique
- Recommendations for further analysis

## Testing

The project includes comprehensive test coverage:

- Round-trip verification (obfuscate → deobfuscate == original) for every technique
- Pipeline round-trips for every permutation of all six stages
- Multi-round pipeline testing
- Entropy math validation
- Malformed-input rejection testing
- CLI behavior testing including built-binary end-to-end tests

Run all tests with: `go test ./...`

Coverage reports are generated in the `coverage/` directory.

## Legal and Ethical Notes

### Dual-Use Disclaimer

Payload obfuscation is a dual-use technique with legitimate applications in both offensive and defensive cybersecurity:

- **Offensive use**: Malware authors use obfuscation to evade signature-based detection
- **Defensive use**: Security researchers use obfuscation understanding to improve behavioral detection, design better signatures, and analyze threat samples

### Authorized Use Only

This engine must only be used:

- On payloads you personally created for testing purposes
- On samples from sanctioned malware-analysis laboratories
- On infrastructure you own or have explicit written authorization to test
- In educational settings with proper oversight

### Prohibited Use

- Never use against security controls on systems you do not own
- Never use for evading controls on production systems without permission
- Never distribute obfuscated payloads for malicious purposes

The educational value of understanding these techniques is significant for improving overall security posture, but this must always be balanced with legal and ethical responsibilities.

## License

MIT License - See the LICENSE file for full terms and conditions. This project is provided "as is" without warranty of any kind, either express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement.