package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"payload-obfuscation-engine/internal/engine"
)

const usage = `payload-obfuscate - payload obfuscation engine (defensive/educational use only)

Usage:
  payload-obfuscate list
  payload-obfuscate analyze [-i FILE] [--rounds N]
  payload-obfuscate obfuscate [-i FILE] [-o FILE] [-s STAGES] [--rounds N]
  payload-obfuscate deobfuscate [-i FILE] [-o FILE] [-s STAGES] [--rounds N]

Commands:
  list         List available obfuscation techniques
  analyze      Print size and Shannon entropy of input
  obfuscate    Apply the pipeline to the input payload
  deobfuscate  Reverse the pipeline to recover the original payload

Flags:
  -i, --input FILE    Input file (default: stdin)
  -o, --output FILE   Output file (default: stdout)
  -s, --stages LIST   Comma-separated pipeline stages in order
                      (default: xor,base64,hex)
  -r, --rounds N      Apply the pipeline N times (default: 1)
  -h, --help          Show this help
`

// Options holds a parsed command line.
type Options struct {
	Command string
	Input   string
	Output  string
	Stages  []string
	Rounds  int
}

// Run executes the CLI and returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err := execute(opts, stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func parseArgs(args []string) (Options, error) {
	if len(args) == 0 {
		return Options{}, errors.New("missing command")
	}
	opts := Options{Command: args[0], Rounds: 1}
	switch opts.Command {
	case "list":
		if len(args) > 1 {
			return Options{}, fmt.Errorf("unexpected argument %q", args[1])
		}
		return opts, nil
	case "obfuscate", "deobfuscate", "analyze":
	default:
		return Options{}, fmt.Errorf("unknown command %q (use -h for help)", opts.Command)
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", arg)
			}
			i++
			return args[i], nil
		}
		var err error
		switch arg {
		case "-i", "--input":
			opts.Input, err = next()
		case "-o", "--output":
			opts.Output, err = next()
		case "-s", "--stages":
			var value string
			value, err = next()
			if err == nil {
				opts.Stages = append(opts.Stages, strings.Split(value, ",")...)
			}
		case "-r", "--rounds":
			var value string
			value, err = next()
			if err == nil {
				opts.Rounds, err = strconv.Atoi(value)
				if err == nil && opts.Rounds < 1 {
					err = errors.New("rounds must be >= 1")
				}
			}
		default:
			if strings.HasPrefix(arg, "-") {
				return Options{}, fmt.Errorf("unknown flag %q", arg)
			}
			return Options{}, fmt.Errorf("unexpected argument %q", arg)
		}
		if err != nil {
			return Options{}, err
		}
	}
	return opts, nil
}

func execute(opts Options, stdin io.Reader, stdout io.Writer) error {
	switch opts.Command {
	case "list":
		for _, name := range engine.Names() {
			fmt.Fprintln(stdout, name)
		}
		return nil
	case "analyze":
		data, err := readInput(opts, stdin)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "size: %d bytes\n", len(data))
		fmt.Fprintf(stdout, "entropy: %.4f bits/byte\n", engine.Entropy(data))
		return nil
	}
	payload, err := readInput(opts, stdin)
	if err != nil {
		return err
	}
	if len(opts.Stages) == 0 {
		opts.Stages = []string{"xor", "base64", "hex"}
	}
	builder, err := engine.NewBuilder(opts.Stages)
	if err != nil {
		return err
	}
	transform := builder.Build
	if opts.Command == "deobfuscate" {
		transform = builder.Deobfuscate
	}
	for round := 0; round < opts.Rounds; round++ {
		payload, err = transform(payload)
		if err != nil {
			return fmt.Errorf("round %d: %w", round+1, err)
		}
	}
	return writeOutput(opts, payload, stdout)
}

func readInput(opts Options, stdin io.Reader) ([]byte, error) {
	if opts.Input == "" {
		return io.ReadAll(stdin)
	}
	data, err := os.ReadFile(opts.Input)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", opts.Input, err)
	}
	return data, nil
}

func writeOutput(opts Options, data []byte, stdout io.Writer) error {
	if opts.Output == "" {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(opts.Output, data, 0o600)
}
