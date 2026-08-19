package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"payload-obfuscation-engine/internal/cli"
)

var samplePayload = []byte("MZ\x90\x00\x03\x00\x00\x00fake-shellcode-payload-for-education\x00")

func runCLI(args []string, stdin []byte) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := cli.Run(args, bytes.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestListCommand(t *testing.T) {
	code, out, errOut := runCLI([]string{"list"}, nil)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut)
	}
	for _, name := range []string{"xor", "base64", "split", "hex", "uuid", "url"} {
		if !strings.Contains(out, name) {
			t.Errorf("list output missing %q:\n%s", name, out)
		}
	}
	lines := strings.Fields(out)
	if len(lines) != 6 {
		t.Errorf("expected 6 techniques, got %d: %v", len(lines), lines)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errOut := runCLI([]string{"frobnicate"}, nil)
	if code == 0 || !strings.Contains(errOut, "unknown command") {
		t.Errorf("expected failure, code=%d stderr=%q", code, errOut)
	}
}

func TestUnknownFlag(t *testing.T) {
	code, _, _ := runCLI([]string{"obfuscate", "--bogus"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for unknown flag")
	}
}

func TestUnknownStageFails(t *testing.T) {
	code, _, errOut := runCLI([]string{"obfuscate", "-s", "xor,nope"}, samplePayload)
	if code == 0 || !strings.Contains(errOut, "unknown technique") {
		t.Errorf("expected failure, code=%d stderr=%q", code, errOut)
	}
}

func TestMissingInputFileFails(t *testing.T) {
	code, _, errOut := runCLI([]string{"obfuscate", "-i", filepath.Join(t.TempDir(), "nope.bin")}, nil)
	if code == 0 || !strings.Contains(errOut, "reading") {
		t.Errorf("expected failure, code=%d stderr=%q", code, errOut)
	}
}

func TestInvalidRoundsRejected(t *testing.T) {
	code, _, _ := runCLI([]string{"obfuscate", "-r", "0"}, samplePayload)
	if code == 0 {
		t.Error("expected failure for rounds=0")
	}
}

func TestStdinStdoutRoundTrip(t *testing.T) {
	stages := "xor,base64,uuid,url,split,hex"
	code, obf, errOut := runCLI([]string{"obfuscate", "-s", stages}, samplePayload)
	if code != 0 {
		t.Fatalf("obfuscate failed: %s", errOut)
	}
	if obf == string(samplePayload) {
		t.Error("obfuscated output must differ from input")
	}
	code, dec, errOut := runCLI([]string{"deobfuscate", "-s", stages}, []byte(obf))
	if code != 0 {
		t.Fatalf("deobfuscate failed: %s", errOut)
	}
	if !bytes.Equal([]byte(dec), samplePayload) {
		t.Errorf("roundtrip mismatch:\n got: %q\nwant: %q", dec, samplePayload)
	}
}

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "payload.bin")
	enc := filepath.Join(dir, "payload.enc")
	dec := filepath.Join(dir, "payload.dec")
	if err := os.WriteFile(in, samplePayload, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI([]string{"obfuscate", "-i", in, "-o", enc, "-s", "hex,xor"}, nil)
	if code != 0 {
		t.Fatalf("obfuscate failed: %s", errOut)
	}
	code, _, errOut = runCLI([]string{"deobfuscate", "-i", enc, "-o", dec, "-s", "hex,xor"}, nil)
	if code != 0 {
		t.Fatalf("deobfuscate failed: %s", errOut)
	}
	got, err := os.ReadFile(dec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, samplePayload) {
		t.Error("file roundtrip mismatch")
	}
}

func TestRoundsFlag(t *testing.T) {
	stages := "xor,base64"
	code, obf, errOut := runCLI([]string{"obfuscate", "-s", stages, "-r", "3"}, samplePayload)
	if code != 0 {
		t.Fatalf("obfuscate failed: %s", errOut)
	}
	code, dec, errOut := runCLI([]string{"deobfuscate", "-s", stages, "-r", "3"}, []byte(obf))
	if code != 0 {
		t.Fatalf("deobfuscate failed: %s", errOut)
	}
	if !bytes.Equal([]byte(dec), samplePayload) {
		t.Error("multi-round roundtrip mismatch")
	}
}

func TestDefaultPipeline(t *testing.T) {
	code, obf, errOut := runCLI([]string{"obfuscate"}, samplePayload)
	if code != 0 {
		t.Fatalf("obfuscate failed: %s", errOut)
	}
	code, dec, errOut := runCLI([]string{"deobfuscate"}, []byte(obf))
	if code != 0 {
		t.Fatalf("deobfuscate failed: %s", errOut)
	}
	if !bytes.Equal([]byte(dec), samplePayload) {
		t.Error("default pipeline roundtrip mismatch")
	}
}

func TestAnalyzeCommand(t *testing.T) {
	code, out, errOut := runCLI([]string{"analyze"}, bytes.Repeat([]byte{0x41}, 100))
	if code != 0 {
		t.Fatalf("analyze failed: %s", errOut)
	}
	if !strings.Contains(out, "size: 100 bytes") {
		t.Errorf("size missing from analyze output: %q", out)
	}
	if !strings.Contains(out, "entropy: 0.0000") {
		t.Errorf("entropy missing from analyze output: %q", out)
	}
}

func TestAnalyzeInputFile(t *testing.T) {
	in := filepath.Join(t.TempDir(), "data.bin")
	if err := os.WriteFile(in, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI([]string{"analyze", "-i", in}, nil)
	if code != 0 {
		t.Fatalf("analyze failed: %s", errOut)
	}
	if !strings.Contains(out, "size: 6 bytes") {
		t.Errorf("unexpected analyze output: %q", out)
	}
}

func TestHelpFlag(t *testing.T) {
	code, out, _ := runCLI([]string{"-h"}, nil)
	if code != 0 || !strings.Contains(out, "Usage") {
		t.Error("help output missing")
	}
}

func TestBuiltBinaryEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in short mode")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "payload-obfuscate.exe")
	build := exec.Command("go", "build", "-o", exe, "../../cmd/payload-obfuscate")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	in := filepath.Join(dir, "in.bin")
	enc := filepath.Join(dir, "enc.bin")
	dec := filepath.Join(dir, "dec.bin")
	if err := os.WriteFile(in, samplePayload, 0o600); err != nil {
		t.Fatal(err)
	}
	stages := "xor,split,uuid,url,base64,hex"
	run := func(args ...string) string {
		cmd := exec.Command(exe, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	run("obfuscate", "-i", in, "-o", enc, "-s", stages)
	run("deobfuscate", "-i", enc, "-o", dec, "-s", stages)
	got, err := os.ReadFile(dec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, samplePayload) {
		t.Error("built binary roundtrip mismatch")
	}
	if out := run("analyze", "-i", in); !strings.Contains(out, "entropy:") {
		t.Errorf("analyze output missing entropy: %q", out)
	}
}
