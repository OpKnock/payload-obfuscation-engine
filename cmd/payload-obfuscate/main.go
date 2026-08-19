package main

import (
	"os"

	"payload-obfuscation-engine/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
