# Payload Obfuscation Engine — just commands

default:
	@just --list

test:
	go test ./...

build:
	go build -o bin/payload-obfuscate ./cmd/payload-obfuscate

fmt:
	gofmt -w .

vet:
	go vet ./...

check: fmt vet test

clean:
	rm -rf bin
