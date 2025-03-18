.PHONY: binaries, vendor, unit-tests

# Build the binaries
binaries:
	go build -o bin/skiff ./cmd/skiff

# Run tests
unit-tests:
	go test -v ./cmd/skiff/...

vendor:
	go mod tidy
	go mod vendor
	go mod verify
