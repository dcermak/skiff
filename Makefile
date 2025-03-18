.PHONY: binaries, vendor

# Build the binaries
binaries:
	go build -o bin/skiff ./cmd/skiff

vendor:
	go mod tidy
	go mod vendor
	go mod verify
