.PHONY: binaries

# Build the binaries
binaries:
	go build -o bin/skiff ./cmd/skiff
