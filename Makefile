.PHONY: binaries vendor unit-tests behave

# Build the binaries
binaries:
	go build -o bin/skiff ./cmd/skiff

# Run unit tests
unit-tests:
	go test -v ./cmd/skiff/...

# Run behave tests
behave:
	behave features/

vendor:
	go mod tidy
	go mod vendor
	go mod verify
