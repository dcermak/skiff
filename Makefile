.PHONY: binaries vendor vendor-in-container unit-tests behave

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

vendor-in-container:
	podman run --rm --env HOME=/root \
		-v $(CURDIR):/src:Z -w /src \
		registry.suse.com/bci/golang:1.25 \
		make vendor
