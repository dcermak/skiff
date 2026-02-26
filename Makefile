.PHONY: binaries vendor unit-tests behave

# Build the binaries
binaries:
	go build -o bin/skiff ./cmd/skiff

test-image:
	cd pkg; buildah bud --layers -t skiff-test-image -f TestImage.containerfile .

# Run unit tests
unit-tests: test-image
	go test -v ./...

# Run behave tests
behave:
	behave features/

vendor:
	go mod tidy
	go mod vendor
	go mod verify
