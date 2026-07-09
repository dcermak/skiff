.PHONY: binaries vendor vendor-in-container unit-tests behave test-image test-image-fedora integration-tests

# Build the binaries
binaries:
	go build -o bin/skiff ./cmd/skiff

test-image:
	cd pkg; buildah bud --layers -t skiff-test-image -f TestImage.containerfile .

test-image-fedora:
	cd pkg; buildah bud --layers -t skiff-test-image-fedora -f TestImageFedora.containerfile .

# Run unit tests (no buildah / namespace setup / network required)
unit-tests:
	go test ./...

# Run integration tests (requires the local test images and namespace setup)
integration-tests: test-image test-image-fedora
	go test -tags=integration ./...

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
