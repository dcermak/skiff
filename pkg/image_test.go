package skiff

import (
	"context"
	"testing"

	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
)

func TestImageAndLayersFromURI(t *testing.T) {
	ctx := context.Background()
	sysCtx := &types.SystemContext{}

	// Test with invalid URI
	_, _, err := ImageAndLayersFromURI(ctx, sysCtx, "invalid://uri")
	if err == nil {
		t.Error("Expected error for invalid URI, but got none")
	}

	// Test with empty URI
	_, _, err = ImageAndLayersFromURI(ctx, sysCtx, "")
	if err == nil {
		t.Error("Expected error for empty URI, but got none")
	}
}

func TestLayersFromImageDigest(t *testing.T) {
	// This test would require a mock storage.Store
	// For now, we'll test the function signature

	// Create a test digest
	testDigest := digest.Digest("sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	// Test with nil store (this will cause an error, which is expected)
	_, err := layersFromImageDigest(nil, testDigest)
	if err == nil {
		t.Error("Expected error for nil store, but got none")
	}
}

func TestDigestValidation(t *testing.T) {
	tests := []struct {
		name        string
		digestStr   string
		expectValid bool
	}{
		{
			name:        "valid sha256 digest",
			digestStr:   "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectValid: true,
		},
		{
			name:        "invalid digest format",
			digestStr:   "invalid-digest",
			expectValid: false,
		},
		{
			name:        "empty digest",
			digestStr:   "",
			expectValid: false,
		},
		{
			name:        "sha256 with wrong length",
			digestStr:   "sha256:1234567890abcdef",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := digest.Parse(tt.digestStr)
			if tt.expectValid && err != nil {
				t.Errorf("Expected valid digest, but got error: %v", err)
			}
			if !tt.expectValid && err == nil {
				t.Errorf("Expected invalid digest, but got no error")
			}
		})
	}
}
