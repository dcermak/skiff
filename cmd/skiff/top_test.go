package main

import (
	"context"
	"io"
	"testing"

	"container/heap"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestHumanReadableSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero bytes", 0, "0 B"},
		{"small bytes", 500, "500 B"},
		{"1 KB", 1000, "1.0 kB"},
		{"1.5 KB", 1500, "1.5 kB"},
		{"1 MB", 1000000, "1.0 MB"},
		{"1.5 MB", 1500000, "1.5 MB"},
		{"1 GB", 1000000000, "1.0 GB"},
		{"1.5 GB", 1500000000, "1.5 GB"},
		{"large number", 1234567890, "1.2 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HumanReadableSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("HumanReadableSize(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestFileHeap(t *testing.T) {
	h := &FileHeap{}
	heap.Init(h)

	// Test empty heap
	if h.Len() != 0 {
		t.Errorf("Expected empty heap to have length 0, got %d", h.Len())
	}

	// Test pushing items
	items := []FileInfo{
		{Path: "/file1", Size: 100},
		{Path: "/file2", Size: 50},
		{Path: "/file3", Size: 200},
	}

	for _, item := range items {
		heap.Push(h, item)
	}

	if h.Len() != 3 {
		t.Errorf("Expected heap to have length 3, got %d", h.Len())
	}

	// Test that smallest item is at the top (min heap)
	smallest := heap.Pop(h).(FileInfo)
	if smallest.Size != 50 {
		t.Errorf("Expected smallest item to have size 50, got %d", smallest.Size)
	}

	// Test remaining items
	if h.Len() != 2 {
		t.Errorf("Expected heap to have length 2 after pop, got %d", h.Len())
	}

	next := heap.Pop(h).(FileInfo)
	if next.Size != 100 {
		t.Errorf("Expected next item to have size 100, got %d", next.Size)
	}

	last := heap.Pop(h).(FileInfo)
	if last.Size != 200 {
		t.Errorf("Expected last item to have size 200, got %d", last.Size)
	}

	if h.Len() != 0 {
		t.Errorf("Expected empty heap after all pops, got length %d", h.Len())
	}
}

// MockImage implements types.Image for testing
type MockImage struct {
	layers []types.BlobInfo
}

func (m *MockImage) LayerInfos() []types.BlobInfo {
	return m.layers
}

// Implement other required methods with empty implementations
func (m *MockImage) Reference() types.ImageReference                                 { return nil }
func (m *MockImage) Manifest(ctx context.Context) ([]byte, string, error)            { return nil, "", nil }
func (m *MockImage) Signatures(ctx context.Context) ([][]byte, error)                { return nil, nil }
func (m *MockImage) ConfigInfo() types.BlobInfo                                      { return types.BlobInfo{} }
func (m *MockImage) ConfigBlob(ctx context.Context) ([]byte, error)                  { return nil, nil }
func (m *MockImage) OCIConfig(ctx context.Context) (*v1.Image, error)                { return nil, nil }
func (m *MockImage) LayerInfosForCopy(ctx context.Context) ([]types.BlobInfo, error) { return nil, nil }
func (m *MockImage) EmbeddedDockerReferenceConflicts(ref reference.Named) bool       { return false }
func (m *MockImage) Inspect(ctx context.Context) (*types.ImageInspectInfo, error)    { return nil, nil }
func (m *MockImage) UpdatedImageNeedsLayerDiffIDs(options types.ManifestUpdateOptions) bool {
	return false
}
func (m *MockImage) UpdatedImage(ctx context.Context, options types.ManifestUpdateOptions) (types.Image, error) {
	return nil, nil
}
func (m *MockImage) SupportsGetBlobAt() bool { return false }
func (m *MockImage) GetBlobAt(ctx context.Context, info types.BlobInfo, chunks []types.BlobInfo) (chan io.ReadCloser, chan error, error) {
	return nil, nil, nil
}
func (m *MockImage) SupportsEncryption(ctx context.Context) bool { return false }
func (m *MockImage) Size() (int64, error)                        { return 0, nil }
func (m *MockImage) Close() error                                { return nil }

func TestGetFilteredLayers(t *testing.T) {
	// Create mock layers with proper digest format
	layer1 := types.BlobInfo{Digest: digest.Digest("sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")}
	layer2 := types.BlobInfo{Digest: digest.Digest("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")}
	layer3 := types.BlobInfo{Digest: digest.Digest("sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")}
	layer4 := types.BlobInfo{Digest: digest.Digest("sha256:1234567890bbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111")} // Same prefix as layer1

	mockImage := &MockImage{
		layers: []types.BlobInfo{layer1, layer2, layer3, layer4},
	}

	tests := []struct {
		name          string
		filterLayers  []string
		expectedCount int
		expectError   bool
		errorContains string
	}{
		{
			name:          "no filters - return all layers",
			filterLayers:  []string{},
			expectedCount: 4,
			expectError:   false,
		},
		{
			name:          "filter by full digest",
			filterLayers:  []string{"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "filter by partial digest",
			filterLayers:  []string{"1234567890abcdef"},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "filter by non-existent layer",
			filterLayers:  []string{"nonexistent"},
			expectedCount: 0,
			expectError:   true,
			errorContains: "layer nonexistent not found",
		},
		{
			name:          "filter by ambiguous partial digest",
			filterLayers:  []string{"1234567890"},
			expectedCount: 0,
			expectError:   true,
			errorContains: "multiple layers match shortened digest",
		},
		{
			name:          "filter by multiple layers",
			filterLayers:  []string{"1234567890abcdef", "abcdef1234567890"},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "filter by duplicate layers",
			filterLayers:  []string{"1234567890abcdef", "1234567890abcdef"},
			expectedCount: 1,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getFilteredLayers(mockImage, tt.filterLayers)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d layers, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 0; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}

func TestFileInfo(t *testing.T) {
	fileInfo := FileInfo{
		Path:              "/test/file.txt",
		Size:              1024,
		HumanReadableSize: "1.0 kB",
		Layer:             "sha256:1234567890abcdef",
	}

	if fileInfo.Path != "/test/file.txt" {
		t.Errorf("Expected path '/test/file.txt', got '%s'", fileInfo.Path)
	}

	if fileInfo.Size != 1024 {
		t.Errorf("Expected size 1024, got %d", fileInfo.Size)
	}

	if fileInfo.HumanReadableSize != "1.0 kB" {
		t.Errorf("Expected human readable size '1.0 kB', got '%s'", fileInfo.HumanReadableSize)
	}

	if fileInfo.Layer != "sha256:1234567890abcdef" {
		t.Errorf("Expected layer 'sha256:1234567890abcdef', got '%s'", fileInfo.Layer)
	}
}
