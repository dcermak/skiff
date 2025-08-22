package main

import (
	"strings"
	"testing"

	"container/heap"

	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"

	skiff "github.com/dcermak/skiff/pkg"
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
			result := skiff.HumanReadableSize(tt.bytes)
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


func TestGetLayersByDiffID(t *testing.T) {
	// Create test layers
	layer1 := types.BlobInfo{Digest: digest.Digest("sha256:layer1digest")}
	layer2 := types.BlobInfo{Digest: digest.Digest("sha256:layer2digest")}
	layer3 := types.BlobInfo{Digest: digest.Digest("sha256:layer3digest")}
	manifestLayers := []types.BlobInfo{layer1, layer2, layer3}

	// Create test diffIDs
	diffID1 := digest.Digest("sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	diffID2 := digest.Digest("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	diffID3 := digest.Digest("sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
	allDiffIDs := []digest.Digest{diffID1, diffID2, diffID3}

	tests := []struct {
		name          string
		filterDiffIDs []string
		expectedCount int
		expectError   bool
		errorContains string
	}{
		{
			name:          "no filters - return all layers",
			filterDiffIDs: []string{},
			expectedCount: 3,
			expectError:   false,
		},
		{
			name:          "filter by full diffID",
			filterDiffIDs: []string{"sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "filter by partial diffID",
			filterDiffIDs: []string{"1234567890abcdef"},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "filter by non-existent diffID",
			filterDiffIDs: []string{"nonexistent"},
			expectedCount: 0,
			expectError:   true,
			errorContains: "diffID nonexistent not found",
		},
		{
			name:          "filter by multiple diffIDs",
			filterDiffIDs: []string{"1234567890abcdef", "abcdef1234567890"},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "filter by partial diffID - second layer",
			filterDiffIDs: []string{"abcdef1234"},
			expectedCount: 1,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layers, diffIDs, err := getLayersByDiffID(manifestLayers, allDiffIDs, tt.filterDiffIDs)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(layers) != tt.expectedCount {
				t.Errorf("Expected %d layers, got %d", tt.expectedCount, len(layers))
			}

			if len(diffIDs) != tt.expectedCount {
				t.Errorf("Expected %d diffIDs, got %d", tt.expectedCount, len(diffIDs))
			}
		})
	}
}

func TestFileInfo(t *testing.T) {
	diffID := digest.Digest("sha256:1234567890abcdef")
	fileInfo := FileInfo{
		Path:              "/test/file.txt",
		Size:              1024,
		HumanReadableSize: "1.0 kB",
		DiffID:            diffID,
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

	if fileInfo.DiffID != diffID {
		t.Errorf("Expected diffID '%s', got '%s'", diffID, fileInfo.DiffID)
	}
}
