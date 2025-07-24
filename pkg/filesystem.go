package skiff

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/types"
)

// FileInfo represents a file in a container image
type FileInfo struct {
	Path  string
	Size  int64
	Layer string // layer digest this file belongs to
}

// HumanReadableSize converts a byte count to a human readable string
// From https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
func HumanReadableSize(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// ExtractFilesystem extracts all files from an image's layers
// Returns a map of file paths to FileInfo
func ExtractFilesystem(ctx context.Context, img types.Image, sysCtx *types.SystemContext) (map[string]FileInfo, error) {
	imgSrc, err := img.Reference().NewImageSource(ctx, sysCtx)
	if err != nil {
		return nil, err
	}
	defer imgSrc.Close()

	files := make(map[string]FileInfo)
	layerInfos := img.LayerInfos()

	for _, layer := range layerInfos {
		blob, _, err := imgSrc.GetBlob(ctx, layer, none.NoCache)
		if err != nil {
			return nil, err
		}
		defer blob.Close()

		uncompressedStream, _, err := compression.AutoDecompress(blob)
		if err != nil {
			return nil, fmt.Errorf("auto-decompressing input: %w", err)
		}
		defer uncompressedStream.Close()

		tr := tar.NewReader(uncompressedStream)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read tar header: %w", err)
			}

			path, err := filepath.Abs(filepath.Join("/", hdr.Name))
			if err != nil {
				return nil, fmt.Errorf("error generating absolute representation of path: %w", err)
			}

			// Only process regular files for now
			if hdr.Typeflag == tar.TypeReg {
				files[path] = FileInfo{
					Path:  path,
					Size:  hdr.Size,
					Layer: layer.Digest.Encoded(),
				}
			}
		}
	}

	return files, nil
}
