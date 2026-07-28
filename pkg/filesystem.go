package skiff

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path/filepath"

	"go.podman.io/image/v5/pkg/blobinfocache/none"
	"go.podman.io/image/v5/pkg/compression"
	"go.podman.io/image/v5/types"
	"github.com/opencontainers/go-digest"
)

// FileInfo represents a file in a container image
type FileInfo struct {
	Path   string
	Size   int64
	DiffID digest.Digest // diffID of the layer this file belongs to
}

// ExtractFilesystem extracts all files from an image's layers
// Returns a map of file paths to FileInfo
func ExtractFilesystem(ctx context.Context, img types.Image, sysCtx *types.SystemContext) (map[string]FileInfo, error) {
	imgSrc, err := img.Reference().NewImageSource(ctx, sysCtx)
	if err != nil {
		return nil, err
	}
	defer imgSrc.Close()

	layerInfos, err := BlobInfoFromImage(ctx, sysCtx, img)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob info from image: %w", err)
	}

	conf, err := img.OCIConfig(ctx)
	diffIDs := []digest.Digest{}
	if err == nil && conf != nil && conf.RootFS.Type == "layers" {
		diffIDs = conf.RootFS.DiffIDs
	}

	if len(layerInfos) != len(diffIDs) {
		return nil, fmt.Errorf("layerInfos (%d) and diffIDs (%d) length mismatch", len(layerInfos), len(diffIDs))
	}

	files := make(map[string]FileInfo)

	for i, layer := range layerInfos {
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

		layerDiffID := diffIDs[i]

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
					Path:   path,
					Size:   hdr.Size,
					DiffID: layerDiffID,
				}
			}
		}
	}

	return files, nil
}
