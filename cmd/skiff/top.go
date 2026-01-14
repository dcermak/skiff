package main

import (
	"archive/tar"
	"container/heap"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

var topCommand = cli.Command{
	Name:      "top",
	Usage:     "Analyze a container image and list files by size",
	ArgsUsage: "[image]",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "include-pseudo", Usage: "Include pseudo-filesystems (/dev, /proc, /sys)"},
		&cli.BoolFlag{Name: "follow-symlinks", Usage: "Follow symbolic links"},
		&cli.BoolFlag{
			Name:  "human-readable",
			Usage: "Show file sizes in human readable format",
		},
		&cli.StringSliceFlag{
			Name:    "layer",
			Usage:   "Filter results to specific layer(s) by diffID (uncompressed SHA256). If not specified, all layers are included (not an empty result).",
			Aliases: []string{"l", "diff-id"},
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{Name: "image", UsageText: "Container image ref"},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		image := c.StringArg("image")
		if image == "" {
			return fmt.Errorf("image URL is required")
		}

		humanReadable := c.Bool("human-readable")
		layers := c.StringSlice("layer")
		if c.IsSet("layer") && len(layers) == 0 {
			return fmt.Errorf("--layer flag provided but no diffID specified; please provide at least one diffID")
		}

		sysCtx := types.SystemContext{}

		return analyzeLayers(ctx, &sysCtx, image, layers, humanReadable)
	},
}

const defaultFileLimit = 10

type FileInfo struct {
	Path              string
	Size              int64
	HumanReadableSize string
	DiffID            digest.Digest // diffID of the layer this file belongs to
}

type FileHeap []FileInfo

func (h FileHeap) Len() int           { return len(h) }
func (h FileHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h FileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *FileHeap) Push(x interface{}) {
	*h = append(*h, x.(FileInfo))
}

func (h *FileHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}

// getLayersByDiffID returns layer blob infos filtered by user-provided diffIDs
// by looking up diffIDs and mapping to manifest layers
func getLayersByDiffID(manifestLayers []types.BlobInfo, allDiffIDs []digest.Digest, filterDiffIDs []string) ([]types.BlobInfo, []digest.Digest, error) {
	// If no filtering, return all layers with all their diffIDs
	if len(filterDiffIDs) == 0 {
		return manifestLayers, allDiffIDs, nil
	}

	// Filter layers by user-provided diffIDs
	var filteredLayers []types.BlobInfo
	var filteredDiffIDs []digest.Digest

	// Map user diffIDs to layer indices
	for _, userDiffID := range filterDiffIDs {
		found := false
		for i, configDiffID := range allDiffIDs {
			// Match full diffID or prefix
			if configDiffID.String() == userDiffID || strings.HasPrefix(configDiffID.Encoded(), userDiffID) {
				if i < len(manifestLayers) {
					filteredLayers = append(filteredLayers, manifestLayers[i])
					filteredDiffIDs = append(filteredDiffIDs, configDiffID)
					found = true
					break
				}
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("diffID %s not found in image", userDiffID)
		}
	}

	return filteredLayers, filteredDiffIDs, nil
}

// analyzeLayers fetches layers for a given image reference
// reads the associated layer archives and lists file info
func analyzeLayers(ctx context.Context, sysCtx *types.SystemContext, uri string, layers []string, humanReadable bool) error {
	// represents an image from any transport (docker://, containers-storage://, etc.)
	img, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return err
	}

	// image source that helps us fetch layers to eventually show files from the stream
	imgSrc, err := img.Reference().NewImageSource(ctx, sysCtx)
	if err != nil {
		return err
	}
	defer imgSrc.Close()

	// Get transport-specific layer blob infos
	manifestLayers, err := skiff.BlobInfoFromImage(ctx, sysCtx, img)
	if err != nil {
		return fmt.Errorf("failed to get blob info from image: %w", err)
	}

	conf, err := img.OCIConfig(ctx)
	allDiffIDs := []digest.Digest{}

	// only get them if the rootfs type is correct
	if err == nil && conf != nil && conf.RootFS.Type == "layers" {
		allDiffIDs = conf.RootFS.DiffIDs
	}

	// Check that manifestLayers and allDiffIDs have matching lengths
	if len(manifestLayers) != len(allDiffIDs) {
		return fmt.Errorf("manifestLayers (%d) and allDiffIDs (%d) length mismatch", len(manifestLayers), len(allDiffIDs))
	}

	// Get filtered layers and their diffIDs
	layerInfos, diffIDs, err := getLayersByDiffID(manifestLayers, allDiffIDs, layers)
	if err != nil {
		return err
	}

	h := &FileHeap{}
	heap.Init(h)

	for i, layer := range layerInfos {
		blob, _, err := imgSrc.GetBlob(context.Background(), layer, none.NoCache)
		if err != nil {
			return err
		}
		defer blob.Close()

		uncompressedStream, _, err := compression.AutoDecompress(blob)
		if err != nil {
			return fmt.Errorf("auto-decompressing input: %w", err)
		}
		defer uncompressedStream.Close()

		// Get the diffID for this layer
		layerDiffID := diffIDs[i]

		tr := tar.NewReader(uncompressedStream)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read tar header: %w", err)
			}

			// TODO(danishprakash): follow symlinks
			// if hdr.Typeflag == tar.TypeSymlink

			path, err := filepath.Abs(filepath.Join("/", hdr.Name))
			if err != nil {
				// Log the error but continue processing other files
				fmt.Fprintf(os.Stderr, "warning: error generating absolute representation of path %s: %v\n", hdr.Name, err)
				continue
			}

			if hdr.Typeflag == tar.TypeReg {
				fileInfo := FileInfo{
					Path:   path,
					Size:   hdr.Size,
					DiffID: layerDiffID,
				}
				if humanReadable {
					fileInfo.HumanReadableSize = skiff.HumanReadableSize(hdr.Size)
				}
				heap.Push(h, fileInfo)
				if h.Len() > defaultFileLimit {
					heap.Pop(h)
				}
			}
		}
	}

	// Extract files from heap in reverse order (largest first)
	var files []FileInfo
	for h.Len() > 0 {
		files = append(files, heap.Pop(h).(FileInfo))
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	defer w.Flush()
	fmt.Fprintln(w, "FILE PATH\tSIZE\tDIFF ID")

	slices.Reverse(files)
	for _, f := range files {
		var size string
		if humanReadable {
			size = f.HumanReadableSize
		} else {
			size = strconv.FormatInt(f.Size, 10)
		}
		// Show first 12 chars of diffID (digest.Digest.Encoded() gives us just the hex part)
		// TODO(dcermak) switch to skiff.FormatDigest(f.DiffID, false)
		diffIDDisplay := f.DiffID.Encoded()
		if len(diffIDDisplay) > 12 {
			diffIDDisplay = diffIDDisplay[:12]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", f.Path, size, diffIDDisplay)
	}
	return nil
}
