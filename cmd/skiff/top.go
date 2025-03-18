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
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

var topCommand = cli.Command{
	Name:  "top",
	Usage: "Analyze a container image and list files by size",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "include-pseudo", Usage: "Include pseudo-filesystems (/dev, /proc, /sys)"},
		&cli.BoolFlag{Name: "follow-symlinks", Usage: "Follow symbolic links"},
		&cli.BoolFlag{
			Name:    "human-readable",
			Usage:   "Show file sizes in human readable format",
			Aliases: []string{"h"},
		},
		&cli.StringSliceFlag{
			Name:    "layer",
			Usage:   "Filter results to specific layer(s) by SHA256 digest. If not specified, all layers are included (not an empty result).",
			Aliases: []string{"l"},
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
			return fmt.Errorf("--layer flag provided but no layer digest specified; please provide at least one layer digest")
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
	Layer             string // layer ID this file belongs to
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

// getFilteredLayers returns only the layers that needs to be
// processed/extracted e.g. after user specifies specific layer(s)
// using --layer, we shouldn't be processing all the layers.
// If layers is empty, returns all layers in the image.
func getFilteredLayers(img types.Image, layers []string) ([]types.BlobInfo, error) {
	allLayers := img.LayerInfos()

	if len(layers) == 0 {
		return allLayers, nil // No filtering needed
	}

	// Build a map for efficient layer lookup
	layerMap := make(map[string]types.BlobInfo)
	for _, layer := range allLayers {
		layerMap[layer.Digest.Encoded()] = layer
	}

	var filteredLayers []types.BlobInfo
	seenLayers := make(map[string]bool) // Track which layers we've already added

	for _, filter := range layers {
		var matchedLayersDigests []string
		for layerDigest := range layerMap {
			if layerDigest == filter || strings.HasPrefix(layerDigest, filter) {
				matchedLayersDigests = append(matchedLayersDigests, layerDigest)
			}
		}

		if len(matchedLayersDigests) == 0 {
			return nil, fmt.Errorf("layer %s not found in image", filter)
		}
		if len(matchedLayersDigests) > 1 {
			return nil, fmt.Errorf("multiple layers match shortened digest %s", filter)
		}

		matchedLayerDigest := matchedLayersDigests[0]
		layer := layerMap[matchedLayerDigest]

		// Only add if we haven't seen this layer before
		if !seenLayers[layer.Digest.String()] {
			filteredLayers = append(filteredLayers, layer)
			seenLayers[layer.Digest.String()] = true
		}
	}

	return filteredLayers, nil
}

// analyzeLayers fetches layers for a given image reference
// reads the associated layer archives and lists file info
func analyzeLayers(ctx context.Context, sysCtx *types.SystemContext, uri string, layers []string, humanReadable bool) error {
	img, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return err
	}

	imgSrc, err := img.Reference().NewImageSource(ctx, sysCtx)
	if err != nil {
		return err
	}
	defer imgSrc.Close()

	h := &FileHeap{}
	heap.Init(h)

	layerInfos, err := getFilteredLayers(img, layers)
	if err != nil {
		return err
	}

	for _, layer := range layerInfos {
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
				heap.Push(h, FileInfo{
					Path:              path,
					Size:              hdr.Size,
					HumanReadableSize: HumanReadableSize(hdr.Size),
					Layer:             layer.Digest.Encoded(),
				})
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
	fmt.Fprintln(w, "FILE PATH\tSIZE\tLAYER ID")

	slices.Reverse(files)
	for _, f := range files {
		var size string
		if humanReadable {
			size = f.HumanReadableSize
		} else {
			size = strconv.FormatInt(f.Size, 10)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", f.Path, size, f.Layer[:12])
	}
	return nil
}
