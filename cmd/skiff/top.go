package main

import (
	"archive/tar"
	"container/heap"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/urfave/cli/v3"
)

var topCommand = cli.Command{
	Name:  "top",
	Usage: "Analyze a container image and list files by size",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "include-pseudo", Usage: "Include pseudo-filesystems (/dev, /proc, /sys)"},
		&cli.BoolFlag{Name: "follow-symlinks", Usage: "Follow symbolic links"},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{Name: "image", Min: 1, Max: 1, Values: &url, UsageText: "Container image ref"},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		sysCtx := types.SystemContext{}
		return analyzeLayers(url[0], ctx, &sysCtx)
	},
}

const defaultFileLimit = 10

type FileInfo struct {
	Path  string
	Size  int64
	Layer string // layer ID this file belongs to
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

// analyzeLayers fetches layers for a given image reference
// reads the associated layer archives and lists file info
// TODO: containers-storage transport fails
func analyzeLayers(url string, ctx context.Context, sysCtx *types.SystemContext) error {
	ref, err := alltransports.ParseImageName(url)
	if err != nil {
		return err
	}
	imgSrc, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return err
	}
	defer imgSrc.Close()

	img, err := image.FromUnparsedImage(ctx, sysCtx, image.UnparsedInstance(imgSrc, nil))
	if err != nil {
		return err
	}

	h := &FileHeap{}
	heap.Init(h)

	files := make([]FileInfo, h.Len())
	layerInfos := img.LayerInfos()
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

			// TODO: follow symlinks?
			// if hdr.Typeflag == tar.TypeSymlink

			if hdr.Typeflag == tar.TypeReg {
				heap.Push(h, FileInfo{Path: hdr.Name, Size: hdr.Size, Layer: strings.TrimPrefix(layer.Digest.String(), "sha256:")})
				if h.Len() > defaultFileLimit {
					heap.Pop(h)
				}
			}
		}

	}

	for i := 0; h.Len() > 0; i++ {
		files = append(files, heap.Pop(h).(FileInfo))
	}

	maxPathLen, maxSizeLen, maxLayerLen := 0, 0, 12
	for _, f := range files {
		if len(f.Path) > maxPathLen {
			maxPathLen = len(f.Path)
		}
		sizeStr := strconv.FormatInt(f.Size, 10)
		if len(sizeStr) > maxSizeLen {
			maxSizeLen = len(sizeStr)
		}
	}

	fmt.Printf("%-*s	%*s	%-*s\n", maxPathLen, "File Path", maxSizeLen, "Size", maxLayerLen, "Layer ID")
	fmt.Println(strings.Repeat("-", maxPathLen+maxSizeLen+maxLayerLen+15)) // also consider two tab chars

	slices.Reverse(files)
	for _, f := range files {
		sizeStr := strconv.FormatInt(f.Size, 10)
		fmt.Printf("%-*s	%*s	%-*s\n", maxPathLen, f.Path, maxSizeLen, sizeStr, maxLayerLen, f.Layer[:12])
	}

	return nil
}
