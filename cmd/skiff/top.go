package main

import (
	"container/heap"
	"context"
	"fmt"
	"os"
	"slices"
	"text/tabwriter"

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
		&cli.BoolFlag{Name: "human-readable", Usage: "Display sizes in human readable format (e.g., 1K, 234M, 2G)"},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{Name: "image", UsageText: "Container image ref"},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		image := c.StringArg("image")
		if image == "" {
			return fmt.Errorf("image URL is required")
		}

		sysCtx := types.SystemContext{}
		return analyzeLayers(image, ctx, &sysCtx, c.Bool("human-readable"))
	},
}

const defaultFileLimit = 10

type FileHeap []skiff.FileInfo

func (h FileHeap) Len() int           { return len(h) }
func (h FileHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h FileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *FileHeap) Push(x interface{}) {
	*h = append(*h, x.(skiff.FileInfo))
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
func analyzeLayers(uri string, ctx context.Context, sysCtx *types.SystemContext, humanReadable bool) error {
	img, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return err
	}

	filesMap, err := skiff.ExtractFilesystem(ctx, img, sysCtx)
	if err != nil {
		return err
	}

	// Convert map to slice and build heap
	h := &FileHeap{}
	heap.Init(h)

	for _, file := range filesMap {
		heap.Push(h, file)
		if h.Len() > defaultFileLimit {
			heap.Pop(h)
		}
	}

	// Extract files from heap in reverse order (largest first)
	var files []skiff.FileInfo
	for h.Len() > 0 {
		files = append(files, heap.Pop(h).(skiff.FileInfo))
	}

	slices.Reverse(files)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	defer w.Flush()

	fmt.Fprintln(w, "File Path\tSize\tLayer ID")

	for _, f := range files {
		var sizeStr string
		if humanReadable {
			sizeStr = skiff.HumanReadableSize(f.Size)
		} else {
			sizeStr = fmt.Sprintf("%d", f.Size)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", f.Path, sizeStr, f.Layer[:12])
	}

	return nil
}
