package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	"text/tabwriter"

	"github.com/containers/image/v5/types"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

// FileDiff represents a file difference between two images
type FileDiff struct {
	Path       string
	ChangeType string // "ADDED", "DELETED", "MODIFIED"
	SizeDiff   int64  // positive for additions, negative for deletions
}

var diffCommand = cli.Command{
	Name:  "diff",
	Usage: "Show differences between two container images",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "human-readable", Usage: "Display sizes in human readable format (e.g., 1K, 234M, 2G)"},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{Name: "image1", UsageText: "First image reference"},
		&cli.StringArg{Name: "image2", UsageText: "Second image reference"},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		image1 := c.StringArg("image1")
		image2 := c.StringArg("image2")
		if image1 == "" || image2 == "" {
			return fmt.Errorf("both image references are required")
		}

		sysCtx := types.SystemContext{}
		return imageDiff(image1, image2, ctx, &sysCtx, c.Bool("human-readable"))
	},
}

// imageDiff compares two images and shows their differences
func imageDiff(uri1, uri2 string, ctx context.Context, sysCtx *types.SystemContext, humanReadable bool) error {
	img1, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri1)
	if err != nil {
		return fmt.Errorf("failed to load first image: %w", err)
	}

	img2, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri2)
	if err != nil {
		return fmt.Errorf("failed to load second image: %w", err)
	}

	files1, err := skiff.ExtractFilesystem(ctx, img1, sysCtx)
	if err != nil {
		return fmt.Errorf("failed to extract filesystem from first image: %w", err)
	}

	files2, err := skiff.ExtractFilesystem(ctx, img2, sysCtx)
	if err != nil {
		return fmt.Errorf("failed to extract filesystem from second image: %w", err)
	}

	diffs := filesystemDiff(files1, files2)
	displayDiffs(diffs, humanReadable)

	return nil
}

// filesystemDiff compares two filesystem maps and returns differences
func filesystemDiff(files1, files2 map[string]skiff.FileInfo) []FileDiff {
	var diffs []FileDiff

	// We're handling 3 cases:
	// 1. DELETED: file exists in image1 but not in image2
	// 2. MODIFIED: file exists in both images but has different size
	// 3. ADDED: file exists in image2 but not in image1

	// 1. DELETED: find files only in image1
	for path, file1 := range files1 {
		if _, exists := files2[path]; !exists {
			diffs = append(diffs, FileDiff{
				Path:       path,
				ChangeType: "DELETED",
				SizeDiff:   -file1.Size, // negative for deletions
			})
		}
	}

	for path, file2 := range files2 {
		if file1, exists := files1[path]; exists {
			// 2. MODIFIED: file exists in both images
			if file1.Size != file2.Size {
				diffs = append(diffs, FileDiff{
					Path:       path,
					ChangeType: "MODIFIED",
					SizeDiff:   file2.Size - file1.Size,
				})
			}
		} else {
			// 3. ADDED: file exists in image2
			diffs = append(diffs, FileDiff{
				Path:       path,
				ChangeType: "ADDED",
				SizeDiff:   file2.Size, // positive for additions
			})
		}
	}

	// sort by path for consistent output
	// TODO(danishprakash): optionally sorty by size diff
	sort.Slice(diffs, func(i, j int) bool {
		return diffs[i].Path < diffs[j].Path
	})

	return diffs
}

// displayDiffs displays the file differences in a formatted table
func displayDiffs(diffs []FileDiff, humanReadable bool) {
	if len(diffs) == 0 {
		fmt.Println("No differences found between the images.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	defer w.Flush()

	// header
	fmt.Fprintln(w, "Change\tSize Diff\tPath")
	for _, diff := range diffs {
		var sizeStr string
		if humanReadable {
			if diff.SizeDiff > 0 {
				sizeStr = "+" + skiff.HumanReadableSize(diff.SizeDiff)
			} else {
				sizeStr = "-" + skiff.HumanReadableSize(-diff.SizeDiff)
			}
		} else {
			sizeStr = fmt.Sprintf("%+d", diff.SizeDiff)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", diff.ChangeType, sizeStr, diff.Path)
	}
}
