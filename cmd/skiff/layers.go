package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

func ShowLayerUsage(ctx context.Context, sysCtx *types.SystemContext, uri string, output io.Writer, fullDigest bool) error {
	img, layers, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return err
	}

	inspect, err := img.Inspect(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(output, 0, 8, 2, ' ', 0)
	defer w.Flush()

	if len(layers) > 0 {
		if len(inspect.LayersData) != len(layers) {
			return fmt.Errorf(
				"internal error: image inspect returned %d layers, storage returned %d layers",
				len(inspect.LayersData),
				len(layers),
			)
		}
		fmt.Fprintln(w, "Diff ID\tUncompressed Size")
		for _, l := range layers {
			fmt.Fprintf(w, "%s\t%d\n", skiff.FormatDigest(l.UncompressedDigest, fullDigest), l.UncompressedSize)
		}

	} else {
		// in theory, the OCI Config contains the 'rootfs.diffids' array
		// with the diffIDs i.e. the uncompressed digests
		// => use that if available otherwise we fall back to compressed digests
		conf, err := img.OCIConfig(ctx)
		diffIDs := []digest.Digest{}

		// only get them if the rootfs type is correct
		if err == nil && conf != nil && conf.RootFS.Type == "layers" {
			diffIDs = conf.RootFS.DiffIDs
		}

		if len(diffIDs) == len(inspect.LayersData) {
			fmt.Fprintln(w, "Diff ID\tCompressed Size")
			for i, l := range inspect.LayersData {
				fmt.Fprintf(w, "%s\t%d\n", skiff.FormatDigest(conf.RootFS.DiffIDs[i], fullDigest), l.Size)
			}
		} else {
			fmt.Fprintln(w, "Compressed Digest\tCompressed Size")
			for _, l := range inspect.LayersData {
				fmt.Fprintf(w, "%s\t%d\n", skiff.FormatDigest(l.Digest, fullDigest), l.Size)
			}
		}
	}
	return nil
}

var LayerUsage cli.Command = cli.Command{
	Name:      "layers",
	Usage:     "Print the size of each layer in an image.",
	Arguments: []cli.Argument{&cli.StringArg{Name: "url", UsageText: "Image reference (e.g., registry.example.com/image:tag)"}},
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "full-digest",
			Usage:   "Show full digests instead of truncated (12 chars)",
			Aliases: []string{"full-diff-id"}},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		url := c.StringArg("url")
		if url == "" {
			return fmt.Errorf("image URL is required")
		}

		sysCtx := types.SystemContext{}
		return ShowLayerUsage(ctx, &sysCtx, url, c.Writer, c.Bool("full-digest"))
	},
}
