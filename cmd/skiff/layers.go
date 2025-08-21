package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/containers/image/v5/types"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

func ShowLayerUsage(ctx context.Context, sysCtx *types.SystemContext, uri string, output io.Writer) error {
	img, layers, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return err
	}

	inspect, err := img.Inspect(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(output, 0, 8, 2, ' ', 0)
	if layers != nil && len(layers) > 0 {
		if len(inspect.LayersData) != len(layers) {
			return fmt.Errorf(
				"internal error: image inspect returned %d layers, storage returned %d layers",
				len(inspect.LayersData),
				len(layers),
			)
		}
		fmt.Fprintln(w, "Digest\tSize\tUncompressed Digest\tUncompressed Size")
		for i, l := range inspect.LayersData {
			fmt.Fprintf(w, "%s\t%d\t%s\t%d\n", l.Digest, l.Size, layers[i].UncompressedDigest, layers[i].UncompressedSize)
		}

	} else {
		fmt.Fprintln(w, "Digest\tSize")
		for _, l := range inspect.LayersData {
			fmt.Fprintf(w, "%s\t%d\n", l.Digest, l.Size)
		}
	}
	return w.Flush()
}

var LayerUsage cli.Command = cli.Command{
	Name:      "layers",
	Usage:     "Print the size of each layer in an image.",
	Arguments: []cli.Argument{&cli.StringArg{Name: "url", UsageText: "Image reference (e.g., registry.example.com/image:tag)"}},
	Action: func(ctx context.Context, c *cli.Command) error {
		url := c.StringArg("url")
		if url == "" {
			return fmt.Errorf("image URL is required")
		}

		sysCtx := types.SystemContext{}
		return ShowLayerUsage(ctx, &sysCtx, url, c.Writer)
	},
}
