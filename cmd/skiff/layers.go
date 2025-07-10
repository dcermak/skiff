package main

import (
	"context"
	"fmt"

	"github.com/containers/image/v5/types"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

func ShowLayerUsage(ctx context.Context, sysCtx *types.SystemContext, uri string) (string, error) {
	img, layers, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return "", err
	}

	inspect, err := img.Inspect(ctx)
	if err != nil {
		return "", err
	}

	res := ""
	if layers != nil && len(layers) > 0 {
		if len(inspect.LayersData) != len(layers) {
			return "", fmt.Errorf(
				"internal error: image inspect returned %d layers, storage returned %d layers",
				len(inspect.LayersData),
				len(layers),
			)
		}
		for i, l := range inspect.LayersData {
			res += fmt.Sprintf("%s %d %s %d\n", l.Digest, l.Size, layers[i].ID, layers[i].UncompressedSize)
		}

	} else {
		for _, l := range inspect.LayersData {
			res += fmt.Sprintf("%s %d\n", l.Digest, l.Size)
		}
	}
	return res, nil
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
		out, err := ShowLayerUsage(ctx, &sysCtx, url)
		if err == nil {
			fmt.Print(out)
		}
		return err
	},
}
