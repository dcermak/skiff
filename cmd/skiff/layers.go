package main

import (
	"context"
	"fmt"

	"github.com/containers/image/v5/types"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

func ShowLayerUsage(ctx context.Context, sysCtx *types.SystemContext, uri string) (string, error) {
	img, err := skiff.ImageFromURI(ctx, sysCtx, uri)
	if err != nil {
		return "", err
	}

	inspect, err := img.Inspect(ctx)
	if err != nil {
		return "", err
	}

	res := ""
	for _, l := range inspect.LayersData {
		res += fmt.Sprintf("%s %d\n", l.Digest, l.Size)
	}

	return res, nil
}

var LayerUsage cli.Command = cli.Command{
	Name:      "layers",
	Usage:     "Print the size of each layer in an image.",
	Arguments: []cli.Argument{&cli.StringArg{Name: "url", UsageText: ""}},
	Action: func(ctx context.Context, c *cli.Command) error {
		sysCtx := types.SystemContext{}
		out, err := ShowLayerUsage(ctx, &sysCtx, c.StringArg("url"))
		if err == nil {
			fmt.Print(out)
		}
		return err
	},
}
