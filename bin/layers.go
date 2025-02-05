package main

import (
	"context"
	"fmt"

	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/urfave/cli/v3"
)

func ShowLayerUsage(url string, ctx context.Context, sysCtx *types.SystemContext) (string, error) {
	ref, err := alltransports.ParseImageName(url)
	if err != nil {
		return "", err
	}
	imgSrc, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return "", err
	}
	defer imgSrc.Close()

	img, err := image.FromUnparsedImage(ctx, sysCtx, image.UnparsedInstance(imgSrc, nil))
	if err != nil {
		return "", err
	}

	inspect, err := img.Inspect(ctx)
	if err != nil {
		return "", err
	}

	res := ""
	for _, l := range inspect.LayersData {
		res += fmt.Sprintf("%s: %d\n", l.Digest.Hex(), l.Size)
	}

	return res, nil
}

var url []string

var LayerUsage cli.Command = cli.Command{
	Name:      "layers",
	Usage:     "Print the size of each layer in an image.",
	Arguments: []cli.Argument{&cli.StringArg{Name: "url", Min: 1, Max: 1, Values: &url, UsageText: ""}},
	Action: func(ctx context.Context, c *cli.Command) error {
		sysCtx := types.SystemContext{}
		out, err := ShowLayerUsage(url[0], ctx, &sysCtx)
		if err == nil {
			fmt.Println(out)
		}
		return err
	},
}
