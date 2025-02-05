package main

import (
	"context"
	"fmt"
	"os"

	"github.com/containers/storage/pkg/reexec"

	"github.com/urfave/cli/v3"
)

func main() {

	cmd := &cli.Command{
		Name:  "skiff",
		Usage: "Analyze the disk usage and directory structure of OCI images and its layers",
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			reexec.Init()
			return ctx, nil
		},
		Commands: []*cli.Command{&LayerUsage},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}
