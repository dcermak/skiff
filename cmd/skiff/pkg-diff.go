package main

import (
	"context"
	"fmt"

	"github.com/containers/image/v5/types"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"

	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
)

var pkgDiffCommand = cli.Command{
	Name:  "pkg_diff",
	Usage: "Diff the packages of two container images",
	Arguments: []cli.Argument{
		&cli.StringArg{Name: "oldImage", UsageText: "Original Container Image ref"},
		&cli.StringArg{Name: "newImage", UsageText: "New Container Image ref"},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		oldImage := c.StringArg("oldImage")
		if oldImage == "" {
			return fmt.Errorf("old image URL is required")
		}
		newImage := c.StringArg("newImage")
		if newImage == "" {
			return fmt.Errorf("newImage URL is required")
		}

		sysCtx := types.SystemContext{}
		return getPkgMetadataFromImg(oldImage, ctx, &sysCtx)
	},
}

// getPkgMetadataFromImg fetches layers for a given image reference
// reads the associated layer archives and lists file info
func getPkgMetadataFromImg(uri string, ctx context.Context, sysCtx *types.SystemContext) error {
	img, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return err
	}

	resolver, err := skiff.NewOCIResolver(ctx, img, sysCtx)
	if err != nil {
		return fmt.Errorf("failed to create OCI resolver: %w", err)
	}
	defer resolver.Close()

	ctlg := redhat.NewDBCataloger()
	pkgs, _, err := ctlg.Catalog(ctx, resolver)
	if err != nil {
		return fmt.Errorf("failed to catalog packages: %w", err)
	}

	fmt.Printf("Found %d packages in %s\n", len(pkgs), uri)
	for _, p := range pkgs {
		fmt.Printf("- %s %s\n", p.Name, p.Version)
	}

	return nil
}
