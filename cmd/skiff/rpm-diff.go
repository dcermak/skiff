package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
	"github.com/urfave/cli/v3"
	"go.podman.io/image/v5/types"
	"golang.org/x/sync/errgroup"

	skiff "github.com/dcermak/skiff/pkg"
)

var rpmDiffCommand = cli.Command{
	Name:  "rpm-diff",
	Usage: "Diff the RPM packages of two container images",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "old-image",
			Usage:    "Original Container Image ref",
			Aliases:  []string{"o"},
			Required: true,
		},
		&cli.StringFlag{
			Name:     "new-image",
			Usage:    "New Container Image ref",
			Aliases:  []string{"n"},
			Required: true,
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		oldImage := strings.TrimSpace(c.String("old-image"))
		if oldImage == "" {
			return fmt.Errorf("--old-image is required")
		}
		newImage := strings.TrimSpace(c.String("new-image"))
		if newImage == "" {
			return fmt.Errorf("--new-image is required")
		}

		sysCtx := types.SystemContext{}

		g, gctx := errgroup.WithContext(ctx)
		var oldPkgs, newPkgs []pkg.Package
		g.Go(func() (err error) {
			oldPkgs, err = catalogRpms(gctx, oldImage, &sysCtx)
			if err != nil {
				return fmt.Errorf("cataloging old image: %w", err)
			}
			return nil
		})
		g.Go(func() (err error) {
			newPkgs, err = catalogRpms(gctx, newImage, &sysCtx)
			if err != nil {
				return fmt.Errorf("cataloging new image: %w", err)
			}
			return nil
		})
		if err := g.Wait(); err != nil {
			return err
		}

		result := skiff.DiffPackages(oldPkgs, newPkgs)
		printDiffResult(c.Writer, result)
		return nil
	},
}

func catalogRpms(ctx context.Context, uri string, sysCtx *types.SystemContext) ([]pkg.Package, error) {
	img, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return nil, err
	}
	defer img.Close()

	resolver, err := skiff.NewOCIResolver(ctx, img, sysCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI resolver: %w", err)
	}
	defer resolver.Close()

	ctlg := redhat.NewDBCataloger()
	pkgs, _, err := ctlg.Catalog(ctx, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to catalog packages: %w", err)
	}
	return pkgs, nil
}

func printDiffResult(w io.Writer, result skiff.DiffResult) {
	total := len(result.Added) + len(result.Removed) + len(result.Modified) + result.Unchanged
	fmt.Fprintf(w, "Package groups: %d added, %d removed, %d modified, %d unchanged (total: %d)\n\n",
		len(result.Added), len(result.Removed), len(result.Modified), result.Unchanged, total)

	if len(result.Added) > 0 {
		fmt.Fprintln(w, "Added:")
		for _, d := range result.Added {
			fmt.Fprintf(w, "  + %s %s\n", identityHeader(d.Identity), versionsString(d.New))
		}
		fmt.Fprintln(w)
	}

	if len(result.Removed) > 0 {
		fmt.Fprintln(w, "Removed:")
		for _, d := range result.Removed {
			fmt.Fprintf(w, "  - %s %s\n", identityHeader(d.Identity), versionsString(d.Old))
		}
		fmt.Fprintln(w)
	}

	if len(result.Modified) > 0 {
		fmt.Fprintln(w, "Modified:")
		if hasMultiInstance(result.Modified) {
			fmt.Fprintln(w, "  (Multi-instance groups report version/arch membership only.)")
		}
		for _, d := range result.Modified {
			fmt.Fprintf(w, "  ~ %s\n", identityHeader(d.Identity))
			for _, ch := range d.Changes {
				fmt.Fprintf(w, "        %s: %s -> %s\n", ch.Field, ch.Old, ch.New)
			}
		}
		fmt.Fprintln(w)
	}
}

func identityHeader(id skiff.Identity) string {
	var b strings.Builder
	b.WriteString(id.Name)
	if id.Arch != "" {
		b.WriteString(" [")
		b.WriteString(id.Arch)
		b.WriteString("]")
	}
	scope := scopeLabel(id.Namespace, id.Distro)
	if scope != "" {
		b.WriteString(" (")
		b.WriteString(scope)
		b.WriteString(")")
	}
	return b.String()
}

func scopeLabel(namespace, distro string) string {
	switch {
	case namespace != "" && distro != "":
		return namespace + "/" + distro
	case namespace != "":
		return namespace
	case distro != "":
		return distro
	default:
		return ""
	}
}

func hasMultiInstance(diffs []skiff.PackageDiff) bool {
	for _, d := range diffs {
		if len(d.Old) > 1 || len(d.New) > 1 {
			return true
		}
	}
	return false
}

func versionsString(pkgs []pkg.Package) string {
	if len(pkgs) == 1 {
		return pkgs[0].Version
	}
	versions := make([]string, len(pkgs))
	for i, p := range pkgs {
		versions[i] = p.Version
	}
	return "[" + strings.Join(versions, ", ") + "]"
}
