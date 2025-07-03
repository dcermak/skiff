package main

import (
	"context"
	"fmt"
	"os"

	"github.com/containers/storage/pkg/reexec"
	"github.com/containers/storage/pkg/unshare"
	"github.com/syndtr/gocapability/capability"

	"github.com/urfave/cli/v3"
)

func main() {

	cmd := &cli.Command{
		Name:  "skiff",
		Usage: "Analyze the disk usage and directory structure of OCI images and its layers",
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			var neededCapabilities = []capability.Cap{
				capability.CAP_CHOWN,
				capability.CAP_DAC_OVERRIDE,
				capability.CAP_FOWNER,
				capability.CAP_FSETID,
				capability.CAP_MKNOD,
				capability.CAP_SETFCAP,
			}

			reexec.Init()

			// NewPid is deprecated so let's copy and paste its implementation 🙄
			capabilities, err := capability.NewPid2(0)
			if err != nil {
				return ctx, err
			}
			err = capabilities.Load()
			if err != nil {
				return ctx, err
			}

			for _, cap := range neededCapabilities {
				if !capabilities.Get(capability.EFFECTIVE, cap) {
					// We miss a capability we need, create a user namespaces
					unshare.MaybeReexecUsingUserNamespace(true)
				}
			}

			return ctx, nil
		},
		Commands: []*cli.Command{&LayerUsage, &topCommand},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}
