package skiff

import (
	"context"
	"fmt"

	"github.com/containers/common/libimage"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage"
)

// ImageFromURI tries to obtain the image from the "most likely source"
//
// If the uri includes a transport, then the uri is parsed and an Image instance
// is returned.
//
// If the uri does not contain a transport, then this function first tries to
// load the image from the (rootless) container storage. If that fails, we try
// to load it from a registry by prepending the `docker://` transport.
func ImageFromURI(ctx context.Context, sysCtx *types.SystemContext, uri string) (types.Image, error) {
	ref, err := alltransports.ParseImageName(uri)

	// transport name missing => lookup in storage first:
	if err != nil {
		opts, err := storage.DefaultStoreOptions()
		if err != nil {
			return nil, err
		}
		store, err := storage.GetStore(opts)
		if err != nil {
			return nil, err
		}

		runtime, err := libimage.RuntimeFromStore(store, nil)
		if err != nil {
			return nil, err
		}

		img, _, err := runtime.LookupImage(uri, nil)

		// found the image in store => exit
		if err == nil {
			ref, err := img.StorageReference()
			if err != nil {
				return nil, err
			}

			imgCloser, err := ref.NewImage(ctx, sysCtx)
			if err != nil {
				return nil, err
			}
			defer imgCloser.Close()

			return imgCloser, nil
		}

		// we didn't find it in the container storage
		// -> now we assume it's a registry url:
		uri = fmt.Sprintf("docker://%s", uri)

		// but we have to redo the parsing
		ref, err = alltransports.ParseImageName(uri)
		if err != nil {
			return nil, err
		}
	}

	// at this point we're sure we have a transport
	imgSrc, err := ref.NewImage(ctx, sysCtx)
	if err != nil {
		return nil, err
	}
	defer imgSrc.Close()

	return imgSrc, nil
}
