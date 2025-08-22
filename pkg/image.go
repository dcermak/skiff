package skiff

import (
	"context"
	"fmt"
	"slices"

	"github.com/containers/common/libimage"
	storageTransport "github.com/containers/image/v5/storage"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage"
	"github.com/opencontainers/go-digest"
)

func layersFromImageDigest(store storage.Store, digest digest.Digest) ([]storage.Layer, error) {
	storeImgs, err := store.ImagesByDigest(digest)
	if err != nil {
		return nil, err
	}
	if len(storeImgs) >= 1 {
		storeImg := storeImgs[0]

		imgLayers := make([]storage.Layer, 0)

		parentLayerID := storeImg.TopLayer

		for parentLayerID != "" {
			curLayer, err := store.Layer(parentLayerID)
			if err != nil {
				return nil, err
			}

			imgLayers = append(imgLayers, *curLayer)
			parentLayerID = curLayer.Parent
		}
		// Important: we started inserting the topLayer, but the rest of
		// the code expects layer[0] to be the bottom layer!!
		slices.Reverse(imgLayers)

		return imgLayers, nil
	}
	return nil, fmt.Errorf("Did not find image %s in the image store", digest)
}

// ImageAndLayersFromURI tries to obtain the image from the "most likely source"
//
// If the uri includes a transport, then the uri is parsed and an Image instance
// is returned.
//
// If the uri does not contain a transport, then this function first tries to
// load the image from the (rootless) container storage. If that fails, we try
// to load it from a registry by prepending the `docker://` transport.
//
// If the image is present in the local container store, then we also return the
// layers of that image.
func ImageAndLayersFromURI(ctx context.Context, sysCtx *types.SystemContext, uri string) (types.Image, []storage.Layer, error) {
	ref, err := alltransports.ParseImageName(uri)

	// transport name missing or its using the containers-storage
	// => lookup in storage first:
	if err != nil || ref.Transport().Name() == storageTransport.Transport.Name() {
		opts, err := storage.DefaultStoreOptions()
		if err != nil {
			return nil, nil, err
		}
		store, err := storage.GetStore(opts)
		if err != nil {
			return nil, nil, err
		}

		runtime, err := libimage.RuntimeFromStore(store, nil)
		if err != nil {
			return nil, nil, err
		}

		img, _, err := runtime.LookupImage(uri, nil)

		// found the image in store => exit
		if err == nil {
			ref, err := img.StorageReference()
			if err != nil {
				return nil, nil, err
			}

			imgCloser, err := ref.NewImage(ctx, sysCtx)
			if err != nil {
				return nil, nil, err
			}
			defer imgCloser.Close()

			layers, err := layersFromImageDigest(store, img.Digest())
			if err == nil {
				return imgCloser, layers, nil
			}
			return imgCloser, nil, nil
		}

		// we didn't find it in the container storage
		// -> now we assume it's a registry url:
		uri = fmt.Sprintf("docker://%s", uri)

		// but we have to redo the parsing
		ref, err = alltransports.ParseImageName(uri)
		if err != nil {
			return nil, nil, err
		}
	}

	// at this point we're sure we have a transport
	img, err := ref.NewImage(ctx, sysCtx)
	if err != nil {
		return nil, nil, err
	}
	defer img.Close()

	return img, nil, nil
}

// BlobInfoFromImage extracts layer blob information that can be later used with
// `GetBlob` from a container image, handling different transport types
// appropriately.
//
// Returns a slice of BlobInfo containing layer information needed for
// blob retrieval operations.
func BlobInfoFromImage(img types.Image, ctx context.Context, sysCtx *types.SystemContext) ([]types.BlobInfo, error) {
	var layerInfos []types.BlobInfo

	// For containers-storage transport, use LayerInfosForCopy to get storage-accessible digests
	// For other transports (like docker), use LayerInfos which works fine
	ref := img.Reference()
	if ref.Transport().Name() == "containers-storage" {
		imgSrc, err := img.Reference().NewImageSource(ctx, sysCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to create image source for containers-storage transport: %w", err)
		}
		defer imgSrc.Close()

		layerInfos, err = imgSrc.LayerInfosForCopy(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get layer infos for copy from containers-storage: %w", err)
		}
	} else {
		// Convert LayerInfo to BlobInfo for consistency
		imgLayerInfos := img.LayerInfos()
		layerInfos = make([]types.BlobInfo, len(imgLayerInfos))
		for i, layer := range imgLayerInfos {
			layerInfos[i] = layer
		}
	}
	return layerInfos, nil
}

// FormatDigest returns either the digest if `fullDigest` is `true` or the first
// twelve characters of the hash/encoded value if `fullDigest` is `false`.
func FormatDigest(digest digest.Digest, fullDigest bool) string {
	if fullDigest {
		return digest.String()
	}

	encoded := digest.Encoded()
	if len(encoded) >= 12 {
		return encoded[:12]
	}
	return encoded
}
