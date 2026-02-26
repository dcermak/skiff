package skiff

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/stereoscope/pkg/file"
	syftFile "github.com/anchore/syft/syft/file"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
)

// OCIResolver implements syft.file.Resolver for OCI images without full extraction.
type OCIResolver struct {
	img          types.Image
	imgSrc       types.ImageSource
	sysCtx       *types.SystemContext
	fsIndex      map[string]*FileEntry
	symlinkCache map[string]string
}

// FileEntry represents a file in the virtual filesystem.
type FileEntry struct {
	Path        string
	Size        int64
	Mode        int64
	ModTime     time.Time
	LayerDigest digest.Digest
	LinkTarget  string
	UID         int
	GID         int
	TypeFlag    byte
}

// NewOCIResolver creates a new resolver and builds the in-memory file index.
func NewOCIResolver(ctx context.Context, img types.Image, sysCtx *types.SystemContext) (*OCIResolver, error) {
	imgSrc, err := img.Reference().NewImageSource(ctx, sysCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create image source: %w", err)
	}

	resolver := &OCIResolver{
		img:          img,
		imgSrc:       imgSrc,
		sysCtx:       sysCtx,
		fsIndex:      make(map[string]*FileEntry),
		symlinkCache: make(map[string]string),
	}

	if err := resolver.buildIndex(ctx); err != nil {
		imgSrc.Close()
		return nil, err
	}

	return resolver, nil
}

// Close closes the underlying image source.
func (r *OCIResolver) Close() error {
	if r.imgSrc != nil {
		return r.imgSrc.Close()
	}
	return nil
}

func (r *OCIResolver) buildIndex(ctx context.Context) error {
	layerInfos, err := BlobInfoFromImage(ctx, r.sysCtx, r.img)
	if err != nil {
		return err
	}

	// Iterate from bottom to top
	for _, layer := range layerInfos {
		if err := r.processLayer(ctx, layer); err != nil {
			return err
		}
	}
	return nil
}

func (r *OCIResolver) processLayer(ctx context.Context, layer types.BlobInfo) error {
	blob, _, err := r.imgSrc.GetBlob(ctx, layer, none.NoCache)
	if err != nil {
		return fmt.Errorf("failed to get blob %s: %w", layer.Digest, err)
	}
	defer blob.Close()

	uncompressedStream, _, err := compression.AutoDecompress(blob)
	if err != nil {
		return fmt.Errorf("failed to decompress blob %s: %w", layer.Digest, err)
	}
	defer uncompressedStream.Close()

	return r.processLayerTar(tar.NewReader(uncompressedStream), layer.Digest)
}

type whiteoutEntry struct {
	// dir is the parent directory of the whiteout marker (with trailing slash
	// from filepath.Split).
	dir string
	// target is the full path to remove for regular whiteouts; empty for
	// opaque whiteouts.
	target string
	opaque bool
}

// processLayerTar reads a single layer tar stream and updates fsIndex.
//
// It uses a collect-then-apply strategy so that whiteouts only affect entries
// from lower layers, never entries introduced by the same layer.
func (r *OCIResolver) processLayerTar(tr *tar.Reader, layerDigest digest.Digest) error {
	var newEntries []*FileEntry
	var whiteouts []whiteoutEntry

	// Phase 1: scan all tar entries
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		cleanPath := filepath.Clean(filepath.Join("/", hdr.Name))

		dir, file := filepath.Split(cleanPath)
		if strings.HasPrefix(file, ".wh.") {
			name := strings.TrimPrefix(file, ".wh.")
			if name == ".wh..opq" {
				whiteouts = append(whiteouts, whiteoutEntry{dir: dir, opaque: true})
			} else {
				whiteouts = append(whiteouts, whiteoutEntry{dir: dir, target: filepath.Join(dir, name)})
			}
			continue
		}

		newEntries = append(newEntries, &FileEntry{
			Path:        cleanPath,
			Size:        hdr.Size,
			Mode:        hdr.Mode,
			ModTime:     hdr.ModTime,
			LayerDigest: layerDigest,
			LinkTarget:  hdr.Linkname,
			UID:         hdr.Uid,
			GID:         hdr.Gid,
			TypeFlag:    hdr.Typeflag,
		})
	}

	// Phase 2: apply whiteouts against existing fsIndex (lower layers only)
	for _, wo := range whiteouts {
		if wo.opaque {
			// Opaque whiteout: remove everything inside the directory from
			// lower layers. The dir string already has a trailing slash, so
			// the prefix match won't accidentally hit the directory entry
			// itself (e.g. "/foo/bar" does not start with "/foo/bar/").
			for p := range r.fsIndex {
				if strings.HasPrefix(p, wo.dir) {
					delete(r.fsIndex, p)
				}
			}
		} else {
			delete(r.fsIndex, wo.target)
			// Cascade: also remove all children when the target is a
			// directory.
			prefix := wo.target + "/"
			for p := range r.fsIndex {
				if strings.HasPrefix(p, prefix) {
					delete(r.fsIndex, p)
				}
			}
		}
	}

	// Phase 3: merge new entries from this layer
	for _, entry := range newEntries {
		r.fsIndex[entry.Path] = entry
	}

	return nil
}

// -- ContentResolver Interface --

func (r *OCIResolver) FileContentsByLocation(loc syftFile.Location) (io.ReadCloser, error) {
	entry, ok := r.fsIndex[loc.RealPath]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", loc.RealPath)
	}

	// We need to reopen the layer stream and seek to the file
	// This is inefficient but avoids extracting everything.
	// Optimally we would cache the offset in FileEntry during indexing, but tar doesn't easily give offset.
	// So we scan.

	blob, _, err := r.imgSrc.GetBlob(context.Background(), types.BlobInfo{Digest: entry.LayerDigest, Size: -1}, none.NoCache)
	if err != nil {
		return nil, err
	}

	uncompressedStream, _, err := compression.AutoDecompress(blob)
	if err != nil {
		blob.Close()
		return nil, err
	}

	tr := tar.NewReader(uncompressedStream)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			uncompressedStream.Close()
			blob.Close()
			return nil, err
		}

		cleanPath := filepath.Clean(filepath.Join("/", hdr.Name))
		if cleanPath == loc.RealPath {
			// Found it. Return a ReadCloser that closes the underlying streams.
			return &tarReadCloser{
				Reader: tr,
				closers: []io.Closer{
					uncompressedStream,
					blob,
				},
			}, nil
		}
	}

	uncompressedStream.Close()
	blob.Close()
	return nil, fmt.Errorf("file content not found for path: %s in layer %s", loc.RealPath, entry.LayerDigest)
}

type tarReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (t *tarReadCloser) Close() error {
	var errs error
	for _, c := range t.closers {
		if err := c.Close(); err != nil {
			if errs == nil {
				errs = err
			} else {
				errs = fmt.Errorf("%v; %v", errs, err)
			}
		}
	}
	return errs
}

// -- PathResolver Interface --

func (r *OCIResolver) HasPath(p string) bool {
	// Must resolve symlinks to answer correctly
	path := filepath.Clean(p)
	resolved, err := r.resolveSymlink(path)
	if err != nil {
		return false
	}
	_, ok := r.fsIndex[resolved]
	return ok
}

// FilesByPath returns locations for the given paths.
// It MUST resolve symlinks.
func (r *OCIResolver) FilesByPath(paths ...string) ([]syftFile.Location, error) {
	var locations []syftFile.Location

	for _, p := range paths {
		cleanPath := filepath.Clean(p)
		resolvedPath, err := r.resolveSymlink(cleanPath)
		if err != nil {
			// If we can't resolve it, it might not exist or be broken.
			// Syft expects us to return what we can found or error if strict?
			// Usually partial results are okay, but if a specific path is requested and missing, that might be an issue.
			// For now, if it doesn't exist, we skip it.
			continue
		}

		entry, ok := r.fsIndex[resolvedPath]
		if !ok {
			continue
		}

		loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{
			RealPath:     resolvedPath,
			FileSystemID: entry.LayerDigest.String(),
		})
		// If the requested path was different from resolved (symlink), set AccessPath
		if cleanPath != resolvedPath {
			loc.AccessPath = cleanPath
		}
		locations = append(locations, loc)
	}
	return locations, nil
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.Split(p, string(filepath.Separator)) {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

func (r *OCIResolver) resolveSymlink(p string) (string, error) {
	if cached, ok := r.symlinkCache[p]; ok {
		return cached, nil
	}

	const maxLinks = 255
	linksWalked := 0

	// resolved is the verified non-symlink prefix built so far.
	resolved := "/"
	remaining := splitPath(p)

	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]

		if part == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}

		candidate := filepath.Join(resolved, part)

		entry, ok := r.fsIndex[candidate]
		if !ok || entry.TypeFlag != tar.TypeSymlink {
			resolved = candidate
			continue
		}

		linksWalked++
		if linksWalked > maxLinks {
			return "", errors.New("too many symbolic links")
		}

		target := entry.LinkTarget
		if filepath.IsAbs(target) {
			// Absolute target: restart from root with cleaned target prepended.
			remaining = append(splitPath(filepath.Clean(target)), remaining...)
			resolved = "/"
		} else {
			// Relative target: prepend raw parts so ".." components are handled
			// naturally by the loop without resetting the verified prefix.
			remaining = append(splitPath(target), remaining...)
		}
	}

	result := filepath.Clean(resolved)
	r.symlinkCache[p] = result
	return result, nil
}

// FilesByGlob returns locations matching the glob patterns.
func (r *OCIResolver) FilesByGlob(patterns ...string) ([]syftFile.Location, error) {
	var locations []syftFile.Location
	seen := make(map[string]struct{})

	for _, pattern := range patterns {
		for pathStr, entry := range r.fsIndex {
			matched, err := doublestar.Match(pattern, pathStr)
			if err != nil {
				return nil, err
			}
			if matched {
				// Only return files, not directories, as per interface hint?
				// The interface doc says "only returns locations to files (NOT directories)"
				if entry.TypeFlag == tar.TypeDir {
					continue
				}

				if _, ok := seen[pathStr]; ok {
					continue
				}
				seen[pathStr] = struct{}{}

				resolvedPath, err := r.resolveSymlink(pathStr)
				if err != nil {
					// If we can't resolve (broken link), skip it?
					continue
				}

				resolvedEntry, ok := r.fsIndex[resolvedPath]
				if !ok {
					continue
				}

				loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{
					RealPath:     resolvedPath,
					FileSystemID: resolvedEntry.LayerDigest.String(),
				})

				if pathStr != resolvedPath {
					loc.AccessPath = pathStr
				}

				locations = append(locations, loc)
			}
		}
	}
	return locations, nil
}

func (r *OCIResolver) FilesByMIMEType(types ...string) ([]syftFile.Location, error) {
	// Not implemented for now, as it requires reading content to guess MIME type usually,
	// unless we rely on extension. Syft mostly uses this for binary detection.
	// We can return empty for now or implement if needed.
	return nil, nil
}

func (r *OCIResolver) RelativeFileByPath(_ syftFile.Location, path string) *syftFile.Location {
	// "fetches a single file at the given path relative to the layer squash of the given reference"
	// We can just look up the path in our index.
	// The location argument is usually the "anchor" file.
	// If path is absolute, use it. If relative, join with anchor's dir.

	// This method signature in syft/file/resolver.go is:
	// RelativeFileByPath(_ Location, path string) *Location

	// TODO: Implementation logic if strictly needed.
	// For now, naive implementation:
	resolvedPath := path
	if !filepath.IsAbs(path) {
		// We don't have the context of the 'Location' argument easily without parsing it?
		// Actually we do receive it.
		// But let's assume absolute paths for now as most lookups are.
		return nil
	}

	entry, ok := r.fsIndex[resolvedPath]
	if !ok {
		return nil
	}
	loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{
		RealPath:     resolvedPath,
		FileSystemID: entry.LayerDigest.String(),
	})
	return &loc
}

// -- LocationResolver Interface --

func (r *OCIResolver) AllLocations(ctx context.Context) <-chan syftFile.Location {
	ch := make(chan syftFile.Location)
	go func() {
		defer close(ch)
		for path, entry := range r.fsIndex {
			select {
			case <-ctx.Done():
				return
			case ch <- syftFile.NewLocationFromCoordinates(syftFile.Coordinates{
				RealPath:     path,
				FileSystemID: entry.LayerDigest.String(),
			}):
			}
		}
	}()
	return ch
}

// -- MetadataResolver Interface --

func (r *OCIResolver) FileMetadataByLocation(loc syftFile.Location) (syftFile.Metadata, error) {
	entry, ok := r.fsIndex[loc.RealPath]
	if !ok {
		return syftFile.Metadata{}, fmt.Errorf("file not found: %s", loc.RealPath)
	}

	// We need to construct syftFile.Metadata (which embeds file.Metadata)
	// syftFile.Metadata = file.Metadata
	// file.Metadata has FileInfo, Path, Type, etc.

	info := &fileInfo{
		name:    filepath.Base(entry.Path),
		size:    entry.Size,
		mode:    fs.FileMode(entry.Mode),
		modTime: entry.ModTime,
		isDir:   entry.TypeFlag == tar.TypeDir,
	}

	meta := syftFile.Metadata{
		FileInfo:        info,
		Path:            entry.Path,
		LinkDestination: entry.LinkTarget,
		UserID:          entry.UID,
		GroupID:         entry.GID,
		Type:            file.TypeFromTarType(entry.TypeFlag),
		// MIMEType: ... (requires content read)
	}

	return meta, nil
}

// fileInfo implements fs.FileInfo
type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode // This is a bit tricky, might need standard os.FileMode conversion if using standard fs interface
	modTime time.Time
	isDir   bool
}

func (f *fileInfo) Name() string       { return f.name }
func (f *fileInfo) Size() int64        { return f.size }
func (f *fileInfo) Mode() fs.FileMode  { return f.mode } // The interface in stereoscope might differ slightly from os.FileMode
func (f *fileInfo) ModTime() time.Time { return f.modTime }
func (f *fileInfo) IsDir() bool        { return f.isDir }
func (f *fileInfo) Sys() any           { return nil }
