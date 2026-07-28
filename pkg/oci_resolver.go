package skiff

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/anchore/stereoscope/pkg/file"
	syftFile "github.com/anchore/syft/syft/file"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/opencontainers/go-digest"
	"go.podman.io/image/v5/pkg/blobinfocache/none"
	"go.podman.io/image/v5/pkg/compression"
	"go.podman.io/image/v5/types"
)

// OCIResolver presents an OCI image as Syft's file.Resolver without
// on-disk extraction.
//
// Path invariant: every fsIndex key is a clean absolute slash path
// produced by cleanTarPath. All path manipulation in this file uses
// the `path` package, never `filepath`, because OCI/tar paths are
// logical slash-separated paths independent of host OS.
//
// Layer-history limitation: fsIndex stores the SQUASHED view — only
// the last writer/whiteout per path is retained. Methods that try to
// honor Syft's "same layer or lower" semantics (notably
// RelativeFileByPath) are therefore best-effort: a path written low
// and overwritten high will be visible only at the high layer index,
// and an anchor in between will fail the layer filter even though the
// contract would expect a lower-layer view (see
// TestRelativeFileByPath_OverwriteLimitation).
//
// Hard links are resolved at index time: every FileEntry stores
// ContentLayerDigest and ContentPath naming where the bytes actually
// live in the source tar. The squashed fsIndex would otherwise lose
// the connection between a hard link `/b` and a target `/a` that gets
// whiteouted or overwritten in a later layer.
//
// TODO(perf): if rpm-diff against large production images becomes
// slow, consider an LRU around openBlob's decompressed-tar stream.
// Decompressed layer size is unbounded relative to BlobInfo.Size, and
// resolver methods run concurrently across two images, so any cache
// must be bounded and thread-safe. Benchmark first against a real
// workload — the hard-link dedup in FilesByGlob already eliminates
// most of the duplicate reads that motivated the original proposal.
type OCIResolver struct {
	img          types.Image
	imgSrc       types.ImageSource
	sysCtx       *types.SystemContext
	fsIndex      map[string]*FileEntry
	symlinkCache map[string]string
	// openBlob, when set, returns a fully decompressed tar stream for a
	// layer digest. Production code wires this through imgSrc.GetBlob +
	// compression.AutoDecompress; tests can substitute a buffer-backed
	// implementation without standing up an imgSrc. If nil (raw
	// &OCIResolver{} literals from older tests), the inline imgSrc path
	// is used.
	openBlob func(ctx context.Context, d digest.Digest) (io.ReadCloser, error)
}

const unknownLayerIndex = -1

// FileEntry represents a file in the virtual filesystem.
//
// ContentLayerDigest and ContentPath name where this entry's bytes
// live in the source tar:
//   - regular files: mirror LayerDigest / Path
//   - hard links: copied from the resolved target so reads survive
//     subsequent overwrite/whiteout of the target
//   - other types (dir, symlink, device, FIFO, char): empty; not
//     read via FileContentsByLocation
type FileEntry struct {
	Path               string
	Size               int64
	Mode               fs.FileMode
	ModTime            time.Time
	LayerDigest        digest.Digest
	LayerIndex         int
	LinkTarget         string
	UID                int
	GID                int
	TypeFlag           byte
	ContentLayerDigest digest.Digest
	ContentPath        string
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
	resolver.openBlob = func(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
		blob, _, err := imgSrc.GetBlob(ctx, types.BlobInfo{Digest: d, Size: -1}, none.NoCache)
		if err != nil {
			return nil, err
		}
		decompressed, _, err := compression.AutoDecompress(blob)
		if err != nil {
			blob.Close()
			return nil, err
		}
		return &multiCloser{Reader: decompressed, closers: []io.Closer{decompressed, blob}}, nil
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

	for i, layer := range layerInfos {
		if err := r.processLayer(ctx, layer, i); err != nil {
			return err
		}
	}
	return nil
}

func (r *OCIResolver) processLayer(ctx context.Context, layer types.BlobInfo, index int) error {
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

	return r.processLayerTar(tar.NewReader(uncompressedStream), layer.Digest, index)
}

// tarHeaderMode reconstructs fs.FileMode from a tar header without going
// through (*tar.Header).FileInfo, which heap-allocates a wrapper per call.
func tarHeaderMode(hdr *tar.Header) fs.FileMode {
	m := fs.FileMode(hdr.Mode & 0o777)
	switch hdr.Typeflag {
	case tar.TypeDir:
		m |= fs.ModeDir
	case tar.TypeSymlink:
		m |= fs.ModeSymlink
	case tar.TypeLink:
	case tar.TypeChar:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case tar.TypeBlock:
		m |= fs.ModeDevice
	case tar.TypeFifo:
		m |= fs.ModeNamedPipe
	}
	return m
}

// cleanTarPath validates and normalizes a tar header path. Unlike
// path.Clean("/"+name), it rejects ..-escape outright: a malicious
// "../../etc/passwd" cleans to "/etc/passwd" under path.Clean and the
// index never sees the attack; here it returns an error.
//
// Empty and ./.. segments are normalized. Double-slash segments are
// rejected as suspicious. A trailing slash (typical for tar directory
// entries) is tolerated.
func cleanTarPath(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty path")
	}
	trimmed := strings.Trim(name, "/")
	if trimmed == "" {
		return "/", nil
	}
	var parts []string
	for _, seg := range strings.Split(trimmed, "/") {
		switch seg {
		case "":
			return "", fmt.Errorf("path %q contains empty segment", name)
		case ".":
			continue
		case "..":
			if len(parts) == 0 {
				return "", fmt.Errorf("path %q escapes root", name)
			}
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, seg)
		}
	}
	if len(parts) == 0 {
		return "/", nil
	}
	return "/" + strings.Join(parts, "/"), nil
}

type whiteoutEntry struct {
	// dir is the parent directory of the whiteout marker (with trailing slash
	// from path.Split).
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
//
// Hard links are resolved during Phase 1, before whiteouts apply, so a
// same-layer `whiteout(/a) + hardlink(/b -> /a)` pattern still lets /b
// serve the lower-layer bytes that /a used to point at. This is the
// resolver's chosen model — real builders may emit such patterns
// differently; if a real fixture surfaces a different expectation,
// revisit.
func (r *OCIResolver) processLayerTar(tr *tar.Reader, layerDigest digest.Digest, layerIndex int) error {
	seen := make(map[string]struct{})
	layerEntries := make(map[string]*FileEntry)
	var newEntries []*FileEntry
	var whiteouts []whiteoutEntry

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		cleanPath, err := cleanTarPath(hdr.Name)
		if err != nil {
			return fmt.Errorf("invalid tar entry name %q: %w", hdr.Name, err)
		}

		if _, dup := seen[cleanPath]; dup {
			return fmt.Errorf("duplicate path in layer tar: %s", cleanPath)
		}
		seen[cleanPath] = struct{}{}

		dir, base := path.Split(cleanPath)
		if strings.HasPrefix(base, ".wh.") {
			suffix := strings.TrimPrefix(base, ".wh.")
			if suffix == "" {
				return fmt.Errorf("invalid whiteout marker %q: empty basename after \".wh.\" prefix", cleanPath)
			}
			if suffix == ".wh..opq" {
				whiteouts = append(whiteouts, whiteoutEntry{dir: dir, opaque: true})
			} else {
				whiteouts = append(whiteouts, whiteoutEntry{dir: dir, target: path.Join(dir, suffix)})
			}
			continue
		}

		entry := &FileEntry{
			Path:        cleanPath,
			Size:        hdr.Size,
			Mode:        tarHeaderMode(hdr),
			ModTime:     hdr.ModTime,
			LayerDigest: layerDigest,
			LayerIndex:  layerIndex,
			LinkTarget:  hdr.Linkname,
			UID:         hdr.Uid,
			GID:         hdr.Gid,
			TypeFlag:    hdr.Typeflag,
		}

		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			entry.ContentLayerDigest = layerDigest
			entry.ContentPath = cleanPath
		case tar.TypeLink:
			if hdr.Linkname == "" {
				return fmt.Errorf("hard link at %s has empty target", cleanPath)
			}
			targetPath, err := cleanTarPath(hdr.Linkname)
			if err != nil {
				return fmt.Errorf("invalid hard link target %q at %s: %w", hdr.Linkname, cleanPath, err)
			}
			target := layerEntries[targetPath]
			if target == nil {
				target = r.fsIndex[targetPath]
			}
			if target == nil {
				return fmt.Errorf("broken hard link at %s -> %s: target not found", cleanPath, targetPath)
			}
			switch target.TypeFlag {
			case tar.TypeReg, tar.TypeRegA, tar.TypeLink:
				// Allowed. TypeLink targets already carry resolved
				// content coordinates from when they were indexed, so
				// chains collapse to the original regular entry with
				// no per-call hop cap.
			case tar.TypeDir:
				return fmt.Errorf("invalid hard link at %s -> %s: target is a directory", cleanPath, targetPath)
			default:
				return fmt.Errorf("unsupported hard link target type %d at %s -> %s (only regular files are supported)", target.TypeFlag, cleanPath, targetPath)
			}
			entry.ContentLayerDigest = target.ContentLayerDigest
			entry.ContentPath = target.ContentPath
			// Align reported size with what reads will actually produce;
			// hard-link tar headers commonly carry Size=0.
			entry.Size = target.Size
		}

		newEntries = append(newEntries, entry)
		layerEntries[cleanPath] = entry
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

// fileSystemID returns the layer digest that downstream tools should key
// off for this entry. For hard links this is the layer where the bytes
// actually live (ContentLayerDigest), not the layer that introduced the
// link entry itself; for regular files the two are equal.
func fileSystemID(e *FileEntry) string {
	if e.ContentLayerDigest != "" {
		return e.ContentLayerDigest.String()
	}
	return e.LayerDigest.String()
}

// lexSmallestAlias returns the lexicographically smallest path in
// fsIndex whose content coordinates match (contentLayerDigest, contentPath).
// Returns "" when no entry matches.
func (r *OCIResolver) lexSmallestAlias(contentLayerDigest digest.Digest, contentPath string) string {
	var smallest string
	for p, e := range r.fsIndex {
		if e.ContentLayerDigest == contentLayerDigest && e.ContentPath == contentPath {
			if smallest == "" || p < smallest {
				smallest = p
			}
		}
	}
	return smallest
}

// -- ContentResolver Interface --

func (r *OCIResolver) FileContentsByLocation(loc syftFile.Location) (io.ReadCloser, error) {
	entry, ok := r.fsIndex[loc.RealPath]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", loc.RealPath)
	}

	layerDigest := entry.ContentLayerDigest
	targetPath := entry.ContentPath
	if layerDigest == "" || targetPath == "" {
		// Legacy entry (e.g. raw &FileEntry{} test literal) — fall
		// back to addressing by the location's own path.
		layerDigest = entry.LayerDigest
		targetPath = loc.RealPath
	}

	return r.readFromLayer(context.Background(), layerDigest, targetPath)
}

// readFromTar advances tr until it finds the header at targetPath and
// returns the reader positioned at that entry's payload. Entries with
// invalid tar names are skipped rather than failing the search.
func readFromTar(tr *tar.Reader, targetPath string) (io.Reader, error) {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("file not found in tar: %s", targetPath)
		}
		if err != nil {
			return nil, err
		}
		clean, err := cleanTarPath(hdr.Name)
		if err != nil {
			continue
		}
		if clean == targetPath {
			return tr, nil
		}
	}
}

func (r *OCIResolver) readFromLayer(ctx context.Context, layerDigest digest.Digest, targetPath string) (io.ReadCloser, error) {
	rc, err := r.openBlobInternal(ctx, layerDigest)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(rc)
	payload, err := readFromTar(tr, targetPath)
	if err != nil {
		rc.Close()
		return nil, err
	}
	return &multiCloser{Reader: payload, closers: []io.Closer{rc}}, nil
}

// openBlobInternal returns a decompressed tar stream for the given layer
// digest, preferring the injected openBlob hook and falling back to the
// imgSrc path for raw &OCIResolver{} literals used by older tests.
func (r *OCIResolver) openBlobInternal(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	if r.openBlob != nil {
		return r.openBlob(ctx, d)
	}
	if r.imgSrc == nil {
		return nil, errors.New("OCIResolver has no blob source")
	}
	blob, _, err := r.imgSrc.GetBlob(ctx, types.BlobInfo{Digest: d, Size: -1}, none.NoCache)
	if err != nil {
		return nil, err
	}
	decompressed, _, err := compression.AutoDecompress(blob)
	if err != nil {
		blob.Close()
		return nil, err
	}
	return &multiCloser{Reader: decompressed, closers: []io.Closer{decompressed, blob}}, nil
}

// multiCloser bundles a Reader with one or more underlying Closers.
type multiCloser struct {
	io.Reader
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	var errs error
	for _, c := range m.closers {
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
	cleaned := path.Clean(p)
	resolved, err := r.resolveSymlink(cleaned)
	if err != nil {
		return false
	}
	_, ok := r.fsIndex[resolved]
	return ok
}

// FilesByPath returns locations for the given paths. Must resolve symlinks.
// Directories are skipped per Syft's PathResolver contract.
func (r *OCIResolver) FilesByPath(paths ...string) ([]syftFile.Location, error) {
	var locations []syftFile.Location

	for _, p := range paths {
		cleanPath := path.Clean(p)
		resolvedPath, err := r.resolveSymlink(cleanPath)
		if err != nil {
			continue
		}

		entry, ok := r.fsIndex[resolvedPath]
		if !ok {
			continue
		}
		if entry.TypeFlag == tar.TypeDir {
			continue
		}

		loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{
			RealPath:     resolvedPath,
			FileSystemID: fileSystemID(entry),
		})
		if cleanPath != resolvedPath {
			loc.AccessPath = cleanPath
		}
		locations = append(locations, loc)
	}
	return locations, nil
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.Split(p, "/") {
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
			resolved = path.Dir(resolved)
			continue
		}

		candidate := path.Join(resolved, part)

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
		if path.IsAbs(target) {
			// Absolute target: restart from root with cleaned target prepended.
			remaining = append(splitPath(path.Clean(target)), remaining...)
			resolved = "/"
		} else {
			// Relative target: prepend raw parts so ".." components are handled
			// naturally by the loop without resetting the verified prefix.
			remaining = append(splitPath(target), remaining...)
		}
	}

	result := path.Clean(resolved)
	r.symlinkCache[p] = result
	return result, nil
}

// FilesByGlob returns locations matching the glob patterns.
//
// Iteration is deterministic: paths are walked in sorted order and only
// the first match per content key (or per resolved path, for legacy
// entries with no content coords) is recorded. This makes result order
// and the choice of canonical RealPath independent of map iteration
// order and of the order patterns are passed in.
//
// Hard links are deduped by (ContentLayerDigest, ContentPath); RealPath
// is set to the lexicographically smallest alias in the index that
// shares those coordinates.
func (r *OCIResolver) FilesByGlob(patterns ...string) ([]syftFile.Location, error) {
	sortedPaths := make([]string, 0, len(r.fsIndex))
	for p := range r.fsIndex {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	var locations []syftFile.Location
	seen := make(map[string]struct{})

	for _, pathStr := range sortedPaths {
		entry := r.fsIndex[pathStr]
		if entry.TypeFlag == tar.TypeDir {
			continue
		}

		matched := false
		for _, pattern := range patterns {
			m, err := doublestar.Match(pattern, pathStr)
			if err != nil {
				return nil, err
			}
			if m {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		resolvedPath, err := r.resolveSymlink(pathStr)
		if err != nil {
			continue
		}

		resolvedEntry, ok := r.fsIndex[resolvedPath]
		if !ok {
			continue
		}
		if resolvedEntry.TypeFlag == tar.TypeDir {
			continue
		}

		var key, realPath string
		if resolvedEntry.ContentLayerDigest != "" && resolvedEntry.ContentPath != "" {
			key = resolvedEntry.ContentLayerDigest.String() + ":" + resolvedEntry.ContentPath
			realPath = r.lexSmallestAlias(resolvedEntry.ContentLayerDigest, resolvedEntry.ContentPath)
			if realPath == "" {
				realPath = resolvedPath
			}
		} else {
			// Legacy entry (test literal): dedup by resolved path; keep
			// the symlink-resolution RealPath the original code used.
			key = resolvedPath
			realPath = resolvedPath
		}

		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{
			RealPath:     realPath,
			FileSystemID: fileSystemID(resolvedEntry),
		})
		if pathStr != realPath {
			loc.AccessPath = pathStr
		}
		locations = append(locations, loc)
	}
	return locations, nil
}

func (r *OCIResolver) FilesByMIMEType(types ...string) ([]syftFile.Location, error) {
	return nil, nil
}

// RelativeFileByPath resolves a path relative to an anchor location.
// Absolute paths are cleaned in place; relative paths are joined with the
// anchor's directory. Directories are skipped, and results from layers
// higher than the anchor's layer are rejected (best-effort given the
// squashed fsIndex — see the type-level comment).
func (r *OCIResolver) RelativeFileByPath(anchor syftFile.Location, p string) *syftFile.Location {
	var lookup string
	if path.IsAbs(p) {
		lookup = path.Clean(p)
	} else {
		lookup = path.Clean(path.Join(path.Dir(anchor.RealPath), p))
	}

	resolvedPath, err := r.resolveSymlink(lookup)
	if err != nil {
		return nil
	}

	entry, ok := r.fsIndex[resolvedPath]
	if !ok {
		return nil
	}
	if entry.TypeFlag == tar.TypeDir {
		return nil
	}

	if anchorEntry, ok := r.fsIndex[anchor.RealPath]; ok {
		if anchorEntry.LayerIndex != unknownLayerIndex && entry.LayerIndex != unknownLayerIndex {
			if entry.LayerIndex > anchorEntry.LayerIndex {
				return nil
			}
		}
	}

	loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{
		RealPath:     resolvedPath,
		FileSystemID: fileSystemID(entry),
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
				FileSystemID: fileSystemID(entry),
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

	info := &fileInfo{
		name:    path.Base(entry.Path),
		size:    entry.Size,
		mode:    entry.Mode,
		modTime: entry.ModTime,
	}

	meta := syftFile.Metadata{
		FileInfo:        info,
		Path:            entry.Path,
		LinkDestination: entry.LinkTarget,
		UserID:          entry.UID,
		GroupID:         entry.GID,
		Type:            file.TypeFromTarType(entry.TypeFlag),
	}

	return meta, nil
}

// fileInfo implements fs.FileInfo
type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

func (f *fileInfo) Name() string       { return f.name }
func (f *fileInfo) Size() int64        { return f.size }
func (f *fileInfo) Mode() fs.FileMode  { return f.mode }
func (f *fileInfo) ModTime() time.Time { return f.modTime }
func (f *fileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f *fileInfo) Sys() any           { return nil }
