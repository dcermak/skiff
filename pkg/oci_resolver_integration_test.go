//go:build integration

package skiff

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	imgspec "github.com/opencontainers/image-spec/specs-go"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/image/v5/types"
	"go.podman.io/storage/pkg/reexec"
	"go.podman.io/storage/pkg/unshare"
)

func TestMain(m *testing.M) {
	if reexec.Init() {
		return
	}
	unshare.MaybeReexecUsingUserNamespace(true)
	os.Exit(m.Run())
}

func TestOCIResolver(t *testing.T) {
	// Use a known stable image digest
	// registry.suse.com/bci/bci-busybox@sha256:7c7d8d3ff8813e62ec46501b458c47cabf818867afd8ade209f729e181a3f7ea
	uri := "docker://registry.suse.com/bci/bci-busybox@sha256:7c7d8d3ff8813e62ec46501b458c47cabf818867afd8ade209f729e181a3f7ea"

	ctx := context.Background()
	sysCtx := &types.SystemContext{}

	img, _, err := ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		t.Logf("Skipping test: unable to fetch image (network/auth issue?): %v", err)
		t.SkipNow()
	}

	resolver, err := NewOCIResolver(ctx, img, sysCtx)
	if err != nil {
		t.Fatalf("Failed to create OCIResolver: %v", err)
	}
	defer resolver.Close()

	t.Run("HasPath", func(t *testing.T) {
		if !resolver.HasPath("/bin/sh") {
			t.Error("Expected /bin/sh to exist")
		}
		if resolver.HasPath("/nonexistent/file") {
			t.Error("Expected /nonexistent/file to NOT exist")
		}
	})

	t.Run("FilesByPath", func(t *testing.T) {
		locs, err := resolver.FilesByPath("/bin/sh")
		if err != nil {
			t.Errorf("FilesByPath failed: %v", err)
		}
		if len(locs) == 0 {
			t.Error("Expected locations for /bin/sh")
		} else {
			t.Logf("Found /bin/sh at: %s (Layer: %s)", locs[0].RealPath, locs[0].FileSystemID)
		}
	})

	t.Run("FilesByGlob", func(t *testing.T) {
		locs, err := resolver.FilesByGlob("**/busybox")
		if err != nil {
			t.Errorf("FilesByGlob failed: %v", err)
		}
		if len(locs) == 0 {
			t.Error("Expected matches for **/busybox")
		} else {
			t.Logf("Found %d matches for **/busybox", len(locs))
			for _, l := range locs {
				t.Logf(" - %s", l.RealPath)
			}
		}
	})

	t.Run("FileContentsByLocation", func(t *testing.T) {
		locs, err := resolver.FilesByPath("/etc/passwd")
		if err != nil || len(locs) == 0 {
			t.Fatalf("Failed to locate /etc/passwd")
		}

		rc, err := resolver.FileContentsByLocation(locs[0])
		if err != nil {
			t.Fatalf("Failed to get content: %v", err)
		}
		defer rc.Close()

		content, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("Failed to read content: %v", err)
		}

		s := string(content)
		if !strings.Contains(s, "root:x:0:0") {
			t.Errorf("Content of /etc/passwd did not contain expected string 'root:x:0:0'. Got:\n%s", s)
		}

		// Metadata should surface the content-classified MIME type.
		meta, err := resolver.FileMetadataByLocation(locs[0])
		if err != nil {
			t.Fatalf("FileMetadataByLocation(/etc/passwd): %v", err)
		}
		if meta.MIMEType == "" {
			t.Error("expected MIMEType to be populated for /etc/passwd")
		} else if !strings.HasPrefix(meta.MIMEType, "text/") {
			t.Logf("MIMEType of /etc/passwd = %q (expected a text/* type)", meta.MIMEType)
		}
	})

	t.Run("FileMetadataByLocation", func(t *testing.T) {
		locs, err := resolver.FilesByPath("/bin/sh")
		if err != nil || len(locs) == 0 {
			t.Fatal("Failed to locate /bin/sh")
		}

		meta, err := resolver.FileMetadataByLocation(locs[0])
		if err != nil {
			t.Fatalf("Failed to get metadata: %v", err)
		}

		if meta.Path != "/bin/sh" && meta.Path != "/usr/bin/sh" {
			t.Logf("Metadata path: %s", meta.Path)
		}
		if meta.Mode().Perm()&0111 == 0 {
			t.Error("Expected /bin/sh to be executable")
		}
	})
}

func TestOCIResolver_Whiteouts(t *testing.T) {
	// Uses localhost/skiff-test-image:latest which must be built locally
	// from TestImage.containerfile.
	uri := "localhost/skiff-test-image:latest"

	ctx := context.Background()
	sysCtx := &types.SystemContext{}

	img, _, err := ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		t.Skipf("Skipping: test image %s not available locally (build via `make test-image`): %v", uri, err)
	}

	resolver, err := NewOCIResolver(ctx, img, sysCtx)
	if err != nil {
		t.Fatalf("Failed to create OCIResolver: %v", err)
	}
	defer resolver.Close()

	tests := []struct {
		path   string
		exists bool
		desc   string
	}{
		{"/src/data/foo/bar", false, "Deleted file should be whiteouted"},
		{"/src/data/foo", false, "Deleted directory should be whiteouted"},
		{"/src/data", true, "Parent directory should persist"},
		{"/usr/bin/vim", true, "Installed package file should exist"},
		{"/bin/sh", true, "Base image file should exist"},

		{"/opaque-test/dir/file1", false, "Opaque whiteout should hide lower-layer file1"},
		{"/opaque-test/dir/file2", false, "Opaque whiteout should hide lower-layer file2"},
		{"/opaque-test/dir/newfile", true, "Same-layer file should survive opaque whiteout"},
		{"/opaque-test/dir", true, "Directory should survive opaque whiteout"},
		{"/opaque-test", true, "Parent of opaque-whited directory should persist"},

		{"/nested-test/a", false, "Removed directory should not exist"},
		{"/nested-test/a/top", false, "Direct child of removed directory should not exist"},
		{"/nested-test/a/b/c/file", false, "Deep child of removed directory should not exist"},
		{"/nested-test/a/b/c", false, "Nested subdirectory of removed directory should not exist"},
		{"/nested-test/a/b", false, "Intermediate subdirectory of removed directory should not exist"},
		{"/nested-test", true, "Parent of removed directory should persist"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			exists := resolver.HasPath(tc.path)
			if exists != tc.exists {
				t.Errorf("Path %s: expected exists=%v, got %v", tc.path, tc.exists, exists)
			}
		})
	}
}

// TestOCIResolver_DuplicatePaths exercises last-writer-wins handling of
// duplicate tar entries within a single layer. Container builders never emit
// such layers, so we hand-craft one and load it through the real oci:
// transport, driving the full resolve path (GetBlob -> AutoDecompress ->
// processLayerTar -> readFromLayer) end to end.
func TestOCIResolver_DuplicatePaths(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	entries := []struct {
		name     string
		typeflag byte
		content  string
	}{
		{"dir/", tar.TypeDir, ""},   // duplicate directory (first)
		{"foo", tar.TypeReg, "a"},   // duplicate regular file (first)
		{"dir/", tar.TypeDir, ""},   // duplicate directory (second)
		{"foo", tar.TypeReg, "bb"},  // duplicate regular file (last writer wins)
	}
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Size: int64(len(e.content)), Mode: 0o644}
		if e.typeflag == tar.TypeDir {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", e.name, err)
		}
		if len(e.content) > 0 {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatalf("Write(%s): %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}

	dir := t.TempDir()
	writeOCIImage(t, dir, buf.Bytes())

	ctx := context.Background()
	sysCtx := &types.SystemContext{}
	img, _, err := ImageAndLayersFromURI(ctx, sysCtx, "oci:"+dir+":latest")
	if err != nil {
		t.Fatalf("failed to load synthetic image: %v", err)
	}

	resolver, err := NewOCIResolver(ctx, img, sysCtx)
	if err != nil {
		t.Fatalf("NewOCIResolver: %v", err)
	}
	defer resolver.Close()

	// Duplicate directory is tolerated: it resolves without error and exists.
	if !resolver.HasPath("/dir") {
		t.Error("expected /dir to exist (duplicate directory should be tolerated)")
	}

	locs, err := resolver.FilesByPath("/foo")
	if err != nil || len(locs) == 0 {
		t.Fatalf("FilesByPath(/foo): locs=%v err=%v", locs, err)
	}

	// Metadata reflects the last writer ("bb"), not the first ("a").
	meta, err := resolver.FileMetadataByLocation(locs[0])
	if err != nil {
		t.Fatalf("FileMetadataByLocation(/foo): %v", err)
	}
	if meta.Size() != 2 {
		t.Errorf("size = %d, want 2 (last writer 'bb')", meta.Size())
	}
	if meta.MIMEType == "" {
		t.Error("expected MIMEType to be populated for /foo")
	}

	// Content read must land on the same (last) occurrence via ContentOrdinal.
	rc, err := resolver.FileContentsByLocation(locs[0])
	if err != nil {
		t.Fatalf("FileContentsByLocation(/foo): %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read /foo: %v", err)
	}
	if string(got) != "bb" {
		t.Errorf("content = %q, want %q (last writer wins)", got, "bb")
	}
}

// writeOCIImage assembles a minimal single-layer OCI image layout in dir from
// the given uncompressed layer tar bytes, ready to load as "oci:<dir>:latest".
// Blobs, config, manifest, index.json and oci-layout are written by hand using
// only already-vendored dependencies (no go-containerregistry / re-vendor).
func writeOCIImage(t *testing.T, dir string, layerTar []byte) {
	t.Helper()

	// diff ID addresses the *uncompressed* tar (image config rootfs.diff_ids),
	// which is what layerDiffIDs() reads to align FileSystemIDs.
	diffID := digest.FromBytes(layerTar)

	// The manifest layer descriptor addresses the gzip-compressed blob.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(layerTar); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	layerBlob := gz.Bytes()
	layerDigest := digest.FromBytes(layerBlob)

	blobsDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		t.Fatalf("mkdir blobs: %v", err)
	}
	writeBlob := func(d digest.Digest, data []byte) {
		if err := os.WriteFile(filepath.Join(blobsDir, d.Encoded()), data, 0o644); err != nil {
			t.Fatalf("write blob %s: %v", d, err)
		}
	}
	writeBlob(layerDigest, layerBlob)

	config := imgspecv1.Image{
		Platform: imgspecv1.Platform{Architecture: "amd64", OS: "linux"},
		RootFS:   imgspecv1.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configDigest := digest.FromBytes(configJSON)
	writeBlob(configDigest, configJSON)

	manifest := imgspecv1.Manifest{
		Versioned: imgspec.Versioned{SchemaVersion: 2},
		MediaType: imgspecv1.MediaTypeImageManifest,
		Config: imgspecv1.Descriptor{
			MediaType: imgspecv1.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configJSON)),
		},
		Layers: []imgspecv1.Descriptor{{
			MediaType: imgspecv1.MediaTypeImageLayerGzip,
			Digest:    layerDigest,
			Size:      int64(len(layerBlob)),
		}},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manifestDigest := digest.FromBytes(manifestJSON)
	writeBlob(manifestDigest, manifestJSON)

	index := imgspecv1.Index{
		Versioned: imgspec.Versioned{SchemaVersion: 2},
		MediaType: imgspecv1.MediaTypeImageIndex,
		Manifests: []imgspecv1.Descriptor{{
			MediaType:   imgspecv1.MediaTypeImageManifest,
			Digest:      manifestDigest,
			Size:        int64(len(manifestJSON)),
			Platform:    &imgspecv1.Platform{Architecture: "amd64", OS: "linux"},
			Annotations: map[string]string{imgspecv1.AnnotationRefName: "latest"},
		}},
	}
	indexJSON, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), indexJSON, 0o644); err != nil {
		t.Fatalf("write index.json: %v", err)
	}

	layoutJSON, err := json.Marshal(imgspecv1.ImageLayout{Version: imgspecv1.ImageLayoutVersion})
	if err != nil {
		t.Fatalf("marshal oci-layout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, imgspecv1.ImageLayoutFile), layoutJSON, 0o644); err != nil {
		t.Fatalf("write oci-layout: %v", err)
	}
}
