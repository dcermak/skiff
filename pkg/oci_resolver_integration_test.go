//go:build integration

package skiff

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

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
