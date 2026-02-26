package skiff

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/containers/image/v5/types"
	"github.com/containers/storage/pkg/reexec"
	"github.com/containers/storage/pkg/unshare"
	"github.com/opencontainers/go-digest"
)

func newTestResolver(entries map[string]*FileEntry) *OCIResolver {
	return &OCIResolver{
		fsIndex:      entries,
		symlinkCache: make(map[string]string),
	}
}

func symlink(target string) *FileEntry {
	return &FileEntry{TypeFlag: tar.TypeSymlink, LinkTarget: target}
}

func regularFile() *FileEntry {
	return &FileEntry{TypeFlag: tar.TypeReg}
}

type tarEntry struct {
	name     string
	typeflag byte
	content  string
	linkname string
}

func buildTar(t *testing.T, entries []tarEntry) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Size:     int64(len(e.content)),
			Linkname: e.linkname,
			Mode:     0644,
		}
		if e.typeflag == tar.TypeDir {
			hdr.Mode = 0755
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
		t.Fatalf("tar.Close: %v", err)
	}
	return tar.NewReader(&buf)
}

var testDigest = digest.FromString("test-layer")

func TestProcessLayerTar(t *testing.T) {
	t.Run("regular file whiteout", func(t *testing.T) {
		r := newTestResolver(map[string]*FileEntry{
			"/dir":          {Path: "/dir", TypeFlag: tar.TypeDir},
			"/dir/keep":     {Path: "/dir/keep", TypeFlag: tar.TypeReg},
			"/dir/toremove": {Path: "/dir/toremove", TypeFlag: tar.TypeReg},
		})

		tr := buildTar(t, []tarEntry{
			{name: "dir/.wh.toremove", typeflag: tar.TypeReg},
		})

		if err := r.processLayerTar(tr, testDigest); err != nil {
			t.Fatal(err)
		}

		if _, ok := r.fsIndex["/dir/toremove"]; ok {
			t.Error("/dir/toremove should have been removed by whiteout")
		}
		if _, ok := r.fsIndex["/dir/keep"]; !ok {
			t.Error("/dir/keep should still exist")
		}
		if _, ok := r.fsIndex["/dir"]; !ok {
			t.Error("/dir should still exist")
		}
	})

	t.Run("directory whiteout cascades to children", func(t *testing.T) {
		r := newTestResolver(map[string]*FileEntry{
			"/parent":              {Path: "/parent", TypeFlag: tar.TypeDir},
			"/parent/sub":          {Path: "/parent/sub", TypeFlag: tar.TypeDir},
			"/parent/sub/a":        {Path: "/parent/sub/a", TypeFlag: tar.TypeReg},
			"/parent/sub/b":        {Path: "/parent/sub/b", TypeFlag: tar.TypeReg},
			"/parent/sub/deep/c":   {Path: "/parent/sub/deep/c", TypeFlag: tar.TypeReg},
			"/parent/other":        {Path: "/parent/other", TypeFlag: tar.TypeReg},
		})

		tr := buildTar(t, []tarEntry{
			{name: "parent/.wh.sub", typeflag: tar.TypeReg},
		})

		if err := r.processLayerTar(tr, testDigest); err != nil {
			t.Fatal(err)
		}

		for _, gone := range []string{"/parent/sub", "/parent/sub/a", "/parent/sub/b", "/parent/sub/deep/c"} {
			if _, ok := r.fsIndex[gone]; ok {
				t.Errorf("%s should have been removed by directory whiteout", gone)
			}
		}
		if _, ok := r.fsIndex["/parent/other"]; !ok {
			t.Error("/parent/other should still exist")
		}
		if _, ok := r.fsIndex["/parent"]; !ok {
			t.Error("/parent should still exist")
		}
	})

	t.Run("opaque whiteout removes lower-layer contents", func(t *testing.T) {
		r := newTestResolver(map[string]*FileEntry{
			"/dir":       {Path: "/dir", TypeFlag: tar.TypeDir},
			"/dir/old1":  {Path: "/dir/old1", TypeFlag: tar.TypeReg},
			"/dir/old2":  {Path: "/dir/old2", TypeFlag: tar.TypeReg},
			"/other":     {Path: "/other", TypeFlag: tar.TypeReg},
		})

		tr := buildTar(t, []tarEntry{
			{name: "dir/", typeflag: tar.TypeDir},
			{name: "dir/.wh..wh..opq", typeflag: tar.TypeReg},
			{name: "dir/newfile", typeflag: tar.TypeReg, content: "new"},
		})

		if err := r.processLayerTar(tr, testDigest); err != nil {
			t.Fatal(err)
		}

		for _, gone := range []string{"/dir/old1", "/dir/old2"} {
			if _, ok := r.fsIndex[gone]; ok {
				t.Errorf("%s should have been removed by opaque whiteout", gone)
			}
		}
		if _, ok := r.fsIndex["/dir/newfile"]; !ok {
			t.Error("/dir/newfile from same layer should exist")
		}
		if _, ok := r.fsIndex["/dir"]; !ok {
			t.Error("/dir directory entry from same layer should exist")
		}
		if _, ok := r.fsIndex["/other"]; !ok {
			t.Error("/other should be unaffected")
		}
	})

	t.Run("opaque whiteout preserves same-layer entries regardless of tar order", func(t *testing.T) {
		// The opaque whiteout appears AFTER a same-layer file in the tar
		// stream. The collect-then-apply strategy must preserve it.
		r := newTestResolver(map[string]*FileEntry{
			"/dir/lower": {Path: "/dir/lower", TypeFlag: tar.TypeReg},
		})

		tr := buildTar(t, []tarEntry{
			{name: "dir/samefile", typeflag: tar.TypeReg, content: "data"},
			{name: "dir/.wh..wh..opq", typeflag: tar.TypeReg},
		})

		if err := r.processLayerTar(tr, testDigest); err != nil {
			t.Fatal(err)
		}

		if _, ok := r.fsIndex["/dir/lower"]; ok {
			t.Error("/dir/lower from lower layer should have been removed")
		}
		if _, ok := r.fsIndex["/dir/samefile"]; !ok {
			t.Error("/dir/samefile from same layer should survive opaque whiteout")
		}
	})

	t.Run("new layer entries overwrite lower-layer entries", func(t *testing.T) {
		r := newTestResolver(map[string]*FileEntry{
			"/file": {Path: "/file", TypeFlag: tar.TypeReg, Size: 100},
		})

		tr := buildTar(t, []tarEntry{
			{name: "file", typeflag: tar.TypeReg, content: "updated"},
		})

		if err := r.processLayerTar(tr, testDigest); err != nil {
			t.Fatal(err)
		}

		entry := r.fsIndex["/file"]
		if entry == nil {
			t.Fatal("/file should exist")
		}
		if entry.Size != 7 {
			t.Errorf("expected updated size 7, got %d", entry.Size)
		}
		if entry.LayerDigest != testDigest {
			t.Errorf("expected layer digest %s, got %s", testDigest, entry.LayerDigest)
		}
	})
}

func TestResolveSymlink(t *testing.T) {
	tests := []struct {
		name    string
		index   map[string]*FileEntry
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "no symlinks",
			index: map[string]*FileEntry{"/a/b/c": regularFile()},
			input: "/a/b/c",
			want:  "/a/b/c",
		},
		{
			name: "absolute symlink",
			index: map[string]*FileEntry{
				"/bin":         symlink("/usr/bin"),
				"/usr/bin/sh":  regularFile(),
			},
			input: "/bin/sh",
			want:  "/usr/bin/sh",
		},
		{
			name: "relative symlink with dotdot",
			index: map[string]*FileEntry{
				"/a/b/link": symlink("../foo"),
				"/a/foo/c":  regularFile(),
			},
			input: "/a/b/link/c",
			want:  "/a/foo/c",
		},
		{
			// /bin -> /usr/bin (absolute), /usr/bin -> lib (relative to /usr), so /usr/lib
			name: "chained symlinks",
			index: map[string]*FileEntry{
				"/bin":     symlink("/usr/bin"),
				"/usr/bin": symlink("lib"),
				"/usr/lib/sh": regularFile(),
			},
			input: "/bin/sh",
			want:  "/usr/lib/sh",
		},
		{
			name: "result cached on second call",
			index: map[string]*FileEntry{
				"/link": symlink("/real"),
				"/real": regularFile(),
			},
			input: "/link",
			want:  "/real",
		},
		{
			name:    "symlink loop",
			index:   map[string]*FileEntry{"/a": symlink("/b"), "/b": symlink("/a")},
			input:   "/a",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestResolver(tc.index)
			got, err := r.resolveSymlink(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveSymlink(%q) = %q, want %q", tc.input, got, tc.want)
			}
			// Verify cache hit
			if cached, ok := r.symlinkCache[tc.input]; !ok || cached != tc.want {
				t.Errorf("cache miss or wrong value: %v %q", ok, cached)
			}
		})
	}
}

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

	// 1. Test Path Existence
	t.Run("HasPath", func(t *testing.T) {
		if !resolver.HasPath("/bin/sh") {
			t.Error("Expected /bin/sh to exist")
		}
		if resolver.HasPath("/nonexistent/file") {
			t.Error("Expected /nonexistent/file to NOT exist")
		}
	})

	// 2. Test FilesByPath (and implied symlink resolution if any)
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

	// 3. Test Glob
	t.Run("FilesByGlob", func(t *testing.T) {
		// Glob for busybox anywhere.
		// Note: /bin/busybox might not be a key in our index if /bin is a symlink and the file is actually at /usr/bin/busybox.
		// Our simple resolver iterates keys, so it won't traverse the /bin symlink during globbing.
		// Using **/busybox ensures we find it regardless of where it physically lives.
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

	// 4. Test Content Retrieval
	t.Run("FileContentsByLocation", func(t *testing.T) {
		// /etc/passwd is standard
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

	// 5. Test Metadata
	t.Run("FileMetadataByLocation", func(t *testing.T) {
		locs, err := resolver.FilesByPath("/bin/sh")
		if err != nil || len(locs) == 0 {
			t.Fatal("Failed to locate /bin/sh")
		}

		meta, err := resolver.FileMetadataByLocation(locs[0])
		if err != nil {
			t.Fatalf("Failed to get metadata: %v", err)
		}

		if meta.Path != "/bin/sh" && meta.Path != "/usr/bin/sh" { // Depending on distro
			// BusyBox usually has /bin/sh
			// But check actual resolved path
			t.Logf("Metadata path: %s", meta.Path)
		}
		// Check mode is executable (approximate check)
		if meta.Mode().Perm()&0111 == 0 {
			t.Error("Expected /bin/sh to be executable")
		}
	})
}

func TestOCIResolver_Whiteouts(t *testing.T) {
	// Uses localhost/skiff-test-image:latest which must be built locally
	// from TestImage.containerfile.
	// Contains:
	// - /src/data/foo/bar (created then deleted) -> file whiteout
	// - /src/data/foo (created then deleted) -> directory whiteout
	// - /src/data (remains)
	// - /opaque-test/dir/{file1,file2} created, then dir replaced with
	//   newfile -> opaque whiteout
	// - /nested-test/a/b/c/file + /nested-test/a/top created, then
	//   /nested-test/a removed -> cascading directory whiteout
	uri := "localhost/skiff-test-image:latest"

	ctx := context.Background()
	sysCtx := &types.SystemContext{}

	img, _, err := ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		t.Fatalf("Failed to load test image %s: %v. Ensure image is built locally.", uri, err)
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
		// Original file/directory whiteout tests
		{"/src/data/foo/bar", false, "Deleted file should be whiteouted"},
		{"/src/data/foo", false, "Deleted directory should be whiteouted"},
		{"/src/data", true, "Parent directory should persist"},
		{"/usr/bin/vim", true, "Installed package file should exist"},
		{"/bin/sh", true, "Base image file should exist"},

		// Opaque whiteout tests: old contents gone, new content present
		{"/opaque-test/dir/file1", false, "Opaque whiteout should hide lower-layer file1"},
		{"/opaque-test/dir/file2", false, "Opaque whiteout should hide lower-layer file2"},
		{"/opaque-test/dir/newfile", true, "Same-layer file should survive opaque whiteout"},
		{"/opaque-test/dir", true, "Directory should survive opaque whiteout"},
		{"/opaque-test", true, "Parent of opaque-whited directory should persist"},

		// Nested directory whiteout: entire subtree gone
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
