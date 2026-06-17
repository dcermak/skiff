package skiff

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	syftFile "github.com/anchore/syft/syft/file"
	"github.com/opencontainers/go-digest"
)

func newTestResolver(entries map[string]*FileEntry) *OCIResolver {
	return &OCIResolver{
		fsIndex:      entries,
		symlinkCache: make(map[string]string),
	}
}

func symlink(target string) *FileEntry {
	return &FileEntry{TypeFlag: tar.TypeSymlink, LinkTarget: target, LayerIndex: unknownLayerIndex}
}

func regularFile() *FileEntry {
	return &FileEntry{TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex}
}

type tarEntry struct {
	name     string
	typeflag byte
	content  string
	linkname string
}

func buildTarBytes(t *testing.T, entries []tarEntry) []byte {
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
	return buf.Bytes()
}

func buildTar(t *testing.T, entries []tarEntry) *tar.Reader {
	t.Helper()
	return tar.NewReader(bytes.NewReader(buildTarBytes(t, entries)))
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

		if err := r.processLayerTar(tr, testDigest, 0); err != nil {
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
			"/parent":            {Path: "/parent", TypeFlag: tar.TypeDir},
			"/parent/sub":        {Path: "/parent/sub", TypeFlag: tar.TypeDir},
			"/parent/sub/a":      {Path: "/parent/sub/a", TypeFlag: tar.TypeReg},
			"/parent/sub/b":      {Path: "/parent/sub/b", TypeFlag: tar.TypeReg},
			"/parent/sub/deep/c": {Path: "/parent/sub/deep/c", TypeFlag: tar.TypeReg},
			"/parent/other":      {Path: "/parent/other", TypeFlag: tar.TypeReg},
		})

		tr := buildTar(t, []tarEntry{
			{name: "parent/.wh.sub", typeflag: tar.TypeReg},
		})

		if err := r.processLayerTar(tr, testDigest, 0); err != nil {
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
			"/dir":      {Path: "/dir", TypeFlag: tar.TypeDir},
			"/dir/old1": {Path: "/dir/old1", TypeFlag: tar.TypeReg},
			"/dir/old2": {Path: "/dir/old2", TypeFlag: tar.TypeReg},
			"/other":    {Path: "/other", TypeFlag: tar.TypeReg},
		})

		tr := buildTar(t, []tarEntry{
			{name: "dir/", typeflag: tar.TypeDir},
			{name: "dir/.wh..wh..opq", typeflag: tar.TypeReg},
			{name: "dir/newfile", typeflag: tar.TypeReg, content: "new"},
		})

		if err := r.processLayerTar(tr, testDigest, 0); err != nil {
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
		r := newTestResolver(map[string]*FileEntry{
			"/dir/lower": {Path: "/dir/lower", TypeFlag: tar.TypeReg},
		})

		tr := buildTar(t, []tarEntry{
			{name: "dir/samefile", typeflag: tar.TypeReg, content: "data"},
			{name: "dir/.wh..wh..opq", typeflag: tar.TypeReg},
		})

		if err := r.processLayerTar(tr, testDigest, 0); err != nil {
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

		if err := r.processLayerTar(tr, testDigest, 2); err != nil {
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
		if entry.LayerIndex != 2 {
			t.Errorf("expected layer index 2, got %d", entry.LayerIndex)
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
				"/bin":        symlink("/usr/bin"),
				"/usr/bin/sh": regularFile(),
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
			name: "chained symlinks",
			index: map[string]*FileEntry{
				"/bin":        symlink("/usr/bin"),
				"/usr/bin":    symlink("lib"),
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
			if cached, ok := r.symlinkCache[tc.input]; !ok || cached != tc.want {
				t.Errorf("cache miss or wrong value: %v %q", ok, cached)
			}
		})
	}
}

func TestFilesByPath_SkipsDirectories(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/etc":         {Path: "/etc", TypeFlag: tar.TypeDir, LayerIndex: unknownLayerIndex},
		"/etc/passwd":  {Path: "/etc/passwd", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
	})

	locs, err := r.FilesByPath("/etc", "/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 || locs[0].RealPath != "/etc/passwd" {
		t.Errorf("expected only /etc/passwd, got %v", locs)
	}
}

func TestFilesByGlob_SkipsSymlinkToDirectory(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/usr/lib": {Path: "/usr/lib", TypeFlag: tar.TypeDir, LayerIndex: unknownLayerIndex},
		"/lib":     symlink("/usr/lib"),
	})

	locs, err := r.FilesByGlob("/lib")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 0 {
		t.Errorf("expected no locations (symlink to directory), got %v", locs)
	}
}

func TestFilesByGlob_DedupeByResolvedPath(t *testing.T) {
	// Both /bin and /sbin are symlinks pointing at /usr/bin. A glob
	// matching both must return a single Location whose RealPath is the
	// resolved target — pinning the physical-file-dedupe semantic.
	r := newTestResolver(map[string]*FileEntry{
		"/usr/bin/ls": {Path: "/usr/bin/ls", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
		"/bin/ls":     symlink("/usr/bin/ls"),
		"/sbin/ls":    symlink("/usr/bin/ls"),
	})

	locs, err := r.FilesByGlob("/*bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 {
		t.Fatalf("expected 1 deduped location, got %d: %v", len(locs), locs)
	}
	if locs[0].RealPath != "/usr/bin/ls" {
		t.Errorf("expected RealPath=/usr/bin/ls (resolved), got %q", locs[0].RealPath)
	}
}

func TestFileMetadataByLocation_PreservesTypeBits(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/dir":  {Path: "/dir", TypeFlag: tar.TypeDir, Mode: fs.ModeDir | 0755, LayerIndex: unknownLayerIndex},
		"/link": {Path: "/link", TypeFlag: tar.TypeSymlink, Mode: fs.ModeSymlink | 0777, LinkTarget: "/dir", LayerIndex: unknownLayerIndex},
	})

	dirMeta, err := r.FileMetadataByLocation(syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/dir"}))
	if err != nil {
		t.Fatal(err)
	}
	if !dirMeta.Mode().IsDir() {
		t.Errorf("expected dir mode IsDir() true, got mode=%v", dirMeta.Mode())
	}

	linkMeta, err := r.FileMetadataByLocation(syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/link"}))
	if err != nil {
		t.Fatal(err)
	}
	if linkMeta.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("expected symlink mode bit set, got mode=%v", linkMeta.Mode())
	}
}

func TestRelativeFileByPath_RelativeResolution(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/etc/yum.repos.d/anchor": {Path: "/etc/yum.repos.d/anchor", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
		"/etc/yum.repos.d/sibling": {Path: "/etc/yum.repos.d/sibling", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
	})

	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/etc/yum.repos.d/anchor"})
	loc := r.RelativeFileByPath(anchor, "sibling")
	if loc == nil {
		t.Fatal("expected non-nil location for sibling")
	}
	if loc.RealPath != "/etc/yum.repos.d/sibling" {
		t.Errorf("got %q, want /etc/yum.repos.d/sibling", loc.RealPath)
	}
}

func TestRelativeFileByPath_AbsolutePathCleaning(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/a/c":     {Path: "/a/c", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
		"/anchor":  {Path: "/anchor", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
	})
	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/anchor"})

	loc := r.RelativeFileByPath(anchor, "/a//b/../c")
	if loc == nil {
		t.Fatal("expected non-nil location for cleaned absolute path")
	}
	if loc.RealPath != "/a/c" {
		t.Errorf("got %q, want /a/c", loc.RealPath)
	}
}

func TestRelativeFileByPath_SkipsDirectories(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/dir":    {Path: "/dir", TypeFlag: tar.TypeDir, LayerIndex: unknownLayerIndex},
		"/anchor": {Path: "/anchor", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
	})
	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/anchor"})

	if loc := r.RelativeFileByPath(anchor, "/dir"); loc != nil {
		t.Errorf("expected nil for directory, got %+v", loc)
	}
}

func TestRelativeFileByPath_LayerAccept(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/anchor": {Path: "/anchor", TypeFlag: tar.TypeReg, LayerIndex: 2},
		"/target": {Path: "/target", TypeFlag: tar.TypeReg, LayerIndex: 1},
	})
	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/anchor"})
	if loc := r.RelativeFileByPath(anchor, "/target"); loc == nil {
		t.Error("expected non-nil: target layer is lower than anchor")
	}
}

func TestRelativeFileByPath_LayerReject(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/anchor": {Path: "/anchor", TypeFlag: tar.TypeReg, LayerIndex: 1},
		"/target": {Path: "/target", TypeFlag: tar.TypeReg, LayerIndex: 2},
	})
	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/anchor"})
	if loc := r.RelativeFileByPath(anchor, "/target"); loc != nil {
		t.Errorf("expected nil: target layer is higher than anchor, got %+v", loc)
	}
}

func TestRelativeFileByPath_UnknownLayerOnAnchorBypassesFilter(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/anchor": {Path: "/anchor", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
		"/target": {Path: "/target", TypeFlag: tar.TypeReg, LayerIndex: 5},
	})
	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/anchor"})
	if loc := r.RelativeFileByPath(anchor, "/target"); loc == nil {
		t.Error("expected non-nil when anchor's layer is unknown")
	}
}

func TestRelativeFileByPath_UnknownLayerOnTargetBypassesFilter(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/anchor": {Path: "/anchor", TypeFlag: tar.TypeReg, LayerIndex: 1},
		"/target": {Path: "/target", TypeFlag: tar.TypeReg, LayerIndex: unknownLayerIndex},
	})
	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/anchor"})
	if loc := r.RelativeFileByPath(anchor, "/target"); loc == nil {
		t.Error("expected non-nil when target's layer is unknown")
	}
}

func TestRelativeFileByPath_OverwriteLimitation(t *testing.T) {
	// Documented limitation: the squashed fsIndex stores only the last
	// writer for each path. A file originally written at layer 0 and
	// overwritten at layer 2 is only present at the higher index.
	// An anchor at layer 1 cannot recover the lower-layer view and
	// therefore fails the layer filter even though Syft's "same layer
	// or lower" contract would expect it visible.
	r := newTestResolver(map[string]*FileEntry{
		"/anchor": {Path: "/anchor", TypeFlag: tar.TypeReg, LayerIndex: 1},
		"/target": {Path: "/target", TypeFlag: tar.TypeReg, LayerIndex: 2},
	})
	anchor := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/anchor"})
	if loc := r.RelativeFileByPath(anchor, "/target"); loc != nil {
		t.Errorf("documented squash approximation: expected nil, got %+v", loc)
	}
}

func TestCleanTarPath(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: "foo", want: "/foo"},
		{in: "/foo", want: "/foo"},
		{in: "foo/bar", want: "/foo/bar"},
		{in: "foo/", want: "/foo"},
		{in: "./foo", want: "/foo"},
		{in: "foo/./bar", want: "/foo/bar"},
		{in: "foo/bar/../baz", want: "/foo/baz"},
		{in: "/", want: "/"},
		{in: "", wantErr: "empty"},
		{in: "../escape", wantErr: "escapes root"},
		{in: "foo/../../escape", wantErr: "escapes root"},
		{in: "foo//bar", wantErr: "empty segment"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := cleanTarPath(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("cleanTarPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// --- Hard link tests ---

func TestProcessLayerTar_HardLinkSameLayer(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{})
	tr := buildTar(t, []tarEntry{
		{name: "src", typeflag: tar.TypeReg, content: "hello"},
		{name: "link", typeflag: tar.TypeLink, linkname: "src"},
	})
	if err := r.processLayerTar(tr, testDigest, 0); err != nil {
		t.Fatal(err)
	}
	link := r.fsIndex["/link"]
	if link == nil {
		t.Fatal("/link missing")
	}
	if link.ContentLayerDigest != testDigest {
		t.Errorf("ContentLayerDigest=%q, want %q", link.ContentLayerDigest, testDigest)
	}
	if link.ContentPath != "/src" {
		t.Errorf("ContentPath=%q, want /src", link.ContentPath)
	}
	if link.Size != 5 {
		t.Errorf("Size=%d, want 5 (target size)", link.Size)
	}
	if link.LinkTarget != "src" {
		t.Errorf("LinkTarget=%q, want raw \"src\"", link.LinkTarget)
	}
}

func TestProcessLayerTar_HardLinkLowerLayer(t *testing.T) {
	lower := digest.FromString("lower-layer")
	r := newTestResolver(map[string]*FileEntry{
		"/src": {
			Path: "/src", TypeFlag: tar.TypeReg,
			LayerDigest:        lower,
			ContentLayerDigest: lower,
			ContentPath:        "/src",
			Size:               42,
		},
	})
	tr := buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "src"},
	})
	if err := r.processLayerTar(tr, testDigest, 1); err != nil {
		t.Fatal(err)
	}
	link := r.fsIndex["/link"]
	if link == nil {
		t.Fatal("/link missing")
	}
	if link.ContentLayerDigest != lower {
		t.Errorf("ContentLayerDigest=%q, want %q", link.ContentLayerDigest, lower)
	}
	if link.ContentPath != "/src" {
		t.Errorf("ContentPath=%q, want /src", link.ContentPath)
	}
	if link.Size != 42 {
		t.Errorf("Size=%d, want 42 (target size)", link.Size)
	}
}

func TestProcessLayerTar_HardLinkSurvivesOverwrite(t *testing.T) {
	lower := digest.FromString("lower-layer")
	upper := digest.FromString("upper-layer")
	r := newTestResolver(map[string]*FileEntry{
		"/src": {
			Path: "/src", TypeFlag: tar.TypeReg,
			LayerDigest:        lower,
			ContentLayerDigest: lower,
			ContentPath:        "/src",
		},
	})
	// Mid layer adds the hard link.
	if err := r.processLayerTar(buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "src"},
	}), digest.FromString("mid-layer"), 1); err != nil {
		t.Fatal(err)
	}
	// Upper layer overwrites /src.
	if err := r.processLayerTar(buildTar(t, []tarEntry{
		{name: "src", typeflag: tar.TypeReg, content: "new"},
	}), upper, 2); err != nil {
		t.Fatal(err)
	}
	link := r.fsIndex["/link"]
	if link == nil {
		t.Fatal("/link missing")
	}
	if link.ContentLayerDigest != lower {
		t.Errorf("ContentLayerDigest=%q, want %q (link must keep layer-of-creation content)", link.ContentLayerDigest, lower)
	}
	// /src in the squashed index should now point at the upper layer.
	if got := r.fsIndex["/src"].ContentLayerDigest; got != upper {
		t.Errorf("/src ContentLayerDigest=%q, want %q", got, upper)
	}
}

func TestProcessLayerTar_HardLinkSurvivesWhiteout(t *testing.T) {
	lower := digest.FromString("lower-layer")
	r := newTestResolver(map[string]*FileEntry{
		"/src": {
			Path: "/src", TypeFlag: tar.TypeReg,
			LayerDigest:        lower,
			ContentLayerDigest: lower,
			ContentPath:        "/src",
		},
	})
	if err := r.processLayerTar(buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "src"},
	}), digest.FromString("mid"), 1); err != nil {
		t.Fatal(err)
	}
	// Upper layer whiteouts /src.
	if err := r.processLayerTar(buildTar(t, []tarEntry{
		{name: ".wh.src", typeflag: tar.TypeReg},
	}), digest.FromString("upper"), 2); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.fsIndex["/src"]; ok {
		t.Error("/src should be whiteouted from squashed view")
	}
	link := r.fsIndex["/link"]
	if link == nil {
		t.Fatal("/link missing")
	}
	if link.ContentLayerDigest != lower || link.ContentPath != "/src" {
		t.Errorf("link content=(%q,%q), want (%q,/src)", link.ContentLayerDigest, link.ContentPath, lower)
	}
}

func TestProcessLayerTar_HardLinkSurvivesOpaqueWhiteout(t *testing.T) {
	lower := digest.FromString("lower-layer")
	r := newTestResolver(map[string]*FileEntry{
		"/dir":     {Path: "/dir", TypeFlag: tar.TypeDir, LayerDigest: lower},
		"/dir/src": {Path: "/dir/src", TypeFlag: tar.TypeReg, LayerDigest: lower, ContentLayerDigest: lower, ContentPath: "/dir/src"},
	})
	if err := r.processLayerTar(buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "dir/src"},
	}), digest.FromString("mid"), 1); err != nil {
		t.Fatal(err)
	}
	// Upper layer opaque-whiteouts /dir.
	if err := r.processLayerTar(buildTar(t, []tarEntry{
		{name: "dir/", typeflag: tar.TypeDir},
		{name: "dir/.wh..wh..opq", typeflag: tar.TypeReg},
	}), digest.FromString("upper"), 2); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.fsIndex["/dir/src"]; ok {
		t.Error("/dir/src should be opaque-whiteouted")
	}
	link := r.fsIndex["/link"]
	if link == nil {
		t.Fatal("/link missing")
	}
	if link.ContentLayerDigest != lower || link.ContentPath != "/dir/src" {
		t.Errorf("link content=(%q,%q), want (%q,/dir/src)", link.ContentLayerDigest, link.ContentPath, lower)
	}
}

func TestProcessLayerTar_HardLinkSameLayerWhiteout(t *testing.T) {
	// Pins the resolver's chosen model for 2e: a layer that both
	// whiteouts /a and hard-links /b -> /a serves the lower-layer
	// bytes through /b.
	lower := digest.FromString("lower-layer")
	r := newTestResolver(map[string]*FileEntry{
		"/a": {
			Path: "/a", TypeFlag: tar.TypeReg,
			LayerDigest:        lower,
			ContentLayerDigest: lower,
			ContentPath:        "/a",
			Size:               9,
		},
	})
	tr := buildTar(t, []tarEntry{
		{name: ".wh.a", typeflag: tar.TypeReg},
		{name: "b", typeflag: tar.TypeLink, linkname: "a"},
	})
	if err := r.processLayerTar(tr, digest.FromString("mid"), 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.fsIndex["/a"]; ok {
		t.Error("/a should be whiteouted")
	}
	link := r.fsIndex["/b"]
	if link == nil {
		t.Fatal("/b missing")
	}
	if link.ContentLayerDigest != lower || link.ContentPath != "/a" {
		t.Errorf("link content=(%q,%q), want (%q,/a)", link.ContentLayerDigest, link.ContentPath, lower)
	}
	if link.Size != 9 {
		t.Errorf("Size=%d, want 9 (target's size)", link.Size)
	}
}

func TestProcessLayerTar_HardLinkChain(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{})
	tr := buildTar(t, []tarEntry{
		{name: "src", typeflag: tar.TypeReg, content: "data"},
		{name: "link1", typeflag: tar.TypeLink, linkname: "src"},
		{name: "link2", typeflag: tar.TypeLink, linkname: "link1"},
	})
	if err := r.processLayerTar(tr, testDigest, 0); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/link1", "/link2"} {
		e := r.fsIndex[p]
		if e == nil {
			t.Fatalf("%s missing", p)
		}
		if e.ContentLayerDigest != testDigest || e.ContentPath != "/src" {
			t.Errorf("%s content=(%q,%q), want (%q,/src)", p, e.ContentLayerDigest, e.ContentPath, testDigest)
		}
	}
}

func TestProcessLayerTar_TypeRegAAsContentAndAsLinkTarget(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{})
	tr := buildTar(t, []tarEntry{
		{name: "src", typeflag: tar.TypeRegA, content: "hello"},
		{name: "link", typeflag: tar.TypeLink, linkname: "src"},
	})
	if err := r.processLayerTar(tr, testDigest, 0); err != nil {
		t.Fatal(err)
	}
	src := r.fsIndex["/src"]
	if src == nil || src.ContentLayerDigest != testDigest || src.ContentPath != "/src" {
		t.Errorf("src content coords not populated: %+v", src)
	}
	link := r.fsIndex["/link"]
	if link == nil || link.ContentPath != "/src" {
		t.Errorf("link to TypeRegA not resolved: %+v", link)
	}
}

func TestProcessLayerTar_BrokenHardLink(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{})
	tr := buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "nonexistent"},
	})
	err := r.processLayerTar(tr, testDigest, 0)
	if err == nil || !strings.Contains(err.Error(), "broken hard link") {
		t.Fatalf("expected broken-hard-link error, got %v", err)
	}
}

func TestProcessLayerTar_EmptyHardLinkTarget(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{})
	tr := buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: ""},
	})
	err := r.processLayerTar(tr, testDigest, 0)
	if err == nil || !strings.Contains(err.Error(), "empty target") {
		t.Fatalf("expected empty-target error, got %v", err)
	}
}

func TestProcessLayerTar_DirectoryHardLinkTarget(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/dir": {Path: "/dir", TypeFlag: tar.TypeDir},
	})
	tr := buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "dir"},
	})
	err := r.processLayerTar(tr, testDigest, 0)
	if err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("expected directory-target error, got %v", err)
	}
}

func TestProcessLayerTar_UnsupportedHardLinkTargetType(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/sym": symlink("/anywhere"),
	})
	tr := buildTar(t, []tarEntry{
		{name: "link", typeflag: tar.TypeLink, linkname: "sym"},
	})
	err := r.processLayerTar(tr, testDigest, 0)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported-target-type error, got %v", err)
	}
}

func TestProcessLayerTar_ValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
		wantSub string
	}{
		{
			name:    "escape in entry name",
			entries: []tarEntry{{name: "../escape", typeflag: tar.TypeReg}},
			wantSub: "escapes root",
		},
		{
			name: "escape in hard link target",
			entries: []tarEntry{
				{name: "src", typeflag: tar.TypeReg, content: "x"},
				{name: "link", typeflag: tar.TypeLink, linkname: "../escape"},
			},
			wantSub: "escapes root",
		},
		{
			name:    "escape in whiteout dir",
			entries: []tarEntry{{name: "../bad/.wh.victim", typeflag: tar.TypeReg}},
			wantSub: "escapes root",
		},
		{
			name:    "escape in opaque whiteout dir",
			entries: []tarEntry{{name: "../bad/.wh..wh..opq", typeflag: tar.TypeReg}},
			wantSub: "escapes root",
		},
		{
			name:    "empty whiteout basename",
			entries: []tarEntry{{name: ".wh.", typeflag: tar.TypeReg}},
			wantSub: "empty basename",
		},
		{
			name: "duplicate path in single layer",
			entries: []tarEntry{
				{name: "foo", typeflag: tar.TypeReg, content: "a"},
				{name: "foo", typeflag: tar.TypeReg, content: "b"},
			},
			wantSub: "duplicate path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestResolver(map[string]*FileEntry{})
			err := r.processLayerTar(buildTar(t, tc.entries), testDigest, 0)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

// --- FilesByGlob determinism + hard-link dedup ---

func TestFilesByGlob_Deterministic(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/usr/bin/ls": {Path: "/usr/bin/ls", TypeFlag: tar.TypeReg, ContentLayerDigest: testDigest, ContentPath: "/usr/bin/ls"},
		"/bin/ls":     symlink("/usr/bin/ls"),
		"/sbin/ls":    symlink("/usr/bin/ls"),
		"/etc/hosts":  {Path: "/etc/hosts", TypeFlag: tar.TypeReg, ContentLayerDigest: testDigest, ContentPath: "/etc/hosts"},
	})
	first, err := r.FilesByGlob("/*bin/ls", "/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.FilesByGlob("/*bin/ls", "/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic result:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestFilesByGlob_PatternOrderIndependent(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/usr/bin/ls": {Path: "/usr/bin/ls", TypeFlag: tar.TypeReg, ContentLayerDigest: testDigest, ContentPath: "/usr/bin/ls"},
		"/etc/hosts":  {Path: "/etc/hosts", TypeFlag: tar.TypeReg, ContentLayerDigest: testDigest, ContentPath: "/etc/hosts"},
	})
	a, _ := r.FilesByGlob("/usr/bin/ls", "/etc/hosts")
	b, _ := r.FilesByGlob("/etc/hosts", "/usr/bin/ls")
	if !reflect.DeepEqual(a, b) {
		t.Errorf("pattern-order sensitive:\na=%+v\nb=%+v", a, b)
	}
}

func TestFilesByGlob_HardLinkDedupRpmDB(t *testing.T) {
	contentDigest := testDigest
	contentPath := "/usr/lib/sysimage/rpm/rpmdb.sqlite"
	r := newTestResolver(map[string]*FileEntry{
		contentPath: {
			Path: contentPath, TypeFlag: tar.TypeReg,
			LayerDigest: contentDigest, ContentLayerDigest: contentDigest, ContentPath: contentPath,
		},
		"/var/lib/rpm/rpmdb.sqlite": {
			Path: "/var/lib/rpm/rpmdb.sqlite", TypeFlag: tar.TypeLink,
			LayerDigest: contentDigest, ContentLayerDigest: contentDigest, ContentPath: contentPath,
			LinkTarget: contentPath,
		},
	})
	locs, err := r.FilesByGlob("**/rpmdb.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 {
		t.Fatalf("expected 1 deduped location, got %d: %+v", len(locs), locs)
	}
	if locs[0].RealPath != contentPath {
		t.Errorf("RealPath=%q, want %q (lex smallest alias)", locs[0].RealPath, contentPath)
	}
	if locs[0].FileSystemID != contentDigest.String() {
		t.Errorf("FileSystemID=%q, want %q", locs[0].FileSystemID, contentDigest)
	}
}

func TestFilesByGlob_SymlinkToHardLink(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/sym": symlink("/hardlink"),
		"/hardlink": {
			Path: "/hardlink", TypeFlag: tar.TypeLink,
			LayerDigest: testDigest, ContentLayerDigest: testDigest, ContentPath: "/regular",
			LinkTarget: "/regular",
		},
		"/regular": {
			Path: "/regular", TypeFlag: tar.TypeReg,
			LayerDigest: testDigest, ContentLayerDigest: testDigest, ContentPath: "/regular",
		},
	})
	locs, err := r.FilesByGlob("/sym")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 {
		t.Fatalf("expected 1 location, got %d: %+v", len(locs), locs)
	}
	// Aliases of /regular's content coords are /hardlink and /regular.
	// Lex smallest = /hardlink.
	if locs[0].RealPath != "/hardlink" {
		t.Errorf("RealPath=%q, want /hardlink (lex smallest alias)", locs[0].RealPath)
	}
	if locs[0].AccessPath != "/sym" {
		t.Errorf("AccessPath=%q, want /sym", locs[0].AccessPath)
	}
}

// --- Read path with openBlob fake ---

func TestFileContentsByLocation_HardLinkOpensContentDigest(t *testing.T) {
	contentLayer := digest.FromString("content-layer")
	linkLayer := digest.FromString("link-layer")
	contentBytes := buildTarBytes(t, []tarEntry{
		{name: "src", typeflag: tar.TypeReg, content: "hello"},
	})

	var requested []digest.Digest
	r := newTestResolver(map[string]*FileEntry{
		"/src": {
			Path: "/src", TypeFlag: tar.TypeReg,
			LayerDigest: contentLayer, ContentLayerDigest: contentLayer, ContentPath: "/src", Size: 5,
		},
		"/link": {
			Path: "/link", TypeFlag: tar.TypeLink,
			LayerDigest: linkLayer, ContentLayerDigest: contentLayer, ContentPath: "/src", Size: 5,
			LinkTarget: "/src",
		},
	})
	r.openBlob = func(_ context.Context, d digest.Digest) (io.ReadCloser, error) {
		requested = append(requested, d)
		if d == contentLayer {
			return io.NopCloser(bytes.NewReader(contentBytes)), nil
		}
		return nil, errors.New("unexpected digest: " + d.String())
	}

	loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/link"})
	rc, err := r.FileContentsByLocation(loc)
	if err != nil {
		t.Fatalf("FileContentsByLocation: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("read %q, want %q", got, "hello")
	}

	if len(requested) != 1 || requested[0] != contentLayer {
		t.Errorf("requested digests=%v, want exactly [%s]", requested, contentLayer)
	}
}

func TestFileContentsByLocation_OpenBlobErrorNoLeak(t *testing.T) {
	r := newTestResolver(map[string]*FileEntry{
		"/x": {
			Path: "/x", TypeFlag: tar.TypeReg,
			LayerDigest: testDigest, ContentLayerDigest: testDigest, ContentPath: "/x",
		},
	})
	r.openBlob = func(_ context.Context, _ digest.Digest) (io.ReadCloser, error) {
		return nil, errors.New("simulated blob failure")
	}
	loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/x"})
	rc, err := r.FileContentsByLocation(loc)
	if err == nil {
		rc.Close()
		t.Fatal("expected error, got nil")
	}
	if rc != nil {
		t.Errorf("expected nil ReadCloser on error, got %T", rc)
	}
}

// trackingCloser counts Close() invocations so tests can confirm no leak.
type trackingCloser struct {
	io.Reader
	closed *int
}

func (t *trackingCloser) Close() error {
	*t.closed++
	return nil
}

func TestFileContentsByLocation_TargetMissingInTarClosesBlob(t *testing.T) {
	// openBlob returns a tar that does NOT contain the requested target.
	// readFromLayer must close the blob before returning the error.
	emptyTar := buildTarBytes(t, []tarEntry{
		{name: "other", typeflag: tar.TypeReg, content: "x"},
	})
	closed := 0
	r := newTestResolver(map[string]*FileEntry{
		"/missing": {
			Path: "/missing", TypeFlag: tar.TypeReg,
			LayerDigest: testDigest, ContentLayerDigest: testDigest, ContentPath: "/missing",
		},
	})
	r.openBlob = func(_ context.Context, _ digest.Digest) (io.ReadCloser, error) {
		return &trackingCloser{Reader: bytes.NewReader(emptyTar), closed: &closed}, nil
	}
	loc := syftFile.NewLocationFromCoordinates(syftFile.Coordinates{RealPath: "/missing"})
	if _, err := r.FileContentsByLocation(loc); err == nil {
		t.Fatal("expected error when target missing in tar")
	}
	if closed != 1 {
		t.Errorf("blob closed %d times, want 1", closed)
	}
}
