//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"go.podman.io/image/v5/types"
	"go.podman.io/storage/pkg/reexec"
	"go.podman.io/storage/pkg/unshare"

	skiff "github.com/dcermak/skiff/pkg"
)

func TestMain(m *testing.M) {
	if reexec.Init() {
		return
	}
	unshare.MaybeReexecUsingUserNamespace(true)
	os.Exit(m.Run())
}

// TestCatalogRpms_LeapBDB exercises catalogRpms against the Leap-based
// local test image, which stores its rpmdb in BerkeleyDB format.
func TestCatalogRpms_LeapBDB(t *testing.T) {
	uri := "localhost/skiff-test-image:latest"
	ctx := context.Background()
	sysCtx := &types.SystemContext{}

	img, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		t.Skipf("Skipping: test image %s not available locally (build via `make test-image`): %v", uri, err)
	}
	img.Close()

	pkgs, err := catalogRpms(ctx, uri, sysCtx)
	if err != nil {
		t.Fatalf("catalogRpms failed: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("expected catalogRpms to return at least one package")
	}

	var rpmCount int
	var sawVimSmall bool
	for _, p := range pkgs {
		if p.Type == pkg.RpmPkg {
			rpmCount++
		}
		if p.Name == "vim-small" {
			sawVimSmall = true
		}
	}
	if rpmCount == 0 {
		t.Errorf("expected at least one pkg.RpmPkg entry, got %d packages with no RPM type", len(pkgs))
	}
	if !sawVimSmall {
		t.Error("expected vim-small (installed by TestImage.containerfile) to be present")
	}
}

// TestCatalogRpms_FedoraSQLiteDiff exercises catalogRpms against a Fedora-based
// image whose rpmdb is in SQLite format. This is the regression guard for the
// "sql: unknown driver \"sqlite\"" failure: without the modernc.org/sqlite
// blank import, both catalogRpms calls would error out.
//
// The old image is pinned to the same Fedora digest as
// pkg/TestImageFedora.containerfile so the "old" and "new" sides agree on
// baseline package set. The new image adds `tree` on top.
func TestCatalogRpms_FedoraSQLiteDiff(t *testing.T) {
	oldURI := "docker://registry.fedoraproject.org/fedora:44@sha256:0c6072366ebf8ea1c8c0f3a118aad3e9a9247d3065d499e54d62968f69351966"
	newURI := "localhost/skiff-test-image-fedora:latest"

	ctx := context.Background()
	sysCtx := &types.SystemContext{}

	oldImg, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, oldURI)
	if err != nil {
		t.Skipf("Skipping: unable to fetch %s (network/auth issue?): %v", oldURI, err)
	}
	oldImg.Close()

	newImg, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, newURI)
	if err != nil {
		t.Skipf("Skipping: test image %s not available locally (build via `make test-image-fedora`): %v", newURI, err)
	}
	newImg.Close()

	oldPkgs, err := catalogRpms(ctx, oldURI, sysCtx)
	if err != nil {
		t.Fatalf("catalogRpms(%s) failed: %v", oldURI, err)
	}
	if len(oldPkgs) == 0 {
		t.Fatalf("catalogRpms(%s) returned no packages; SQLite driver may not be registered", oldURI)
	}

	newPkgs, err := catalogRpms(ctx, newURI, sysCtx)
	if err != nil {
		t.Fatalf("catalogRpms(%s) failed: %v", newURI, err)
	}
	if len(newPkgs) == 0 {
		t.Fatalf("catalogRpms(%s) returned no packages; SQLite driver may not be registered", newURI)
	}

	// Regression guard for hard-link dedup: rpmdb is hard-linked at
	// both /var/lib/rpm/rpmdb.sqlite and /usr/lib/sysimage/rpm/rpmdb.sqlite
	// on modern Fedora. Before the dedup fix, both aliases were
	// catalogued and every package appeared twice in the package list.
	assertNoDuplicateRows(t, "old", oldPkgs)
	assertNoDuplicateRows(t, "new", newPkgs)

	result := skiff.DiffPackages(oldPkgs, newPkgs)

	if !containsName(result.Added, "tree") {
		t.Errorf("expected tree to be in Added, got Added=%s", diffNames(result.Added))
	}

	for _, baseline := range []string{"bash", "glibc"} {
		if containsName(result.Added, baseline) {
			t.Errorf("expected %s to be Unchanged (present in both images), but it appears in Added", baseline)
		}
		if containsName(result.Removed, baseline) {
			t.Errorf("expected %s to be Unchanged (present in both images), but it appears in Removed", baseline)
		}
	}
}

func assertNoDuplicateRows(t *testing.T, side string, pkgs []pkg.Package) {
	t.Helper()
	seen := make(map[string]struct{})
	for _, p := range pkgs {
		if p.Type != pkg.RpmPkg {
			continue
		}
		key := p.Name + "|" + p.Version + "|" + rpmArchFromPkg(p)
		if _, dup := seen[key]; dup {
			t.Errorf("%s side: duplicate (name,version,arch) row: %s", side, key)
		}
		seen[key] = struct{}{}
	}
}

func rpmArchFromPkg(p pkg.Package) string {
	switch m := p.Metadata.(type) {
	case pkg.RpmDBEntry:
		return m.Arch
	case pkg.RpmArchive:
		return m.Arch
	}
	return ""
}

func containsName(diffs []skiff.PackageDiff, name string) bool {
	for _, d := range diffs {
		if d.Identity.Name == name {
			return true
		}
	}
	return false
}

func diffNames(diffs []skiff.PackageDiff) []string {
	names := make([]string, len(diffs))
	for i, d := range diffs {
		names[i] = d.Identity.Name
	}
	return names
}
