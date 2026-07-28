package skiff

import (
	"strconv"
	"strings"
	"testing"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

func mkPkg(name, version string, pkgType pkg.Type) pkg.Package {
	return pkg.Package{Name: name, Version: version, Type: pkgType}
}

func mkRpmPkg(name, version string, size int) pkg.Package {
	p := mkPkg(name, version, pkg.RpmPkg)
	p.Metadata = pkg.RpmDBEntry{Size: size}
	return p
}

func mkPkgWithLicense(name, version string, pkgType pkg.Type, licenses ...string) pkg.Package {
	p := mkPkg(name, version, pkgType)
	p.Licenses = pkg.NewLicenseSet(pkg.NewLicensesFromValues(licenses...)...)
	return p
}

// mkRpmPurlPkg builds a Syft-style RPM Package with both metadata and PURL,
// mirroring how the redhat cataloger populates packages.
func mkRpmPurlPkg(name, version, release, arch, distro, upstream string, epoch *int) pkg.Package {
	purlVersion := version + "-" + release
	qualifiers := map[string]string{}
	if arch != "" {
		qualifiers["arch"] = arch
	}
	if distro != "" {
		qualifiers["distro"] = distro
	}
	if upstream != "" {
		qualifiers["upstream"] = upstream
	}
	if epoch != nil {
		qualifiers["epoch"] = strconv.Itoa(*epoch)
	}
	purl := packageurl.NewPackageURL(
		packageurl.TypeRPM,
		"opensuse",
		name,
		purlVersion,
		packageurl.QualifiersFromMap(qualifiers),
		"",
	).ToString()

	pkgVersion := version + "-" + release
	if epoch != nil {
		pkgVersion = strconv.Itoa(*epoch) + ":" + pkgVersion
	}

	return pkg.Package{
		Name:    name,
		Version: pkgVersion,
		Type:    pkg.RpmPkg,
		PURL:    purl,
		Metadata: pkg.RpmDBEntry{
			Name:    name,
			Version: version,
			Release: release,
			Arch:    arch,
			Epoch:   epoch,
		},
	}
}

func intPtr(n int) *int { return &n }

func TestDiffPackages_BasicAddRemoveModifyUnchanged(t *testing.T) {
	oldPkgs := []pkg.Package{
		mkPkg("glibc", "2.34", pkg.RpmPkg),
		mkPkg("bash", "5.1", pkg.RpmPkg),
		mkPkg("curl", "7.80", pkg.RpmPkg),
	}
	newPkgs := []pkg.Package{
		mkPkg("bash", "5.2", pkg.RpmPkg),
		mkPkg("curl", "7.80", pkg.RpmPkg),
		mkPkg("vim", "9.0", pkg.RpmPkg),
	}

	result := DiffPackages(oldPkgs, newPkgs)

	if len(result.Removed) != 1 || result.Removed[0].Identity.Name != "glibc" {
		t.Errorf("expected glibc removed, got removed=%v", result.Removed)
	}
	if len(result.Added) != 1 || result.Added[0].Identity.Name != "vim" {
		t.Errorf("expected vim added, got added=%v", result.Added)
	}
	if len(result.Modified) != 1 || result.Modified[0].Identity.Name != "bash" {
		t.Errorf("expected bash modified, got modified=%v", result.Modified)
	}
	if !hasFieldChange(result.Modified[0].Changes, FieldVersion, "5.1", "5.2") {
		t.Errorf("expected version change 5.1->5.2 on bash, got %v", result.Modified[0].Changes)
	}
	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged (curl), got %d", result.Unchanged)
	}
}

func TestDiffPackages_VersionBumpSameDistro_IsModified(t *testing.T) {
	// Regression guard: this test only passes once the `upstream` PURL
	// qualifier is dropped from identity. A real RPM upgrade changes both
	// the package version AND the upstream (source-RPM filename).
	oldPkg := mkRpmPurlPkg("glibc", "2.34", "150500.1.10", "x86_64", "opensuse-15.6", "glibc-2.34-150500.1.10.src.rpm", intPtr(0))
	newPkg := mkRpmPurlPkg("glibc", "2.35", "150500.2.1", "x86_64", "opensuse-15.6", "glibc-2.35-150500.2.1.src.rpm", intPtr(0))

	result := DiffPackages([]pkg.Package{oldPkg}, []pkg.Package{newPkg})

	if len(result.Modified) != 1 {
		t.Fatalf("expected glibc Modified, got added=%d removed=%d modified=%d",
			len(result.Added), len(result.Removed), len(result.Modified))
	}
	if !hasFieldChange(result.Modified[0].Changes, FieldVersion, "0:2.34-150500.1.10", "0:2.35-150500.2.1") {
		t.Errorf("expected version FieldChange, got %v", result.Modified[0].Changes)
	}
}

func TestDiffPackages_EpochAndVersionBump_SingleVersionChange(t *testing.T) {
	oldPkg := mkRpmPurlPkg("kernel", "5.14", "1", "x86_64", "opensuse-15.6", "", intPtr(0))
	newPkg := mkRpmPurlPkg("kernel", "6.4", "1", "x86_64", "opensuse-15.6", "", intPtr(1))

	result := DiffPackages([]pkg.Package{oldPkg}, []pkg.Package{newPkg})

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(result.Modified))
	}
	for _, c := range result.Modified[0].Changes {
		if c.Field == FieldEpoch {
			t.Errorf("epoch change must not be emitted when version also changes, got %v", result.Modified[0].Changes)
		}
	}
	if !hasFieldChange(result.Modified[0].Changes, FieldVersion, "0:5.14-1", "1:6.4-1") {
		t.Errorf("expected version change, got %v", result.Modified[0].Changes)
	}
}

func TestDiffPackages_EpochOnlyBump(t *testing.T) {
	// Same name+version-release but epoch differs; pkg.Version is derived
	// from epoch:version-release so they will differ — but for this test
	// we construct two packages with identical pkg.Version where only
	// metadata epoch differs, exercising the epoch-fallback path.
	oldP := pkg.Package{
		Name:    "foo",
		Version: "1.0-1",
		Type:    pkg.RpmPkg,
		PURL: packageurl.NewPackageURL("rpm", "opensuse", "foo", "1.0-1",
			packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "distro": "opensuse-15.6", "epoch": "0"}), "").ToString(),
		Metadata: pkg.RpmDBEntry{Name: "foo", Version: "1.0", Release: "1", Arch: "x86_64", Epoch: intPtr(0)},
	}
	newP := pkg.Package{
		Name:    "foo",
		Version: "1.0-1",
		Type:    pkg.RpmPkg,
		PURL: packageurl.NewPackageURL("rpm", "opensuse", "foo", "1.0-1",
			packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "distro": "opensuse-15.6", "epoch": "1"}), "").ToString(),
		Metadata: pkg.RpmDBEntry{Name: "foo", Version: "1.0", Release: "1", Arch: "x86_64", Epoch: intPtr(1)},
	}

	result := DiffPackages([]pkg.Package{oldP}, []pkg.Package{newP})

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got added=%d removed=%d modified=%d",
			len(result.Added), len(result.Removed), len(result.Modified))
	}
	if !hasFieldChange(result.Modified[0].Changes, FieldEpoch, "0", "1") {
		t.Errorf("expected epoch change 0->1, got %v", result.Modified[0].Changes)
	}
}

func TestDiffPackages_ArchChange_IsRemovedAndAdded(t *testing.T) {
	oldPkg := mkRpmPurlPkg("glibc", "2.34", "1", "x86_64", "opensuse-15.6", "", nil)
	newPkg := mkRpmPurlPkg("glibc", "2.34", "1", "aarch64", "opensuse-15.6", "", nil)

	result := DiffPackages([]pkg.Package{oldPkg}, []pkg.Package{newPkg})

	if len(result.Removed) != 1 || len(result.Added) != 1 {
		t.Fatalf("expected 1 removed + 1 added, got removed=%d added=%d modified=%d",
			len(result.Removed), len(result.Added), len(result.Modified))
	}
	if result.Removed[0].Identity.Arch != "x86_64" {
		t.Errorf("removed arch=%q, want x86_64", result.Removed[0].Identity.Arch)
	}
	if result.Added[0].Identity.Arch != "aarch64" {
		t.Errorf("added arch=%q, want aarch64", result.Added[0].Identity.Arch)
	}
}

func TestDiffPackages_DistroChange_IsRemovedAndAdded(t *testing.T) {
	oldPkg := mkRpmPurlPkg("glibc", "2.34", "1", "x86_64", "opensuse-15.6", "", nil)
	newPkg := mkRpmPurlPkg("glibc", "2.34", "1", "x86_64", "opensuse-16.0", "", nil)

	result := DiffPackages([]pkg.Package{oldPkg}, []pkg.Package{newPkg})

	if len(result.Removed) != 1 || len(result.Added) != 1 {
		t.Fatalf("expected 1 removed + 1 added, got removed=%d added=%d modified=%d",
			len(result.Removed), len(result.Added), len(result.Modified))
	}
	if result.Removed[0].Identity.Distro != "opensuse-15.6" {
		t.Errorf("removed distro=%q, want opensuse-15.6", result.Removed[0].Identity.Distro)
	}
	if result.Added[0].Identity.Distro != "opensuse-16.0" {
		t.Errorf("added distro=%q, want opensuse-16.0", result.Added[0].Identity.Distro)
	}
}

func TestDiffPackages_NamespaceChange_IsRemovedAndAdded(t *testing.T) {
	purl1 := packageurl.NewPackageURL("rpm", "opensuse", "foo", "1.0-1",
		packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64"}), "").ToString()
	purl2 := packageurl.NewPackageURL("rpm", "redhat", "foo", "1.0-1",
		packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64"}), "").ToString()
	oldP := pkg.Package{Name: "foo", Version: "1.0-1", Type: pkg.RpmPkg, PURL: purl1,
		Metadata: pkg.RpmDBEntry{Arch: "x86_64"}}
	newP := pkg.Package{Name: "foo", Version: "1.0-1", Type: pkg.RpmPkg, PURL: purl2,
		Metadata: pkg.RpmDBEntry{Arch: "x86_64"}}

	result := DiffPackages([]pkg.Package{oldP}, []pkg.Package{newP})

	if len(result.Removed) != 1 || len(result.Added) != 1 {
		t.Fatalf("expected 1 removed + 1 added, got removed=%d added=%d",
			len(result.Removed), len(result.Added))
	}
	if result.Removed[0].Identity.Namespace != "opensuse" {
		t.Errorf("removed namespace=%q, want opensuse", result.Removed[0].Identity.Namespace)
	}
	if result.Added[0].Identity.Namespace != "redhat" {
		t.Errorf("added namespace=%q, want redhat", result.Added[0].Identity.Namespace)
	}
}

func TestDiffPackages_UpstreamOnlyChange_IsUnchanged(t *testing.T) {
	// Upstream is identity-neutral and not a tracked change field.
	oldPkg := mkRpmPurlPkg("foo", "1.0", "1", "x86_64", "opensuse-15.6", "foo-old.src.rpm", nil)
	newPkg := mkRpmPurlPkg("foo", "1.0", "1", "x86_64", "opensuse-15.6", "foo-new.src.rpm", nil)

	result := DiffPackages([]pkg.Package{oldPkg}, []pkg.Package{newPkg})

	if result.Unchanged != 1 || len(result.Modified) != 0 {
		t.Fatalf("expected upstream-only change to be Unchanged, got unchanged=%d modified=%d",
			result.Unchanged, len(result.Modified))
	}
}

func TestDiffPackages_UpstreamAndSizeChange_OnlySizeReported(t *testing.T) {
	oldPkg := mkRpmPurlPkg("foo", "1.0", "1", "x86_64", "opensuse-15.6", "foo-old.src.rpm", nil)
	oldPkg.Metadata = pkg.RpmDBEntry{Name: "foo", Version: "1.0", Release: "1", Arch: "x86_64", Size: 1000}
	newPkg := mkRpmPurlPkg("foo", "1.0", "1", "x86_64", "opensuse-15.6", "foo-new.src.rpm", nil)
	newPkg.Metadata = pkg.RpmDBEntry{Name: "foo", Version: "1.0", Release: "1", Arch: "x86_64", Size: 2000}

	result := DiffPackages([]pkg.Package{oldPkg}, []pkg.Package{newPkg})

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(result.Modified))
	}
	for _, c := range result.Modified[0].Changes {
		if c.Field == "upstream" {
			t.Errorf("upstream must not surface as FieldChange, got %v", result.Modified[0].Changes)
		}
	}
	if !hasFieldChange(result.Modified[0].Changes, FieldSize, "1000", "2000") {
		t.Errorf("expected size change, got %v", result.Modified[0].Changes)
	}
}

func TestDiffPackages_UnknownQualifier_IgnoredByIdentity(t *testing.T) {
	// Allowlist regression guard: a hypothetical future Syft qualifier
	// must not split a normal upgrade into Removed+Added.
	purl1 := packageurl.NewPackageURL("rpm", "opensuse", "foo", "1.0-1",
		packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "distro": "opensuse-15.6", "repository_id": "a"}), "").ToString()
	purl2 := packageurl.NewPackageURL("rpm", "opensuse", "foo", "1.0-1",
		packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "distro": "opensuse-15.6", "repository_id": "b"}), "").ToString()
	oldP := pkg.Package{Name: "foo", Version: "1.0-1", Type: pkg.RpmPkg, PURL: purl1,
		Metadata: pkg.RpmDBEntry{Arch: "x86_64"}}
	newP := pkg.Package{Name: "foo", Version: "1.0-1", Type: pkg.RpmPkg, PURL: purl2,
		Metadata: pkg.RpmDBEntry{Arch: "x86_64"}}

	result := DiffPackages([]pkg.Package{oldP}, []pkg.Package{newP})

	if result.Unchanged != 1 || len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Errorf("unknown qualifier must be ignored by identity, got added=%d removed=%d unchanged=%d",
			len(result.Added), len(result.Removed), result.Unchanged)
	}
}

func TestDiffPackages_MalformedPURL_UsesFallbackIdentity(t *testing.T) {
	p := pkg.Package{
		Name:     "foo",
		Version:  "1.0-1",
		Type:     pkg.RpmPkg,
		PURL:     "not-a-purl",
		Metadata: pkg.RpmDBEntry{Arch: "x86_64"},
	}
	id := rpmPackageIdentity(p)
	if !strings.HasPrefix(id, "fallback|") {
		t.Errorf("malformed PURL must produce fallback identity, got %q", id)
	}
	if !strings.Contains(id, "foo") || !strings.Contains(id, "x86_64") {
		t.Errorf("fallback identity should encode name and arch, got %q", id)
	}
}

func TestDiffPackages_MalformedCrossDistro_CollapseByDesign(t *testing.T) {
	// Documented degraded behavior: without a parseable PURL, the
	// fallback identity loses distro, so two malformed packages from
	// different distros collapse into one group.
	oldP := pkg.Package{
		Name: "foo", Version: "1.0-1", Type: pkg.RpmPkg,
		PURL:     "not-a-purl-leap-15",
		Metadata: pkg.RpmDBEntry{Arch: "x86_64"},
	}
	newP := pkg.Package{
		Name: "foo", Version: "1.0-1", Type: pkg.RpmPkg,
		PURL:     "not-a-purl-leap-16",
		Metadata: pkg.RpmDBEntry{Arch: "x86_64"},
	}
	result := DiffPackages([]pkg.Package{oldP}, []pkg.Package{newP})
	if result.Unchanged != 1 {
		t.Errorf("expected fallback to collapse into a single Unchanged group, got unchanged=%d added=%d removed=%d",
			result.Unchanged, len(result.Added), len(result.Removed))
	}
}

func TestPackageVersion_RpmDBEntryAndArchive_EquivalentVersions(t *testing.T) {
	// Verifies both RPM cataloger paths produce comparable pkg.Version
	// strings via Syft's toELVersion (vendor/.../redhat/parse_rpm_db.go).
	epoch := intPtr(1)
	dbVersion := "1:2.34-150500.1.10"

	dbPkg := pkg.Package{
		Name:    "glibc",
		Version: dbVersion,
		Type:    pkg.RpmPkg,
		PURL: packageurl.NewPackageURL("rpm", "opensuse", "glibc", "2.34-150500.1.10",
			packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "epoch": "1"}), "").ToString(),
		Metadata: pkg.RpmDBEntry{Name: "glibc", Version: "2.34", Release: "150500.1.10", Arch: "x86_64", Epoch: epoch},
	}
	archivePkg := pkg.Package{
		Name:    "glibc",
		Version: dbVersion,
		Type:    pkg.RpmPkg,
		PURL: packageurl.NewPackageURL("rpm", "opensuse", "glibc", "2.34-150500.1.10",
			packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "epoch": "1"}), "").ToString(),
		Metadata: pkg.RpmArchive{Name: "glibc", Version: "2.34", Release: "150500.1.10", Arch: "x86_64", Epoch: epoch},
	}

	// Bumped variant of each
	bumped := pkg.Package{
		Name:    "glibc",
		Version: "1:2.39-150500.1.10",
		Type:    pkg.RpmPkg,
		PURL: packageurl.NewPackageURL("rpm", "opensuse", "glibc", "2.39-150500.1.10",
			packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "epoch": "1"}), "").ToString(),
		Metadata: pkg.RpmDBEntry{Name: "glibc", Version: "2.39", Release: "150500.1.10", Arch: "x86_64", Epoch: epoch},
	}

	for _, base := range []pkg.Package{dbPkg, archivePkg} {
		result := DiffPackages([]pkg.Package{base}, []pkg.Package{bumped})
		if len(result.Modified) != 1 {
			t.Fatalf("expected 1 modified, got %d (base metadata type %T)", len(result.Modified), base.Metadata)
		}
		if !hasFieldChange(result.Modified[0].Changes, FieldVersion, dbVersion, "1:2.39-150500.1.10") {
			t.Errorf("expected version change for %T metadata, got %v", base.Metadata, result.Modified[0].Changes)
		}
	}
}

func TestRpmPackageIdentity_RawPurlReorderedQualifiers(t *testing.T) {
	a := pkg.Package{Type: pkg.RpmPkg, PURL: "pkg:rpm/opensuse/glibc@2.34-1?arch=x86_64&distro=opensuse-15.6"}
	b := pkg.Package{Type: pkg.RpmPkg, PURL: "pkg:rpm/opensuse/glibc@2.34-1?distro=opensuse-15.6&arch=x86_64"}
	if rpmPackageIdentity(a) != rpmPackageIdentity(b) {
		t.Errorf("reordered qualifiers must normalize to same identity:\n a=%q\n b=%q",
			rpmPackageIdentity(a), rpmPackageIdentity(b))
	}
}

func TestRpmPackageIdentity_RawPurlEncodedQualifiers(t *testing.T) {
	a := pkg.Package{Type: pkg.RpmPkg, PURL: "pkg:rpm/opensuse/glibc@2.34-1?arch=x86_64&distro=opensuse-15.6"}
	b := pkg.Package{Type: pkg.RpmPkg, PURL: "pkg:rpm/opensuse/glibc@2.34-1?arch=x86_64&distro=opensuse%2D15.6"}
	if rpmPackageIdentity(a) != rpmPackageIdentity(b) {
		t.Errorf("encoded qualifier values must match unencoded equivalents:\n a=%q\n b=%q",
			rpmPackageIdentity(a), rpmPackageIdentity(b))
	}
}

func TestDiffPackages_MultiVersion_InstancesChange(t *testing.T) {
	oldPkgs := []pkg.Package{
		mkRpmPurlPkg("kernel", "5.14", "1", "x86_64", "opensuse-15.6", "", nil),
		mkRpmPurlPkg("kernel", "6.4", "1", "x86_64", "opensuse-15.6", "", nil),
	}
	newPkgs := []pkg.Package{
		mkRpmPurlPkg("kernel", "6.4", "1", "x86_64", "opensuse-15.6", "", nil),
		mkRpmPurlPkg("kernel", "6.6", "1", "x86_64", "opensuse-15.6", "", nil),
	}

	result := DiffPackages(oldPkgs, newPkgs)

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(result.Modified))
	}
	want := []FieldChange{{Field: FieldInstances, Old: "5.14-1/x86_64,6.4-1/x86_64", New: "6.4-1/x86_64,6.6-1/x86_64"}}
	if len(result.Modified[0].Changes) != 1 ||
		result.Modified[0].Changes[0] != want[0] {
		t.Errorf("expected single instances change %v, got %v", want, result.Modified[0].Changes)
	}
}

func TestDiffPackages_MultiVersion_SameInstancesDifferentSize_Unchanged(t *testing.T) {
	// Documented limitation: multi-instance groups report version/arch
	// multiset membership only. Size drift inside the group is ignored.
	a := mkRpmPurlPkg("kernel", "5.14", "1", "x86_64", "opensuse-15.6", "", nil)
	a.Metadata = pkg.RpmDBEntry{Name: "kernel", Version: "5.14", Release: "1", Arch: "x86_64", Size: 1000}
	b := mkRpmPurlPkg("kernel", "6.4", "1", "x86_64", "opensuse-15.6", "", nil)
	b.Metadata = pkg.RpmDBEntry{Name: "kernel", Version: "6.4", Release: "1", Arch: "x86_64", Size: 2000}

	aPrime := mkRpmPurlPkg("kernel", "5.14", "1", "x86_64", "opensuse-15.6", "", nil)
	aPrime.Metadata = pkg.RpmDBEntry{Name: "kernel", Version: "5.14", Release: "1", Arch: "x86_64", Size: 9999}
	bSame := mkRpmPurlPkg("kernel", "6.4", "1", "x86_64", "opensuse-15.6", "", nil)
	bSame.Metadata = pkg.RpmDBEntry{Name: "kernel", Version: "6.4", Release: "1", Arch: "x86_64", Size: 2000}

	result := DiffPackages([]pkg.Package{a, b}, []pkg.Package{aPrime, bSame})
	if result.Unchanged != 1 || len(result.Modified) != 0 {
		t.Errorf("documented: multi-instance ignores size drift; got unchanged=%d modified=%d",
			result.Unchanged, len(result.Modified))
	}
}

func TestDiffPackages_MultiVersion_DuplicateBehaviorPinned(t *testing.T) {
	// Pinned: two identical canonical instances on the old side and one
	// on the new side produce a multiset-style diff (duplicates
	// preserved). If anything changes this to set semantics in the
	// future, this test will fail to surface the regression.
	dup := mkRpmPurlPkg("kernel", "5.14", "1", "x86_64", "opensuse-15.6", "", nil)
	dup2 := mkRpmPurlPkg("kernel", "5.14", "1", "x86_64", "opensuse-15.6", "", nil)
	single := mkRpmPurlPkg("kernel", "5.14", "1", "x86_64", "opensuse-15.6", "", nil)

	result := DiffPackages([]pkg.Package{dup, dup2}, []pkg.Package{single})

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(result.Modified))
	}
	want := FieldChange{Field: FieldInstances, Old: "5.14-1/x86_64,5.14-1/x86_64", New: "5.14-1/x86_64"}
	if len(result.Modified[0].Changes) != 1 || result.Modified[0].Changes[0] != want {
		t.Errorf("expected %v, got %v", want, result.Modified[0].Changes)
	}
}

func TestDiffPackages_SizeChange(t *testing.T) {
	oldPkgs := []pkg.Package{mkRpmPkg("glibc", "2.34", 1000)}
	newPkgs := []pkg.Package{mkRpmPkg("glibc", "2.34", 2000)}

	result := DiffPackages(oldPkgs, newPkgs)

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified (size change), got %d", len(result.Modified))
	}
	if !hasFieldChange(result.Modified[0].Changes, FieldSize, "1000", "2000") {
		t.Errorf("expected size change, got %v", result.Modified[0].Changes)
	}
}

func TestDiffPackages_LicenseChange(t *testing.T) {
	oldPkgs := []pkg.Package{mkPkgWithLicense("zlib", "1.2", pkg.RpmPkg, "MIT")}
	newPkgs := []pkg.Package{mkPkgWithLicense("zlib", "1.2", pkg.RpmPkg, "BSD-3-Clause")}

	result := DiffPackages(oldPkgs, newPkgs)

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified (license change), got %d", len(result.Modified))
	}
	found := false
	for _, c := range result.Modified[0].Changes {
		if c.Field == FieldLicense {
			found = true
		}
	}
	if !found {
		t.Errorf("expected license change, got %v", result.Modified[0].Changes)
	}
}

func TestDiffPackages_BothEmpty(t *testing.T) {
	result := DiffPackages(nil, nil)

	if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Modified) != 0 || result.Unchanged != 0 {
		t.Errorf("expected all-zero result for empty inputs, got added=%d removed=%d modified=%d unchanged=%d",
			len(result.Added), len(result.Removed), len(result.Modified), result.Unchanged)
	}
}

func TestDiffPackages_OldEmptyNewPopulated(t *testing.T) {
	newPkgs := []pkg.Package{
		mkPkg("bash", "5.1", pkg.RpmPkg),
		mkPkg("curl", "7.80", pkg.RpmPkg),
	}

	result := DiffPackages(nil, newPkgs)

	if len(result.Added) != 2 {
		t.Errorf("expected 2 added, got %d", len(result.Added))
	}
}

func TestDiffPackages_Identical(t *testing.T) {
	pkgs := []pkg.Package{
		mkRpmPkg("glibc", "2.34", 1000),
		mkRpmPkg("bash", "5.1", 500),
	}
	pkgsCopy := make([]pkg.Package, len(pkgs))
	copy(pkgsCopy, pkgs)

	result := DiffPackages(pkgs, pkgsCopy)

	if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Modified) != 0 {
		t.Errorf("expected no diffs for identical inputs, got added=%d removed=%d modified=%d",
			len(result.Added), len(result.Removed), len(result.Modified))
	}
	if result.Unchanged != 2 {
		t.Errorf("expected 2 unchanged, got %d", result.Unchanged)
	}
}

func TestDiffPackages_DifferentTypes(t *testing.T) {
	oldPkgs := []pkg.Package{mkPkg("requests", "2.28", pkg.PythonPkg)}
	newPkgs := []pkg.Package{mkPkg("requests", "2.28", pkg.NpmPkg)}

	result := DiffPackages(oldPkgs, newPkgs)

	if len(result.Removed) != 1 || result.Removed[0].Identity.Type != pkg.PythonPkg {
		t.Errorf("expected python requests removed, got removed=%v", result.Removed)
	}
	if len(result.Added) != 1 || result.Added[0].Identity.Type != pkg.NpmPkg {
		t.Errorf("expected npm requests added, got added=%v", result.Added)
	}
}

func TestPackageSize(t *testing.T) {
	tests := []struct {
		name     string
		metadata interface{}
		wantSize int
		wantOk   bool
	}{
		{"RpmDBEntry", pkg.RpmDBEntry{Size: 42000}, 42000, true},
		{"RpmArchive", pkg.RpmArchive{Size: 42000}, 42000, true},
		{"DpkgDBEntry", pkg.DpkgDBEntry{InstalledSize: 1500}, 1500, true},
		{"ApkDBEntry", pkg.ApkDBEntry{InstalledSize: 3000}, 3000, true},
		{"AlpmDBEntry", pkg.AlpmDBEntry{Size: 8000}, 8000, true},
		{"PortageEntry", pkg.PortageEntry{InstalledSize: 600}, 600, true},
		{"PythonPackage", pkg.PythonPackage{}, 0, false},
		{"nil metadata", nil, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{Metadata: tt.metadata}
			size, ok := PackageSize(p)
			if size != tt.wantSize || ok != tt.wantOk {
				t.Errorf("PackageSize() = (%d, %v), want (%d, %v)",
					size, ok, tt.wantSize, tt.wantOk)
			}
		})
	}
}

func TestSortDiffs_DeterministicTieBreaker(t *testing.T) {
	// Two diffs that differ only by the distro qualifier (and so only by
	// DiffKey) must sort deterministically across repeated calls.
	a := mkRpmPurlPkg("foo", "1.0", "1", "x86_64", "opensuse-15.6", "", nil)
	b := mkRpmPurlPkg("foo", "1.0", "1", "x86_64", "opensuse-16.0", "", nil)

	firstRun := DiffPackages([]pkg.Package{a, b}, nil)
	for i := 0; i < 10; i++ {
		again := DiffPackages([]pkg.Package{a, b}, nil)
		if len(again.Removed) != 2 {
			t.Fatalf("iter %d: expected 2 removed, got %d", i, len(again.Removed))
		}
		if again.Removed[0].Identity.DiffKey != firstRun.Removed[0].Identity.DiffKey {
			t.Errorf("iter %d: sort order changed (%q vs %q)",
				i, again.Removed[0].Identity.DiffKey, firstRun.Removed[0].Identity.DiffKey)
		}
	}
}

func hasFieldChange(changes []FieldChange, field, oldV, newV string) bool {
	for _, c := range changes {
		if c.Field == field && c.Old == oldV && c.New == newV {
			return true
		}
	}
	return false
}
