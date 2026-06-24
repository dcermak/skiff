package skiff

import (
	"sort"
	"strconv"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

const (
	FieldVersion   = "version"
	FieldEpoch     = "epoch"
	FieldSize      = "size"
	FieldLicense   = "license"
	FieldInstances = "instances"
)

type Identity struct {
	Type      pkg.Type
	Name      string
	Arch      string
	Namespace string
	Distro    string
	DiffKey   string
}

type FieldChange struct {
	Field string
	Old   string
	New   string
}

type PackageDiff struct {
	Identity Identity
	Old      []pkg.Package
	New      []pkg.Package
	Changes  []FieldChange
}

type DiffResult struct {
	Added     []PackageDiff
	Removed   []PackageDiff
	Modified  []PackageDiff
	Unchanged int
}

// rpmPurlView is the result of parsing a package's PURL once and caching the
// qualifiers used by identity, arch, distro, namespace, and epoch lookups.
// Parsed fields (`parsed`, `arch`, `distro`, namespace via `parsed.Namespace`)
// are only meaningful when ok == true; callers must fall back to metadata
// otherwise.
type rpmPurlView struct {
	parsed  packageurl.PackageURL
	ok      bool
	arch    string
	distro  string
	epoch   string
	epochOk bool
}

func newRpmPurlView(purl string) rpmPurlView {
	if purl == "" {
		return rpmPurlView{}
	}
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		return rpmPurlView{}
	}
	v := rpmPurlView{parsed: parsed, ok: true}
	for _, q := range parsed.Qualifiers {
		switch q.Key {
		case "arch":
			v.arch = q.Value
		case "distro":
			v.distro = q.Value
		case "epoch":
			v.epoch = q.Value
			v.epochOk = true
		}
	}
	return v
}

// PackageSize extracts the installed size from a package's metadata.
// Returns (size, true) for package types that carry size info, (0, false) otherwise.
func PackageSize(p pkg.Package) (int, bool) {
	switch m := p.Metadata.(type) {
	case pkg.RpmDBEntry:
		return m.Size, true
	case pkg.RpmArchive:
		return m.Size, true
	case pkg.DpkgDBEntry:
		return m.InstalledSize, true
	case pkg.ApkDBEntry:
		return m.InstalledSize, true
	case pkg.AlpmDBEntry:
		return m.Size, true
	case pkg.PortageEntry:
		return m.InstalledSize, true
	default:
		return 0, false
	}
}

// rpmPackageIdentity returns a stable bucketing identity for an RPM package.
//
// Identity (drives Added/Removed/Modified bucketing):
//
//	PURL Type, Namespace, Name, qualifiers `arch` and `distro` only.
//	Allowlist is deliberate — future Syft qualifiers won't silently
//	split normal upgrades.
//
// Dropped from identity:
//
//	PURL Version              – version bumps must surface as Modified.
//	PURL `epoch` qualifier    – epoch already encoded in pkg.Version.
//	PURL `upstream` qualifier – embeds source-RPM filename with
//	                            version/release; keeping it would
//	                            force normal upgrades into Removed+Added.
//
// Cross-distro/cross-namespace compares (e.g. Leap 15 vs Leap 16) are
// Removed+Added because Distro and Namespace stay in identity; the
// printer surfaces both fields so users see why two near-identical
// rows split.
//
// Fallback identity ("fallback|<Type>|<Name>|<Arch>") fires on missing
// or unparseable PURLs. It loses namespace and distro, so two packages
// that differ only in those qualifiers WILL collapse together. The
// "fallback|" prefix guarantees no collision with a real PURL string
// and makes degraded entries visible in any DiffKey print/log.
func rpmPackageIdentity(p pkg.Package) string {
	return identityFromView(newRpmPurlView(p.PURL), p)
}

func identityFromView(view rpmPurlView, p pkg.Package) string {
	if !view.ok {
		return fallbackIdentityFromView(view, p)
	}

	kept := packageurl.Qualifiers{}
	for _, q := range view.parsed.Qualifiers {
		if q.Key == "arch" || q.Key == "distro" {
			kept = append(kept, q)
		}
	}

	normalized := packageurl.PackageURL{
		Type:       view.parsed.Type,
		Namespace:  view.parsed.Namespace,
		Name:       view.parsed.Name,
		Qualifiers: kept,
	}
	return normalized.ToString()
}

func fallbackIdentityFromView(view rpmPurlView, p pkg.Package) string {
	return "fallback|" + string(p.Type) + "|" + p.Name + "|" + archFromView(view, p)
}

// rpmArchForDiff is the cold-path wrapper around archFromView for callers
// that don't already have a parsed view. The hot path computes a view once
// per package and uses archFromView directly.
func rpmArchForDiff(p pkg.Package) string {
	return archFromView(newRpmPurlView(p.PURL), p)
}

func archFromView(view rpmPurlView, p pkg.Package) string {
	if view.arch != "" {
		return view.arch
	}
	switch m := p.Metadata.(type) {
	case pkg.RpmDBEntry:
		return m.Arch
	case pkg.RpmArchive:
		return m.Arch
	default:
		return ""
	}
}

// rpmPackageEpoch prefers RPM metadata epoch and falls back to the
// PURL `epoch` qualifier. Returns ("", false) when truly absent.
func rpmPackageEpoch(p pkg.Package) (string, bool) {
	return epochFromView(newRpmPurlView(p.PURL), p)
}

func epochFromView(view rpmPurlView, p pkg.Package) (string, bool) {
	switch m := p.Metadata.(type) {
	case pkg.RpmDBEntry:
		if m.Epoch != nil {
			return strconv.Itoa(*m.Epoch), true
		}
	case pkg.RpmArchive:
		if m.Epoch != nil {
			return strconv.Itoa(*m.Epoch), true
		}
	}
	if view.epochOk {
		return view.epoch, true
	}
	return "", false
}

// pkgWithView carries a package alongside its parsed-PURL view so each
// hot-path consumer (sort tiebreak, identity assembly, per-field diff)
// reuses one parse per package instead of re-parsing.
type pkgWithView struct {
	pkg  pkg.Package
	view rpmPurlView
}

// DiffPackages compares two package lists and classifies each identity
// group as Added, Removed, Modified, or Unchanged.
func DiffPackages(oldPkgs, newPkgs []pkg.Package) DiffResult {
	oldMap := groupByIdentity(oldPkgs)
	newMap := groupByIdentity(newPkgs)

	var result DiffResult

	seen := make(map[string]struct{})
	for k := range oldMap {
		seen[k] = struct{}{}
	}
	for k := range newMap {
		seen[k] = struct{}{}
	}

	for key := range seen {
		oldGroup, inOld := oldMap[key]
		newGroup, inNew := newMap[key]

		switch {
		case inOld && !inNew:
			result.Removed = append(result.Removed, PackageDiff{
				Identity: identityFromGroup(oldGroup, key),
				Old:      stripViews(oldGroup),
			})
		case !inOld && inNew:
			result.Added = append(result.Added, PackageDiff{
				Identity: identityFromGroup(newGroup, key),
				New:      stripViews(newGroup),
			})
		default:
			changes := diffPackageGroups(oldGroup, newGroup)
			if len(changes) == 0 {
				result.Unchanged++
			} else {
				result.Modified = append(result.Modified, PackageDiff{
					Identity: identityFromGroup(newGroup, key),
					Old:      stripViews(oldGroup),
					New:      stripViews(newGroup),
					Changes:  changes,
				})
			}
		}
	}

	sortDiffs(result.Added)
	sortDiffs(result.Removed)
	sortDiffs(result.Modified)

	return result
}

func stripViews(group []pkgWithView) []pkg.Package {
	out := make([]pkg.Package, len(group))
	for i, g := range group {
		out[i] = g.pkg
	}
	return out
}

func identityFromGroup(group []pkgWithView, diffKey string) Identity {
	first := group[0]
	namespace := ""
	if first.view.ok {
		namespace = first.view.parsed.Namespace
	}
	return Identity{
		Type:      first.pkg.Type,
		Name:      first.pkg.Name,
		Arch:      archFromView(first.view, first.pkg),
		Namespace: namespace,
		Distro:    first.view.distro,
		DiffKey:   diffKey,
	}
}

func groupByIdentity(pkgs []pkg.Package) map[string][]pkgWithView {
	m := make(map[string][]pkgWithView)
	for _, p := range pkgs {
		view := newRpmPurlView(p.PURL)
		key := identityFromView(view, p)
		m[key] = append(m[key], pkgWithView{pkg: p, view: view})
	}
	for k, group := range m {
		sort.Slice(group, func(i, j int) bool {
			if group[i].pkg.Version != group[j].pkg.Version {
				return group[i].pkg.Version < group[j].pkg.Version
			}
			return archFromView(group[i].view, group[i].pkg) < archFromView(group[j].view, group[j].pkg)
		})
		m[k] = group
	}
	return m
}

// diffPackageGroups returns the per-field differences between two
// package groups sharing the same identity.
//
// Multi-instance groups (more than one package on either side) report
// version/arch multiset membership only; size/license drift inside a
// multi-instance group is intentionally not reported.
func diffPackageGroups(old, new []pkgWithView) []FieldChange {
	if len(old) > 1 || len(new) > 1 {
		oldSet := canonicalInstances(old)
		newSet := canonicalInstances(new)
		if oldSet == newSet {
			return nil
		}
		return []FieldChange{{Field: FieldInstances, Old: oldSet, New: newSet}}
	}

	if len(old) != 1 || len(new) != 1 {
		return nil
	}

	a, b := old[0], new[0]
	var changes []FieldChange

	versionChanged := a.pkg.Version != b.pkg.Version
	if versionChanged {
		changes = append(changes, FieldChange{Field: FieldVersion, Old: a.pkg.Version, New: b.pkg.Version})
	} else {
		aEpoch, aOk := epochFromView(a.view, a.pkg)
		bEpoch, bOk := epochFromView(b.view, b.pkg)
		if aOk != bOk || aEpoch != bEpoch {
			changes = append(changes, FieldChange{Field: FieldEpoch, Old: aEpoch, New: bEpoch})
		}
	}

	aSize, aSzOk := PackageSize(a.pkg)
	bSize, bSzOk := PackageSize(b.pkg)
	if aSzOk != bSzOk || aSize != bSize {
		changes = append(changes, FieldChange{
			Field: FieldSize,
			Old:   strconv.Itoa(aSize),
			New:   strconv.Itoa(bSize),
		})
	}

	if !licensesEqual(a.pkg, b.pkg) {
		changes = append(changes, FieldChange{
			Field: FieldLicense,
			Old:   licenseString(a.pkg),
			New:   licenseString(b.pkg),
		})
	}

	return changes
}

func canonicalInstances(pkgs []pkgWithView) string {
	items := make([]string, len(pkgs))
	for i, p := range pkgs {
		items[i] = p.pkg.Version + "/" + archFromView(p.view, p.pkg)
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func licensesEqual(a, b pkg.Package) bool {
	aLic := a.Licenses.ToSlice()
	bLic := b.Licenses.ToSlice()
	if len(aLic) != len(bLic) {
		return false
	}
	for i := range aLic {
		if aLic[i].Value != bLic[i].Value || aLic[i].SPDXExpression != bLic[i].SPDXExpression {
			return false
		}
	}
	return true
}

func licenseString(p pkg.Package) string {
	lics := p.Licenses.ToSlice()
	values := make([]string, len(lics))
	for i, l := range lics {
		values[i] = l.Value
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func sortDiffs(diffs []PackageDiff) {
	sort.Slice(diffs, func(i, j int) bool {
		a, b := diffs[i].Identity, diffs[j].Identity
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Arch != b.Arch {
			return a.Arch < b.Arch
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Distro != b.Distro {
			return a.Distro < b.Distro
		}
		return a.DiffKey < b.DiffKey
	})
}
