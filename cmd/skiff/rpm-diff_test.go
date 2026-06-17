package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

// minimalRoot builds a root command containing only rpmDiffCommand and no
// Before hook. The production root's Before performs reexec/unshare which
// must not run inside `go test`.
func minimalRoot() *cli.Command {
	return &cli.Command{
		Name:     "skiff",
		Commands: []*cli.Command{&rpmDiffCommand},
	}
}

func TestRpmDiffFlagValidation(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantSubs string
	}{
		{
			name:     "missing old-image",
			args:     []string{"skiff", "rpm-diff", "-n", "docker://busybox"},
			wantSubs: "old-image",
		},
		{
			name:     "missing new-image",
			args:     []string{"skiff", "rpm-diff", "-o", "docker://busybox"},
			wantSubs: "new-image",
		},
		{
			name:     "whitespace old-image",
			args:     []string{"skiff", "rpm-diff", "-o", "   ", "-n", "docker://busybox"},
			wantSubs: "old-image",
		},
		{
			name:     "whitespace new-image",
			args:     []string{"skiff", "rpm-diff", "-o", "docker://busybox", "-n", "   "},
			wantSubs: "new-image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := minimalRoot().Run(context.Background(), tt.args)
			if err == nil {
				t.Fatalf("expected error mentioning %q", tt.wantSubs)
			}
			if !strings.Contains(err.Error(), tt.wantSubs) {
				t.Errorf("expected error to mention %q, got %q", tt.wantSubs, err)
			}
		})
	}
}

func TestRpmDiffMissingBothFlags(t *testing.T) {
	err := minimalRoot().Run(context.Background(),
		[]string{"skiff", "rpm-diff"})
	if err == nil {
		t.Fatal("expected error when both flags are missing")
	}
	if !strings.Contains(err.Error(), "old-image") && !strings.Contains(err.Error(), "new-image") {
		t.Errorf("expected error to name a missing flag, got %q", err)
	}
}

func TestRpmDiffRegistered(t *testing.T) {
	root := newRootCommand()
	if root.Command("rpm-diff") == nil {
		t.Fatal("expected newRootCommand() to register rpm-diff")
	}
}

func TestPrintDiffResult(t *testing.T) {
	result := skiff.DiffResult{
		Added: []skiff.PackageDiff{{
			Identity: skiff.Identity{Type: pkg.RpmPkg, Name: "cowsay", Arch: "x86_64"},
			New:      []pkg.Package{{Name: "cowsay", Version: "3.04"}},
		}},
		Removed: []skiff.PackageDiff{{
			Identity: skiff.Identity{Type: pkg.RpmPkg, Name: "figlet", Arch: "x86_64"},
			Old:      []pkg.Package{{Name: "figlet", Version: "2.2.5"}},
		}},
		Modified: []skiff.PackageDiff{{
			Identity: skiff.Identity{Type: pkg.RpmPkg, Name: "bash", Arch: "x86_64"},
			Old:      []pkg.Package{{Name: "bash", Version: "5.1"}},
			New:      []pkg.Package{{Name: "bash", Version: "5.2"}},
			Changes:  []skiff.FieldChange{{Field: skiff.FieldVersion, Old: "5.1", New: "5.2"}},
		}},
		Unchanged: 42,
	}

	var buf bytes.Buffer
	printDiffResult(&buf, result)
	out := buf.String()

	wantSubs := []string{
		"Package groups: 1 added, 1 removed, 1 modified, 42 unchanged (total: 45)",
		"Added:",
		"  + cowsay [x86_64] 3.04",
		"Removed:",
		"  - figlet [x86_64] 2.2.5",
		"Modified:",
		"  ~ bash [x86_64]",
		"version: 5.1 -> 5.2",
	}
	for _, s := range wantSubs {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n--- got ---\n%s", s, out)
		}
	}
}
