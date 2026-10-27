// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// coreModulePath is the Eshu core module. The published SDK modules live under
// github.com/eshu-hq/eshu-sdk, a different prefix.
const coreModulePath = "github.com/eshu-hq/eshu/go"

// TestImportBoundaryRejectsCoreAndCrossCollectorImports is the CI gate that
// keeps a standalone collector repository standalone: no Eshu internal
// implementation imports and no cross-collector implementation imports. Only
// the published SDK modules, OpenTelemetry (spans the emission core already
// carries), and yaml for the manifest shape tests are allowed besides the
// standard library. The self-import prefix is derived from go.mod so renaming
// the module can never desync this allowlist.
func TestImportBoundaryRejectsCoreAndCrossCollectorImports(t *testing.T) {
	t.Parallel()

	violations, err := importViolations(".", allowedImportPrefixes(modulePath(t)))
	if err != nil {
		t.Fatalf("importViolations() error = %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("forbidden imports:\n%s", strings.Join(violations, "\n"))
	}
}

func allowedImportPrefixes(module string) []string {
	return []string{
		module,
		"github.com/eshu-hq/eshu-sdk/collector",
		"github.com/eshu-hq/eshu-sdk/factschema",
		"go.opentelemetry.io/otel",
		"gopkg.in/yaml.v3",
	}
}

// importViolations parses every .go file under root and reports each import
// outside allowedPrefixes. Every directory is scanned, scripts/ and nested
// testdata/ included, so a forbidden import cannot hide in a helper tree. Only
// .git and the top-level testdata/ directory (fixture data, whose .go.txt
// files are not compiled) are skipped.
func importViolations(root string, allowedPrefixes []string) ([]string, error) {
	var violations []string
	walk := func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if rel == ".git" || rel == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			target := strings.Trim(imp.Path.Value, `"`)
			allowed := false
			for _, prefix := range allowedPrefixes {
				if target == prefix || strings.HasPrefix(target, prefix+"/") {
					allowed = true
					break
				}
			}
			if !allowed && !isStandardImport(target) {
				violations = append(violations, path+": "+target)
			}
		}
		return nil
	}
	if err := filepath.WalkDir(root, walk); err != nil {
		return nil, err
	}
	return violations, nil
}

// isStandardImport reports whether target is a standard-library import: it
// contains no dot in its first path segment.
func isStandardImport(target string) bool {
	first := target
	if i := strings.Index(first, "/"); i >= 0 {
		first = first[:i]
	}
	return !strings.Contains(first, ".")
}

// modulePath returns the module path from go.mod.
func modulePath(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if module, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(module)
		}
	}
	t.Fatal("go.mod has no module line")
	return ""
}
