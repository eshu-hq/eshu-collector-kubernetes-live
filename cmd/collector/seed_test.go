// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-kubernetes-live"
)

const goodImage = "ghcr.io/eshu-hq/eshu-collector-kubernetes-live@sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func writeFile(t *testing.T, path string, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestSeedWritesBinaryAndManifestAndIsIdempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	executable := filepath.Join(dir, "self")
	writeFile(t, executable, "binary-bytes-v1", 0o600)
	dest := filepath.Join(dir, "nested", "component")
	manifest := []byte("kind: ComponentPackage\n")

	digest, err := seed(dest, executable, manifest)
	if err != nil {
		t.Fatalf("seed() error = %v", err)
	}
	sum := sha256.Sum256([]byte("binary-bytes-v1"))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %s", digest)
	}
	assertSeeded(t, dest, "binary-bytes-v1", string(manifest))

	// A second run, and a run over stale files, converges on the same state.
	writeFile(t, filepath.Join(dest, "collector"), "stale", 0o600)
	writeFile(t, filepath.Join(dest, "manifest.yaml"), "stale", 0o600)
	for range 2 {
		if _, err := seed(dest, executable, manifest); err != nil {
			t.Fatalf("re-seed error = %v", err)
		}
		assertSeeded(t, dest, "binary-bytes-v1", string(manifest))
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("destination holds %d entries, want exactly collector and manifest.yaml", len(entries))
	}
}

func assertSeeded(t *testing.T, dest string, binary string, manifest string) {
	t.Helper()
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("destination mode = %v, want 0750", info.Mode().Perm())
	}
	info, err = os.Stat(filepath.Join(dest, "collector"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode = %v, want 0755", info.Mode().Perm())
	}
	got, err := os.ReadFile(filepath.Join(dest, "collector"))
	if err != nil || string(got) != binary {
		t.Fatalf("binary content = %q (err %v)", got, err)
	}
	info, err = os.Stat(filepath.Join(dest, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("manifest mode = %v, want 0644", info.Mode().Perm())
	}
	got, err = os.ReadFile(filepath.Join(dest, "manifest.yaml"))
	if err != nil || string(got) != manifest {
		t.Fatalf("manifest content = %q (err %v)", got, err)
	}
}

func TestSeedRefusesBadInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	executable := filepath.Join(dir, "self")
	writeFile(t, executable, "x", 0o600)
	if _, err := seed("  ", executable, nil); err == nil {
		t.Error("seed() with no destination error = nil")
	}
	if _, err := seed(filepath.Join(dir, "d"), filepath.Join(dir, "missing"), nil); err == nil {
		t.Error("seed() with a missing executable error = nil")
	}
	blocker := filepath.Join(dir, "file")
	writeFile(t, blocker, "x", 0o600)
	if _, err := seed(filepath.Join(blocker, "sub"), executable, nil); err == nil {
		t.Error("seed() under a regular file error = nil")
	}
}

func TestWriteAtomicReportsWriteAndCreateFailures(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := writeAtomic(filepath.Join(dir, "out"), 0o644, func(io.Writer) error {
		return errors.New("boom")
	}); err == nil {
		t.Error("writeAtomic(write error) = nil")
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Error("failed writeAtomic left the target behind")
	}
	if err := writeAtomic(filepath.Join(dir, "missing", "out"), 0o644, func(w io.Writer) error {
		return nil
	}); err == nil {
		t.Error("writeAtomic(missing dir) = nil")
	}
}

func TestManifestForStampsOnlyADigestPinnedImage(t *testing.T) {
	t.Parallel()

	got, err := manifestFor(collector.ManifestYAML, goodImage)
	if err != nil {
		t.Fatalf("manifestFor() error = %v", err)
	}
	if !bytes.Contains(got, []byte("image: "+goodImage+"\n")) {
		t.Fatalf("stamped manifest lacks the image:\n%s", got)
	}
	if _, err := manifestFor(collector.ManifestYAML, "ghcr.io/eshu-hq/x:latest"); err == nil {
		t.Error("manifestFor(tag) error = nil")
	}
}

// TestRunSeedRejectsBadFlags proves flag misuse exits before any file is
// written.
func TestRunSeedRejectsBadFlags(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := runSeed([]string{"--bogus"}, &stdout, nil); err == nil {
		t.Error("runSeed(--bogus) error = nil")
	}
	if err := runSeed([]string{"extra"}, &stdout, nil); err == nil {
		t.Error("runSeed(positional) error = nil")
	}
}

// TestSelectImageRefPrefersTheFlagThenTheEnvironment proves the stamp source
// order and the single-newline trim on each source.
func TestSelectImageRefPrefersTheFlagThenTheEnvironment(t *testing.T) {
	t.Parallel()

	if got := selectImageRef("flag-ref\n", func(string) string { return "env-ref" }); got != "flag-ref" {
		t.Fatalf("flag source = %q, want the trimmed flag", got)
	}
	if got := selectImageRef("\n", func(string) string { return "env-ref\n" }); got != "env-ref" {
		t.Fatalf("env source = %q, want the trimmed environment", got)
	}
	if got := selectImageRef("", nil); got != "" {
		t.Fatalf("nil getenv = %q, want empty", got)
	}
}

// TestManifestForRequiresExactlyOneArtifactImage proves a stamp is never
// dropped onto a manifest with zero (or two) artifact entries.
func TestManifestForRequiresExactlyOneArtifactImage(t *testing.T) {
	t.Parallel()

	if _, err := manifestFor([]byte("kind: ComponentPackage\n"), goodImage); err == nil {
		t.Error("manifestFor(no artifact) error = nil")
	}
}

// TestCopyExecutableRefusesADirectorySource proves a non-file executable
// surfaces as a write failure instead of an empty binary.
func TestCopyExecutableRefusesADirectorySource(t *testing.T) {
	t.Parallel()

	if _, err := copyExecutable(t.TempDir(), filepath.Join(t.TempDir(), "out")); err == nil {
		t.Error("copyExecutable(directory) error = nil")
	}
}
