// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
