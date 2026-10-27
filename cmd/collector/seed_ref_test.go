// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-kubernetes-live"
)

var digest64 = strings.Repeat("ab12", 16)

// placeholderRef is the artifact image line value the repository manifest
// carries.
const placeholderRef = "ghcr.io/eshu-hq/eshu-collector-kubernetes-live@sha256:" +
	"0000000000000000000000000000000000000000000000000000000000000000"

// hostileRefs must each exit non-zero and write nothing. They carry
// characters that mean something to YAML, to a regexp replacement template, or
// to a shell, or break the one-trailing-newline rule.
var hostileRefs = map[string]string{
	"dollar group":       "a$1b@sha256:" + digest64,
	"dollar brace":       "a${0}b@sha256:" + digest64,
	"double quote":       `a"b@sha256:` + digest64,
	"single quote":       "a'b@sha256:" + digest64,
	"hash":               "a#b@sha256:" + digest64,
	"open bracket":       "a[b@sha256:" + digest64,
	"close bracket":      "a]b@sha256:" + digest64,
	"brace":              "a{b}@sha256:" + digest64,
	"colon space":        "a: b@sha256:" + digest64,
	"ampersand":          "a&b@sha256:" + digest64,
	"asterisk":           "*a@sha256:" + digest64,
	"tab":                "a\tb@sha256:" + digest64,
	"carriage return":    "a@sha256:" + digest64 + "\r",
	"two trailing lines": "a@sha256:" + digest64 + "\n\n",
	"embedded newline":   "a\nb@sha256:" + digest64,
	"leading space":      " a@sha256:" + digest64,
	"trailing space":     "a@sha256:" + digest64 + " ",
	"uppercase digest":   "a@sha256:" + strings.ToUpper(digest64),
	"uppercase name":     "A@sha256:" + digest64,
	"short digest":       "a@sha256:" + digest64[:63],
	"long digest":        "a@sha256:" + digest64 + "0",
	"tag only":           "ghcr.io/eshu-hq/x:latest",
	"tag and digest":     "a:tag@sha256:" + digest64,
	"empty segment":      "a//b@sha256:" + digest64,
	"leading dash":       "-a@sha256:" + digest64,
	"double separator":   "a..b@sha256:" + digest64,
	"no name":            "@sha256:" + digest64,
}

func seedWith(t *testing.T, flagRef string, envRef string) (dest string, err error) {
	t.Helper()
	dest = filepath.Join(t.TempDir(), "component")
	args := []string{"--dest", dest}
	if flagRef != "" {
		args = append(args, "--image-ref", flagRef)
	}
	err = runSeed(args, &bytes.Buffer{}, func(key string) string {
		if key == imageRefEnv {
			return envRef
		}
		return ""
	})
	return dest, err
}

// TestSeedRejectsHostileRefsAndWritesNothing proves, through both the flag and
// the environment variable, that a malformed reference exits with an error
// before the destination is touched and that the error never echoes the value.
func TestSeedRejectsHostileRefsAndWritesNothing(t *testing.T) {
	t.Parallel()

	for name, ref := range hostileRefs {
		t.Run("flag/"+name, func(t *testing.T) {
			t.Parallel()
			dest, err := seedWith(t, ref, "")
			if err == nil {
				t.Fatalf("runSeed(flag %q) error = nil", name)
			}
			if strings.Contains(err.Error(), digest64) || strings.Contains(err.Error(), ref) {
				t.Fatalf("rejection echoes the value: %v", err)
			}
			if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
				t.Fatalf("destination %q exists after a rejected stamp", dest)
			}
		})
		t.Run("env/"+name, func(t *testing.T) {
			t.Parallel()
			dest, err := seedWith(t, "", ref)
			if err == nil {
				t.Fatalf("runSeed(env %q) error = nil", name)
			}
			if strings.Contains(err.Error(), digest64) || strings.Contains(err.Error(), ref) {
				t.Fatalf("rejection echoes the value: %v", err)
			}
			if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
				t.Fatalf("destination %q exists after a rejected stamp", dest)
			}
		})
	}
}

// TestSeedStampsTheDeployedDigest proves the happy path: the flag (or the
// environment) stamps the digest-pinned reference into the seeded manifest
// while the binary is copied byte-identical.
func TestSeedStampsTheDeployedDigest(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		flag, env string
	}{
		"flag wins":        {flag: goodImage},
		"environment":      {env: goodImage},
		"flag beats env":   {flag: goodImage, env: "ghcr.io/eshu-hq/other@sha256:" + digest64},
		"trailing newline": {flag: goodImage + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dest, err := seedWith(t, tc.flag, tc.env)
			if err != nil {
				t.Fatalf("runSeed() error = %v", err)
			}
			raw, err := os.ReadFile(filepath.Join(dest, "manifest.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte("image: "+goodImage+"\n")) {
				t.Fatalf("seeded manifest lacks the stamped image:\n%s", raw)
			}
		})
	}
}

// TestSeedLeavesThePlaceholderUntouched proves the default: without a
// reference the repository placeholder ships verbatim.
func TestSeedLeavesThePlaceholderUntouched(t *testing.T) {
	t.Parallel()

	dest, err := seedWith(t, "", "")
	if err != nil {
		t.Fatalf("runSeed() error = %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dest, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("image: "+placeholderRef+"\n")) {
		t.Fatalf("seeded manifest lacks the placeholder image:\n%s", raw)
	}
	if !bytes.Equal(raw, collector.ManifestYAML) {
		t.Fatal("seeded manifest differs from the embedded manifest")
	}
}
