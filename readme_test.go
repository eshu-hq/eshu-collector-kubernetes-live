// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"os"
	"strings"
	"testing"
)

// TestReadmePinsMatchGoMod keeps the extracted-path proof's require block in
// step with go.mod: a stale rc pin contradicts the change's stated
// requirement and is a same-file fix.
func TestReadmePinsMatchGoMod(t *testing.T) {
	t.Parallel()

	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, mod := range []string{
		"github.com/eshu-hq/eshu-sdk/collector",
		"github.com/eshu-hq/eshu-sdk/factschema",
	} {
		pin := ""
		for _, line := range strings.Split(string(goMod), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, mod+" ") {
				pin = strings.TrimSpace(strings.TrimPrefix(line, mod+" "))
				break
			}
		}
		if pin == "" {
			t.Fatalf("go.mod has no pin for %s", mod)
		}
		if !strings.Contains(string(readme), mod+" "+pin) {
			t.Errorf("README.md does not pin %s %s from go.mod", mod, pin)
		}
	}
}

// TestReadmeProofClaimsCoverPodTemplateFullHarness keeps the "What is
// proven" paragraph honest: collector rc.4 allowlists env_from_secret, so the
// README must claim full-harness for pod_template instead of the spent
// schema-only exclusion and its StillBlocked pin.
func TestReadmeProofClaimsCoverPodTemplateFullHarness(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"including `pod_template`",
		"all 13 emitted kinds",
		"containers.env_from_secret",
		"TestExtractedPayloadsPassConformance",
		"k8s_rbac_role",
		"k8s_rbac_binding",
		"eks_pod_identity_association",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README.md does not mention %q", want)
		}
	}
	for _, gone := range []string{
		"except `pod_template`",
		"TestExtractedPodTemplateFullHarnessStillBlocked",
	} {
		if strings.Contains(text, gone) {
			t.Errorf("README.md still mentions spent exclusion %q", gone)
		}
	}
	if strings.Contains(text, "for all 10\nemitted kinds") || strings.Contains(text, "for all 10 emitted kinds") {
		t.Error("README.md still claims 10 emitted kinds; the manifest declares 13")
	}
}
