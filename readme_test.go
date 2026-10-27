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

// TestReadmeProofClaimsNameThePodTemplateExclusion keeps the "What is
// proven" paragraph honest: after pod_template moved to a schema-only path,
// the README must state the exclusion instead of claiming full-harness for
// every kubernetes_live fact.
func TestReadmeProofClaimsNameThePodTemplateExclusion(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"except `pod_template`",
		"all 13 emitted kinds",
		"containers.env_from_secret",
		"TestExtractedPodTemplateFullHarnessStillBlocked",
		"k8s_rbac_role",
		"k8s_rbac_binding",
		"eks_pod_identity_association",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README.md does not mention %q", want)
		}
	}
	if strings.Contains(text, "for all 10\nemitted kinds") || strings.Contains(text, "for all 10 emitted kinds") {
		t.Error("README.md still claims 10 emitted kinds; the manifest declares 13")
	}
}
