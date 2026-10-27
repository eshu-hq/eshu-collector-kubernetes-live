// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	pinnedAction     = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	secretUsePattern = regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`)
)

const (
	// tagShapeCheck is the exact tag filter the workflow must run before it
	// publishes anything.
	tagShapeCheck = `grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'`
	// signerIdentity is the certificate identity a keyless signature from this
	// workflow carries, derived from the running workflow reference.
	signerIdentity = "https://github.com/${{ github.workflow_ref }}"
	// oidcIssuerFlag pins the GitHub Actions OIDC issuer on the verify step.
	oidcIssuerFlag = `--certificate-oidc-issuer "https://token.actions.githubusercontent.com"`
	// sbomFile is the SBOM the generate and attest steps must agree on.
	sbomFile = "eshu-collector-kubernetes-live.spdx.json"
)

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type workflowFile struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []workflowStep    `yaml:"steps"`
	} `yaml:"jobs"`
}

// stepIndex returns the position of the first step for which match is true,
// or -1.
func stepIndex(steps []workflowStep, match func(workflowStep) bool) int {
	for i, step := range steps {
		if match(step) {
			return i
		}
	}
	return -1
}

// contractProblems checks the steps that make a published image trustworthy:
// the tag, manifest, and conformance checks run before anything is pushed,
// one platform is built, the signature is verified against a pinned identity
// and issuer, and the provenance and SBOM attestations are generated and
// verified.
func contractProblems(steps []workflowStep) []string {
	var problems []string
	tagIdx := stepIndex(steps, func(s workflowStep) bool { return strings.Contains(s.Run, tagShapeCheck) })
	if tagIdx < 0 {
		problems = append(problems, "no step filters the tag with "+tagShapeCheck)
	}
	versionIdx := stepIndex(steps, func(s workflowStep) bool {
		return strings.Contains(s.Run, "manifest.yaml") && strings.Contains(s.Run, "TAG_NAME") && strings.Contains(s.Run, "exit 1")
	})
	if versionIdx < 0 {
		problems = append(problems, "no step fails unless the tag matches manifest.yaml metadata.version")
	}
	conformanceIdx := stepIndex(steps, func(s workflowStep) bool {
		return strings.Contains(s.Run, "go test") && strings.Contains(s.Run, "TestExtractedNonPodTemplatePayloadsPassConformance")
	})
	if conformanceIdx < 0 {
		problems = append(problems, "no step runs the conformance proof (go test with TestExtractedNonPodTemplatePayloadsPassConformance) before publishing")
	}
	publishIdx := stepIndex(steps, func(s workflowStep) bool { return fmt.Sprint(s.With["push"]) == "true" })
	if publishIdx < 0 {
		problems = append(problems, "no step pushes the image")
	} else {
		if tagIdx >= 0 && tagIdx > publishIdx {
			problems = append(problems, "the tag shape check runs after the image is pushed")
		}
		if versionIdx >= 0 && versionIdx > publishIdx {
			problems = append(problems, "the manifest version check runs after the image is pushed")
		}
		if conformanceIdx >= 0 && conformanceIdx > publishIdx {
			problems = append(problems, "the conformance proof runs after the image is pushed")
		}
		if got := fmt.Sprint(steps[publishIdx].With["platforms"]); got != "linux/amd64" {
			problems = append(problems, fmt.Sprintf("build platforms = %q, want exactly linux/amd64", got))
		}
	}
	verifyIdx := stepIndex(steps, func(s workflowStep) bool { return strings.Contains(s.Run, "cosign verify") })
	if verifyIdx < 0 {
		problems = append(problems, "no step runs cosign verify")
	} else {
		verify := steps[verifyIdx]
		if verify.Env["CERTIFICATE_IDENTITY"] != signerIdentity {
			problems = append(problems, fmt.Sprintf("cosign identity = %q, want %q", verify.Env["CERTIFICATE_IDENTITY"], signerIdentity))
		}
		for _, want := range []string{`--certificate-identity "${CERTIFICATE_IDENTITY}"`, oidcIssuerFlag} {
			if !strings.Contains(verify.Run, want) {
				problems = append(problems, "cosign verify lacks "+want)
			}
		}
		if strings.Contains(verify.Run, "regexp") {
			problems = append(problems, "cosign verify matches the identity by regular expression, want the exact identity")
		}
	}
	attestIdx := stepIndex(steps, func(s workflowStep) bool { return strings.Contains(s.Run, "gh attestation verify") })
	if attestIdx < 0 {
		problems = append(problems, "no step runs gh attestation verify")
	} else {
		run := steps[attestIdx].Run
		if strings.Count(run, "gh attestation verify") < 2 {
			problems = append(problems, "gh attestation verify must run for provenance and for the SBOM")
		}
		for _, want := range []string{`-R "${GITHUB_REPOSITORY}"`, "--predicate-type https://spdx.dev/Document/v2.3"} {
			if !strings.Contains(run, want) {
				problems = append(problems, "gh attestation verify lacks "+want)
			}
		}
	}
	return problems
}

// releaseSteps loads the release workflow steps.
func releaseSteps(t *testing.T) []workflowStep {
	t.Helper()
	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow workflowFile
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	steps, ok := workflow.Jobs["image"]
	if !ok {
		t.Fatal("release.yml has no image job")
	}
	return steps.Steps
}

// TestReleaseWorkflowKeepsThePublishingContract proves the release workflow
// publishes one pinned platform only after the tag, manifest, and
// conformance checks, and verifies the signature and both attestations.
func TestReleaseWorkflowKeepsThePublishingContract(t *testing.T) {
	t.Parallel()

	if problems := contractProblems(releaseSteps(t)); len(problems) > 0 {
		t.Fatalf("release workflow contract:\n%s", strings.Join(problems, "\n"))
	}
}

// TestReleaseWorkflowPinsActionsByCommitSHA keeps a published image from
// changing what built it: every third-party action runs at a full commit SHA.
func TestReleaseWorkflowPinsActionsByCommitSHA(t *testing.T) {
	t.Parallel()

	for _, step := range releaseSteps(t) {
		if step.Uses != "" && !pinnedAction.MatchString(step.Uses) {
			t.Errorf("step %q uses %q, want a full commit SHA pin", step.Name, step.Uses)
		}
	}
}

// TestReleaseWorkflowUsesNoSecretsInBuild keeps credentials out of the build:
// the only secret the workflow touches is the ephemeral GITHUB_TOKEN for the
// registry login.
func TestReleaseWorkflowUsesNoSecretsInBuild(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range secretUsePattern.FindAllStringSubmatch(string(raw), -1) {
		if match[1] != "GITHUB_TOKEN" {
			t.Errorf("release.yml references secret %q, want only GITHUB_TOKEN", match[1])
		}
	}
}

// TestReleaseWorkflowNamesTheCollectorSBOM proves the generate and attest
// steps agree on this collector's SBOM file.
func TestReleaseWorkflowNamesTheCollectorSBOM(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(raw), sbomFile); count != 2 {
		t.Fatalf("sbom file %q appears %d times, want exactly 2 (generate and attest)", sbomFile, count)
	}
}
