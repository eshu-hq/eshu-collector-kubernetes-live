// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// mainHeadStepRun returns the script of the release workflow step that refuses
// a tag whose commit is not the protected main head.
func mainHeadStepRun(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow workflowFile
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	steps := workflow.Jobs["image"].Steps
	idx := stepIndex(steps, func(s workflowStep) bool { return s.Name == mainHeadStepName })
	if idx < 0 {
		t.Fatalf("release.yml has no step named %q", mainHeadStepName)
	}
	return steps[idx].Run
}

// gitIn runs git in dir and returns its trimmed stdout.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestReleaseMainHeadStepComparesTagCommitWithMain runs the workflow's own
// script the way the runner does (bash -e) in a clone of a scratch origin, so
// a tag cut from any commit other than the main head cannot publish.
func TestReleaseMainHeadStepComparesTagCommitWithMain(t *testing.T) {
	t.Parallel()

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}
	script := mainHeadStepRun(t)

	origin := t.TempDir()
	gitIn(t, origin, "init", "--quiet", "--initial-branch=main")
	gitIn(t, origin, "commit", "--quiet", "--allow-empty", "-m", "first")
	older := gitIn(t, origin, "rev-parse", "HEAD")
	gitIn(t, origin, "commit", "--quiet", "--allow-empty", "-m", "second")
	head := gitIn(t, origin, "rev-parse", "HEAD")
	gitIn(t, origin, "checkout", "--quiet", "-b", "feature")
	gitIn(t, origin, "commit", "--quiet", "--allow-empty", "-m", "unmerged")
	unmerged := gitIn(t, origin, "rev-parse", "HEAD")

	for name, tc := range map[string]struct {
		commit string
		want   bool
	}{
		"tag at the main head":        {head, true},
		"tag at an older main commit": {older, false},
		"tag at an unmerged commit":   {unmerged, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			clone := t.TempDir()
			gitIn(t, clone, "clone", "--quiet", origin, ".")
			cmd := exec.Command(bash, "-e", "-c", script)
			cmd.Dir = clone
			cmd.Env = append(os.Environ(), "TAG_NAME=v9.9.9", "TAG_COMMIT="+tc.commit)
			out, err := cmd.CombinedOutput()
			if got := err == nil; got != tc.want {
				t.Fatalf("commit %s: passed = %t, want %t\n%s", tc.commit, got, tc.want, out)
			}
			if !tc.want && !strings.Contains(string(out), "not the protected main head") {
				t.Fatalf("refusal lacks the explanatory message:\n%s", out)
			}
		})
	}
}

// TestReleaseMainHeadGuardRejectsViolations plants each way the guard can be
// weakened in a copy of the workflow, so a gate that always passes is caught.
func TestReleaseMainHeadGuardRejectsViolations(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	good := string(raw)
	for name, mutate := range map[string]func(string) string{
		"guard renamed": func(s string) string { return strings.Replace(s, mainHeadStepName, "Check the tag", 1) },
		"guard runs on every event": func(s string) string {
			return strings.Replace(s, "      - name: "+mainHeadStepName+"\n        if: github.ref_type == 'tag'\n", "      - name: "+mainHeadStepName+"\n", 1)
		},
		"guard compares the wrong commit": func(s string) string {
			return strings.Replace(s, "TAG_COMMIT: ${{ github.sha }}", "TAG_COMMIT: ${{ github.ref }}", 1)
		},
		"guard does not fetch main": func(s string) string { return strings.Replace(s, "          git fetch origin main --quiet\n", "", 1) },
		"guard never fails": func(s string) string {
			return strings.Replace(s, `not the protected main head ${main_head}" >&2
            exit 1`, `not the protected main head ${main_head}" >&2`, 1)
		},
		"job env drops the tag name": func(s string) string {
			return strings.Replace(s, "      TAG_NAME: ${{ github.ref_name }}\n", "", 1)
		},
		"checkout keeps credentials": func(s string) string {
			return strings.Replace(s, "persist-credentials: false", "persist-credentials: true", 1)
		},
		"guard runs after the manifest check": func(s string) string {
			start := strings.Index(s, "      - name: "+mainHeadStepName)
			end := strings.Index(s, "      - name: Require the tag to match the manifest version")
			next := strings.Index(s, "      - name: Set up")
			if start < 0 || end < start || next < end {
				return s
			}
			return s[:start] + s[end:next] + s[start:end] + s[next:]
		},
	} {
		mutated := mutate(good)
		if mutated == good {
			t.Errorf("%s: the mutation did not change the workflow", name)
			continue
		}
		var workflow workflowFile
		if err := yaml.Unmarshal([]byte(mutated), &workflow); err != nil {
			t.Errorf("%s: mutated workflow does not parse: %v", name, err)
			continue
		}
		image := workflow.Jobs["image"]
		if len(mainHeadProblems(image.Steps, image.Env)) == 0 {
			t.Errorf("%s: the gate accepted a violating workflow", name)
		}
	}
}
