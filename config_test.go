// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
)

func liveScopeID(t *testing.T) string {
	t.Helper()
	scopeID, err := corecollector.ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatal(err)
	}
	return scopeID
}

func validLiveTargetConfig() map[string]any {
	return map[string]any{
		"cluster_id": "ops-qa-1",
		"source_uri": "https://kubernetes.default.svc",
	}
}

// TestResolveTargetRejectsUnknownFieldsClosed proves the config surface fails
// closed: an unknown key is rejected without naming it, because a pasted
// credential must never be echoed back.
func TestResolveTargetRejectsUnknownFieldsClosed(t *testing.T) {
	t.Parallel()

	config := validLiveTargetConfig()
	config["token"] = "SECRET"
	_, _, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
	if err == nil {
		t.Fatal("resolveTarget() error = nil, want unknown-field rejection")
	}
	if strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("rejection echoes the key or value: %v", err)
	}
}

// TestResolveTargetRequiresClusterID proves a blank cluster identity fails
// fast: the scope anchor must be operator-declared and stable.
func TestResolveTargetRequiresClusterID(t *testing.T) {
	t.Parallel()

	config := validLiveTargetConfig()
	delete(config, "cluster_id")
	if _, _, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" }); err == nil {
		t.Fatal("resolveTarget() error = nil, want cluster_id rejection")
	}
}

// TestResolveTargetRequiresSourceURI proves a blank source URI fails fast:
// the host validator requires one on every fact.
func TestResolveTargetRequiresSourceURI(t *testing.T) {
	t.Parallel()

	config := validLiveTargetConfig()
	delete(config, "source_uri")
	if _, _, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" }); err == nil {
		t.Fatal("resolveTarget() error = nil, want source_uri rejection")
	}
}

// TestResolveTargetEnforcesScopeInSingleTargetMode proves single-target mode
// enforces claim-scope matching at config decode: a claim for another
// cluster is rejected here instead of being scanned.
func TestResolveTargetEnforcesScopeInSingleTargetMode(t *testing.T) {
	t.Parallel()

	config := validLiveTargetConfig()
	if _, _, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" }); err != nil {
		t.Fatalf("resolveTarget(matching) error = %v, want the configured target", err)
	}
	_, _, err := resolveTarget(config, "kubernetes_live:does-not-match", func(string) string { return "" })
	if err == nil {
		t.Fatal("resolveTarget(mismatched single target) error = nil, want scope rejection")
	}
	if !strings.Contains(err.Error(), "no configured target matches scope_id") {
		t.Fatalf("rejection = %v, want scope mismatch", err)
	}
}

// TestResolveTargetReadsPerTargetLimits proves the documented limits knob is
// wired: a snake_case limits object decodes into the enforcement bounds the
// handler uses, instead of failing closed as an unknown field.
func TestResolveTargetReadsPerTargetLimits(t *testing.T) {
	t.Parallel()

	config := validLiveTargetConfig()
	config["limits"] = map[string]any{
		"max_records_per_claim": 100,
		"max_payload_bytes":     2048,
		"max_result_bytes":      4096,
		"claim_timeout_seconds": 60,
	}
	_, limits, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	want := ResourceUse{
		MaxRecordsPerClaim:  100,
		MaxPayloadBytes:     2048,
		MaxResultBytes:      4096,
		ClaimTimeoutSeconds: 60,
	}
	if limits != want {
		t.Fatalf("limits = %+v, want %+v", limits, want)
	}
}

// TestResolveTargetAcceptsTopLevelLimitsSnakeCase proves the host envelope's
// snake_case spelling of the same four budget keys decodes identically.
func TestResolveTargetAcceptsTopLevelLimitsSnakeCase(t *testing.T) {
	t.Parallel()

	config := map[string]any{
		"targets": []any{validLiveTargetConfig()},
		"limits": map[string]any{
			"max_records_per_claim": 100,
			"max_payload_bytes":     2048,
			"max_result_bytes":      4096,
			"claim_timeout_seconds": 60,
		},
	}
	_, limits, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if limits.MaxRecordsPerClaim != 100 || limits.MaxPayloadBytes != 2048 ||
		limits.MaxResultBytes != 4096 || limits.ClaimTimeoutSeconds != 60 {
		t.Fatalf("limits = %+v, want the top-level budgets", limits)
	}
}

// TestResolveTargetAcceptsTopLevelLimitsCamelCase proves the host's camelCase
// spelling of the same four budget keys decodes identically: the host sends
// claimTimeoutSeconds/maxPayloadBytes/maxRecordsPerClaim/maxResultBytes.
func TestResolveTargetAcceptsTopLevelLimitsCamelCase(t *testing.T) {
	t.Parallel()

	config := map[string]any{
		"targets": []any{validLiveTargetConfig()},
		"limits": map[string]any{
			"maxRecordsPerClaim":  100,
			"maxPayloadBytes":     2048,
			"maxResultBytes":      4096,
			"claimTimeoutSeconds": 60,
		},
	}
	_, limits, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveTarget(camelCase envelope) error = %v", err)
	}
	if limits.MaxRecordsPerClaim != 100 || limits.MaxPayloadBytes != 2048 ||
		limits.MaxResultBytes != 4096 || limits.ClaimTimeoutSeconds != 60 {
		t.Fatalf("limits = %+v, want the top-level budgets", limits)
	}
}

// TestResolveTargetPrefersPerTargetLimitsOverTopLevel proves precedence: the
// matched target's own bounds win where set and the top-level envelope fills
// only the gaps, before the handler bounds and built-in defaults.
func TestResolveTargetPrefersPerTargetLimitsOverTopLevel(t *testing.T) {
	t.Parallel()

	target := validLiveTargetConfig()
	target["limits"] = map[string]any{"max_records_per_claim": 111}
	config := map[string]any{
		"targets": []any{target},
		"limits": map[string]any{
			"max_records_per_claim": 100,
			"max_payload_bytes":     2048,
			"max_result_bytes":      4096,
			"claim_timeout_seconds": 60,
		},
	}
	_, limits, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	want := ResourceUse{
		MaxRecordsPerClaim:  111,
		MaxPayloadBytes:     2048,
		MaxResultBytes:      4096,
		ClaimTimeoutSeconds: 60,
	}
	if limits != want {
		t.Fatalf("limits = %+v, want %+v (per-target wins, envelope fills gaps)", limits, want)
	}
}

// TestResolveTargetAcceptsPerTargetCamelCaseLimits proves the camelCase
// tolerance also covers a target's own limits object: the host forwards the
// subtree verbatim, so an operator camelCase spelling there must not fail.
func TestResolveTargetAcceptsPerTargetCamelCaseLimits(t *testing.T) {
	t.Parallel()

	config := validLiveTargetConfig()
	config["limits"] = map[string]any{"maxRecordsPerClaim": 100}
	_, limits, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if limits.MaxRecordsPerClaim != 100 {
		t.Fatalf("limits.MaxRecordsPerClaim = %d, want 100", limits.MaxRecordsPerClaim)
	}
}

// TestResolveTargetRejectsUnknownLimitsField proves the limits object stays
// fail-closed in both spellings: an unknown bound is rejected without naming
// it, because a misplaced credential key must never be echoed.
func TestResolveTargetRejectsUnknownLimitsField(t *testing.T) {
	t.Parallel()

	for name, limits := range map[string]map[string]any{
		"top-level":         {"max_records_per_claim": 100, "token": "SECRET"},
		"per-target":        {"maxRecordsPerClaim": 100, "token": "SECRET"},
		"top-level-unknown": {"mex_records_per_claim": 100},
	} {
		config := map[string]any{"targets": []any{validLiveTargetConfig()}}
		if name == "per-target" {
			target := validLiveTargetConfig()
			target["limits"] = limits
			config["targets"] = []any{target}
		} else {
			config["limits"] = limits
		}
		_, _, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
		if err == nil {
			t.Fatalf("%s: resolveTarget() error = nil, want unknown-field rejection", name)
		}
		if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "mex_") {
			t.Fatalf("%s: rejection echoes the key or value: %v", name, err)
		}
	}
}

// TestResolveTargetRejectsNonObjectTopLevelLimits proves a top-level limits
// value that is not an object fails bounded without echoing the value.
func TestResolveTargetRejectsNonObjectTopLevelLimits(t *testing.T) {
	t.Parallel()

	config := map[string]any{
		"targets": []any{validLiveTargetConfig()},
		"limits":  "SECRET",
	}
	_, _, err := resolveTarget(config, liveScopeID(t), func(string) string { return "" })
	if err == nil {
		t.Fatal("resolveTarget() error = nil, want limits type rejection")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("rejection echoes the value: %v", err)
	}
}
