// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"strings"
	"testing"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// liveEnvelopeClaim builds the host claim for the ops-qa cluster the envelope
// tests target. The scope ID is derived with the same ClusterScopeID the
// handler uses, so the test pins the match rather than a hardcoded string.
func liveEnvelopeClaim(t *testing.T) sdk.Claim {
	t.Helper()
	scopeID, err := corecollector.ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatal(err)
	}
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "k8s-live-qa-1",
		CollectorKind: CollectorKind,
		SourceSystem:  SourceSystem,
		Scope:         sdk.Scope{ID: scopeID, Kind: "cluster"},
		SourceRunID:   "run-1",
		GenerationID:  "generation-1",
		WorkItemID:    "work-1",
		FencingToken:  "7",
		Attempt:       1,
		ConfigHandle:  "component-config:kubernetes-live",
	}
}

// liveTargetConfig is one k8s-live activation target: the operator-declared
// durable cluster identity plus the per-target source URI the SDK contract
// requires on every fact.
func liveTargetConfig() map[string]any {
	return map[string]any{
		"cluster_id":   "ops-qa-1",
		"display_name": "ops-qa",
		"provider":     "eks",
		"environment":  "ops-qa",
		"source_uri":   "https://kubernetes.default.svc",
	}
}

// liveHostEnvelope is the SDK request Config shape the future IaC activation
// produces: the component-extension host forwards the activation config
// subtree verbatim, so the targets sit next to the top-level limits object
// (camelCase, as the host sends them) and the host-minted token object.
func liveHostEnvelope() map[string]any {
	return map[string]any{
		"targets": []any{liveTargetConfig()},
		"limits": map[string]any{
			"claimTimeoutSeconds": 300,
			"maxPayloadBytes":     1048576,
			"maxRecordsPerClaim":  50000,
			"maxResultBytes":      50331648,
		},
		"host_github_app_token": map[string]any{
			"token":    "minted-per-claim",
			"scope_id": "cluster-scope",
		},
	}
}

// TestResolveTargetAcceptsTopLevelLimitsEnvelope is the eshu-hq/eshu#8861
// lesson applied from day one: the host forwards the full activation config
// subtree, so a {"targets":[...]} config carrying a top-level limits object
// must resolve instead of failing every claim terminal with invalid_config.
func TestResolveTargetAcceptsTopLevelLimitsEnvelope(t *testing.T) {
	t.Parallel()

	scopeID, err := corecollector.ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatal(err)
	}
	_, limits, err := resolveTarget(liveHostEnvelope(), scopeID)
	if err != nil {
		t.Fatalf("resolveTarget(envelope) error = %v, want the host limits envelope accepted", err)
	}
	want := ResourceUse{
		MaxRecordsPerClaim:  50000,
		MaxPayloadBytes:     1048576,
		MaxResultBytes:      50331648,
		ClaimTimeoutSeconds: 300,
	}
	if limits != want {
		t.Fatalf("limits = %+v, want %+v (top-level budgets mapped onto the target)", limits, want)
	}
}

// TestResolveTargetIgnoresHostMintedKeys proves host-minted keys are accepted
// and ignored: they never fail decode and never reach an error.
func TestResolveTargetIgnoresHostMintedKeys(t *testing.T) {
	t.Parallel()

	scopeID, err := corecollector.ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveTarget(liveHostEnvelope(), scopeID); err != nil {
		t.Fatalf("resolveTarget(envelope+token) error = %v, want the host token key ignored", err)
	}
}

// TestResolveTargetRejectsUnknownEnvelopeKey proves the envelope stays
// fail-closed: a genuinely unknown top-level key is still rejected without
// naming it, because an operator key can be a pasted credential.
func TestResolveTargetRejectsUnknownEnvelopeKey(t *testing.T) {
	t.Parallel()

	scopeID, err := corecollector.ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatal(err)
	}
	config := liveHostEnvelope()
	config["bogus_key"] = 1
	_, _, err = resolveTarget(config, scopeID)
	if err == nil {
		t.Fatal("resolveTarget() error = nil, want unknown-field rejection")
	}
	if strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("rejection echoes the key: %v", err)
	}
}

// TestHandleServesClaimWithHostEnvelope proves end to end that an SDK request
// shaped like the future IaC activation serves the claim instead of returning
// terminal invalid_config. The fake client serves no cluster data, so the
// scan reports collection_failed; what matters is the config was accepted.
func TestHandleServesClaimWithHostEnvelope(t *testing.T) {
	t.Parallel()

	result, err := Handler{ClientFactory: emptyLiveClientFactory{}}.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           liveEnvelopeClaim(t),
		Contract:        Contract(),
		Config:          liveHostEnvelope(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	for _, status := range result.Statuses {
		if status.FailureClass == FailureInvalidConfig {
			t.Fatalf("result carries invalid_config %+v, want the host envelope accepted", result.Statuses)
		}
	}
	if len(result.Facts) != 0 {
		t.Fatalf("empty fake cluster yields %d facts, want 0", len(result.Facts))
	}
}
