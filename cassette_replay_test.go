// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"testing"
	"time"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// replayClaim returns a claim for one recorded cassette scope. The scope ID is
// a literal from the matching fixture so the test pins the fixture contract.
func replayClaim(scopeID string) sdk.Claim {
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "k8s-replay-test",
		CollectorKind: CollectorKind,
		SourceSystem:  SourceSystem,
		Scope:         sdk.Scope{ID: scopeID, Kind: "cluster"},
		SourceRunID:   "run-replay-1",
		GenerationID:  "generation-replay-1",
		WorkItemID:    "work-replay-1",
		FencingToken:  "9",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Hour).UTC(),
		ConfigHandle:  "component-config:kubernetes-live",
	}
}

// TestCassetteClaimResultValidates is the stdio-carriage proof: a credentialed
// backend is absent (nil client factory) yet the claim still serves, because
// the activation config selects cassette replay. Both the complete and the
// warning-partial cassettes must produce results the SDK rc.4 validator
// accepts, with the claim generation echoed onto the result and every fact
// ref and the source system, scope, and credential-free URI aligned.
func TestCassetteClaimResultValidates(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		scopeID   string
		fixture   string
		wantState sdk.ResultState
		wantFacts int
	}{
		"complete": {
			scopeID:   "kubernetes_live:replay-single",
			fixture:   "collector/testdata/replay-single-cluster.json",
			wantState: sdk.ResultComplete,
			wantFacts: 2,
		},
		"warning partial": {
			scopeID:   "kubernetes_live:replay-warn",
			fixture:   "collector/testdata/replay-warning-partial.json",
			wantState: sdk.ResultPartial,
			wantFacts: 2,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claim := replayClaim(tc.scopeID)
			result, err := Handler{}.Handle(context.Background(), Request{
				ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
				Claim:           claim,
				Contract:        Contract(),
				Config:          map[string]any{"cassette_file": tc.fixture},
			})
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if result.State != tc.wantState {
				t.Fatalf("State = %q, want %q", result.State, tc.wantState)
			}
			if len(result.Facts) != tc.wantFacts {
				t.Fatalf("Facts = %d, want %d", len(result.Facts), tc.wantFacts)
			}
			if result.Generation.ID != claim.GenerationID {
				t.Fatalf("Generation.ID = %q, want the claim generation %q",
					result.Generation.ID, claim.GenerationID)
			}
			for i, fact := range result.Facts {
				if fact.SourceRef.ScopeID != claim.Scope.ID {
					t.Fatalf("fact[%d] scope = %q, want the claim scope %q",
						i, fact.SourceRef.ScopeID, claim.Scope.ID)
				}
				if fact.SourceRef.SourceSystem != claim.SourceSystem {
					t.Fatalf("fact[%d] source_system = %q, want %q",
						i, fact.SourceRef.SourceSystem, claim.SourceSystem)
				}
				if fact.SourceRef.GenerationID != claim.GenerationID {
					t.Fatalf("fact[%d] generation = %q, want the claim generation",
						i, fact.SourceRef.GenerationID)
				}
			}
			report, err := sdk.NewValidator(Contract()).ValidateResult(result)
			if err != nil {
				t.Fatalf("ValidateResult() error = %v", err)
			}
			if report.FactCount != tc.wantFacts {
				t.Fatalf("FactCount = %d, want %d", report.FactCount, tc.wantFacts)
			}
		})
	}
}

// TestRecordWithoutClusterYieldsNoFacts documents the record verdict for #24:
// record capture is not portable over the stdio claim plane. Without a live
// cluster backend (and with no cassette configured) a claim against a
// configured target returns terminal collection_failed with zero facts —
// there is nothing to capture. Recording stays in-tree; this satellite only
// replays.
func TestRecordWithoutClusterYieldsNoFacts(t *testing.T) {
	t.Parallel()

	claim := replayClaim(mustScopeID(t, "ops-qa-1"))
	result, err := Handler{}.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config: map[string]any{
			"cluster_id": "ops-qa-1",
			"source_uri": "https://kubernetes.default.svc",
		},
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal (no cluster, no cassette, nothing to record)", result.State)
	}
	if len(result.Statuses) != 1 || result.Statuses[0].FailureClass != FailureCollection {
		t.Fatalf("Statuses = %+v, want one terminal collection_failed", result.Statuses)
	}
	if len(result.Facts) != 0 {
		t.Fatalf("Facts = %d, want zero: no cluster means no capture", len(result.Facts))
	}
}

func mustScopeID(t *testing.T, clusterID string) string {
	t.Helper()
	scopeID, err := corecollector.ClusterScopeID(clusterID)
	if err != nil {
		t.Fatal(err)
	}
	return scopeID
}
