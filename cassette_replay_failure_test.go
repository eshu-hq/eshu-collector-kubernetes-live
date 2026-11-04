// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// replayFailureClaim returns a claim for the pre-recorded single-cluster
// cassette. The scope ID is a literal from the fixture so the test pins the
// fixture contract.
func replayFailureClaim() sdk.Claim {
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "k8s-replay-failure-test",
		CollectorKind: CollectorKind,
		SourceSystem:  SourceSystem,
		Scope:         sdk.Scope{ID: "kubernetes_live:replay-single", Kind: "cluster"},
		SourceRunID:   "run-replay-fail-1",
		GenerationID:  "generation-replay-fail-1",
		WorkItemID:    "work-replay-fail-1",
		FencingToken:  "9",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Hour).UTC(),
		ConfigHandle:  "component-config:kubernetes-live",
	}
}

func replayFailureConfig() map[string]any {
	return map[string]any{"cassette_file": "collector/testdata/replay-single-cluster.json"}
}

// requireReplayTerminal fails the test unless Handle ends terminal with the
// named failure class and zero facts.
func requireReplayTerminal(t *testing.T, name string, config map[string]any, claim sdk.Claim, class string) sdk.Result {
	t.Helper()
	result, err := Handler{}.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          config,
	})
	if err != nil {
		t.Fatalf("%s: Handle() error = %v, want a terminal result", name, err)
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("%s: State = %q, want terminal", name, result.State)
	}
	if len(result.Statuses) != 1 || result.Statuses[0].FailureClass != class {
		t.Fatalf("%s: Statuses = %+v, want one %s", name, result.Statuses, class)
	}
	if len(result.Facts) != 0 {
		t.Fatalf("%s: Facts = %d, want zero on a failed claim", name, len(result.Facts))
	}
	return result
}

// TestHandleReplayRejectsBadCassetteRef proves the cassette selection fails
// closed: a config that mixes live target keys with the cassette key, and a
// blank or non-string cassette path, never reach the filesystem. Every case
// ends terminal invalid_config with no facts.
func TestHandleReplayRejectsBadCassetteRef(t *testing.T) {
	t.Parallel()

	cases := map[string]map[string]any{
		"mixed cassette and live keys": {
			"cassette_file": "collector/testdata/replay-single-cluster.json",
			"cluster_id":    "ops-qa-1",
			"source_uri":    "https://kubernetes.default.svc",
		},
		"blank cassette_file":      {"cassette_file": "   "},
		"non-string cassette_file": {"cassette_file": 42},
		"null cassette_file":       {"cassette_file": nil},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireReplayTerminal(t, name, config, replayFailureClaim(), FailureInvalidConfig)
		})
	}
}

// TestHandleReplayIgnoresHostMintedKeys proves a host-minted host_* key may
// sit beside the cassette selection: the replay still serves, and the token
// value never affects the result.
func TestHandleReplayIgnoresHostMintedKeys(t *testing.T) {
	t.Parallel()

	config := replayFailureConfig()
	config["host_github_app_token"] = "minted-per-claim-token"
	result, err := Handler{}.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           replayFailureClaim(),
		Contract:        Contract(),
		Config:          config,
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if len(result.Facts) != 2 {
		t.Fatalf("Facts = %d, want 2", len(result.Facts))
	}
}

// TestHandleRejectsNilConfigWithoutCassette proves a missing config takes the
// live path and fails closed: with no cassette selection and no target, the
// claim ends terminal invalid_config with no facts.
func TestHandleRejectsNilConfigWithoutCassette(t *testing.T) {
	t.Parallel()

	requireReplayTerminal(t, "nil config", nil, replayFailureClaim(), FailureInvalidConfig)
}

// TestHandleReplayFailsClosedOnMissingFile proves a cassette path that cannot
// be read ends terminal invalid_config instead of an empty result.
func TestHandleReplayFailsClosedOnMissingFile(t *testing.T) {
	t.Parallel()

	requireReplayTerminal(t, "missing file",
		map[string]any{"cassette_file": "collector/testdata/does-not-exist.json"},
		replayFailureClaim(), FailureInvalidConfig)
}

// TestHandleReplayRejectsUnknownScope proves a claim for a scope the cassette
// does not carry fails instead of replaying a neighbor scope.
func TestHandleReplayRejectsUnknownScope(t *testing.T) {
	t.Parallel()

	claim := replayFailureClaim()
	claim.Scope.ID = "kubernetes_live:does-not-exist"
	requireReplayTerminal(t, "unknown scope", replayFailureConfig(), claim, FailureInvalidConfig)
}

// TestHandleReplayRejectsInvalidLimits proves a malformed top-level limits
// envelope on the replay path ends terminal invalid_config.
func TestHandleReplayRejectsInvalidLimits(t *testing.T) {
	t.Parallel()

	config := replayFailureConfig()
	config["limits"] = "not-an-object"
	requireReplayTerminal(t, "invalid limits", config, replayFailureClaim(), FailureInvalidConfig)
}

// TestHandleReplayMapsSpentDeadlineToRetryable proves an already-spent lease
// deadline never touches the cassette: the claim ends retryable
// claim_deadline_exceeded with no facts, so the host re-plans it.
func TestHandleReplayMapsSpentDeadlineToRetryable(t *testing.T) {
	t.Parallel()

	claim := replayFailureClaim()
	claim.Deadline = time.Now().Add(-time.Minute).UTC()
	result, err := Handler{}.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          replayFailureConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v, want a retryable result", err)
	}
	if result.State != sdk.ResultRetryable {
		t.Fatalf("State = %q, want retryable", result.State)
	}
	if len(result.Statuses) != 1 || result.Statuses[0].FailureClass != FailureClaimDeadline {
		t.Fatalf("Statuses = %+v, want one claim_deadline_exceeded", result.Statuses)
	}
	if len(result.Facts) != 0 {
		t.Fatal("failed result carries facts")
	}
}

// secretsOnlyWarningCassette is a single-scope cassette whose only fact is a
// secrets/IAM coverage warning. It pins the regression where a secrets-only
// warning snapshot replayed partial with WarningCount 0.
func secretsOnlyWarningCassette(t *testing.T) string {
	t.Helper()
	document := `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
		`"scope_id":"kubernetes_live:replay-secrets-warn","source_system":"kubernetes_live",` +
		`"scope_kind":"cluster","collector_kind":"kubernetes_live",` +
		`"generation_id":"g-secrets-warn-1","observed_at":"2026-03-04T05:06:07.089Z",` +
		`"facts":[{"fact_kind":"secrets_iam_coverage_warning",` +
		`"stable_fact_key":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",` +
		`"schema_version":"1.0.0","payload":{"warning_kind":"hidden","source_state":"unknown"},` +
		`"source_uri":"https://api.replay-secrets-warn.example.test/cluster"}]}]}`
	path := filepath.Join(t.TempDir(), "replay-secrets-warn.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestHandleReplayCountsSecretsWarningPartial proves a secrets-only warning
// cassette replays partial with WarningCount equal to its warning facts: the
// partial status must report the warnings present, not zero.
func TestHandleReplayCountsSecretsWarningPartial(t *testing.T) {
	t.Parallel()

	claim := replayFailureClaim()
	claim.Scope.ID = "kubernetes_live:replay-secrets-warn"
	result, err := Handler{}.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          map[string]any{"cassette_file": secretsOnlyWarningCassette(t)},
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State != sdk.ResultPartial {
		t.Fatalf("State = %q, want partial (warning fact replayed)", result.State)
	}
	if len(result.Statuses) != 1 {
		t.Fatalf("Statuses = %+v, want one partial warning status", result.Statuses)
	}
	status := result.Statuses[0]
	if status.WarningCount != 1 {
		t.Fatalf("WarningCount = %d, want 1 (the replayed secrets warning)", status.WarningCount)
	}
	if status.FactCount != 1 {
		t.Fatalf("FactCount = %d, want 1", status.FactCount)
	}
}
