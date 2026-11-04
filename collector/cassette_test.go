// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
)

// TestCassetteLoaderRejectsBadSchema proves the cassette loader enforces the
// recorded schema contract before any fact is built: a wrong schema_version,
// zero scopes, and missing required fields all fail closed. It mirrors the
// in-tree format.go validation the port copies.
func TestCassetteLoaderRejectsBadSchema(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"not JSON":           `{nope`,
		"bad schema version": `{"collector":"kubernetes_live","schema_version":"2","scopes":[]}`,
		"zero scopes":        `{"collector":"kubernetes_live","schema_version":"1","scopes":[]}`,
		"missing scope_id": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"source_system":"kubernetes_live","scope_kind":"cluster","collector_kind":"kubernetes_live",` +
			`"generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z","facts":[]}]}`,
		"missing source_system": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","scope_kind":"cluster","collector_kind":"kubernetes_live",` +
			`"generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z","facts":[]}]}`,
		"missing scope_kind": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","collector_kind":"kubernetes_live",` +
			`"generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z","facts":[]}]}`,
		"missing collector_kind": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z","facts":[]}]}`,
		"missing generation_id": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","observed_at":"2026-03-04T05:06:07.089Z","facts":[]}]}`,
		"zero observed_at": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","generation_id":"g1","facts":[]}]}`,
		"missing fact_kind": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z",` +
			`"facts":[{"stable_fact_key":"k1","schema_version":"1.0.0","payload":{}}]}]}`,
		"missing stable_fact_key": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z",` +
			`"facts":[{"fact_kind":"kubernetes_live.namespace","schema_version":"1.0.0","payload":{}}]}]}`,
		"missing schema_version": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z",` +
			`"facts":[{"fact_kind":"kubernetes_live.namespace","stable_fact_key":"k1","payload":{}}]}]}`,
		"missing payload": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z",` +
			`"facts":[{"fact_kind":"kubernetes_live.namespace","stable_fact_key":"k1","schema_version":"1.0.0"}]}]}`,
		"missing source_uri": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z",` +
			`"facts":[{"fact_kind":"kubernetes_live.namespace","stable_fact_key":"k1","schema_version":"1.0.0",` +
			`"payload":{}}]}]}`,
		"blank source_uri": `{"collector":"kubernetes_live","schema_version":"1","scopes":[{` +
			`"scope_id":"s1","source_system":"kubernetes_live","scope_kind":"cluster",` +
			`"collector_kind":"kubernetes_live","generation_id":"g1","observed_at":"2026-03-04T05:06:07.089Z",` +
			`"facts":[{"fact_kind":"kubernetes_live.namespace","stable_fact_key":"k1","schema_version":"1.0.0",` +
			`"payload":{},"source_uri":"   "}]}]}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAndValidate([]byte(document)); err == nil {
				t.Fatalf("ParseAndValidate() error = nil, want rejection of %s", name)
			}
		})
	}

	if _, err := LoadFile("testdata/does-not-exist.json"); err == nil {
		t.Fatal("LoadFile(missing) error = nil, want a read failure")
	}
	corrupt := t.TempDir() + "/corrupt.json"
	if err := os.WriteFile(corrupt, []byte(`{nope`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(corrupt); err == nil {
		t.Fatal("LoadFile(corrupt) error = nil, want a parse failure")
	}

	if _, err := LoadFile("testdata/replay-single-cluster.json"); err != nil {
		t.Fatalf("LoadFile(valid fixture) error = %v", err)
	}
}

// TestCassetteReplayYieldsClaimedScopeOnly proves one claim replays one scope:
// the multi-cluster cassette yields only the claimed scope's envelopes with
// intact stable fact keys, and an unknown scope fails instead of replaying a
// neighbor.
func TestCassetteReplayYieldsClaimedScopeOnly(t *testing.T) {
	t.Parallel()

	file, err := LoadFile("testdata/replay-multi-cluster.json")
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	snapshot, err := ReplayClaimedScope(file, "kubernetes_live:replay-a")
	if err != nil {
		t.Fatalf("ReplayClaimedScope(a) error = %v", err)
	}
	if len(snapshot.Envelopes) != 2 {
		t.Fatalf("envelopes = %d, want 2 (scope A only)", len(snapshot.Envelopes))
	}
	wantKeys := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	for i, envelope := range snapshot.Envelopes {
		if envelope.ScopeID != "kubernetes_live:replay-a" {
			t.Fatalf("envelope[%d].ScopeID = %q, want scope A", i, envelope.ScopeID)
		}
		if envelope.StableFactKey != wantKeys[i] {
			t.Fatalf("envelope[%d].StableFactKey = %q, want %q", i, envelope.StableFactKey, wantKeys[i])
		}
	}

	other, err := ReplayClaimedScope(file, "kubernetes_live:replay-b")
	if err != nil {
		t.Fatalf("ReplayClaimedScope(b) error = %v", err)
	}
	if len(other.Envelopes) != 1 {
		t.Fatalf("envelopes = %d, want 1 (scope B only)", len(other.Envelopes))
	}
	// Scope B omits every optional cassette field, pinning the ported
	// defaults: partition key falls back to the scope ID, the trigger kind
	// to snapshot, the collector kind to the scope kind, the fencing token
	// to 1, the confidence to reported, and the record ID to the stable key.
	if other.Scope.PartitionKey != "kubernetes_live:replay-b" {
		t.Fatalf("PartitionKey = %q, want the scope ID default", other.Scope.PartitionKey)
	}
	if other.Generation.TriggerKind != "snapshot" {
		t.Fatalf("TriggerKind = %q, want the snapshot default", other.Generation.TriggerKind)
	}
	envelope := other.Envelopes[0]
	if envelope.CollectorKind != "kubernetes_live" {
		t.Fatalf("CollectorKind = %q, want the scope kind default", envelope.CollectorKind)
	}
	if envelope.FencingToken != 1 {
		t.Fatalf("FencingToken = %d, want the in-tree default 1", envelope.FencingToken)
	}
	if envelope.SourceConfidence != SourceConfidenceReported {
		t.Fatalf("SourceConfidence = %q, want reported", envelope.SourceConfidence)
	}
	if envelope.SourceRef.SourceRecordID != envelope.StableFactKey {
		t.Fatalf("SourceRecordID = %q, want the stable key default", envelope.SourceRef.SourceRecordID)
	}
	if other.Partial {
		t.Fatal("scope B is partial, want complete (no warning facts)")
	}

	if _, err := ReplayClaimedScope(file, "kubernetes_live:does-not-exist"); err == nil {
		t.Fatal("ReplayClaimedScope(unknown) error = nil, want a scope mismatch")
	}
}

// parityClaim returns the fixed claim the parity proof replays under. Every
// field is a literal so the golden file is byte-stable across runs.
func parityClaim() sdkcollector.Claim {
	return sdkcollector.Claim{
		ComponentID:   "dev.eshu.collector.kubernetes-live",
		InstanceID:    "k8s-parity-replay",
		CollectorKind: CollectorKind,
		SourceSystem:  CollectorKind,
		Scope:         sdkcollector.Scope{ID: "kubernetes_live:replay-single", Kind: "cluster"},
		SourceRunID:   "run-parity-1",
		GenerationID:  "generation-parity-1",
		WorkItemID:    "work-parity-1",
		FencingToken:  "9",
		Attempt:       1,
		Deadline:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		ConfigHandle:  "component-config:kubernetes-live",
	}
}

// TestCassetteReplayDeterminismAndGolden proves what this repo can pin about
// cassette replay: the same scope yields the same ordered facts and stable
// keys, fact IDs re-derive deterministically across replays, and the wire
// facts match the checked-in golden file byte for byte. The File/Scope/Fact
// validation plus the envelope mapping are a mechanical port of the in-tree
// format.go/source.go at core commit 95dfc56ebb54, and the fact-ID derivation
// resolves through the published SDK identity package whose StableID body is
// identical to the in-tree one by code inspection: cross-system fact-ID
// equality with the in-tree DeriveFactID is assumed, not guarded by any test
// here, since the in-tree source is not vendored in this repo.
func TestCassetteReplayDeterminismAndGolden(t *testing.T) {
	t.Parallel()

	file, err := LoadFile("testdata/replay-single-cluster.json")
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	snapshot, err := ReplayClaimedScope(file, "kubernetes_live:replay-single")
	if err != nil {
		t.Fatalf("ReplayClaimedScope() error = %v", err)
	}
	if snapshot.Partial {
		t.Fatal("single-cluster snapshot is partial, want complete (no warning facts)")
	}

	result, err := ToSDKResult(parityClaim(), snapshot)
	if err != nil {
		t.Fatalf("ToSDKResult() error = %v", err)
	}
	if len(result.Facts) != 2 {
		t.Fatalf("facts = %d, want 2", len(result.Facts))
	}
	if result.Facts[0].Kind != KubernetesPodTemplateFactKind ||
		result.Facts[1].Kind != KubernetesRelationshipFactKind {
		t.Fatalf("kinds = %q, %q, want pod_template then relationship",
			result.Facts[0].Kind, result.Facts[1].Kind)
	}
	if result.Facts[0].StableKey != "1111111111111111111111111111111111111111111111111111111111111111" ||
		result.Facts[1].StableKey != "2222222222222222222222222222222222222222222222222222222222222222" {
		t.Fatal("stable keys were not preserved verbatim from the cassette")
	}
	for i, fact := range result.Facts {
		if fact.SourceRef.ScopeID != "kubernetes_live:replay-single" {
			t.Fatalf("fact[%d] scope = %q, want the replayed scope", i, fact.SourceRef.ScopeID)
		}
		if fact.SourceRef.FactKey != fact.StableKey {
			t.Fatalf("fact[%d] fact_key != stable_key", i)
		}
	}

	// Fact IDs must re-derive deterministically: the same cassette replays
	// the same IDs every run, exactly like the in-tree source restamping
	// from the CassetteReplay identity after a drain.
	again, err := ReplayClaimedScope(file, "kubernetes_live:replay-single")
	if err != nil {
		t.Fatalf("ReplayClaimedScope() error = %v", err)
	}
	for i := range snapshot.Envelopes {
		if snapshot.Envelopes[i].FactID == "" {
			t.Fatalf("envelope[%d] has no fact ID", i)
		}
		if snapshot.Envelopes[i].FactID != again.Envelopes[i].FactID {
			t.Fatalf("envelope[%d] fact ID is not stable across replays", i)
		}
	}

	encoded, err := json.MarshalIndent(result.Facts, "", "  ")
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	golden, err := os.ReadFile("testdata/replay-single-cluster.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(encoded) != string(golden) {
		t.Fatalf("replayed facts differ from the golden file (%d vs %d bytes)", len(encoded), len(golden))
	}
}

// TestReplayedWarningScopeIsPartial proves a scope that replays warning facts
// maps to a partial snapshot: the cassette schema carries no partial bit, so
// partial derives from the replayed envelopes (the live builder emits
// warnings exactly when evidence is degraded).
func TestReplayedWarningScopeIsPartial(t *testing.T) {
	t.Parallel()

	file, err := LoadFile("testdata/replay-warning-partial.json")
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	snapshot, err := ReplayClaimedScope(file, "kubernetes_live:replay-warn")
	if err != nil {
		t.Fatalf("ReplayClaimedScope() error = %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("warning scope is not partial, want partial (warning facts replayed)")
	}
	if snapshot.Generation.FreshnessHint != "partial" {
		t.Fatalf("FreshnessHint = %q, want partial", snapshot.Generation.FreshnessHint)
	}
	if len(snapshot.Envelopes) != 2 {
		t.Fatalf("envelopes = %d, want 2", len(snapshot.Envelopes))
	}
}
