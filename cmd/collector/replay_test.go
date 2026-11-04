// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-kubernetes-live"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestSeededBinaryStillServesClaim guards the seed subcommand while the claim
// plane gains cassette replay: the `seed` dispatch still installs the binary
// and manifest, and the same binary entrypoint still serves one claim from
// stdin — here a credential-free cassette replay, proving the seeded binary
// serves claims without a live backend behind it.
func TestSeededBinaryStillServesClaim(t *testing.T) {
	t.Parallel()

	dest := filepath.Join(t.TempDir(), "component")
	var seedStdout, seedStderr bytes.Buffer
	if err := run(context.Background(), []string{"seed", "--dest", dest},
		strings.NewReader(""), &seedStdout, &seedStderr, getenv); err != nil {
		t.Fatalf("run(seed) error = %v", err)
	}
	for _, name := range []string{"collector", "manifest.yaml"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Fatalf("seeded %s: %v", name, err)
		}
	}

	claim := sdk.Claim{
		ComponentID:   collector.ComponentID,
		InstanceID:    "k8s-seed-replay-test",
		CollectorKind: collector.CollectorKind,
		SourceSystem:  collector.SourceSystem,
		Scope:         sdk.Scope{ID: "kubernetes_live:replay-single", Kind: "cluster"},
		SourceRunID:   "run-seed-1",
		GenerationID:  "generation-seed-1",
		WorkItemID:    "work-seed-1",
		FencingToken:  "9",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Hour).UTC(),
		ConfigHandle:  "component-config:kubernetes-live",
	}
	raw, err := json.Marshal(collector.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1, Claim: claim, Contract: collector.Contract(),
		Config: map[string]any{
			"cassette_file": "../../collector/testdata/replay-single-cluster.json",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), nil,
		strings.NewReader(string(raw)), &stdout, &stderr, getenv); err != nil {
		t.Fatalf("run(claim) error = %v", err)
	}
	var result sdk.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if len(result.Facts) != 2 {
		t.Fatalf("Facts = %d, want 2 replayed facts", len(result.Facts))
	}
}
