// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-kubernetes-live"
	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func liveClaim(t *testing.T) sdk.Claim {
	t.Helper()
	scopeID, err := corecollector.ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatal(err)
	}
	return sdk.Claim{
		ComponentID:   collector.ComponentID,
		InstanceID:    "k8s-qa-1",
		CollectorKind: collector.CollectorKind,
		SourceSystem:  collector.SourceSystem,
		Scope:         sdk.Scope{ID: scopeID, Kind: "cluster"},
		SourceRunID:   "run-1",
		GenerationID:  "generation-1",
		WorkItemID:    "work-1",
		FencingToken:  "7",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Hour).UTC(),
		ConfigHandle:  "component-config:kubernetes-live",
	}
}

func liveRequest(t *testing.T) string {
	t.Helper()
	return liveRequestWith(t, liveClaim(t))
}

func liveRequestWith(t *testing.T, claim sdk.Claim) string {
	t.Helper()
	raw, err := json.Marshal(collector.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1, Claim: claim, Contract: collector.Contract(),
		Config: map[string]any{
			"targets": []any{map[string]any{
				"cluster_id": "ops-qa-1",
				"source_uri": "https://kubernetes.default.svc",
			}},
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
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func getenv(key string) string { return "" }

// TestRunClaimProvesConfigAcceptanceWithoutACluster is the binary-level proof
// that a live-shaped SDK request is accepted: with no cluster backend the
// binary still decodes the host envelope and serves a valid result. The
// result is terminal collection_failed — the config was accepted and the
// scope matched — never invalid_config and never a process error.
func TestRunClaimProvesConfigAcceptanceWithoutACluster(t *testing.T) {
	t.Parallel()

	claim := liveClaim(t)
	request := liveRequestWith(t, claim)
	for _, args := range [][]string{nil, {"--sdk-stdio"}} {
		var stdout, stderr bytes.Buffer
		err := run(context.Background(), args, strings.NewReader(request), &stdout, &stderr, getenv)
		if err != nil {
			t.Fatalf("run(%v) error = %v", args, err)
		}
		decoder := json.NewDecoder(&stdout)
		decoder.DisallowUnknownFields()
		var result sdk.Result
		if err := decoder.Decode(&result); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if result.State != sdk.ResultTerminal {
			t.Fatalf("State = %q, want terminal (no cluster backend)", result.State)
		}
		if len(result.Statuses) != 1 || result.Statuses[0].FailureClass != collector.FailureCollection {
			t.Fatalf("Statuses = %+v, want one collection_failed", result.Statuses)
		}
		if len(result.Facts) != 0 {
			t.Fatal("failed result carries facts")
		}
		if roundTripped := roundTripClaim(t, claim); result.Claim != roundTripped {
			t.Fatalf("Claim was not echoed: %+v", result.Claim)
		}
		// The binary logs exactly one bounded diagnostic line per claim.
		if lines := strings.Count(strings.TrimSpace(stderr.String()), "\n"); lines != 0 {
			t.Fatalf("stderr = %q, want exactly one log line", stderr.String())
		}
	}
}

// roundTripClaim normalizes a claim through JSON so the test can compare it
// with the decoded echo: time.Time loses its monotonic reading on the wire.
func roundTripClaim(t *testing.T, claim sdk.Claim) sdk.Claim {
	t.Helper()
	raw, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	var got sdk.Claim
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// TestRunClaimReportsConfigFailureAsTerminalResultNotCrash proves a claim for
// an unconfigured cluster is a bounded terminal result instead of a crash.
func TestRunClaimReportsConfigFailureAsTerminalResultNotCrash(t *testing.T) {
	t.Parallel()

	claim := liveClaim(t)
	claim.Scope.ID = "kubernetes_live:does-not-match-any-target"
	raw := liveRequestWith(t, claim)
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), nil, strings.NewReader(raw), &stdout, &stderr, func(string) string { return "" })
	if err != nil {
		t.Fatalf("run() error = %v; a config failure is a bounded terminal result", err)
	}
	var result sdk.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State != sdk.ResultTerminal || result.Statuses[0].FailureClass != collector.FailureInvalidConfig {
		t.Fatalf("result = %+v", result)
	}
}

// TestRunRejectsBadInvocations proves malformed invocations fail the process
// loudly instead of emitting a result.
func TestRunRejectsBadInvocations(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		args  []string
		stdin string
	}{
		"empty stdin":      {nil, ""},
		"garbage stdin":    {nil, "{nope"},
		"extra argument":   {[]string{"serve"}, "{}"},
		"unknown flag":     {[]string{"--nope"}, "{}"},
		"wrong protocol":   {nil, `{"protocol_version":"x"}`},
		"unknown seed arg": {[]string{"seed", "extra"}, ""},
		"seed no dest":     {[]string{"seed"}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if err := run(context.Background(), tc.args, strings.NewReader(tc.stdin), &stdout, &stderr, getenv); err == nil {
				t.Fatal("run() error = nil, want failure")
			}
			if stdout.Len() != 0 {
				t.Fatalf("a rejected invocation wrote %q to stdout", stdout.String())
			}
		})
	}
}
