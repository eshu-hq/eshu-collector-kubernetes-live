// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestCountWarningsCountsOnlyWarningFacts(t *testing.T) {
	t.Parallel()

	envelopes := []corecollector.Envelope{
		{FactKind: FactKindWarning},
		{FactKind: "kubernetes_live.namespace"},
		{FactKind: FactKindWarning},
	}
	if got := countWarnings(envelopes); got != 2 {
		t.Fatalf("countWarnings() = %d, want 2", got)
	}
	if got := countWarnings(nil); got != 0 {
		t.Fatalf("countWarnings(nil) = %d, want 0", got)
	}
}

func TestCheckBudgetsRejectsRecordOverflow(t *testing.T) {
	t.Parallel()

	limits := ResourceUse{MaxRecordsPerClaim: 1, MaxPayloadBytes: 1 << 20}
	facts := []sdk.Fact{{Payload: map[string]any{}}, {Payload: map[string]any{}}}
	if got := checkBudgets(facts, limits); got != FailureRecordBudget {
		t.Fatalf("checkBudgets() = %q, want %q", got, FailureRecordBudget)
	}
}

func TestCheckBudgetsRejectsPayloadOverflow(t *testing.T) {
	t.Parallel()

	limits := ResourceUse{MaxRecordsPerClaim: 10, MaxPayloadBytes: 4}
	facts := []sdk.Fact{{Payload: map[string]any{"k": strings.Repeat("v", 64)}}}
	if got := checkBudgets(facts, limits); got != FailurePayloadBudget {
		t.Fatalf("checkBudgets() = %q, want %q", got, FailurePayloadBudget)
	}
}

func TestCheckBudgetsAcceptsFittingFacts(t *testing.T) {
	t.Parallel()

	limits := ResourceUse{MaxRecordsPerClaim: 10, MaxPayloadBytes: 1 << 20}
	facts := []sdk.Fact{{Payload: map[string]any{"k": "v"}}}
	if got := checkBudgets(facts, limits); got != "" {
		t.Fatalf("checkBudgets() = %q, want no failure", got)
	}
}

func TestEmitWritesOneJSONLine(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	Handler{Log: &buf}.logSuccess(validTestClaimForEmit(), sdk.Result{State: sdk.ResultComplete})
	line := strings.TrimSpace(buf.String())
	if line == "" || strings.Contains(line, "\n") {
		t.Fatalf("emit() wrote %q, want one JSON line", buf.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("emit() wrote invalid JSON: %v", err)
	}
	if decoded["outcome"] != string(sdk.ResultComplete) {
		t.Fatalf("outcome = %v, want the result state", decoded["outcome"])
	}
}

func TestEmitWithNilLogDiscards(t *testing.T) {
	t.Parallel()

	Handler{}.emit(logLine{Event: "test"})
}

func TestHandlerClockDefaultsToWallTime(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	got := Handler{}.now()
	if got.Before(before) || time.Since(got) > time.Minute {
		t.Fatalf("Handler{}.now() = %v, want ~wall time", got)
	}
	fixed := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	if got := (Handler{Now: func() time.Time { return fixed }}).now(); !got.Equal(fixed) {
		t.Fatalf("injected clock now() = %v, want %v", got, fixed)
	}
}

func completeTestSnapshot() corecollector.CollectedSnapshot {
	return corecollector.CollectedSnapshot{
		Envelopes: []corecollector.Envelope{
			{FactKind: "kubernetes_live.namespace", Payload: map[string]any{"k": "v"}},
			{FactKind: "kubernetes_live.namespace", Payload: map[string]any{"k": "v"}},
		},
	}
}

func generousTestLimits() ResourceUse {
	return ResourceUse{MaxRecordsPerClaim: 100, MaxPayloadBytes: 1 << 20, MaxResultBytes: 1 << 20}
}

func TestCompleteResultSucceedsOnFittingSnapshots(t *testing.T) {
	t.Parallel()

	claim := validTestClaimForEmit()
	result := Handler{}.completeResult(claim, completeTestSnapshot(), time.Now().UTC(), generousTestLimits())
	if result.State != sdk.ResultComplete {
		t.Fatalf("state = %q, want complete", result.State)
	}
	if len(result.Facts) != 2 {
		t.Fatalf("facts = %d, want 2", len(result.Facts))
	}
}

func TestCompleteResultRejectsABadFencingToken(t *testing.T) {
	t.Parallel()

	claim := validTestClaimForEmit()
	claim.FencingToken = "seven"
	result := Handler{}.completeResult(claim, completeTestSnapshot(), time.Now().UTC(), generousTestLimits())
	if result.State != sdk.ResultTerminal {
		t.Fatalf("state = %q, want terminal invalid_config", result.State)
	}
}

func TestCompleteResultEnforcesTheRecordBudget(t *testing.T) {
	t.Parallel()

	limits := generousTestLimits()
	limits.MaxRecordsPerClaim = 1
	result := Handler{}.completeResult(validTestClaimForEmit(), completeTestSnapshot(), time.Now().UTC(), limits)
	if result.State != sdk.ResultTerminal {
		t.Fatalf("state = %q, want terminal record budget", result.State)
	}
	if result.Statuses[0].FailureClass != FailureRecordBudget {
		t.Fatalf("class = %q, want %q", result.Statuses[0].FailureClass, FailureRecordBudget)
	}
}

func TestCompleteResultMarksPartialSnapshots(t *testing.T) {
	t.Parallel()

	snap := completeTestSnapshot()
	snap.Partial = true
	result := Handler{}.completeResult(validTestClaimForEmit(), snap, time.Now().UTC(), generousTestLimits())
	if result.State != sdk.ResultPartial {
		t.Fatalf("state = %q, want partial", result.State)
	}
}

func TestCompleteResultEnforcesTheResultBudget(t *testing.T) {
	t.Parallel()

	limits := generousTestLimits()
	limits.MaxResultBytes = 1
	result := Handler{}.completeResult(validTestClaimForEmit(), completeTestSnapshot(), time.Now().UTC(), limits)
	if result.State != sdk.ResultTerminal {
		t.Fatalf("state = %q, want terminal result budget", result.State)
	}
	if result.Statuses[0].FailureClass != FailureResultBudget {
		t.Fatalf("class = %q, want %q", result.Statuses[0].FailureClass, FailureResultBudget)
	}
}

func validTestClaimForEmit() sdk.Claim {
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "k8s-qa-1",
		CollectorKind: CollectorKind,
		SourceSystem:  SourceSystem,
		Scope:         sdk.Scope{ID: "cluster-scope", Kind: "cluster"},
		GenerationID:  "generation-1",
		WorkItemID:    "work-1",
		Attempt:       1,
	}
}

func TestRetryAfterSecondsCeilsPositiveDurations(t *testing.T) {
	t.Parallel()

	if got := retryAfterSeconds(Failure{RetryAfter: 1500 * time.Millisecond}); got != 2 {
		t.Fatalf("retryAfterSeconds(1.5s) = %d, want 2", got)
	}
	if got := retryAfterSeconds(Failure{}); got != defaultRetryAfterSeconds {
		t.Fatalf("retryAfterSeconds(zero) = %d, want the default %d", got, defaultRetryAfterSeconds)
	}
}

func TestClampedDeadlineTimeoutCoversAllBranches(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	if got, ok := clampedDeadlineTimeout(now, time.Time{}, 30*time.Second); !ok || got != 30*time.Second {
		t.Fatalf("zero deadline = (%v, %v), want (budget, true)", got, ok)
	}
	if _, ok := clampedDeadlineTimeout(now, now.Add(-time.Second), 30*time.Second); ok {
		t.Fatal("spent deadline ok = true, want false")
	}
	// Far deadline: the budget wins untouched.
	if got, ok := clampedDeadlineTimeout(now, now.Add(time.Hour), 30*time.Second); !ok || got != 30*time.Second {
		t.Fatalf("far deadline = (%v, %v), want (budget, true)", got, ok)
	}
	// Near deadline: the margin eats into the budget.
	got, ok := clampedDeadlineTimeout(now, now.Add(10*time.Second), 30*time.Second)
	if !ok || got >= 30*time.Second || got <= 0 {
		t.Fatalf("near deadline = (%v, %v), want a clamped positive timeout below budget", got, ok)
	}
}

func TestFencingTokenParsesAndRejects(t *testing.T) {
	t.Parallel()

	if got, err := fencingToken(" 7 "); err != nil || got != 7 {
		t.Fatalf("fencingToken(\" 7 \") = (%d, %v), want (7, nil)", got, err)
	}
	if got, err := fencingToken(""); err != nil || got != 0 {
		t.Fatalf("fencingToken(\"\") = (%d, %v), want (0, nil)", got, err)
	}
	if _, err := fencingToken("seven"); err == nil {
		t.Fatal("fencingToken(\"seven\") error = nil, want rejection")
	}
}

func TestDecodeReasonMapsEveryBranch(t *testing.T) {
	t.Parallel()

	typeErr := &json.UnmarshalTypeError{Value: "number", Type: reflect.TypeOf(""), Field: "limits.x"}
	if got := decodeReason(typeErr); got != "field limits.x has the wrong type" {
		t.Fatalf("type error reason = %q", got)
	}
	if got := decodeReason(errLimitsUnknownField); got != "unknown field" {
		t.Fatalf("unknown-field reason = %q", got)
	}
	if got := decodeReason(errors.New("boom")); got != "malformed JSON" {
		t.Fatalf("opaque error reason = %q, want malformed JSON", got)
	}
}
