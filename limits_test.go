// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUnmarshalJSONAcceptsEitherSpelling proves the dual-spelling contract:
// snake_case activation keys and camelCase host keys decode to the same
// bounds, the activation spelling wins when both are present, null decodes
// to zero, and unknown keys fail closed without naming the key.
func TestUnmarshalJSONAcceptsEitherSpelling(t *testing.T) {
	t.Parallel()

	var snake, camel ResourceUse
	if err := json.Unmarshal([]byte(`{"max_records_per_claim": 7}`), &snake); err != nil {
		t.Fatalf("snake_case decode error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{"maxRecordsPerClaim": 7}`), &camel); err != nil {
		t.Fatalf("camelCase decode error = %v", err)
	}
	if snake.MaxRecordsPerClaim != 7 || camel.MaxRecordsPerClaim != 7 {
		t.Fatalf("decoded bounds = (%d, %d), want (7, 7)", snake.MaxRecordsPerClaim, camel.MaxRecordsPerClaim)
	}
	var both ResourceUse
	if err := json.Unmarshal([]byte(`{"max_records_per_claim": 7, "maxRecordsPerClaim": 9}`), &both); err != nil {
		t.Fatalf("both-spellings decode error = %v", err)
	}
	if both.MaxRecordsPerClaim != 7 {
		t.Fatalf("both-spellings bound = %d, want the snake_case 7", both.MaxRecordsPerClaim)
	}
	var zero ResourceUse
	if err := json.Unmarshal([]byte(`null`), &zero); err != nil {
		t.Fatalf("null decode error = %v", err)
	}
	var wrongType ResourceUse
	if err := json.Unmarshal([]byte(`{"max_records_per_claim": "many"}`), &wrongType); err == nil {
		t.Fatal("wrong-type decode error = nil, want rejection")
	}
	var unknown ResourceUse
	err := json.Unmarshal([]byte(`{"totally_new_key": 1}`), &unknown)
	if err == nil {
		t.Fatal("unknown-key decode error = nil, want fail-closed rejection")
	}
	if strings.Contains(err.Error(), "totally_new_key") {
		t.Fatalf("unknown-key error names the key: %v", err)
	}
}

// TestLimitsWithDefaultsClampsToCeilings proves the ceilings named in
// limits.go are enforced: an over-ceiling activation value resolves to the
// ceiling instead of sizing per-claim memory/CPU without limit.
func TestLimitsWithDefaultsClampsToCeilings(t *testing.T) {
	t.Parallel()

	over := ResourceUse{
		MaxRecordsPerClaim:  5_000_000,
		MaxPayloadBytes:     64 << 20,
		MaxResultBytes:      512 << 20,
		ClaimTimeoutSeconds: 7200,
	}
	got := over.withDefaults()
	want := ResourceUse{
		MaxRecordsPerClaim:  maxRecordsCeiling,
		MaxPayloadBytes:     maxPayloadCeiling,
		MaxResultBytes:      maxResultCeiling,
		ClaimTimeoutSeconds: maxTimeoutCeiling,
	}
	if got != want {
		t.Fatalf("withDefaults(over-ceiling) = %+v, want %+v", got, want)
	}
}

// TestLimitsOverlayClampsToCeilings proves the merged activation value (the
// target's own bounds with the envelope filling the gaps) is clamped too: a
// large envelope value cannot escape through the overlay path.
func TestLimitsOverlayClampsToCeilings(t *testing.T) {
	t.Parallel()

	target := ResourceUse{MaxRecordsPerClaim: 5_000_000}
	envelope := ResourceUse{
		MaxRecordsPerClaim:  50_000,
		MaxPayloadBytes:     64 << 20,
		MaxResultBytes:      3 << 20,
		ClaimTimeoutSeconds: 300,
	}
	got := target.overlay(envelope)
	if got.MaxRecordsPerClaim != maxRecordsCeiling {
		t.Fatalf("overlay MaxRecordsPerClaim = %d, want ceiling %d", got.MaxRecordsPerClaim, maxRecordsCeiling)
	}
	if got.MaxPayloadBytes != maxPayloadCeiling {
		t.Fatalf("overlay MaxPayloadBytes = %d, want ceiling %d", got.MaxPayloadBytes, maxPayloadCeiling)
	}
}

// TestLimitsAtCeilingPassThrough proves values at exactly the ceiling are
// kept: the clamp only cuts values above it.
func TestLimitsAtCeilingPassThrough(t *testing.T) {
	t.Parallel()

	at := ResourceUse{
		MaxRecordsPerClaim:  maxRecordsCeiling,
		MaxPayloadBytes:     maxPayloadCeiling,
		MaxResultBytes:      maxResultCeiling,
		ClaimTimeoutSeconds: maxTimeoutCeiling,
	}
	if got := at.withDefaults(); got != at {
		t.Fatalf("withDefaults(at-ceiling) = %+v, want %+v", got, at)
	}
}
