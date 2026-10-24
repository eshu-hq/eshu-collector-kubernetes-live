// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"strconv"
	"strings"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
)

// This file is new in the extraction (no in-tree origin): it is the boundary
// where the collector-owned emission model meets the published SDK wire
// contract. Per SHIM_MAP §1 (eshu-hq/eshu#8859), in-tree outcomes map to SDK
// ResultState as follows:
//
//   - envelopes committed -> "complete"
//   - ok=false, batch exhausted -> "complete" with zero facts, or "unchanged"
//   - hard error (ping failure, missing auth, invalid config) -> "terminal"
//   - forbidden/partial family list -> "partial" + warning Status +
//     kubernetes_live.warning facts (already in-band in the envelopes)
//   - cancellation -> no result
//
// The retryable set for transient API-server errors is a cutover follow-up
// (SHIM_MAP §6.4); this proof returns what the source yields and lets the
// host classify transport errors.

// SDKProtocolVersion is the collector extension wire contract this producer
// speaks (mirrors the SDK const so a bump is a deliberate edit).
const SDKProtocolVersion = sdkcollector.ProtocolVersionV1Alpha1

// ToSDKResult converts one collected snapshot into the SDK Result wire form
// for the given claim. The claim carries the core-owned work-item identity;
// the snapshot carries the observed evidence. FencingToken arrives on the
// claim as a string (SHIM_MAP §6.7) and must round-trip exactly: a claim
// fencing token that is present but unparseable as an int64 is a terminal
// caller error, never a silent zero.
func ToSDKResult(claim sdkcollector.Claim, snap CollectedSnapshot) (sdkcollector.Result, error) {
	if strings.TrimSpace(string(claim.FencingToken)) != "" {
		if _, err := strconv.ParseInt(strings.TrimSpace(string(claim.FencingToken)), 10, 64); err != nil {
			return sdkcollector.Result{}, fmt.Errorf("claim fencing_token %q does not round-trip to int64: %w", claim.FencingToken, err)
		}
	}
	state := sdkcollector.ResultComplete
	if snap.Partial {
		state = sdkcollector.ResultPartial
	}
	facts := make([]sdkcollector.Fact, 0, len(snap.Envelopes))
	for _, envelope := range snap.Envelopes {
		facts = append(facts, sdkFact(claim, envelope))
	}
	result := sdkcollector.Result{
		ProtocolVersion: SDKProtocolVersion,
		State:           state,
		Claim:           claim,
		Generation: sdkcollector.Generation{
			ID:            snap.Generation.GenerationID,
			ObservedAt:    snap.Generation.ObservedAt,
			FreshnessHint: snap.Generation.FreshnessHint,
		},
		Facts: facts,
	}
	if snap.Partial {
		result.Statuses = []sdkcollector.Status{{
			Class:        sdkcollector.StatusWarning,
			Partial:      true,
			WarningCount: countWarnings(snap.Envelopes),
			FactCount:    len(facts),
		}}
	}
	return result, nil
}

// ExhaustedResult builds the batch-drained result: complete with zero facts.
func ExhaustedResult(claim sdkcollector.Claim) sdkcollector.Result {
	return sdkcollector.Result{
		ProtocolVersion: SDKProtocolVersion,
		State:           sdkcollector.ResultComplete,
		Claim:           claim,
	}
}

// sdkFact maps one collector-owned envelope onto the SDK Fact wire shape
// (SHIM_MAP §3): stable_key <- envelope stable key, source_confidence <-
// reported, source_ref.scope_id <- cluster scope, source_ref.generation_id <-
// committed generation, payload <- factschema-encoded contract payload,
// redactions <- fingerprint/annotation-allowlist redactions.
//
// SourceSystem is claim-aligned, not envelope-verbatim: the published SDK
// contract (collector/validation.go validateSourceRef) requires every fact's
// source_ref.source_system to equal the claim's source_system, so the
// in-tree per-fact family value (posture facts carry "secrets_iam_posture"
// inside a "kubernetes_live" scope) cannot travel verbatim on the wire. The
// dual-kind emission is preserved where the contract allows it: the 6 posture
// fact kinds stay distinct (no posture fact is renormalized into a
// kubernetes_live.* kind), and the component manifest plus CoreFacts
// authorizations declare the per-kind family mapping the host stamps
// downstream. Flagged for reviewer attention in the proof PR.
//
// SourceURI is re-sanitized at the boundary for every fact. The
// kubernetes_live seam already sanitizes in-tree (idempotent here); the
// posture seam carries the operator URI verbatim pre-extraction (known gap,
// pinned on the internal envelope by the parity test), and the SDK contract
// (validateSourceURI) refuses credential-bearing URIs. The boundary therefore
// applies the same sanitizeURL rule to posture facts. An operator target with
// no SourceURI still yields a wire-invalid empty URI (the contract requires
// it non-empty): configuring source_uri per target is an open cutover item,
// recorded in the proof README, not silently defaulted here.
func sdkFact(claim sdkcollector.Claim, envelope Envelope) sdkcollector.Fact {
	return sdkcollector.Fact{
		Kind:             envelope.FactKind,
		SchemaVersion:    envelope.SchemaVersion,
		StableKey:        envelope.StableFactKey,
		SourceConfidence: sdkcollector.SourceConfidence(envelope.SourceConfidence),
		ObservedAt:       envelope.ObservedAt,
		SourceRef: sdkcollector.SourceRef{
			SourceSystem: claim.SourceSystem,
			ScopeID:      envelope.SourceRef.ScopeID,
			GenerationID: envelope.SourceRef.GenerationID,
			FactKey:      envelope.SourceRef.FactKey,
			URI:          sanitizeURL(envelope.SourceRef.SourceURI),
			RecordID:     envelope.SourceRef.SourceRecordID,
		},
		Payload: envelope.Payload,
	}
}

func countWarnings(envelopes []Envelope) int {
	n := 0
	for _, envelope := range envelopes {
		if envelope.FactKind == KubernetesWarningFactKind ||
			envelope.FactKind == SecretsIAMCoverageWarningFactKind {
			n++
		}
	}
	return n
}
