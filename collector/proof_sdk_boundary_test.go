// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// SDK-result boundary proofs, split from proof_parity_test.go under the
// 500-line cap: the collected-snapshot boundary and the synthetic
// missing-kinds fixture the parity pack does not span.

func envelopesOfKind(envelopes []Envelope, kind string) []Envelope {
	var out []Envelope
	for _, envelope := range envelopes {
		if envelope.FactKind == kind {
			out = append(out, envelope)
		}
	}
	return out
}

// proofClaim builds the core-owned work-item identity for one collected
// snapshot, mirroring what the host passes at cutover: scope and generation
// from the observed evidence, fencing token formatted at the seam.
func proofClaim(scope ScopeInfo, generation GenerationInfo, fencingToken int64) sdkcollector.Claim {
	observedAt := generation.ObservedAt
	return sdkcollector.Claim{
		ComponentID:   "dev.eshu.collector.kubernetes-live",
		InstanceID:    "k8s-proof-1",
		CollectorKind: CollectorKind,
		SourceSystem:  CollectorKind,
		Scope:         sdkcollector.Scope{ID: scope.ScopeID, Kind: scope.ScopeKind},
		SourceRunID:   "run-proof-1",
		GenerationID:  generation.GenerationID,
		WorkItemID:    "work-proof-1",
		FencingToken:  strconv.FormatInt(fencingToken, 10),
		Attempt:       1,
		Deadline:      observedAt.Add(time.Hour),
		ConfigHandle:  "proof-config:kubernetes-live",
	}
}

// TestExtractedSDKResultBoundary proves the SDK wire conversion: state tracks
// partial, every envelope maps 1:1 onto an SDK Fact with its stable key,
// kind, version, payload, and source ref preserved, and a malformed claim
// fencing token fails closed instead of silently zeroing.
func TestExtractedSDKResultBoundary(t *testing.T) {
	t.Parallel()

	source := proofSource()
	collected, ok, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if !ok {
		t.Fatal("Next() ok = false, want the parity-full scope")
	}
	claim := proofClaim(collected.Scope, collected.Generation, 7)
	result, err := ToSDKResult(claim, collected)
	if err != nil {
		t.Fatalf("ToSDKResult() error = %v", err)
	}
	if result.ProtocolVersion != sdkcollector.ProtocolVersionV1Alpha1 {
		t.Fatalf("ProtocolVersion = %q, want v1alpha1", result.ProtocolVersion)
	}
	if result.State != sdkcollector.ResultComplete {
		t.Fatalf("State = %q, want complete for the non-partial scope", result.State)
	}
	if len(result.Facts) != len(collected.Envelopes) {
		t.Fatalf("Facts = %d, want %d (1:1 envelope mapping)", len(result.Facts), len(collected.Envelopes))
	}
	for i, fact := range result.Facts {
		envelope := collected.Envelopes[i]
		if fact.Kind != envelope.FactKind || fact.StableKey != envelope.StableFactKey ||
			fact.SchemaVersion != envelope.SchemaVersion {
			t.Fatalf("fact[%d] identity = %v/%v/%v, want %v/%v/%v", i,
				fact.Kind, fact.StableKey, fact.SchemaVersion,
				envelope.FactKind, envelope.StableFactKey, envelope.SchemaVersion)
		}
		// SourceSystem is claim-aligned by contract (see sdkFact); the
		// family value stays on the internal envelope, asserted by the
		// parity test above. The URI is re-sanitized at the boundary (see
		// sdkFact): identical for kubernetes_live facts, credential-free
		// for posture facts. Everything else in the ref is preserved.
		if fact.SourceRef.SourceSystem != claim.SourceSystem ||
			fact.SourceRef.ScopeID != envelope.SourceRef.ScopeID ||
			fact.SourceRef.GenerationID != envelope.SourceRef.GenerationID ||
			fact.SourceRef.FactKey != envelope.SourceRef.FactKey ||
			fact.SourceRef.URI != sanitizeURL(envelope.SourceRef.SourceURI) ||
			fact.SourceRef.RecordID != envelope.SourceRef.SourceRecordID {
			t.Fatalf("fact[%d] source ref not preserved: %#v", i, fact.SourceRef)
		}
		if strings.Contains(fact.SourceRef.URI, "HOSTILESECRET") || strings.Contains(fact.SourceRef.URI, "HOSTILETOKEN") {
			t.Fatalf("fact[%d] wire URI carries credential material: %q", i, fact.SourceRef.URI)
		}
		if string(fact.SourceConfidence) != SourceConfidenceReported {
			t.Fatalf("fact[%d] confidence = %q, want reported", i, fact.SourceConfidence)
		}
	}

	// The hostile scope converts to partial with a warning status.
	if _, _, err := source.Next(context.Background()); err != nil {
		t.Fatalf("advance Next() error = %v", err)
	}
	_ = collected
	hostileSrc := proofSource()
	if _, _, err := hostileSrc.Next(context.Background()); err != nil {
		t.Fatalf("full Next() error = %v", err)
	}
	hostile, ok, err := hostileSrc.Next(context.Background())
	if err != nil {
		t.Fatalf("hostile Next() error = %v", err)
	}
	if !ok {
		t.Fatal("hostile Next() ok = false")
	}
	hostileResult, err := ToSDKResult(proofClaim(hostile.Scope, hostile.Generation, 9), hostile)
	if err != nil {
		t.Fatalf("ToSDKResult(hostile) error = %v", err)
	}
	if hostileResult.State != sdkcollector.ResultPartial {
		t.Fatalf("hostile State = %q, want partial", hostileResult.State)
	}
	if len(hostileResult.Statuses) != 1 || !hostileResult.Statuses[0].Partial {
		t.Fatalf("hostile Statuses = %#v, want one partial warning status", hostileResult.Statuses)
	}

	// A present-but-unparseable claim fencing token fails closed.
	bad := proofClaim(collected.Scope, collected.Generation, 7)
	bad.FencingToken = "not-an-int"
	if _, err := ToSDKResult(bad, collected); err == nil {
		t.Fatal("ToSDKResult with unparseable fencing token succeeded, want terminal caller error")
	}

	// Batch exhaustion yields a complete, fact-free result.
	exhausted := ExhaustedResult(claim)
	if exhausted.State != sdkcollector.ResultComplete || len(exhausted.Facts) != 0 {
		t.Fatalf("ExhaustedResult = %#v, want complete with zero facts", exhausted)
	}
}

// kinds the parity pack does not span (rbac_role, rbac_binding,
// pod_identity_association), proving the constructors the ported RBAC unit
// tests exercise emit payloads the published schemas and the full
// publication harness accept.
func missingKindsFixture(t *testing.T) sdkcollector.Result {
	t.Helper()

	ctx := KubernetesContext{
		ClusterID:           "proof-missing-kinds",
		ScopeID:             "kubernetes_live:proof-missing-kinds",
		GenerationID:        "gen-missing-kinds-1",
		CollectorInstanceID: "k8s-proof-1",
		FencingToken:        11,
		ObservedAt:          proofObservedAt,
		SourceURI:           "https://api.proof-missing-kinds.example.test",
	}
	roleEnv, err := NewKubernetesRBACRoleEnvelope(KubernetesRBACRoleObservation{
		Context: ctx, RoleKind: RBACRoleKindRole, Namespace: "payments",
		Name: "secret-reader", UID: "uid-role-missing-1",
		Rules: []KubernetesRBACRuleSummary{{
			Verbs: []string{"get", "list"}, APIGroups: []string{""},
			Resources:         []string{"secrets"},
			ResourceNameCount: 1, ResourceNamesPresent: true,
		}},
	})
	if err != nil {
		t.Fatalf("NewKubernetesRBACRoleEnvelope() error = %v", err)
	}
	bindEnv, err := NewKubernetesRBACBindingEnvelope(KubernetesRBACBindingObservation{
		Context: ctx, BindingKind: BindingKindRoleBinding, Namespace: "payments",
		Name: "read-secrets", UID: "uid-binding-missing-1",
		RoleRefKind: RBACRoleKindRole, RoleRefName: "secret-reader",
		Subjects: []KubernetesRBACSubject{{Kind: "ServiceAccount", Namespace: "payments", Name: "checkout-sa"}},
	})
	if err != nil {
		t.Fatalf("NewKubernetesRBACBindingEnvelope() error = %v", err)
	}
	assocEnv, err := NewEKSPodIdentityAssociationEnvelope(EKSPodIdentityAssociationObservation{
		Context: ctx, AssociationID: "a-missing-1", ClusterName: "proof-missing-kinds",
		Namespace: "payments", ServiceAccountName: "checkout-sa",
		RoleARN: "arn:aws:iam::123456789012:role/proof-missing",
	})
	if err != nil {
		t.Fatalf("NewEKSPodIdentityAssociationEnvelope() error = %v", err)
	}
	collected := CollectedSnapshot{
		Scope:      ScopeInfo{ScopeID: ctx.ScopeID, ScopeKind: "cluster"},
		Generation: GenerationInfo{GenerationID: ctx.GenerationID, ObservedAt: ctx.ObservedAt},
		Envelopes:  []Envelope{roleEnv, bindEnv, assocEnv},
	}
	claim := proofClaim(collected.Scope, collected.Generation, ctx.FencingToken)
	result, err := ToSDKResult(claim, collected)
	if err != nil {
		t.Fatalf("ToSDKResult() error = %v", err)
	}
	if len(result.Facts) != 3 {
		t.Fatalf("Facts = %d, want 3 (one per missing kind)", len(result.Facts))
	}
	return result
}

// TestExtractedMissingKindsPassConformance proves the three declared kinds
// the parity pack does not span satisfy the full SDK publication contract:
// the harness (manifest, trusted coverage, payload schemas, claim/ref
// agreement, credential-free URIs) passes against synthetic fixtures built
// from the same constructors production collection uses.
func TestExtractedMissingKindsPassConformance(t *testing.T) {
	t.Parallel()

	manifest := proofManifest()
	coreFacts, schemas := proofCoreFacts(t, manifest)
	reserved := make([]string, 0, len(manifest.Spec.EmittedFacts))
	for _, family := range manifest.Spec.EmittedFacts {
		reserved = append(reserved, family.Kind)
	}
	fixture := missingKindsFixture(t)
	if err := conformance.ValidatePayloadSchemas(schemas, fixture); err != nil {
		t.Fatalf("missing-kinds payload schema: %v", err)
	}

	report := conformance.Run(conformance.Request{
		Manifest:          manifest,
		Fixtures:          []sdkcollector.Result{fixture},
		Mode:              conformance.ModeFixture,
		ReservedFactKinds: reserved,
		CoreFacts:         coreFacts,
		PayloadSchemas:    schemas,
	})
	if !report.OK() {
		t.Fatalf("conformance findings = %#v, want passed", report.Findings)
	}
	if report.Summary.FactCount != 3 {
		t.Fatalf("FactCount = %d, want 3", report.Summary.FactCount)
	}
}
