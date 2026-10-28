// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

// Publication-conformance proofs, split from proof_parity_test.go under
// the 500-line cap: the emitted-family manifest and the schema and
// full-harness checks.

// proofManifest declares this producer's emitted families for the
// conformance harness: the 4 kubernetes_live kinds plus the 9 posture kinds
// the manifest/contract/grants advertise (13 total), all reported
// confidence, all trusted to this producer's two collector kinds. The
// fixture pack pins 10 of them; the remaining three (rbac_role,
// rbac_binding, pod_identity_association) are proven by synthetic fixtures
// in TestExtractedMissingKindsPassConformance.
func proofManifest() conformance.Manifest {
	families := []conformance.FactFamily{
		{Kind: KubernetesNamespaceFactKind, SchemaVersions: []string{KubernetesNamespaceSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesPodTemplateFactKind, SchemaVersions: []string{KubernetesPodTemplateSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesRelationshipFactKind, SchemaVersions: []string{KubernetesRelationshipSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesWarningFactKind, SchemaVersions: []string{KubernetesWarningSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesServiceAccountFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesRBACRoleFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesRBACBindingFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesWorkloadIdentityUseFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesGCPWorkloadIdentityBindingFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesServiceAccountTokenPostureFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: EKSIRSAAnnotationFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: EKSPodIdentityAssociationFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: SecretsIAMCoverageWarningFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
	}
	return conformance.Manifest{
		APIVersion: "eshu.dev/v1alpha1",
		Kind:       "ComponentPackage",
		Metadata: conformance.Metadata{
			ID:        "dev.eshu.collector.kubernetes-live",
			Name:      "Kubernetes live collector",
			Publisher: "eshu-hq",
			Version:   "0.1.0",
		},
		Spec: conformance.Spec{
			CompatibleCore: ">=0.0.5 <0.2.0",
			ComponentType:  "collector",
			CollectorKinds: []string{CollectorKind, PostureCollectorKind},
			Runtime: conformance.RuntimeContract{
				SDKProtocol: sdkcollector.ProtocolVersionV1Alpha1,
				Adapter:     "process",
			},
			// Proof placeholder: the release artifact does not exist yet
			// (cutover phase). The digest below is not a published claim;
			// it satisfies the harness's artifact-presence rule so payload
			// conformance can run before release.
			Artifacts: []conformance.Artifact{{
				Platform: "linux/amd64",
				Image:    "ghcr.io/eshu-hq/eshu-collector-kubernetes-live@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			}},
			EmittedFacts: families,
			ConsumerContracts: conformance.ConsumerContracts{
				Reducer: conformance.ReducerContract{
					Phases: []string{conformance.SourceEvidenceOnlyReducerPhase},
				},
			},
		},
	}
}

// proofCoreFacts authorizes this producer's exact emission coverage per
// reserved kind: each kind lists the collector kinds that emit it and the
// schema versions they emit, with payload schemas resolved from the pinned
// fixture pack.
func proofCoreFacts(t *testing.T, manifest conformance.Manifest) (*conformance.CoreFactContext, map[string]json.RawMessage) {
	if t != nil {
		t.Helper()
	}

	authorizations := []conformance.CoreFactAuthorization{}
	schemas := map[string]json.RawMessage{}
	for _, family := range manifest.Spec.EmittedFacts {
		schema, ok := fixturepack.SchemaFor(family.Kind)
		if !ok {
			t.Fatalf("pinned fixture pack ships no schema for %q", family.Kind)
		}
		schemas[family.Kind] = schema
		// Dual-kind authorization: every kind this producer emits is
		// covered under the claim's primary collector kind
		// (kubernetes_live); posture kinds are additionally covered under
		// their family kind (secrets_iam_posture), which each fact
		// preserves per fact in its source ref. The harness matches the
		// fixture claim kind, so the primary entry is what the proof
		// exercises; the family entry documents the preserved seam.
		emissions := []conformance.CoreFactEmission{{CollectorKind: CollectorKind, SchemaVersions: family.SchemaVersions}}
		if familyKind := proofWantCollectorKind(family.Kind); familyKind != CollectorKind {
			emissions = append(emissions, conformance.CoreFactEmission{CollectorKind: familyKind, SchemaVersions: family.SchemaVersions})
		}
		authorizations = append(authorizations, conformance.CoreFactAuthorization{
			Kind:             family.Kind,
			Emissions:        emissions,
			ReducerPhases:    []string{conformance.SourceEvidenceOnlyReducerPhase},
			PayloadSchemaRef: family.Kind,
		})
	}
	return &conformance.CoreFactContext{
		ComponentID:      manifest.Metadata.ID,
		ComponentVersion: manifest.Metadata.Version,
		Facts:            authorizations,
	}, schemas
}

// proofSnapshots collects both fixture scopes through the extracted source
// and converts each to an SDK Result for one claim.
func proofSnapshots(t *testing.T) []sdkcollector.Result {
	t.Helper()

	source := proofSource()
	fencing := map[string]int64{"parity-full": 7, "parity-hostile": 9}
	var fixtures []sdkcollector.Result
	for {
		collected, ok, err := source.Next(context.Background())
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		if !ok {
			break
		}
		result, err := ToSDKResult(proofClaim(collected.Scope, collected.Generation, fencing[collected.Scope.Metadata["cluster_id"]]), collected)
		if err != nil {
			t.Fatalf("ToSDKResult() error = %v", err)
		}
		fixtures = append(fixtures, result)
	}
	if len(fixtures) != 2 {
		t.Fatalf("fixtures = %d, want 2 scopes", len(fixtures))
	}
	return fixtures
}

// proofK8sOnly returns the fixtures with only kubernetes_live.* facts kept,
// for the full-harness half of the proof (see below for why posture facts
// travel a schema-only path until the SDK allowlist grows).
func proofK8sOnly(fixtures []sdkcollector.Result) []sdkcollector.Result {
	out := make([]sdkcollector.Result, 0, len(fixtures))
	for _, fixture := range fixtures {
		kept := fixture
		kept.Facts = nil
		for _, fact := range fixture.Facts {
			if strings.HasPrefix(fact.Kind, "kubernetes_live.") {
				kept.Facts = append(kept.Facts, fact)
			}
		}
		out = append(out, kept)
	}
	return out
}

func proofK8sManifest() (conformance.Manifest, *conformance.CoreFactContext, map[string]json.RawMessage, []string) {
	manifest := proofManifest()
	manifest.Spec.EmittedFacts = nil
	manifest.Spec.CollectorKinds = []string{CollectorKind}
	for _, family := range proofManifest().Spec.EmittedFacts {
		if strings.HasPrefix(family.Kind, "kubernetes_live.") {
			manifest.Spec.EmittedFacts = append(manifest.Spec.EmittedFacts, family)
		}
	}
	coreFacts, schemas := proofCoreFacts(nil, manifest)
	reserved := make([]string, 0, len(manifest.Spec.EmittedFacts))
	for _, family := range manifest.Spec.EmittedFacts {
		reserved = append(reserved, family.Kind)
	}
	return manifest, coreFacts, schemas, reserved
}

// proofK8sFullHarnessManifest is the full-harness half of the proof: the
// kubernetes_live.* families except pod_template. Pod_template travels a
// schema-only path (see TestExtractedPodTemplatePayloadsMatchPackSchemas):
// the rc.3 payload-key heuristic flags its legacy env_from_secret bool, and
// the fix belongs to the SDK allowlist (eshu-hq/eshu#8851). Verdict: arbiter,
// 2026-10-27.
func proofK8sFullHarnessManifest() (conformance.Manifest, *conformance.CoreFactContext, map[string]json.RawMessage, []string) {
	manifest, _, _, _ := proofK8sManifest()
	manifest.Spec.EmittedFacts = nil
	for _, family := range proofManifest().Spec.EmittedFacts {
		if strings.HasPrefix(family.Kind, "kubernetes_live.") && family.Kind != KubernetesPodTemplateFactKind {
			manifest.Spec.EmittedFacts = append(manifest.Spec.EmittedFacts, family)
		}
	}
	coreFacts, schemas := proofCoreFacts(nil, manifest)
	reserved := make([]string, 0, len(manifest.Spec.EmittedFacts))
	for _, family := range manifest.Spec.EmittedFacts {
		reserved = append(reserved, family.Kind)
	}
	return manifest, coreFacts, schemas, reserved
}

// withoutPodTemplateFacts returns the fixtures with pod_template facts
// removed, for the full-harness half of the proof (see
// TestExtractedPodTemplatePayloadsMatchPackSchemas for why pod_template
// travels a schema-only path until the SDK allowlist grows).
func withoutPodTemplateFacts(fixtures []sdkcollector.Result) []sdkcollector.Result {
	out := make([]sdkcollector.Result, 0, len(fixtures))
	for _, fixture := range fixtures {
		kept := fixture
		kept.Facts = nil
		for _, fact := range fixture.Facts {
			if fact.Kind != KubernetesPodTemplateFactKind {
				kept.Facts = append(kept.Facts, fact)
			}
		}
		out = append(out, kept)
	}
	return out
}

// TestExtractedNonPodTemplatePayloadsPassConformance proves the
// kubernetes_live.* facts except pod_template satisfy the full SDK
// publication contract: the conformance harness (manifest, trusted coverage,
// payload schemas, claim/ref agreement, credential-free URIs) passes in the
// producer's own module against the producer's own output. Pod_template is
// EXCLUDED here and travels a schema-only path (see
// TestExtractedPodTemplatePayloadsMatchPackSchemas and
// TestExtractedPodTemplateFullHarnessStillBlocked): the rc.3 payload-key
// heuristic flags its legacy containers.env_from_secret bool, and the fix
// belongs to the SDK allowlist (eshu-hq/eshu#8851). The name states the
// exclusion so no reader mistakes this green for pod_template publication
// proof.
func TestExtractedNonPodTemplatePayloadsPassConformance(t *testing.T) {
	t.Parallel()

	manifest, coreFacts, schemas, reserved := proofK8sFullHarnessManifest()
	fixtures := withoutPodTemplateFacts(proofK8sOnly(proofSnapshots(t)))

	report := conformance.Run(conformance.Request{
		Manifest:          manifest,
		Fixtures:          fixtures,
		Mode:              conformance.ModeFixture,
		ReservedFactKinds: reserved,
		CoreFacts:         coreFacts,
		PayloadSchemas:    schemas,
	})
	if !report.OK() {
		t.Fatalf("conformance findings = %#v, want passed", report.Findings)
	}
	if report.Summary.FixtureCount != 2 {
		t.Fatalf("FixtureCount = %d, want 2", report.Summary.FixtureCount)
	}
	if report.Summary.FactCount == 0 {
		t.Fatal("FactCount = 0, want every emitted fact validated")
	}
}

// TestExtractedPodTemplateFullHarnessStillBlocked pins the P1 exclusion: the
// full publication harness REJECTS pod_template facts on both fixtures with
// BlocksPublication:true for containers.env_from_secret. This test is the
// honest counterpart to the schema-only pod_template proof above — it fails
// if anyone re-adds pod_template to the full-harness manifest/fixtures while
// the SDK allowlist is still missing, and it must be deleted (with the
// rename above reverted to cover pod_template) when the SDK release carries
// the allowlist and the full harness goes green.
func TestExtractedPodTemplateFullHarnessStillBlocked(t *testing.T) {
	t.Parallel()

	manifest, coreFacts, schemas, reserved := proofK8sManifest()
	fixtures := proofK8sOnly(proofSnapshots(t))

	seenPodTemplate := 0
	for _, fixture := range fixtures {
		for _, fact := range fixture.Facts {
			if fact.Kind == KubernetesPodTemplateFactKind {
				seenPodTemplate++
			}
		}
	}
	if seenPodTemplate == 0 {
		t.Fatal("fixtures carry no pod_template fact; the block pin is vacuous")
	}

	report := conformance.Run(conformance.Request{
		Manifest:          manifest,
		Fixtures:          fixtures,
		Mode:              conformance.ModeFixture,
		ReservedFactKinds: reserved,
		CoreFacts:         coreFacts,
		PayloadSchemas:    schemas,
	})
	if report.OK() {
		t.Fatal("full harness passed with pod_template included; the SDK allowlist has landed — " +
			"delete this pin, fold pod_template back into TestExtractedNonPodTemplatePayloadsPassConformance, and rename it")
	}
	blocked := 0
	for _, finding := range report.Findings {
		if finding.Code == conformance.FindingFixtureContractFailed && finding.BlocksPublication &&
			strings.Contains(finding.Message, "containers.env_from_secret") {
			blocked++
		}
	}
	if blocked != 2 {
		t.Fatalf("blocked pod_template findings = %d, want 2 (one per fixture); findings = %#v", blocked, report.Findings)
	}
}

// TestExtractedPodTemplatePayloadsMatchPackSchemas proves the pod_template
// facts the extracted producer emits satisfy the JSON Schema shapes the
// pinned fixture pack ships — the same shapes the target reducer release
// consumes.
//
// It runs the schema-only check (conformance.ValidatePayloadSchemas), not the
// full publication harness, for one SDK-owned reason: the published
// collector's fail-closed payload-key heuristic
// (collector/validation.go validatePayloadKeys) flags the legacy
// containers.env_from_secret field, a boolean that records only whether a
// container references secret-backed env (collector/envelope.go
// ContainerSummary.EnvFromSecret) and never carries a value. Renaming the
// field would break the byte-pinned cutover contract, so the fix belongs to
// the SDK (an allowlist entry alongside eshu-hq/eshu#8851): this proof
// records the handoff and pins everything else green. The full-harness
// pod_template half goes green with the SDK release that carries the
// allowlist. Verdict: arbiter, 2026-10-27.
func TestExtractedPodTemplatePayloadsMatchPackSchemas(t *testing.T) {
	t.Parallel()

	_, _, schemas, _ := proofK8sManifest()
	fixtures := proofK8sOnly(proofSnapshots(t))
	seen := 0
	for i, fixture := range fixtures {
		kept := fixture
		kept.Facts = nil
		for _, fact := range fixture.Facts {
			if fact.Kind == KubernetesPodTemplateFactKind {
				kept.Facts = append(kept.Facts, fact)
			}
		}
		if len(kept.Facts) == 0 {
			t.Fatalf("fixture[%d] carries no pod_template fact", i)
		}
		seen += len(kept.Facts)
		if err := conformance.ValidatePayloadSchemas(schemas, kept); err != nil {
			t.Fatalf("fixture[%d] payload schema: %v", i, err)
		}
	}
	if seen == 0 {
		t.Fatal("no pod_template fact validated")
	}
}

// TestExtractedPosturePayloadsMatchPackSchemas proves the posture facts the
// extracted producer emits satisfy the JSON Schema shapes the pinned fixture
// pack ships — the same shapes the target reducer release consumes.
//
// It runs the schema-only check (conformance.ValidatePayloadSchemas), not the
// full publication harness, for one SDK-owned reason: the published
// collector's fail-closed payload-key heuristic
// (collector/validation.go validatePayloadKeys) rejects legacy posture field
// names that are provably not credentials — integer counts
// (secret_ref_count, image_pull_secret_ref_count) and closed-enum strings
// (automount_token, projected_service_account_token) — while the SDK's own
// redactionSafePayloadKeys allowlist carries no entry for them. Renaming the
// fields would break the byte-pinned cutover contract, so the fix belongs to
// the SDK (allowlist entries, owned by eshu-hq/eshu#8851): this proof records
// the handoff and pins everything else green. The full-harness posture half
// goes green with the SDK release that carries the allowlist.
func TestExtractedPosturePayloadsMatchPackSchemas(t *testing.T) {
	t.Parallel()

	manifest := proofManifest()
	_, schemas := proofCoreFacts(t, manifest)
	fixtures := proofSnapshots(t)
	for i, fixture := range fixtures {
		if err := conformance.ValidatePayloadSchemas(schemas, fixture); err != nil {
			t.Fatalf("fixture[%d] payload schema: %v", i, err)
		}
	}
}
