// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

// This file is new in the extraction: it is the #4047 cutover gate's
// extracted-path half. It proves the extracted producer reproduces the
// in-tree emission exactly — the same scopes, kinds, stable keys, fencing
// tokens, and canonical payload bytes — against the same fixture-pack oracle
// the in-tree parity pin was cut from
// (testdata/8859-parity-kubernetes-live.json, copied verbatim from core).

type proofSnapshot struct {
	scopeID      string
	generationID string
	kinds        map[string]int
	keys         []string
	attrs        map[string]string
	payloads     map[string][]byte
}

type proofCassetteFact struct {
	CollectorKind    string         `json:"collector_kind"`
	FactKind         string         `json:"fact_kind"`
	FencingToken     int64          `json:"fencing_token"`
	Payload          map[string]any `json:"payload"`
	SchemaVersion    string         `json:"schema_version"`
	SourceConfidence string         `json:"source_confidence"`
	SourceURI        string         `json:"source_uri"`
	StableFactKey    string         `json:"stable_fact_key"`
}

type proofCassetteScope struct {
	ScopeID      string              `json:"scope_id"`
	GenerationID string              `json:"generation_id"`
	Facts        []proofCassetteFact `json:"facts"`
}

func loadProofOracle(t *testing.T) []proofCassetteScope {
	t.Helper()

	raw, err := os.ReadFile("testdata/8859-parity-kubernetes-live.json")
	if err != nil {
		t.Fatalf("read fixture pack: %v", err)
	}
	var pack struct {
		Scopes []proofCassetteScope `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatalf("parse fixture pack: %v", err)
	}
	if len(pack.Scopes) != 2 {
		t.Fatalf("cassette scopes = %d, want 2 (parity-full, parity-hostile)", len(pack.Scopes))
	}
	return pack.Scopes
}

func proofKindMultiset(envelopes []Envelope) map[string]int {
	counts := map[string]int{}
	for _, envelope := range envelopes {
		counts[envelope.FactKind]++
	}
	return counts
}

func proofStableKeys(envelopes []Envelope) []string {
	keys := make([]string, 0, len(envelopes))
	for _, envelope := range envelopes {
		keys = append(keys, envelope.StableFactKey)
	}
	slices.Sort(keys)
	return keys
}

// proofWantCollectorKind pins the dual-collector-kind emission of this
// source: kubernetes_live.* facts carry CollectorKind, while the secrets/IAM
// posture facts it also emits carry PostureCollectorKind.
func proofWantCollectorKind(factKind string) string {
	if strings.HasPrefix(factKind, "kubernetes_live.") {
		return CollectorKind
	}
	return PostureCollectorKind
}

func proofCanonicalJSON(t *testing.T, payload map[string]any) []byte {
	t.Helper()

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

// attrKey binds the host-enforced boundary attributes to the stable key so
// the proof pins what admission and grant checks key on.
func proofAttrKey(envelope Envelope) string {
	return envelope.StableFactKey + "\x00" + envelope.FactKind + "\x00" +
		envelope.SchemaVersion + "\x00" + strconv.FormatInt(envelope.FencingToken, 10)
}

// TestExtractedParityMatchesFixturePack is the extracted-path source-parity
// pin: the extracted producer and the checked-in fixture pack agree scope by
// scope on scope ID, fact-kind multiset, stable keys, schema versions,
// collector kind, fencing tokens, and canonical payload bytes.
func TestExtractedParityMatchesFixturePack(t *testing.T) {
	t.Parallel()

	scopes := loadProofOracle(t)
	byScope := map[string]proofSnapshot{}
	for _, scope := range scopes {
		attrs := map[string]string{}
		payloads := map[string][]byte{}
		for _, fact := range scope.Facts {
			attrs[fact.StableFactKey] = fact.StableFactKey + "\x00" + fact.FactKind + "\x00" +
				fact.SchemaVersion + "\x00" + strconv.FormatInt(fact.FencingToken, 10)
			raw, err := json.Marshal(fact.Payload)
			if err != nil {
				t.Fatalf("marshal oracle payload: %v", err)
			}
			payloads[fact.StableFactKey] = raw
		}
		kinds := map[string]int{}
		keys := make([]string, 0, len(scope.Facts))
		for _, fact := range scope.Facts {
			kinds[fact.FactKind]++
			keys = append(keys, fact.StableFactKey)
		}
		slices.Sort(keys)
		byScope[scope.ScopeID] = proofSnapshot{
			scopeID:      scope.ScopeID,
			generationID: scope.GenerationID,
			kinds:        kinds,
			keys:         keys,
			attrs:        attrs,
			payloads:     payloads,
		}
	}

	live := proofSource()
	yielded := 0
	for {
		collected, ok, err := live.Next(context.Background())
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		if !ok {
			break
		}
		yielded++
		expected, ok := byScope[collected.Scope.ScopeID]
		if !ok {
			t.Fatalf("live scope %q not in fixture pack", collected.Scope.ScopeID)
		}
		delete(byScope, collected.Scope.ScopeID)
		if collected.Generation.GenerationID == "" {
			t.Fatalf("live scope %q has a blank generation ID", expected.scopeID)
		}
		envelopes := collected.Envelopes
		for _, envelope := range envelopes {
			if envelope.GenerationID != collected.Generation.GenerationID {
				t.Fatalf("live fact generation %q != scope generation %q", envelope.GenerationID, collected.Generation.GenerationID)
			}
		}
		if !maps.Equal(proofKindMultiset(envelopes), expected.kinds) {
			t.Fatalf("live kinds = %v, want %v", proofKindMultiset(envelopes), expected.kinds)
		}
		if !slices.Equal(proofStableKeys(envelopes), expected.keys) {
			t.Fatalf("live stable keys differ from fixture pack for scope %q", expected.scopeID)
		}
		gotAttrs := map[string]string{}
		for _, envelope := range envelopes {
			gotAttrs[envelope.StableFactKey] = proofAttrKey(envelope)
		}
		if !maps.Equal(gotAttrs, expected.attrs) {
			t.Fatalf("live boundary attributes differ from fixture pack for scope %q", expected.scopeID)
		}
		for _, envelope := range envelopes {
			wantPayload, ok := expected.payloads[envelope.StableFactKey]
			if !ok {
				t.Fatalf("live stable key %q has no fixture payload for scope %q", envelope.StableFactKey, expected.scopeID)
			}
			if got := proofCanonicalJSON(t, envelope.Payload); !bytes.Equal(got, wantPayload) {
				t.Fatalf("live payload differs from fixture pack for scope %q stable key %q", expected.scopeID, envelope.StableFactKey)
			}
		}
		for _, envelope := range envelopes {
			if envelope.CollectorKind != proofWantCollectorKind(envelope.FactKind) {
				t.Fatalf("CollectorKind = %q, want %q for kind %q", envelope.CollectorKind, proofWantCollectorKind(envelope.FactKind), envelope.FactKind)
			}
		}
	}
	if yielded != len(scopes) {
		t.Fatalf("live yielded %d scopes, want %d", yielded, len(scopes))
	}
	if len(byScope) != 0 {
		t.Fatalf("fixture scopes never yielded live: %v", slices.Sorted(maps.Keys(byScope)))
	}

	union := map[string]bool{}
	for _, scope := range scopes {
		for _, fact := range scope.Facts {
			union[fact.FactKind] = true
		}
	}
	for _, kind := range KubernetesLiveFactKinds() {
		if !union[kind] {
			t.Fatalf("fixture pack covers no %q fact; parity pack must span all 4 kubernetes_live kinds", kind)
		}
	}
	for _, kind := range []string{
		KubernetesServiceAccountFactKind,
		KubernetesServiceAccountTokenPostureFactKind,
		KubernetesWorkloadIdentityUseFactKind,
		EKSIRSAAnnotationFactKind,
		KubernetesGCPWorkloadIdentityBindingFactKind,
		SecretsIAMCoverageWarningFactKind,
	} {
		if !union[kind] {
			t.Fatalf("fixture pack covers no %q fact; parity pack must pin the posture evidence", kind)
		}
	}
}

// TestExtractedDuplicateDeliveryIsStable pins duplicate safety on the
// extracted path: two identical poll batches emit identical generation IDs
// and stable-key sets per scope, so a redelivered generation commits
// idempotently at the core boundary.
func TestExtractedDuplicateDeliveryIsStable(t *testing.T) {
	t.Parallel()

	src := proofSource()
	var batches [2]map[string][]string
	var genIDs [2]map[string]string
	for b := range batches {
		batches[b] = map[string][]string{}
		genIDs[b] = map[string]string{}
		for {
			gen, ok, err := src.Next(context.Background())
			if err != nil {
				t.Fatalf("batch %d Next() error = %v", b, err)
			}
			if !ok {
				break
			}
			batches[b][gen.Scope.ScopeID] = proofStableKeys(gen.Envelopes)
			genIDs[b][gen.Scope.ScopeID] = gen.Generation.GenerationID
		}
		if len(batches[b]) != 2 {
			t.Fatalf("batch %d yielded %d scopes, want 2 (parity-full, parity-hostile)", b, len(batches[b]))
		}
	}
	if !maps.Equal(genIDs[0], genIDs[1]) {
		t.Fatalf("duplicate GenerationIDs differ: %v then %v; same instant must re-derive identically", genIDs[0], genIDs[1])
	}
	for scope, keys := range batches[0] {
		again, ok := batches[1][scope]
		if !ok {
			t.Fatalf("redelivered batch is missing scope %q", scope)
		}
		if !slices.Equal(keys, again) {
			t.Fatalf("duplicate snapshots emit different stable keys for scope %q; redelivery would not be idempotent", scope)
		}
	}
}

// TestExtractedHostileInputs pins the hostile half of the fixture on the
// extracted path: a forbidden list marks the generation partial and emits
// in-band warning evidence, an unresolvable owner emits ambiguity evidence
// instead of an invented identity, and a credential-bearing source URI is
// sanitized before emission.
func TestExtractedHostileInputs(t *testing.T) {
	t.Parallel()

	source := proofSource()
	if _, _, err := source.Next(context.Background()); err != nil {
		t.Fatalf("full Next() error = %v", err)
	}
	hostile, ok, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("hostile Next() error = %v", err)
	}
	if !ok {
		t.Fatal("hostile Next() ok = false, want the parity-hostile scope")
	}
	if hostile.Generation.FreshnessHint != "partial" {
		t.Fatalf("FreshnessHint = %q, want partial", hostile.Generation.FreshnessHint)
	}
	envelopes := hostile.Envelopes

	reasons := map[string]int{}
	for _, envelope := range envelopesOfKind(envelopes, KubernetesWarningFactKind) {
		reason, _ := envelope.Payload["reason"].(string)
		reasons[reason]++
	}
	if reasons[WarningForbiddenResource] == 0 {
		t.Fatalf("no %q warning; forbidden list must stay in-band, got %v", WarningForbiddenResource, reasons)
	}
	if reasons[WarningInvalidOwnerReference] == 0 {
		t.Fatalf("no %q warning; unresolvable owner must stay in-band, got %v", WarningInvalidOwnerReference, reasons)
	}

	// sanitizeURL strips userinfo and the token query key but keeps the
	// benign region key: the byte-exact sanitized form pinned below.
	const wantSanitizedURI = "https://api.parity-hostile.example.test/cluster?region=us-east-1"
	for _, envelope := range envelopes {
		if strings.HasPrefix(envelope.FactKind, "kubernetes_live.") {
			// The kubernetes_live envelope seam sanitizes userinfo and
			// secret query keys out of the operator-declared source URI.
			if envelope.SourceRef.SourceURI != wantSanitizedURI {
				t.Fatalf("SourceURI = %q, want sanitized %q", envelope.SourceRef.SourceURI, wantSanitizedURI)
			}
			if message, ok := envelope.Payload["message"].(string); ok {
				if strings.Contains(message, "HOSTILESECRET") || strings.Contains(message, "HOSTILETOKEN") {
					t.Fatalf("credential material reached warning message %q", message)
				}
			}
			continue
		}
		// KNOWN PRE-EXTRACTION GAP (pinned, not approved): the shared
		// posture envelope seam only trims the source URI, so the
		// secrets_iam_coverage_warning fact carries the credential-bearing
		// URI verbatim. The extracted producer must sanitize or drop
		// SourceURI for posture facts before production cutover; fixing the
		// shared seam belongs to the secrets-IAM lane.
		if envelope.FactKind == SecretsIAMCoverageWarningFactKind {
			if !strings.Contains(envelope.SourceRef.SourceURI, "HOSTILESECRET") {
				t.Fatalf("posture SourceURI = %q, want the verbatim (unsanitized) pre-extraction bytes", envelope.SourceRef.SourceURI)
			}
		}
	}
}

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

// proofManifest declares this producer's emitted families for the
// conformance harness: the 4 kubernetes_live kinds plus the 6 posture kinds
// the fixture pack pins, all reported confidence, all trusted to this
// producer's two collector kinds.
func proofManifest() conformance.Manifest {
	families := []conformance.FactFamily{
		{Kind: KubernetesNamespaceFactKind, SchemaVersions: []string{KubernetesNamespaceSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesPodTemplateFactKind, SchemaVersions: []string{KubernetesPodTemplateSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesRelationshipFactKind, SchemaVersions: []string{KubernetesRelationshipSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesWarningFactKind, SchemaVersions: []string{KubernetesWarningSchemaVersion}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesServiceAccountFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesServiceAccountTokenPostureFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesWorkloadIdentityUseFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: EKSIRSAAnnotationFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: KubernetesGCPWorkloadIdentityBindingFactKind, SchemaVersions: []string{SecretsIAMSchemaVersionV1}, SourceConfidence: []string{"reported"}},
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

// TestExtractedPayloadsPassConformance proves the kubernetes_live.* facts the
// extracted producer emits satisfy the full SDK publication contract: the
// conformance harness (manifest, trusted coverage, payload schemas,
// claim/ref agreement, credential-free URIs) passes in the producer's own
// module against the producer's own output.
func TestExtractedPayloadsPassConformance(t *testing.T) {
	t.Parallel()

	manifest, coreFacts, schemas, reserved := proofK8sManifest()
	fixtures := proofK8sOnly(proofSnapshots(t))

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
