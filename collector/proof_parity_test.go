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
