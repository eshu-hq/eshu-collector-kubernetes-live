// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdkconformance "github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
	"gopkg.in/yaml.v3"
)

var digestPattern = regexp.MustCompile(`@sha256:[A-Fa-f0-9]{64}$`)

// placeholderDigest is the artifact digest the repository manifest carries
// permanently. manifest.yaml is go:embed'ed into the binary, so a digest
// written into it would belong to an older build than the image that embeds
// it. The deployed digest is stamped at deploy time by `collector seed
// --image-ref` instead.
const placeholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// isPlaceholderImage reports whether image names the placeholder digest.
func isPlaceholderImage(image string) bool {
	return strings.HasSuffix(image, "@"+placeholderDigest)
}

// TestPlaceholderImageGate pins the gate on both sides: the placeholder passes
// and a real-looking digest fails.
func TestPlaceholderImageGate(t *testing.T) {
	t.Parallel()

	const repo = "ghcr.io/eshu-hq/eshu-collector-kubernetes-live@"
	if !isPlaceholderImage(repo + placeholderDigest) {
		t.Fatal("the placeholder digest must pass the gate")
	}
	if isPlaceholderImage(repo + "sha256:" + strings.Repeat("a", 64)) {
		t.Fatal("a real-looking digest must fail the gate")
	}
}

// loadManifest reads the shipped component manifest for shape tests.
func loadManifest(t *testing.T) sdkconformance.Manifest {
	t.Helper()
	raw, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatalf("os.ReadFile(manifest.yaml) error = %v", err)
	}
	var manifest sdkconformance.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("yaml.Unmarshal(manifest.yaml) error = %v", err)
	}
	return manifest
}

// TestScopeKindAndSourceSystemMatchTheInTreeBaseline proves the cutover keeps
// the durable identity the in-tree collector used: scope kind "cluster",
// source system and collector kind "kubernetes_live" on the emission core,
// the shim contract, and the claim boundary. Stable keys embed these values,
// so any drift renames every fact.
func TestScopeKindAndSourceSystemMatchTheInTreeBaseline(t *testing.T) {
	t.Parallel()

	if corecollector.CollectorKind != "kubernetes_live" {
		t.Fatalf("CollectorKind = %q, want kubernetes_live", corecollector.CollectorKind)
	}
	if CollectorKind != "kubernetes_live" || SourceSystem != "kubernetes_live" {
		t.Fatalf("shim CollectorKind = %q SourceSystem = %q, want kubernetes_live", CollectorKind, SourceSystem)
	}
	if ComponentID != "dev.eshu.collector.kubernetes-live" {
		t.Fatalf("ComponentID = %q, want dev.eshu.collector.kubernetes-live", ComponentID)
	}

	// The parity fixture pack pins the in-tree scope and source system
	// verbatim; the shim must agree with it.
	raw, err := os.ReadFile("collector/testdata/8859-parity-kubernetes-live.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Scopes []struct {
			ScopeKind    string `json:"scope_kind"`
			SourceSystem string `json:"source_system"`
		} `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatalf("fixture pack: %v", err)
	}
	if len(pack.Scopes) == 0 {
		t.Fatal("fixture pack declares no scopes")
	}
	for _, scope := range pack.Scopes {
		if scope.ScopeKind != "cluster" || scope.SourceSystem != "kubernetes_live" {
			t.Fatalf("fixture scope = %q/%q, want cluster/kubernetes_live", scope.ScopeKind, scope.SourceSystem)
		}
	}

	manifest := loadManifest(t)
	if len(manifest.Spec.CollectorKinds) != 1 || manifest.Spec.CollectorKinds[0] != "kubernetes_live" {
		t.Fatalf("collectorKinds = %v, want [kubernetes_live]", manifest.Spec.CollectorKinds)
	}
	if manifest.Metadata.ID != ComponentID {
		t.Fatalf("manifest id = %q, want %q", manifest.Metadata.ID, ComponentID)
	}
}

// TestManifestDeclaresTheEmittedKindsWithPublishedSchemas keeps the manifest,
// the contract the handler emits against, and the published payload schemas
// in step: every kind is declared once with reported confidence and a
// payloadSchemaRef that resolves in the pinned fixture pack.
func TestManifestDeclaresTheEmittedKindsWithPublishedSchemas(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)
	want := FactKinds()
	var got []string
	for _, family := range manifest.Spec.EmittedFacts {
		got = append(got, family.Kind)
		if family.PayloadSchemaRef != family.Kind {
			t.Errorf("%s: payloadSchemaRef = %q, want the kind", family.Kind, family.PayloadSchemaRef)
		}
		if len(family.SourceConfidence) != 1 || family.SourceConfidence[0] != "reported" {
			t.Errorf("%s: sourceConfidence=%v, want [reported]", family.Kind, family.SourceConfidence)
		}
		wantVersion := SchemaVersionV1
		if family.Kind == FactKindPodTemplate {
			wantVersion = SchemaVersionPodTemplate
		}
		if len(family.SchemaVersions) != 1 || family.SchemaVersions[0] != wantVersion {
			t.Errorf("%s: schemaVersions=%v, want [%s]", family.Kind, family.SchemaVersions, wantVersion)
		}
		if _, ok := fixturepack.SchemaFor(family.PayloadSchemaRef); !ok {
			t.Errorf("%s: pinned fixture pack has no schema %q", family.Kind, family.PayloadSchemaRef)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("manifest kinds %v, FactKinds() %v", got, want)
	}
	contract := manifest.Contract()
	if !reflect.DeepEqual(contract, Contract()) {
		t.Fatalf("manifest contract differs from Contract():\n%+v\n%+v", contract, Contract())
	}
}

// TestManifestReleaseProvenance proves releases are reproducible and the
// component manifest is valid: every artifact is digest-pinned, the manifest
// carries the supported core range and wire protocol, and every emitted fact
// family is versioned with declared confidence.
func TestManifestReleaseProvenance(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)
	if strings.TrimSpace(manifest.Metadata.Version) == "" {
		t.Fatal("manifest missing metadata version")
	}
	if manifest.Metadata.Version != "0.1.1" {
		t.Fatalf("metadata.version = %q, want 0.1.1", manifest.Metadata.Version)
	}
	if len(manifest.Spec.Artifacts) == 0 {
		t.Fatal("manifest declares no artifacts")
	}
	for _, artifact := range manifest.Spec.Artifacts {
		if !digestPattern.MatchString(artifact.Image) {
			t.Fatalf("artifact image %q is not digest-pinned", artifact.Image)
		}
		if strings.Contains(artifact.Image, ":latest") {
			t.Fatalf("artifact image %q uses a mutable tag", artifact.Image)
		}
		// The repository manifest names the placeholder, never a real digest:
		// the manifest is embedded in the image, so a committed digest could
		// only describe an older build. Deployments stamp the digest they
		// pulled with `collector seed --image-ref REF@sha256:<digest>`.
		if !isPlaceholderImage(artifact.Image) {
			t.Fatalf("artifact image %q is not the placeholder digest: do not commit a real digest "+
				"(the manifest is embedded in the image); stamp the deployed one with collector seed --image-ref", artifact.Image)
		}
	}
	if len(manifest.Spec.EmittedFacts) == 0 {
		t.Fatal("manifest declares no emitted facts")
	}
	// No consumerContracts.reducer.phases: the only phase the SDK conformance
	// harness accepts for an optional component is source_evidence_only, and
	// these kinds feed real reducers. Declaring nothing is accurate, and the
	// harness accepts it.
	if phases := manifest.Spec.ConsumerContracts.Reducer.Phases; len(phases) != 0 {
		t.Fatalf("manifest declares reducer phases %v; omit consumerContracts (see the comment above)", phases)
	}
	if strings.TrimSpace(manifest.Spec.Telemetry.MetricsPrefix) == "" {
		t.Fatal("manifest missing telemetry metrics prefix")
	}
	if manifest.Spec.Telemetry.MetricsPrefix != MetricsPrefix {
		t.Fatalf("metricsPrefix = %q, want %q", manifest.Spec.Telemetry.MetricsPrefix, MetricsPrefix)
	}
}

// producerGrant is the shape of a core producer grant request. Core issues the
// grant; this repository stores only the request an operator submits.
type producerGrant struct {
	ProducerID     string    `json:"producer_id"`
	Version        string    `json:"version"`
	Kind           string    `json:"kind"`
	SchemaVersions []string  `json:"schema_versions"`
	Scope          string    `json:"scope"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked"`
}

// TestGrantExampleCoversExactlyTheManifestKinds proves the grant request an
// operator submits matches the manifest: one grant per declared core kind,
// bound to this producer and version, scoped to the manifest's collector kind,
// and covering every declared schema version.
func TestGrantExampleCoversExactlyTheManifestKinds(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("grant.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var grants []producerGrant
	if err := json.Unmarshal(raw, &grants); err != nil {
		t.Fatalf("grant.example.json: %v", err)
	}
	manifest := loadManifest(t)
	declared := map[string][]string{}
	for _, family := range manifest.Spec.EmittedFacts {
		declared[family.Kind] = family.SchemaVersions
	}
	got := map[string][]string{}
	for _, grant := range grants {
		if grant.ProducerID != manifest.Metadata.ID || grant.Version != manifest.Metadata.Version {
			t.Fatalf("grant %+v is not bound to %s@%s", grant, manifest.Metadata.ID, manifest.Metadata.Version)
		}
		if grant.Scope != manifest.Spec.CollectorKinds[0] || grant.Revoked || grant.ExpiresAt.IsZero() {
			t.Fatalf("grant %+v must be live and scoped to the collector kind %q", grant, manifest.Spec.CollectorKinds[0])
		}
		if _, dup := got[grant.Kind]; dup {
			t.Fatalf("grant kind %s appears twice", grant.Kind)
		}
		got[grant.Kind] = grant.SchemaVersions
	}
	var missing, extra []string
	for kind := range declared {
		if _, ok := got[kind]; !ok {
			missing = append(missing, kind)
		}
	}
	for kind := range got {
		if _, ok := declared[kind]; !ok {
			extra = append(extra, kind)
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("grant coverage mismatch: missing %v extra %v", missing, extra)
	}
	for kind, versions := range declared {
		sort.Strings(versions)
		have := append([]string(nil), got[kind]...)
		sort.Strings(have)
		if strings.Join(have, ",") != strings.Join(versions, ",") {
			t.Fatalf("grant for %s covers %v, want %v", kind, have, versions)
		}
	}
}
