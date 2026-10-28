// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Boundary and redaction proofs ported verbatim from the in-tree unit
// tests, split from ported_unit_test.go under the 500-line cap: envelope
// validation, URL sanitization, credential persistence, and config
// validation.

func TestPortedEnvelopeBoundaryValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewPodTemplateEnvelope(PodTemplateObservation{
		Identity:            portedSampleIdentity(),
		CollectorInstanceID: "k8s-prod",
	}); err == nil {
		t.Fatalf("expected error for blank generation_id")
	}
	if _, err := NewWarningEnvelope(WarningObservation{
		ClusterID:           "c",
		Reason:              "",
		GenerationID:        "gen-1",
		CollectorInstanceID: "k8s-prod",
	}); err == nil {
		t.Fatalf("expected error for blank reason")
	}
	if _, err := NewRelationshipEnvelope(RelationshipObservation{
		ClusterID:           "c",
		Type:                RelationshipOwnerReference,
		From:                ObjectIdentity{},
		To:                  portedSampleIdentity(),
		GenerationID:        "gen-1",
		CollectorInstanceID: "k8s-prod",
	}); err == nil {
		t.Fatalf("expected error for invalid from identity")
	}
}

func TestPortedSanitizeURLDropsOpaqueCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		wantKept bool
	}{
		{name: "opaque password position", value: "svc:" + portedCredentialSentinel + "@h.internal:5432/tool"},
		{name: "opaque mid-password", value: "svc:pw" + portedCredentialSentinel + "@h.internal/tool"},
		{name: "opaque under an uppercase scheme", value: "SVC:" + portedCredentialSentinel + "@h.internal/tool"},
		{name: "scheme-relative userinfo", value: "//svc:" + portedCredentialSentinel + "@h.internal/tool"},
		{name: "unparseable value", value: "https://svc:pw\"" + portedCredentialSentinel + "@h.internal/tool"},
		{name: "unparseable only as an authority", value: "svc:pw]" + portedCredentialSentinel + "@h.internal/tool"},
		{name: "hierarchical password stays redacted", value: "https://svc:" + portedCredentialSentinel + "@h.internal/tool"},
		{name: "path-segment at sign survives (positive control)", value: "https://h.internal/owners/" + portedCredentialSentinel + "@example.com/x", wantKept: true},
		{name: "opaque tool name survives (positive control)", value: "mcp:tool/" + portedCredentialSentinel, wantKept: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := sanitizeURL(tt.value)
			if tt.wantKept {
				if !strings.Contains(got, portedCredentialSentinel) {
					t.Fatalf("sanitizeURL(%q) = %q dropped a value that carries no credential; the sweep is over-redacting", tt.value, got)
				}
				return
			}
			if strings.Contains(got, portedCredentialSentinel) {
				t.Errorf("sanitizeURL(%q) = %q kept the credential sentinel", tt.value, got)
			}
		})
	}
}

func TestPortedWarningEnvelopeNeverPersistsOpaqueCredential(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, sourceURI string) string {
		t.Helper()
		envelope, err := NewWarningEnvelope(WarningObservation{
			ClusterID:           "prod-us-east-1",
			Reason:              "list_pods_failed",
			ResourceScope:       "namespace/checkout",
			Message:             "listing pods failed",
			GenerationID:        "gen-1",
			CollectorInstanceID: "k8s-prod",
			FencingToken:        7,
			ObservedAt:          time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC),
			SourceURI:           sourceURI,
		})
		if err != nil {
			t.Fatalf("NewWarningEnvelope() error = %v, want nil", err)
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		return string(raw)
	}

	persisted := build(t, "svc:"+portedCredentialSentinel+"@h.internal:6443/api")
	if strings.Contains(persisted, portedCredentialSentinel) {
		t.Errorf("credential sentinel reached the persisted envelope:\n%s", persisted)
	}

	control := build(t, "https://h.internal/owners/"+portedCredentialSentinel+"@example.com/api")
	if !strings.Contains(control, portedCredentialSentinel) {
		t.Fatalf("positive control: path-segment sentinel missing from the marshaled envelope, so the absence assertion above is blind:\n%s", control)
	}
}

func TestPortedConfigValidation(t *testing.T) {
	t.Parallel()

	if _, err := (Config{}).validated(); err == nil {
		t.Fatalf("expected error for empty config")
	}
	if _, err := (Config{CollectorInstanceID: "x"}).validated(); err == nil {
		t.Fatalf("expected error for no clusters")
	}
	dup := Config{
		CollectorInstanceID: "x",
		Clusters:            []ClusterTarget{{ClusterID: "c"}, {ClusterID: "c"}},
	}
	if _, err := dup.validated(); err == nil {
		t.Fatalf("expected error for duplicate cluster_id")
	}
}
