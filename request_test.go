// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// validTestClaim carries every identity field ParseRequest requires, so the
// request decodes and the result echoes it back to the host.
func validTestClaim() sdk.Claim {
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "k8s-qa-1",
		CollectorKind: CollectorKind,
		SourceSystem:  SourceSystem,
		Scope:         sdk.Scope{ID: "cluster-scope", Kind: "cluster"},
		GenerationID:  "generation-1",
	}
}

func encodeTestRequest(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	raw, err := json.Marshal(Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           validTestClaim(),
		Contract:        Contract(),
		Config:          map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mutate == nil {
		return string(raw)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	mutate(doc)
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestParseRequestAcceptsAValidDocument(t *testing.T) {
	t.Parallel()

	request, err := ParseRequest(strings.NewReader(encodeTestRequest(t, nil)))
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if request.Claim.InstanceID != "k8s-qa-1" {
		t.Fatalf("Claim.InstanceID = %q, want the decoded claim echoed", request.Claim.InstanceID)
	}
	if request.ProtocolVersion != sdk.ProtocolVersionV1Alpha1 {
		t.Fatalf("ProtocolVersion = %q, want the decoded version", request.ProtocolVersion)
	}
}

func TestParseRequestRejectsUnknownFieldsWithoutQuotingInput(t *testing.T) {
	t.Parallel()

	const marker = "SECRET-MARKER-5521"
	_, err := ParseRequest(strings.NewReader(encodeTestRequest(t, func(doc map[string]any) {
		doc[marker] = "planted"
	})))
	if err == nil {
		t.Fatal("ParseRequest() error = nil, want unknown-field rejection")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error quotes the input field %q: %v", marker, err)
	}
}

func TestParseRequestRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	_, err := ParseRequest(strings.NewReader(encodeTestRequest(t, nil) + " {}"))
	if err == nil {
		t.Fatal("ParseRequest() error = nil, want trailing-JSON rejection")
	}
}

func TestParseRequestRejectsOversizeDocuments(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("a", MaxRequestBytes+1)
	_, err := ParseRequest(strings.NewReader(big))
	if err == nil {
		t.Fatal("ParseRequest() error = nil, want the size cap enforced")
	}
}

func TestParseRequestRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	_, err := ParseRequest(strings.NewReader("{not json"))
	if err == nil {
		t.Fatal("ParseRequest() error = nil, want malformed-JSON rejection")
	}
}

func TestParseRequestRejectsUnsupportedProtocol(t *testing.T) {
	t.Parallel()

	_, err := ParseRequest(strings.NewReader(encodeTestRequest(t, func(doc map[string]any) {
		doc["protocol_version"] = "collector-sdk/v9"
	})))
	if err == nil {
		t.Fatal("ParseRequest() error = nil, want protocol rejection")
	}
}

func TestParseRequestRequiresClaimIdentity(t *testing.T) {
	t.Parallel()

	fields := map[string]func(*sdk.Claim){
		"claim.component_id":   func(c *sdk.Claim) { c.ComponentID = " " },
		"claim.instance_id":    func(c *sdk.Claim) { c.InstanceID = "" },
		"claim.collector_kind": func(c *sdk.Claim) { c.CollectorKind = "" },
		"claim.source_system":  func(c *sdk.Claim) { c.SourceSystem = "" },
		"claim.scope.id":       func(c *sdk.Claim) { c.Scope.ID = "" },
		"claim.scope.kind":     func(c *sdk.Claim) { c.Scope.Kind = "" },
		"claim.generation_id":  func(c *sdk.Claim) { c.GenerationID = "" },
	}
	for field, blank := range fields {
		claim := validTestClaim()
		blank(&claim)
		raw, err := json.Marshal(Request{
			ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
			Claim:           claim,
			Contract:        Contract(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRequest(strings.NewReader(string(raw))); err == nil {
			t.Errorf("ParseRequest() error = nil, want %s rejection", field)
		}
	}
}

func TestParseRequestRejectsForeignCollectorKind(t *testing.T) {
	t.Parallel()

	claim := validTestClaim()
	claim.CollectorKind = "aws_cloud"
	raw, err := json.Marshal(Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(strings.NewReader(string(raw))); err == nil {
		t.Fatal("ParseRequest() error = nil, want collector-kind rejection")
	}
}
