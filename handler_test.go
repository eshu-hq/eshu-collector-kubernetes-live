// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"testing"
	"time"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// stubLiveClient serves one canned namespace and empty lists for every other
// family. It proves the handler scans the claimed cluster and maps facts
// without a live backend.
type stubLiveClient struct {
	pingErr      error
	namespaces   []corecollector.ObjectMeta
	namespacesEr error
}

func (s *stubLiveClient) PingReadOnly(context.Context) error { return s.pingErr }

func (s *stubLiveClient) ListNamespaces(context.Context) (corecollector.ListResult[corecollector.ObjectMeta], error) {
	if s.namespacesEr != nil {
		return corecollector.ListResult[corecollector.ObjectMeta]{}, s.namespacesEr
	}
	return corecollector.ListResult[corecollector.ObjectMeta]{Items: append([]corecollector.ObjectMeta(nil), s.namespaces...)}, nil
}

func emptyList[T any]() corecollector.ListResult[T] {
	return corecollector.ListResult[T]{}
}

func (s *stubLiveClient) ListPods(context.Context) (corecollector.ListResult[corecollector.WorkloadObject], error) {
	return emptyList[corecollector.WorkloadObject](), nil
}

func (s *stubLiveClient) ListDeployments(context.Context) (corecollector.ListResult[corecollector.WorkloadObject], error) {
	return emptyList[corecollector.WorkloadObject](), nil
}

func (s *stubLiveClient) ListReplicaSets(context.Context) (corecollector.ListResult[corecollector.WorkloadObject], error) {
	return emptyList[corecollector.WorkloadObject](), nil
}

func (s *stubLiveClient) ListStatefulSets(context.Context) (corecollector.ListResult[corecollector.WorkloadObject], error) {
	return emptyList[corecollector.WorkloadObject](), nil
}

func (s *stubLiveClient) ListDaemonSets(context.Context) (corecollector.ListResult[corecollector.WorkloadObject], error) {
	return emptyList[corecollector.WorkloadObject](), nil
}

func (s *stubLiveClient) ListJobs(context.Context) (corecollector.ListResult[corecollector.WorkloadObject], error) {
	return emptyList[corecollector.WorkloadObject](), nil
}

func (s *stubLiveClient) ListCronJobs(context.Context) (corecollector.ListResult[corecollector.WorkloadObject], error) {
	return emptyList[corecollector.WorkloadObject](), nil
}

func (s *stubLiveClient) ListServices(context.Context) (corecollector.ListResult[corecollector.ServiceObject], error) {
	return emptyList[corecollector.ServiceObject](), nil
}

func (s *stubLiveClient) ListIngresses(context.Context) (corecollector.ListResult[corecollector.IngressObject], error) {
	return emptyList[corecollector.IngressObject](), nil
}

func (s *stubLiveClient) ListServiceAccounts(context.Context) (corecollector.ListResult[corecollector.ServiceAccountObject], error) {
	return emptyList[corecollector.ServiceAccountObject](), nil
}

func (s *stubLiveClient) ListRoles(context.Context) (corecollector.ListResult[corecollector.RBACRoleObject], error) {
	return emptyList[corecollector.RBACRoleObject](), nil
}

func (s *stubLiveClient) ListClusterRoles(context.Context) (corecollector.ListResult[corecollector.RBACRoleObject], error) {
	return emptyList[corecollector.RBACRoleObject](), nil
}

func (s *stubLiveClient) ListRoleBindings(context.Context) (corecollector.ListResult[corecollector.RBACBindingObject], error) {
	return emptyList[corecollector.RBACBindingObject](), nil
}

func (s *stubLiveClient) ListClusterRoleBindings(context.Context) (corecollector.ListResult[corecollector.RBACBindingObject], error) {
	return emptyList[corecollector.RBACBindingObject](), nil
}

// emptyLiveClientFactory is the no-cluster backend behind the envelope
// acceptance tests: it implements the client seam with no data.
type emptyLiveClientFactory struct{}

func (emptyLiveClientFactory) Client(context.Context, corecollector.ClusterTarget) (corecollector.Client, error) {
	return &stubLiveClient{}, nil
}

func cannedNamespace() corecollector.ObjectMeta {
	return corecollector.ObjectMeta{
		Version:  "v1",
		Resource: "namespaces",
		Name:     "default",
		UID:      "uid-default-1",
	}
}

func handlerClaim() sdk.Claim {
	scopeID, err := corecollector.ClusterScopeID("ops-qa-1")
	if err != nil {
		panic(err)
	}
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "k8s-handler-test",
		CollectorKind: CollectorKind,
		SourceSystem:  SourceSystem,
		Scope:         sdk.Scope{ID: scopeID, Kind: "cluster"},
		SourceRunID:   "run-1",
		GenerationID:  "generation-handler-1",
		WorkItemID:    "work-1",
		FencingToken:  "7",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Hour).UTC(),
		ConfigHandle:  "component-config:kubernetes-live",
	}
}

func handlerTargetConfig() map[string]any {
	return map[string]any{
		"cluster_id": "ops-qa-1",
		"source_uri": "https://kubernetes.default.svc",
	}
}

func handlerWith(client corecollector.Client) Handler {
	return Handler{
		ClientFactory: corecollector.ClientFactoryFunc(func(context.Context, corecollector.ClusterTarget) (corecollector.Client, error) {
			return client, nil
		}),
	}
}

// TestHandleServesAClaimComplete proves the happy path: the handler scans the
// claimed cluster, echoes the claim, emits facts that validate against the
// contract, and reports complete.
func TestHandleServesAClaimComplete(t *testing.T) {
	t.Parallel()

	claim := handlerClaim()
	handler := handlerWith(&stubLiveClient{namespaces: []corecollector.ObjectMeta{cannedNamespace()}})
	result, err := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if result.Claim != claim {
		t.Fatalf("Claim was not echoed: %+v", result.Claim)
	}
	if len(result.Facts) != 1 {
		t.Fatalf("Facts = %d, want 1 namespace fact", len(result.Facts))
	}
	fact := result.Facts[0]
	if fact.Kind != FactKindNamespace {
		t.Fatalf("Kind = %q, want %q", fact.Kind, FactKindNamespace)
	}
	if fact.SourceRef.ScopeID != claim.Scope.ID {
		t.Fatalf("fact does not carry the claim scope: %+v", fact.SourceRef)
	}
	if fact.SourceRef.SourceSystem != claim.SourceSystem {
		t.Fatalf("SourceSystem = %q, want the claim source system %q", fact.SourceRef.SourceSystem, claim.SourceSystem)
	}
	report, err := sdk.NewValidator(Contract()).ValidateResult(result)
	if err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if report.FactCount != len(result.Facts) {
		t.Fatalf("FactCount = %d, want %d", report.FactCount, len(result.Facts))
	}
}

// TestHandleReportsCollectionFailedWhenTheClusterIsUnreachable proves a scan
// that cannot reach a cluster is a collection failure, not invalid_config:
// the config was accepted and the scope matched.
func TestHandleReportsCollectionFailedWhenTheClusterIsUnreachable(t *testing.T) {
	t.Parallel()

	handler := handlerWith(&stubLiveClient{pingErr: context.DeadlineExceeded})
	result, err := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           handlerClaim(),
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State == sdk.ResultTerminal {
		for _, status := range result.Statuses {
			if status.FailureClass == FailureInvalidConfig {
				t.Fatalf("State is terminal invalid_config %+v, want the config accepted", result.Statuses)
			}
		}
	}
	found := false
	for _, status := range result.Statuses {
		if status.FailureClass == FailureCollection {
			found = true
		}
	}
	if !found {
		t.Fatalf("Statuses = %+v, want collection_failed", result.Statuses)
	}
	if len(result.Facts) != 0 {
		t.Fatal("failed result carries facts")
	}
}

// TestHandleReportsCollectionFailedWithoutAClientFactory proves the zero-value
// client seam is honest: with no live backend configured the claim fails
// terminal collection_failed, never invalid_config.
func TestHandleReportsCollectionFailedWithoutAClientFactory(t *testing.T) {
	t.Parallel()

	result, err := Handler{}.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           handlerClaim(),
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if result.Statuses[0].FailureClass != FailureCollection {
		t.Fatalf("FailureClass = %q, want %q", result.Statuses[0].FailureClass, FailureCollection)
	}
}

// TestHandleRejectsMismatchedSingleTargetClaimTerminal proves end-to-end
// protection: a single-target activation serving a claim for another cluster
// returns terminal invalid_config with no facts, so the wrong cluster is
// never scanned.
func TestHandleRejectsMismatchedSingleTargetClaimTerminal(t *testing.T) {
	t.Parallel()

	claim := handlerClaim()
	claim.Scope.ID = "kubernetes_live:does-not-match-any-target"
	result, err := handlerWith(&stubLiveClient{}).Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if len(result.Facts) != 0 {
		t.Fatal("terminal result carries facts")
	}
	if result.Statuses[0].FailureClass != FailureInvalidConfig {
		t.Fatalf("FailureClass = %q, want %q", result.Statuses[0].FailureClass, FailureInvalidConfig)
	}
}

// TestHandleRejectsUnparseableFencingTokenTerminal proves a claim fencing
// token that is not an integer fails closed instead of silently zeroing.
func TestHandleRejectsUnparseableFencingTokenTerminal(t *testing.T) {
	t.Parallel()

	claim := handlerClaim()
	claim.FencingToken = "not-an-integer"
	result, err := handlerWith(&stubLiveClient{}).Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if result.State != sdk.ResultTerminal || result.Statuses[0].FailureClass != FailureInvalidConfig {
		t.Fatalf("State = %q %+v, want terminal invalid_config", result.State, result.Statuses)
	}
}
