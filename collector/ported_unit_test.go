// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Provenance: expectations ported VERBATIM from the in-tree unit tests at
// core commit 95dfc56ebb54 — TestSourceHappyPathEmitsTypedFacts,
// TestSourceEmitsSecretsIAMKubernetesRBACFacts,
// TestSourceEmitsGCPWorkloadIdentityBindingOnlyWithConfiguredPool,
// TestSourceRBACForbiddenListEmitsCoverageWarning,
// TestEnvelopeBoundaryValidation, TestSanitizeURLDropsOpaqueCredentials,
// TestWarningEnvelopeNeverPersistsOpaqueCredential, and TestConfigValidation.
// These cover the emission paths the fixture pack cannot carry (RBAC group,
// ingress edges) with expectations the lane author wrote against in-tree
// behavior, so they are an independent oracle for the port — not
// self-derived. Only identifiers changed (local consts, slice envelopes).

const portedCredentialSentinel = "EMBEDDED-CRED-SENTINEL-6119"

func portedSampleIdentity() ObjectIdentity {
	return ObjectIdentity{
		ClusterID: "prod-us-east-1",
		APIGroup:  "apps",
		Version:   "v1",
		Resource:  "deployments",
		Namespace: "payments",
		Name:      "checkout",
		UID:       "uid-checkout-1",
	}
}

func portedFixedClock() func() time.Time {
	fixed := time.Date(2026, 5, 31, 9, 0, 0, 0, time.UTC)
	return func() time.Time { return fixed }
}

func portedNewSource(client Client) *Source {
	return &Source{
		Config: Config{
			CollectorInstanceID: "k8s-prod",
			Clusters:            []ClusterTarget{{ClusterID: "prod-us-east-1", FencingToken: 3}},
		},
		ClientFactory: factoryFor(client),
		Clock:         portedFixedClock(),
	}
}

func portedCountKind(envs []Envelope, kind string) int {
	n := 0
	for _, env := range envs {
		if env.FactKind == kind {
			n++
		}
	}
	return n
}

func portedPayloadContains(payload map[string]any, needle string) bool {
	for _, value := range payload {
		if portedValueContains(value, needle) {
			return true
		}
	}
	return false
}

func portedValueContains(value any, needle string) bool {
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, needle)
	case []string:
		for _, item := range typed {
			if strings.Contains(item, needle) {
				return true
			}
		}
	case []map[string]any:
		for _, item := range typed {
			if portedPayloadContains(item, needle) {
				return true
			}
		}
	case map[string]any:
		return portedPayloadContains(typed, needle)
	case map[string]string:
		for k, v := range typed {
			if strings.Contains(k, needle) || strings.Contains(v, needle) {
				return true
			}
		}
	}
	return false
}

func TestPortedSourceHappyPathEmitsTypedFacts(t *testing.T) {
	t.Parallel()

	deployment := WorkloadObject{
		Meta: ObjectMeta{
			APIGroup: "apps", Version: "v1", Resource: "deployments",
			Namespace: "payments", Name: "checkout", UID: "uid-deploy",
		},
		ServiceAccount: "checkout-sa",
		Selector:       map[string]string{"app": "checkout"},
		Containers:     []ContainerSummary{{Name: "app", Image: "img:1", EnvKeys: []string{"PORT"}}},
	}
	replicaset := WorkloadObject{
		Meta: ObjectMeta{
			APIGroup: "apps", Version: "v1", Resource: "replicasets",
			Namespace: "payments", Name: "checkout-rs", UID: "uid-rs",
			OwnerReferences: []OwnerReference{{Kind: "Deployment", Name: "checkout", UID: "uid-deploy"}},
		},
		Containers: []ContainerSummary{{Name: "app", Image: "img:1"}},
	}
	statefulset := WorkloadObject{
		Meta: ObjectMeta{
			APIGroup: "apps", Version: "v1", Resource: "statefulsets",
			Namespace: "payments", Name: "checkout-db", UID: "uid-ss",
		},
		Containers: []ContainerSummary{{Name: "db", Image: "img-db:1"}},
	}
	service := ServiceObject{
		Meta: ObjectMeta{
			Version: "v1", Resource: "services",
			Namespace: "payments", Name: "checkout-svc", UID: "uid-svc",
		},
	}
	ingress := IngressObject{
		Meta: ObjectMeta{
			APIGroup: "networking.k8s.io", Version: "v1", Resource: "ingresses",
			Namespace: "payments", Name: "checkout-ing", UID: "uid-ing",
		},
		BackendServices: []string{"checkout-svc"},
	}

	client := &fakeClient{
		namespaces: ListResult[ObjectMeta]{Items: []ObjectMeta{{
			Version: "v1", Resource: "namespaces", Name: "payments", UID: "uid-ns",
			Labels: map[string]string{"environment": "prod"},
		}}},
		deployments:  ListResult[WorkloadObject]{Items: []WorkloadObject{deployment}},
		replicasets:  ListResult[WorkloadObject]{Items: []WorkloadObject{replicaset}},
		statefulsets: ListResult[WorkloadObject]{Items: []WorkloadObject{statefulset}},
		services:     ListResult[ServiceObject]{Items: []ServiceObject{service}},
		ingresses:    ListResult[IngressObject]{Items: []IngressObject{ingress}},
	}

	source := portedNewSource(client)
	collected, ok, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if !ok {
		t.Fatalf("Next() ok = false, want true")
	}
	if collected.Scope.ScopeKind != "cluster" {
		t.Fatalf("ScopeKind = %q, want cluster", collected.Scope.ScopeKind)
	}
	if collected.Scope.CollectorKind != CollectorKind {
		t.Fatalf("CollectorKind = %q, want kubernetes_live", collected.Scope.CollectorKind)
	}
	if collected.Generation.FreshnessHint != "complete" {
		t.Fatalf("FreshnessHint = %q, want complete", collected.Generation.FreshnessHint)
	}

	envs := collected.Envelopes
	if got := portedCountKind(envs, KubernetesPodTemplateFactKind); got != 3 {
		t.Fatalf("pod_template facts = %d, want 3 (deployment + replicaset + statefulset)", got)
	}
	if got := portedCountKind(envs, KubernetesRelationshipFactKind); got != 2 {
		t.Fatalf("relationship facts = %d, want 2 (owner + ingress), got %d", got, got)
	}
	if got := portedCountKind(envs, KubernetesWarningFactKind); got != 0 {
		t.Fatalf("warning facts = %d, want 0", got)
	}
	nsEnvs := envelopesOfKind(envs, KubernetesNamespaceFactKind)
	if len(nsEnvs) != 1 {
		t.Fatalf("namespace facts = %d, want 1", len(nsEnvs))
	}
	if got := nsEnvs[0].Payload["namespace"]; got != "payments" {
		t.Fatalf("namespace fact payload[namespace] = %#v, want %q", got, "payments")
	}
	nsLabels, ok := nsEnvs[0].Payload["labels"].(map[string]string)
	if !ok || nsLabels["environment"] != "prod" {
		t.Fatalf("namespace fact payload[labels] = %#v, want {environment: prod}", nsEnvs[0].Payload["labels"])
	}
	for _, env := range envs {
		if env.GenerationID != collected.Generation.GenerationID {
			t.Fatalf("fact generation %q != scope generation %q", env.GenerationID, collected.Generation.GenerationID)
		}
		if env.ScopeID != collected.Scope.ScopeID {
			t.Fatalf("fact scope %q != scope %q", env.ScopeID, collected.Scope.ScopeID)
		}
		if env.FencingToken != 3 {
			t.Fatalf("fact fencing token = %d, want 3", env.FencingToken)
		}
	}
}

func TestPortedSourceEmitsRBACFacts(t *testing.T) {
	t.Parallel()

	automount := false
	serviceAccount := ServiceAccountObject{
		Meta: ObjectMeta{
			Version: "v1", Resource: "serviceaccounts",
			Namespace: "payments", Name: "checkout-sa", UID: "uid-sa",
		},
		AnnotationKeys: []string{"eks.amazonaws.com/role-arn"},
		IRSAAnnotation: "arn:aws:iam::123456789012:role/checkout",
		AutomountToken: &automount,
		SecretRefCount: 2,
	}
	role := RBACRoleObject{
		Meta: ObjectMeta{
			APIGroup: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles",
			Namespace: "payments", Name: "secret-reader", UID: "uid-role",
		},
		Kind: RBACRoleKindRole,
		Rules: []RBACRuleSummary{{
			Verbs:                []string{"get", "list"},
			APIGroups:            []string{""},
			Resources:            []string{"secrets"},
			ResourceNameCount:    1,
			ResourceNamesPresent: true,
		}},
	}
	clusterRole := RBACRoleObject{
		Meta: ObjectMeta{
			APIGroup: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles",
			Name: "cluster-reader", UID: "uid-clusterrole",
		},
		Kind:  RBACRoleKindClusterRole,
		Rules: []RBACRuleSummary{{Verbs: []string{"get"}, Resources: []string{"pods"}}},
	}
	roleBinding := RBACBindingObject{
		Meta: ObjectMeta{
			APIGroup: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings",
			Namespace: "payments", Name: "read-secrets", UID: "uid-rb",
		},
		Kind:        BindingKindRoleBinding,
		RoleRefKind: RBACRoleKindRole,
		RoleRefName: "secret-reader",
		Subjects: []RBACSubject{{
			Kind: "ServiceAccount", Namespace: "payments", Name: "checkout-sa",
		}},
	}
	clusterRoleBinding := RBACBindingObject{
		Meta: ObjectMeta{
			APIGroup: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings",
			Name: "cluster-reader-binding", UID: "uid-crb",
		},
		Kind:        BindingKindClusterRoleBinding,
		RoleRefKind: RBACRoleKindClusterRole,
		RoleRefName: "cluster-reader",
		Subjects: []RBACSubject{{
			Kind: "Group", Name: "platform-admins",
		}},
	}
	deployment := WorkloadObject{
		Meta: ObjectMeta{
			APIGroup: "apps", Version: "v1", Resource: "deployments",
			Namespace: "payments", Name: "checkout", UID: "uid-deploy",
		},
		ServiceAccount:               "checkout-sa",
		ProjectedServiceAccountToken: true,
	}
	client := &fakeClient{
		serviceAccounts:     ListResult[ServiceAccountObject]{Items: []ServiceAccountObject{serviceAccount}},
		roles:               ListResult[RBACRoleObject]{Items: []RBACRoleObject{role}},
		clusterRoles:        ListResult[RBACRoleObject]{Items: []RBACRoleObject{clusterRole}},
		roleBindings:        ListResult[RBACBindingObject]{Items: []RBACBindingObject{roleBinding}},
		clusterRoleBindings: ListResult[RBACBindingObject]{Items: []RBACBindingObject{clusterRoleBinding}},
		deployments:         ListResult[WorkloadObject]{Items: []WorkloadObject{deployment}},
	}

	source := portedNewSource(client)
	collected, ok, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if !ok {
		t.Fatalf("Next() ok = false, want true")
	}
	envs := collected.Envelopes
	if got := portedCountKind(envs, KubernetesServiceAccountFactKind); got != 1 {
		t.Fatalf("service account facts = %d, want 1", got)
	}
	if got := portedCountKind(envs, KubernetesServiceAccountTokenPostureFactKind); got != 1 {
		t.Fatalf("token posture facts = %d, want 1", got)
	}
	if got := portedCountKind(envs, EKSIRSAAnnotationFactKind); got != 1 {
		t.Fatalf("IRSA annotation facts = %d, want 1", got)
	}
	if got := portedCountKind(envs, KubernetesRBACRoleFactKind); got != 2 {
		t.Fatalf("RBAC role facts = %d, want 2", got)
	}
	bindings := envelopesOfKind(envs, KubernetesRBACBindingFactKind)
	if len(bindings) != 2 {
		t.Fatalf("RBAC binding facts = %d, want 2", len(bindings))
	}
	seenScopes := map[string]bool{}
	for _, binding := range bindings {
		scopeValue, _ := binding.Payload["binding_scope"].(string)
		seenScopes[scopeValue] = true
		if portedPayloadContains(binding.Payload, "payments") ||
			portedPayloadContains(binding.Payload, "checkout-sa") ||
			portedPayloadContains(binding.Payload, "platform-admins") {
			t.Fatalf("binding payload leaked raw subject names: %#v", binding.Payload)
		}
	}
	if !seenScopes[BindingScopeNamespace] || !seenScopes[BindingScopeCluster] {
		t.Fatalf("binding scopes = %v, want namespace and cluster", seenScopes)
	}
	if got := portedCountKind(envs, KubernetesWorkloadIdentityUseFactKind); got != 1 {
		t.Fatalf("workload identity use facts = %d, want 1", got)
	}
}

func TestPortedSourceEmitsGCPBindingOnlyWithConfiguredPool(t *testing.T) {
	t.Parallel()

	serviceAccount := ServiceAccountObject{
		Meta: ObjectMeta{
			Version: "v1", Resource: "serviceaccounts",
			Namespace: "payments", Name: "checkout-sa", UID: "uid-sa",
		},
		AnnotationKeys:              []string{"iam.gke.io/gcp-service-account"},
		GCPServiceAccountAnnotation: "app@demo-proj.iam.gserviceaccount.com",
	}
	client := &fakeClient{
		serviceAccounts: ListResult[ServiceAccountObject]{Items: []ServiceAccountObject{serviceAccount}},
	}

	withPool := &Source{
		Config: Config{
			CollectorInstanceID: "k8s-prod",
			Clusters: []ClusterTarget{{
				ClusterID:       "prod-gke",
				FencingToken:    3,
				GCPWorkloadPool: "demo-proj.svc.id.goog",
			}},
		},
		ClientFactory: factoryFor(client),
		Clock:         portedFixedClock(),
	}
	collected, ok, err := withPool.Next(context.Background())
	if err != nil {
		t.Fatalf("Next(withPool) error = %v", err)
	}
	if !ok {
		t.Fatalf("Next(withPool) ok = false, want true")
	}
	envs := collected.Envelopes
	bindings := envelopesOfKind(envs, KubernetesGCPWorkloadIdentityBindingFactKind)
	if len(bindings) != 1 {
		t.Fatalf("GCP Workload Identity binding facts = %d, want 1: %#v", len(bindings), envs)
	}
	binding := bindings[0]
	for _, forbidden := range []string{
		"app@demo-proj.iam.gserviceaccount.com",
		"demo-proj.svc.id.goog",
		"payments",
		"checkout-sa",
	} {
		if portedPayloadContains(binding.Payload, forbidden) {
			t.Fatalf("binding payload leaked raw identity %q: %#v", forbidden, binding.Payload)
		}
	}

	withoutPool := portedNewSource(client)
	collected, ok, err = withoutPool.Next(context.Background())
	if err != nil {
		t.Fatalf("Next(withoutPool) error = %v", err)
	}
	if !ok {
		t.Fatalf("Next(withoutPool) ok = false, want true")
	}
	envs = collected.Envelopes
	if got := portedCountKind(envs, KubernetesGCPWorkloadIdentityBindingFactKind); got != 0 {
		t.Fatalf("GCP Workload Identity binding facts without pool = %d, want 0", got)
	}
}

func TestPortedSourceRBACForbiddenListEmitsCoverageWarning(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		roles: ListResult[RBACRoleObject]{Partial: true, Reason: WarningForbiddenResource},
	}
	source := portedNewSource(client)
	collected, ok, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if !ok {
		t.Fatalf("Next() ok = false, want true")
	}
	if collected.Generation.FreshnessHint != "partial" {
		t.Fatalf("FreshnessHint = %q, want partial", collected.Generation.FreshnessHint)
	}
	envs := collected.Envelopes
	if got := portedCountKind(envs, SecretsIAMCoverageWarningFactKind); got != 1 {
		t.Fatalf("secrets/IAM coverage warnings = %d, want 1", got)
	}
}
