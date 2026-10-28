// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package clientgo

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestAdapterMapsServiceAccountIdentity proves the ServiceAccount view keeps
// annotation KEYS (sorted), the IRSA and GCP binding values the source later
// fingerprints or digests, and bounded reference counts — never token, secret,
// or pull-secret names or values.
var automountFalse = false

func TestAdapterMapsServiceAccountIdentity(t *testing.T) {
	t.Parallel()

	account := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments", Name: "checkout-sa", UID: "uid-sa",
			Annotations: map[string]string{
				"eks.amazonaws.com/role-arn":       "arn:aws:iam::123:role/checkout",
				"iam.gke.io/gcp-service-account":   "checkout@gcp-project.iam.gserviceaccount.com",
				"unrelated.example.com/irrelevant": "dropped-from-keys-only-view",
			},
		},
		Secrets:                      []corev1.ObjectReference{{Name: "token-secret-name-must-not-leak"}},
		ImagePullSecrets:             []corev1.LocalObjectReference{{Name: "pull-secret-name-must-not-leak"}},
		AutomountServiceAccountToken: &automountFalse,
	}
	adapter := NewAdapter(fake.NewClientset(account))

	result, err := adapter.ListServiceAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListServiceAccounts() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("serviceaccount count = %d, want 1", len(result.Items))
	}
	got := result.Items[0]
	if got.Meta.Resource != "serviceaccounts" {
		t.Fatalf("resource = %q, want serviceaccounts", got.Meta.Resource)
	}
	if len(got.AnnotationKeys) != 3 {
		t.Fatalf("annotation keys = %v, want all three keys sorted", got.AnnotationKeys)
	}
	for i := 1; i < len(got.AnnotationKeys); i++ {
		if got.AnnotationKeys[i-1] >= got.AnnotationKeys[i] {
			t.Fatalf("annotation keys = %v, want sorted", got.AnnotationKeys)
		}
	}
	if got.IRSAAnnotation != "arn:aws:iam::123:role/checkout" {
		t.Fatalf("IRSA annotation = %q", got.IRSAAnnotation)
	}
	if got.GCPServiceAccountAnnotation == "" {
		t.Fatal("GCP binding annotation is empty")
	}
	if got.SecretRefCount != 1 || got.ImagePullSecretRefCount != 1 {
		t.Fatalf("ref counts = %d/%d, want 1/1", got.SecretRefCount, got.ImagePullSecretRefCount)
	}
	if got.AutomountToken == nil || *got.AutomountToken {
		t.Fatalf("automount = %v, want false", got.AutomountToken)
	}
}

// TestAdapterRedactsRBACRules proves policy rules keep verbs, groups, and
// resources but only the PRESENCE and COUNT of resource names and
// non-resource URLs — the selectors themselves never cross the seam.
func TestAdapterRedactsRBACRules(t *testing.T) {
	t.Parallel()

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "reader", UID: "uid-r"},
		Rules: []rbacv1.PolicyRule{{
			Verbs:           []string{"get", "list"},
			APIGroups:       []string{""},
			Resources:       []string{"pods"},
			ResourceNames:   []string{"checkout-abc", "checkout-def"},
			NonResourceURLs: []string{"/healthz"},
		}},
	}
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-reader", UID: "uid-cr"},
		Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"namespaces"},
		}},
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "readers", UID: "uid-rb"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "reader"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", APIGroup: "", Namespace: "payments", Name: "checkout-sa"}},
	}
	clusterBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-readers", UID: "uid-crb"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-reader"},
		Subjects:   []rbacv1.Subject{{Kind: "Group", APIGroup: "rbac.authorization.k8s.io", Name: "ops"}},
	}
	adapter := NewAdapter(fake.NewClientset(role, clusterRole, binding, clusterBinding))

	roles, err := adapter.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles() error = %v", err)
	}
	if len(roles.Items) != 1 {
		t.Fatalf("role count = %d, want 1", len(roles.Items))
	}
	gotRole := roles.Items[0]
	if gotRole.Kind != "Role" {
		t.Fatalf("kind = %q, want Role", gotRole.Kind)
	}
	if len(gotRole.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(gotRole.Rules))
	}
	rule := gotRole.Rules[0]
	if len(rule.Verbs) != 2 || len(rule.Resources) != 1 {
		t.Fatalf("rule = %+v, want verbs and resources", rule)
	}
	if !rule.ResourceNamesPresent || rule.ResourceNameCount != 2 {
		t.Fatalf("rule = %+v, want resource-name presence and count 2", rule)
	}
	if !rule.NonResourceURLsPresent || rule.NonResourceURLCount != 1 {
		t.Fatalf("rule = %+v, want non-resource-URL presence and count 1", rule)
	}

	clusterRoles, err := adapter.ListClusterRoles(context.Background())
	if err != nil {
		t.Fatalf("ListClusterRoles() error = %v", err)
	}
	if len(clusterRoles.Items) != 1 || clusterRoles.Items[0].Kind != "ClusterRole" {
		t.Fatalf("clusterroles = %+v", clusterRoles.Items)
	}

	bindings, err := adapter.ListRoleBindings(context.Background())
	if err != nil {
		t.Fatalf("ListRoleBindings() error = %v", err)
	}
	if len(bindings.Items) != 1 {
		t.Fatalf("binding count = %d, want 1", len(bindings.Items))
	}
	gotBinding := bindings.Items[0]
	if gotBinding.Kind != "RoleBinding" || gotBinding.RoleRefName != "reader" {
		t.Fatalf("binding = %+v", gotBinding)
	}
	if len(gotBinding.Subjects) != 1 || gotBinding.Subjects[0].Name != "checkout-sa" {
		t.Fatalf("subjects = %+v", gotBinding.Subjects)
	}

	clusterBindings, err := adapter.ListClusterRoleBindings(context.Background())
	if err != nil {
		t.Fatalf("ListClusterRoleBindings() error = %v", err)
	}
	if len(clusterBindings.Items) != 1 || clusterBindings.Items[0].Kind != "ClusterRoleBinding" {
		t.Fatalf("clusterrolebindings = %+v", clusterBindings.Items)
	}
}

// TestProjectedServiceAccountTokenSpotsTokenVolumes proves the projected
// token signal fires only on volumes with a service-account-token source,
// never on plain or empty projected volumes.
func TestProjectedServiceAccountTokenSpotsTokenVolumes(t *testing.T) {
	t.Parallel()

	token := corev1.Volume{
		Name: "token",
		VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
			{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}},
		}}},
	}
	plain := corev1.Volume{
		Name: "config",
		VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
			{ConfigMap: &corev1.ConfigMapProjection{}},
		}}},
	}
	empty := corev1.Volume{Name: "data"}
	if !projectedServiceAccountToken([]corev1.Volume{plain, token}) {
		t.Fatal("token volume present, want true")
	}
	if projectedServiceAccountToken([]corev1.Volume{plain, empty}) {
		t.Fatal("no token volume, want false")
	}
	if projectedServiceAccountToken(nil) {
		t.Fatal("nil volumes, want false")
	}
}
