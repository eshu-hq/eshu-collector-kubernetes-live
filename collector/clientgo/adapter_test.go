// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package clientgo

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
)

// TestAdapterImplementsClientInterface pins the seam: the adapter must satisfy
// the collector Client the source drives, all fifteen list families.
func TestAdapterImplementsClientInterface(t *testing.T) {
	t.Parallel()

	var _ collector.Client = NewAdapter(fake.NewClientset())
}

// TestAdapterMapsDeploymentMetadataOnly proves the core redaction contract on
// the hottest path: image refs and env var NAMES cross the seam, env VALUES
// never do, and only the identity-binding annotations survive.
func TestAdapterMapsDeploymentMetadataOnly(t *testing.T) {
	t.Parallel()

	var replicas int32 = 3
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments", Name: "checkout", UID: "uid-d",
			Labels: map[string]string{"app": "checkout"},
			Annotations: map[string]string{
				"argocd.argoproj.io/tracking-id":                   "checkout:apps/Deployment:payments/checkout",
				"kubectl.kubernetes.io/last-applied-configuration": `{"secret":"must-not-leak"}`,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "checkout-sa",
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "ghcr.io/acme/checkout:1",
						Ports: []corev1.ContainerPort{{ContainerPort: 8080}},
						Env: []corev1.EnvVar{
							{Name: "PLAIN", Value: "plain-value-should-not-leak"},
							{Name: "FROM_SECRET", ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{Key: "k"},
							}},
						},
					}},
				},
			},
		},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 2, AvailableReplicas: 2},
	}
	adapter := NewAdapter(fake.NewClientset(deployment))

	result, err := adapter.ListDeployments(context.Background())
	if err != nil {
		t.Fatalf("ListDeployments() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("deployment count = %d, want 1", len(result.Items))
	}
	got := result.Items[0]
	if got.Meta.Namespace != "payments" || got.Meta.Name != "checkout" || got.Meta.UID != "uid-d" {
		t.Fatalf("identity = %+v, want payments/checkout uid-d", got.Meta)
	}
	if got.Meta.APIGroup != "apps" || got.Meta.Version != "v1" || got.Meta.Resource != "deployments" {
		t.Fatalf("coordinates = %+v, want apps/v1/deployments", got.Meta)
	}
	if len(got.Meta.Labels) != 1 || got.Meta.Labels["app"] != "checkout" {
		t.Fatalf("labels = %v, want the app label", got.Meta.Labels)
	}
	if len(got.Meta.Annotations) != 1 || got.Meta.Annotations["argocd.argoproj.io/tracking-id"] == "" {
		t.Fatalf("annotations = %v, want only the allowlisted tracking id", got.Meta.Annotations)
	}
	if got.ServiceAccount != "checkout-sa" {
		t.Fatalf("service account = %q, want checkout-sa", got.ServiceAccount)
	}
	if len(got.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(got.Containers))
	}
	c := got.Containers[0]
	if c.Image != "ghcr.io/acme/checkout:1" {
		t.Fatalf("image = %q", c.Image)
	}
	if len(c.EnvKeys) != 2 {
		t.Fatalf("env keys = %v, want the two NAMES", c.EnvKeys)
	}
	if !c.EnvFromSecret {
		t.Fatal("EnvFromSecret = false, want true for the secret-backed var")
	}
	for _, key := range c.EnvKeys {
		if key == "plain-value-should-not-leak" {
			t.Fatal("an env VALUE crossed the seam")
		}
	}
	if got.DesiredReplicas == nil || *got.DesiredReplicas != 3 {
		t.Fatalf("desired = %v, want 3", got.DesiredReplicas)
	}
	if got.ReadyReplicas == nil || *got.ReadyReplicas != 2 {
		t.Fatalf("ready = %v, want 2", got.ReadyReplicas)
	}
	if got.AvailableReplicas == nil || *got.AvailableReplicas != 2 {
		t.Fatalf("available = %v, want 2", got.AvailableReplicas)
	}
}

// TestAdapterResolvesPodDigestAndPhase proves pods carry the CRI-resolved
// digest and the observed phase while deployments carry neither.
func TestAdapterResolvesPodDigestAndPhase(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "checkout-abc", UID: "uid-p"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "ghcr.io/acme/checkout:1",
		}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:    "app",
				ImageID: "ghcr.io/acme/checkout@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			}},
		},
	}
	adapter := NewAdapter(fake.NewClientset(pod))

	result, err := adapter.ListPods(context.Background())
	if err != nil {
		t.Fatalf("ListPods() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("pod count = %d, want 1", len(result.Items))
	}
	got := result.Items[0]
	if got.PodPhase == nil || *got.PodPhase != "Running" {
		t.Fatalf("phase = %v, want Running", got.PodPhase)
	}
	if len(got.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(got.Containers))
	}
	if got.Containers[0].ResolvedImageDigest == "" {
		t.Fatal("resolved digest is empty, want the CRI digest normalized")
	}
}

// TestAdapterMapsServiceAndIngressEdges proves selector and backend-service
// edges cross the seam as names only.
func TestAdapterMapsServiceAndIngressEdges(t *testing.T) {
	t.Parallel()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "web-svc", UID: "uid-s"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "checkout"}},
	}
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "web", UID: "uid-i"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{Name: "web-svc"},
							},
						}},
					},
				},
			}},
		},
	}
	adapter := NewAdapter(fake.NewClientset(svc, ing))

	svcResult, err := adapter.ListServices(context.Background())
	if err != nil {
		t.Fatalf("ListServices() error = %v", err)
	}
	if len(svcResult.Items) != 1 || svcResult.Items[0].Selector["app"] != "checkout" {
		t.Fatalf("services = %+v, want the app selector", svcResult.Items)
	}
	ingResult, err := adapter.ListIngresses(context.Background())
	if err != nil {
		t.Fatalf("ListIngresses() error = %v", err)
	}
	if len(ingResult.Items) != 1 {
		t.Fatalf("ingress count = %d, want 1", len(ingResult.Items))
	}
	backends := ingResult.Items[0].BackendServices
	if len(backends) != 1 || backends[0] != "web-svc" {
		t.Fatalf("ingress backends = %v, want [web-svc]", backends)
	}
}

// TestAdapterForbiddenListIsPartial proves one denied family degrades to a
// partial warning instead of aborting the whole snapshot.
func TestAdapterForbiddenListIsPartial(t *testing.T) {
	t.Parallel()

	client := fake.NewClientset()
	client.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "", Resource: "services"}, "", errors.New("rbac: forbidden"),
		)
	})
	adapter := NewAdapter(client)

	result, err := adapter.ListServices(context.Background())
	if err != nil {
		t.Fatalf("ListServices() should not hard-fail on forbidden; err = %v", err)
	}
	if !result.Partial {
		t.Fatal("forbidden list should be partial")
	}
	if result.Reason != collector.WarningForbiddenResource {
		t.Fatalf("partial reason = %q, want forbidden_resource", result.Reason)
	}
}

// TestAdapterListsNamespacesAndReplicaSets proves the remaining core families
// cross the seam with their coordinates intact.
func TestAdapterListsNamespacesAndReplicaSets(t *testing.T) {
	t.Parallel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments", UID: "uid-ns"}}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "checkout-rs", UID: "uid-rs"},
	}
	adapter := NewAdapter(fake.NewClientset(ns, rs))

	nsResult, err := adapter.ListNamespaces(context.Background())
	if err != nil {
		t.Fatalf("ListNamespaces() error = %v", err)
	}
	if len(nsResult.Items) != 1 || nsResult.Items[0].Name != "payments" {
		t.Fatalf("namespaces = %+v, want [payments]", nsResult.Items)
	}
	rsResult, err := adapter.ListReplicaSets(context.Background())
	if err != nil {
		t.Fatalf("ListReplicaSets() error = %v", err)
	}
	if len(rsResult.Items) != 1 || rsResult.Items[0].Meta.Resource != "replicasets" {
		t.Fatalf("replicasets = %+v", rsResult.Items)
	}
}

// TestAuthConfigRequiresKubeconfigPath proves kubeconfig auth fails closed
// without a path instead of falling back to an ambient default.
func TestAuthConfigRequiresKubeconfigPath(t *testing.T) {
	t.Parallel()

	if _, err := (AuthConfig{Mode: AuthModeKubeconfig}).RESTConfig(); err == nil {
		t.Fatal("RESTConfig() error = nil for kubeconfig auth without a path")
	}
	if _, err := (AuthConfig{Mode: "nope"}).RESTConfig(); err == nil {
		t.Fatal("RESTConfig() error = nil for an unknown auth mode")
	}
}
