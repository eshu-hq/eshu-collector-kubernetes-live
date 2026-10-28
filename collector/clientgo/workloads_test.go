// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package clientgo

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func int32Ptr(v int32) *int32 { return &v }

// TestAdapterMapsStatefulSetReplicas proves the StatefulSet desired/observed
// replica mapping mirrors Deployments.
func TestAdapterMapsStatefulSetReplicas(t *testing.T) {
	t.Parallel()

	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "db", UID: "uid-ss"},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(3),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "db", Image: "postgres:16",
			}}}},
		},
		Status: appsv1.StatefulSetStatus{ReadyReplicas: 3, AvailableReplicas: 2},
	}
	adapter := NewAdapter(fake.NewClientset(ss))

	result, err := adapter.ListStatefulSets(context.Background())
	if err != nil {
		t.Fatalf("ListStatefulSets() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("statefulset count = %d, want 1", len(result.Items))
	}
	got := result.Items[0]
	if got.Meta.Resource != "statefulsets" {
		t.Fatalf("resource = %q, want statefulsets", got.Meta.Resource)
	}
	if got.DesiredReplicas == nil || *got.DesiredReplicas != 3 {
		t.Fatalf("desired = %v, want 3", got.DesiredReplicas)
	}
	if got.ReadyReplicas == nil || *got.ReadyReplicas != 3 {
		t.Fatalf("ready = %v, want 3", got.ReadyReplicas)
	}
	if got.AvailableReplicas == nil || *got.AvailableReplicas != 2 {
		t.Fatalf("available = %v, want 2", got.AvailableReplicas)
	}
}

// TestAdapterMapsDaemonSetNodeCounts proves the DaemonSet per-node scheduling
// counts map onto the replica-equivalent fields on an observed basis.
func TestAdapterMapsDaemonSetNodeCounts(t *testing.T) {
	t.Parallel()

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "agent", UID: "uid-ds"},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "agent", Image: "acme/agent:1",
			}}}},
		},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 4, NumberReady: 3, NumberAvailable: 3},
	}
	adapter := NewAdapter(fake.NewClientset(ds))

	result, err := adapter.ListDaemonSets(context.Background())
	if err != nil {
		t.Fatalf("ListDaemonSets() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("daemonset count = %d, want 1", len(result.Items))
	}
	got := result.Items[0]
	if got.Meta.Resource != "daemonsets" {
		t.Fatalf("resource = %q, want daemonsets", got.Meta.Resource)
	}
	if got.DesiredReplicas == nil || *got.DesiredReplicas != 4 {
		t.Fatalf("desired = %v, want 4 (DesiredNumberScheduled)", got.DesiredReplicas)
	}
	if got.ReadyReplicas == nil || *got.ReadyReplicas != 3 {
		t.Fatalf("ready = %v, want 3 (NumberReady)", got.ReadyReplicas)
	}
	if got.AvailableReplicas == nil || *got.AvailableReplicas != 3 {
		t.Fatalf("available = %v, want 3 (NumberAvailable)", got.AvailableReplicas)
	}
}

// TestAdapterMapsJobAndCronJobWithoutReplicas proves Jobs carry the pod
// template and no replica fields, and CronJobs resolve the nested job
// template spec.
func TestAdapterMapsJobAndCronJobWithoutReplicas(t *testing.T) {
	t.Parallel()

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "billing", UID: "uid-j"},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "billing", Image: "acme/billing:1",
			}}}},
		},
	}
	cronJob := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "nightly", UID: "uid-cj"},
		Spec: batchv1.CronJobSpec{
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "nightly", Image: "acme/nightly:1",
					}}}},
				},
			},
		},
	}
	adapter := NewAdapter(fake.NewClientset(job, cronJob))

	jobs, err := adapter.ListJobs(context.Background())
	if err != nil {
		t.Fatalf("ListJobs() error = %v", err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("job count = %d, want 1", len(jobs.Items))
	}
	gotJob := jobs.Items[0]
	if gotJob.Meta.Resource != "jobs" {
		t.Fatalf("resource = %q, want jobs", gotJob.Meta.Resource)
	}
	if len(gotJob.Containers) != 1 || gotJob.Containers[0].Image != "acme/billing:1" {
		t.Fatalf("job containers = %+v", gotJob.Containers)
	}
	if gotJob.DesiredReplicas != nil || gotJob.ReadyReplicas != nil || gotJob.AvailableReplicas != nil {
		t.Fatal("job carries replica fields, want none")
	}

	cronJobs, err := adapter.ListCronJobs(context.Background())
	if err != nil {
		t.Fatalf("ListCronJobs() error = %v", err)
	}
	if len(cronJobs.Items) != 1 {
		t.Fatalf("cronjob count = %d, want 1", len(cronJobs.Items))
	}
	gotCron := cronJobs.Items[0]
	if gotCron.Meta.Resource != "cronjobs" {
		t.Fatalf("resource = %q, want cronjobs", gotCron.Meta.Resource)
	}
	if len(gotCron.Containers) != 1 || gotCron.Containers[0].Image != "acme/nightly:1" {
		t.Fatalf("cronjob containers = %+v (want the nested job template)", gotCron.Containers)
	}
	if gotCron.DesiredReplicas != nil || gotCron.ReadyReplicas != nil || gotCron.AvailableReplicas != nil {
		t.Fatal("cronjob carries replica fields, want none")
	}
}
