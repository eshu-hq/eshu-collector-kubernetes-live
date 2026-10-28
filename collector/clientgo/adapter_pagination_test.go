// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package clientgo

import (
	"context"
	"errors"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
)

// paginationNamespaces returns the five namespaces the paging stub serves.
func paginationNamespaces() []*corev1.Namespace {
	return []*corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "ns-0", UID: "uid-0"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "ns-1", UID: "uid-1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "ns-2", UID: "uid-2"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "ns-3", UID: "uid-3"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "ns-4", UID: "uid-4"}},
	}
}

// serveNamespacePage slices the stub list by the request's Limit/Continue.
// The fake tracker ignores Continue, so the stub honors the paging contract
// the adapter relies on. failOnContinue makes that page fail generically.
func serveNamespacePage(
	action k8stesting.Action,
	all []*corev1.Namespace,
	failOnContinue string,
) (bool, runtime.Object, error) {
	getter, ok := action.(interface{ GetListOptions() metav1.ListOptions })
	if !ok {
		return true, nil, errors.New("list action carries no ListOptions")
	}
	opts := getter.GetListOptions()
	if failOnContinue != "" && opts.Continue == failOnContinue {
		return true, nil, errors.New("mid-stream failure")
	}
	start := 0
	if opts.Continue != "" {
		v, err := strconv.Atoi(opts.Continue)
		if err != nil {
			return true, nil, err
		}
		start = v
	}
	if start > len(all) {
		return true, nil, errors.New("continue offset past the end")
	}
	limit := int(opts.Limit)
	if limit <= 0 {
		limit = len(all) - start
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	list := &corev1.NamespaceList{}
	for _, ns := range all[start:end] {
		list.Items = append(list.Items, *ns)
	}
	if end < len(all) {
		list.Continue = strconv.Itoa(end)
	}
	return true, list, nil
}

// listOptionsOf extracts the ListOptions of a recorded list action.
func listOptionsOf(action k8stesting.Action) metav1.ListOptions {
	return action.(interface{ GetListOptions() metav1.ListOptions }).GetListOptions()
}

// TestAdapterNamespacesFollowContinueAcrossThreePages proves the continue
// loop follows Limit/Continue across three pages: the stub honors the paging
// contract, all five items cross, and the result is complete (Partial=false).
func TestAdapterNamespacesFollowContinueAcrossThreePages(t *testing.T) {
	t.Parallel()

	all := paginationNamespaces()
	client := fake.NewClientset()
	client.PrependReactor("list", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return serveNamespacePage(action, all, "")
	})

	adapter := NewAdapter(client)
	adapter.pageSize = 2

	result, err := adapter.ListNamespaces(context.Background())
	if err != nil {
		t.Fatalf("ListNamespaces() error = %v", err)
	}
	if len(result.Items) != len(all) {
		t.Fatalf("namespace count = %d, want %d", len(result.Items), len(all))
	}
	for i, item := range result.Items {
		if item.Name != all[i].Name {
			t.Fatalf("item %d = %q, want %q", i, item.Name, all[i].Name)
		}
	}
	if result.Partial || result.Reason != "" {
		t.Fatalf("Partial = %v, Reason = %q, want complete", result.Partial, result.Reason)
	}

	var gotLimits []int64
	var gotContinues []string
	for _, action := range client.Actions() {
		if action.GetVerb() != "list" || action.GetResource().Resource != "namespaces" {
			continue
		}
		opts := listOptionsOf(action)
		gotLimits = append(gotLimits, opts.Limit)
		gotContinues = append(gotContinues, opts.Continue)
	}
	if len(gotLimits) != 3 {
		t.Fatalf("list calls = %d, want 3 pages", len(gotLimits))
	}
	for i, limit := range gotLimits {
		if limit != 2 {
			t.Fatalf("page %d Limit = %d, want 2", i, limit)
		}
	}
	wantContinues := []string{"", "2", "4"}
	for i, cont := range gotContinues {
		if cont != wantContinues[i] {
			t.Fatalf("page %d Continue = %q, want %q", i, cont, wantContinues[i])
		}
	}
}

// TestAdapterNamespacesDegradeMidStreamPartial proves a generic failure
// after successful pages degrades to partial through the real List path: the
// stub serves two pages then fails, so the collected prefix is kept with
// Partial=true and Reason partial_list.
func TestAdapterNamespacesDegradeMidStreamPartial(t *testing.T) {
	t.Parallel()

	all := paginationNamespaces()
	client := fake.NewClientset()
	client.PrependReactor("list", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return serveNamespacePage(action, all, "4")
	})

	adapter := NewAdapter(client)
	adapter.pageSize = 2

	result, err := adapter.ListNamespaces(context.Background())
	if err != nil {
		t.Fatalf("ListNamespaces() error = %v, want partial not hard", err)
	}
	if !result.Partial || result.Reason != collector.WarningPartialList {
		t.Fatalf("Partial = %v, Reason = %q, want partial_list", result.Partial, result.Reason)
	}
	if len(result.Items) != 4 {
		t.Fatalf("item count = %d, want the 4 collected before the failure", len(result.Items))
	}
}
