// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package clientgo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
)

// TestDefaultFactoryFailsClosedWithoutABackend proves the seam never builds an
// anonymous client: with no KUBECONFIG and no in-cluster service account the
// factory returns a bounded error, which the handler reports as a retryable
// collection failure instead of a poison terminal.
func TestDefaultFactoryFailsClosedWithoutABackend(t *testing.T) {
	t.Parallel()

	factory := DefaultFactory(func(string) string { return "" })
	_, err := factory.Client(context.Background(), collector.ClusterTarget{ClusterID: "ops-qa"})
	if err == nil {
		t.Fatal("Client() error = nil, want a bounded no-backend error")
	}
	if strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Client() error = %q, must not carry credential material", err)
	}
}

// TestDefaultFactoryHonorsExplicitKubeconfig proves an explicit KUBECONFIG
// wins: a path that cannot load fails at build time (retryable), and a path
// that loads builds a client without touching the network (the source pings,
// not the factory).
func TestDefaultFactoryHonorsExplicitKubeconfig(t *testing.T) {
	t.Parallel()

	getenv := func(key string) string {
		if key == "KUBECONFIG" {
			return "/nonexistent/eshu-test-kubeconfig"
		}
		return ""
	}
	factory := DefaultFactory(getenv)
	_, err := factory.Client(context.Background(), collector.ClusterTarget{ClusterID: "ops-qa"})
	if err == nil {
		t.Fatal("Client() error = nil, want the missing kubeconfig to fail the build")
	}

	kubeconfig := "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://127.0.0.1:1\n  name: test\ncontexts:\n- context:\n    cluster: test\n    user: test\n  name: test\ncurrent-context: test\nusers:\n- name: test\n  user:\n    token: REDACTED\n"
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	goodGetenv := func(key string) string {
		if key == "KUBECONFIG" {
			return path
		}
		return ""
	}
	client, err := DefaultFactory(goodGetenv).Client(context.Background(), collector.ClusterTarget{ClusterID: "ops-qa"})
	if err != nil {
		t.Fatalf("Client() error = %v, want a built client with no dial", err)
	}
	if client == nil {
		t.Fatal("Client() = nil, want a client")
	}
}
