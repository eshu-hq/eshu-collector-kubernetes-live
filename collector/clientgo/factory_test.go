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

// TestRESTConfigRejectsUnusableAuth proves every auth mode fails closed with
// a bounded error instead of an anonymous client: in-cluster without the pod
// files, kubeconfig without a path or with an unreadable file, and an unknown
// mode.
func TestRESTConfigRejectsUnusableAuth(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT"} {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Unsetenv(%s) error = %v", key, err)
		}
	}
	if _, err := (AuthConfig{Mode: AuthModeInCluster}).RESTConfig(); err == nil {
		t.Error("in-cluster without pod files error = nil")
	}
	if _, err := (AuthConfig{Mode: AuthModeKubeconfig}).RESTConfig(); err == nil {
		t.Error("kubeconfig without a path error = nil")
	}
	badPath := filepath.Join(t.TempDir(), "missing-kubeconfig")
	if _, err := (AuthConfig{Mode: AuthModeKubeconfig, KubeconfigPath: badPath}).RESTConfig(); err == nil {
		t.Error("kubeconfig with an unreadable file error = nil")
	}
	if _, err := (AuthConfig{Mode: "teleport"}).RESTConfig(); err == nil {
		t.Error("unknown auth mode error = nil")
	}
}

// TestRESTConfigAppliesRateBounds proves explicit QPS/Burst reach the rest
// config instead of being silently dropped.
func TestRESTConfigAppliesRateBounds(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "kubeconfig")
	content := "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: test\ncontexts:\n- context:\n    cluster: test\n    user: test\n  name: test\ncurrent-context: test\nusers:\n- name: test\n  user:\n    token: test-token\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := (AuthConfig{Mode: AuthModeKubeconfig, KubeconfigPath: path, QPS: 5, Burst: 10}).RESTConfig()
	if err != nil {
		t.Fatalf("RESTConfig() error = %v", err)
	}
	if cfg.QPS != 5 || cfg.Burst != 10 {
		t.Fatalf("rate bounds = (%v, %v), want (5, 10)", cfg.QPS, cfg.Burst)
	}
	if _, err := NewClientset(AuthConfig{Mode: "teleport"}); err == nil {
		t.Error("NewClientset(unknown mode) error = nil")
	}
}

// TestDefaultFactoryAcceptsANilGetenv proves the nil default resolves against
// the process environment (which carries no backend here) instead of panicking.
func TestDefaultFactoryAcceptsANilGetenv(t *testing.T) {
	t.Parallel()

	factory := DefaultFactory(nil)
	if factory == nil {
		t.Fatal("DefaultFactory(nil) = nil factory")
	}
}
