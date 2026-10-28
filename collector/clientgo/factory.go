// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package clientgo

import (
	"context"
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/rest"

	"github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
)

// kubeconfigEnv is the only operator knob the factory reads. It names one
// kubeconfig file for out-of-cluster collection (local runs, rehearsals).
// The in-cluster ServiceAccount needs no knob: the pod runs with
// serviceAccountName eshu-kubernetes-live-collector and KUBECONFIG unset.
const kubeconfigEnv = "KUBECONFIG"

// DefaultFactory builds the ClientFactory the binary wires into the Handler:
// in-cluster service account first, an explicit KUBECONFIG where the seam
// allows, and a bounded error when neither exists. Cluster auth resolves
// from the process environment alone; the target carries only the durable
// cluster identity, never credentials, and no value read here reaches a
// fact, a log, or a status.
func DefaultFactory(getenv func(string) string) collector.ClientFactory {
	if getenv == nil {
		getenv = os.Getenv
	}
	return collector.ClientFactoryFunc(func(_ context.Context, target collector.ClusterTarget) (collector.Client, error) {
		auth, err := resolveAuth(getenv)
		if err != nil {
			return nil, err
		}
		clientset, err := NewClientset(auth)
		if err != nil {
			return nil, fmt.Errorf("build kubernetes client for cluster %q: %w", target.ClusterID, err)
		}
		// No ping here: the source issues the single recorded PingReadOnly
		// right after the factory returns, so readiness stays one API call.
		return NewAdapter(clientset), nil
	})
}

// resolveAuth picks the auth mode from the process environment. An explicit
// KUBECONFIG wins over ambient in-cluster files so tests and rehearsals can
// pin the backend without touching the pod path; with KUBECONFIG unset the
// in-cluster service account is tried, and with neither present the factory
// fails closed with a retryable error instead of an anonymous client.
func resolveAuth(getenv func(string) string) (AuthConfig, error) {
	if path := strings.TrimSpace(getenv(kubeconfigEnv)); path != "" {
		return AuthConfig{Mode: AuthModeKubeconfig, KubeconfigPath: path}, nil
	}
	if _, err := rest.InClusterConfig(); err == nil {
		return AuthConfig{Mode: AuthModeInCluster}, nil
	}
	return AuthConfig{}, fmt.Errorf("no kubernetes backend configured: set %s or run under the in-cluster service account", kubeconfigEnv)
}
