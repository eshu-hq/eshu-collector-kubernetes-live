// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package clientgo is the live cluster backend for the Kubernetes live
// collector: the client-go adapter behind the collector.ClientFactory seam.
//
// Provenance: ported from go/internal/collector/kuberneteslive/clientgo/ in
// eshu-hq/eshu (issue eshu-hq/eshu#8859), with the in-tree
// go/internal/collector/kuberneteslive import rewritten to this module's
// collector package. Nothing else in the mapping changes, so the redaction
// and parity proofs the emission core carries still describe this adapter.
//
// The adapter is the only place client-go and the Kubernetes typed API are
// imported, so the collector source stays backend-neutral and unit-testable
// with fakes. It authenticates read-only through either the in-cluster
// service account or a kubeconfig file, builds a typed clientset, and
// implements collector.Client by listing the fixed core resource set with
// bounded pagination.
//
// The adapter is read-only and metadata-only by construction: it maps typed
// objects into the collector's neutral metadata views and never reads Secret
// values, ConfigMap data payloads, environment variable values, or container
// logs, and it never issues a write, patch, delete, exec, attach,
// portforward, or log request. A forbidden list degrades to a partial result
// with a warning reason rather than aborting the snapshot.
package clientgo
