// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the Eshu Kubernetes live collector, extracted from
// the Eshu core repository (eshu-hq/eshu#8859).
//
// It runs through the Eshu component-extension host with the process runner:
// the host passes one bounded collector-sdk/v1alpha1 request on stdin and the
// collector returns one result on stdout. A claim names one Kubernetes
// cluster scope; the collector lists the configured read-only resource set
// through its client seam and emits the kubernetes_live.* facts plus the
// Kubernetes-relevant secrets/IAM posture facts. It is pre-release and holds
// no producer authority until its reviewed cutover.
//
// The component-extension host forwards the activation config subtree
// verbatim as the SDK request Config, so a request may carry the standard
// host envelope next to the targets: a top-level limits object in snake_case
// or camelCase, mapped onto the claim budgets, and host-minted host_* keys,
// which are accepted and ignored. Any other top-level key fails closed.
//
// Boundary: this package imports only the published SDK modules
// (eshu-sdk/collector, eshu-sdk/factschema), the in-repo emission core in
// collector/, the standard library, and yaml for the manifest shape tests. It
// never imports go/internal, another collector implementation, or any core
// Postgres, graph, queue, or lease handle; the import-boundary test enforces
// this. The host, not this package, validates the result and owns claims and
// commits.
//
// Evidence is metadata-only: the collector never emits Secret values,
// ConfigMap data payloads, or environment variable values. Credentials reach
// the process by environment only and never enter facts, source URIs, logs,
// or statuses.
package collector
