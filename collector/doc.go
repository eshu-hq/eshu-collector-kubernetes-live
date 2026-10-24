// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the extracted Kubernetes live collector
// (eshu-hq/eshu#8859, destination repository eshu-collector-kubernetes-live).
//
// It emits the same kubernetes_live.* and secrets-IAM posture facts as the
// in-tree source it was extracted from, built only on the published SDK
// contracts:
//
//	github.com/eshu-hq/eshu-sdk/collector v0.1.0-rc.2
//	github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.2
//
// There are no replace directives and no imports of the core repository.
// Ported files carry a provenance note naming the in-tree origin file and the
// core commit they were cut from; behavior parity with that commit is pinned
// by the parity proof test in this package.
package collector
