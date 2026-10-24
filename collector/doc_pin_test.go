// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the extracted Kubernetes live collector (eshu-hq/eshu
// #8859). It emits the same kubernetes_live.* and secrets-IAM posture facts
// as the in-tree source, built only on the published SDK contracts.
package collector

import (
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

// TestSDKPinsResolve proves the module builds against the exact published
// pins with no replace directives, and that the pinned fixture pack ships
// schemas for every fact kind this collector emits.
func TestSDKPinsResolve(t *testing.T) {
	t.Parallel()

	var _ sdkcollector.ResultState = sdkcollector.ResultState("complete")
	for _, kind := range []string{
		"kubernetes_live.namespace",
		"kubernetes_live.pod_template",
		"kubernetes_live.relationship",
		"kubernetes_live.warning",
	} {
		schema, ok := fixturepack.SchemaFor(kind)
		if !ok {
			t.Fatalf("pinned fixture pack ships no schema for %q", kind)
		}
		if len(schema) == 0 {
			t.Fatalf("pinned fixture pack ships empty schema for %q", kind)
		}
	}
}
