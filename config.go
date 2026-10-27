// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
)

// targetJSON is one Kubernetes cluster target in the activation config. It
// keeps the emission core's ClusterTarget shape (snake_case keys) so
// activations move unchanged: cluster identity is operator-declared and
// stable across API server URL changes, and credentials never travel inline
// (cluster auth resolves from the process environment behind the client
// factory seam).
type targetJSON struct {
	ClusterID string `json:"cluster_id"`
	// DisplayName is optional operator-facing metadata.
	DisplayName string `json:"display_name"`
	// Provider is optional metadata such as eks, gke, aks, or kind.
	Provider string `json:"provider"`
	// GCPWorkloadPool is the GKE Workload Identity pool. When set,
	// ServiceAccount iam.gke.io/gcp-service-account annotations can emit
	// redaction-safe GCP Workload Identity binding facts.
	GCPWorkloadPool string `json:"gcp_workload_pool"`
	// Environment is optional operator-declared environment metadata.
	Environment string `json:"environment"`
	// FencingToken orders generations for idempotent commit and replay. The
	// claim fencing token wins when present; this is the fallback.
	FencingToken int64 `json:"fencing_token"`
	// SourceURI is a non-sensitive descriptor of the source, recorded on the
	// fact ref after sanitization. The host validator requires a source URI
	// on every fact, so a blank one fails fast instead of emitting facts the
	// host must reject.
	SourceURI string `json:"source_uri"`

	// Limits bounds one claim's emission for this target. It accepts the
	// snake_case keys of the activation file and the camelCase keys the
	// host forwards verbatim; every non-positive field falls back to the
	// top-level envelope value, then the handler value, then the built-in
	// default.
	Limits ResourceUse `json:"limits"`
}

// hostKeyPrefix marks the top-level SDK request config keys the
// component-extension host mints per claim (host_github_app_token today).
// The host owns these credentials: only the minted value crosses the stdio
// boundary, and static activation config must not define them. This satellite
// neither reads nor spends them (cluster auth stays behind the client factory
// seam), so they are accepted and ignored; their values never reach an error,
// a log, or a status. The prefix keeps the decoder tolerant of future
// host-minted keys while staying fail-closed for genuinely unknown keys,
// which can be a pasted credential.
const hostKeyPrefix = "host_"

// resolveTarget decodes the activation config and returns the cluster target
// whose scope ID matches the claim, plus that target's limits. The config is
// either one target object or {"targets":[...]} with the host envelope: an
// optional top-level limits object (snake_case or camelCase) and host-minted
// host_* keys. The matched target's own bounds win where set; the top-level
// envelope fills the gaps, then the handler bounds, then the built-in
// defaults. Every target requires a scope match, including a lone target, so
// a mismatched lone target is rejected at config decode instead of being
// scanned.
func resolveTarget(raw map[string]any, scopeID string, getenv func(string) string) (corecollector.ClusterTarget, ResourceUse, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	targets, topLimits, err := decodeTargets(raw)
	if err != nil {
		return corecollector.ClusterTarget{}, ResourceUse{}, err
	}
	if len(targets) == 0 {
		return corecollector.ClusterTarget{}, ResourceUse{}, fmt.Errorf("collector configuration requires at least one target")
	}

	for i, target := range targets {
		mapped, err := mapTarget(target)
		if err != nil {
			return corecollector.ClusterTarget{}, ResourceUse{}, fmt.Errorf("targets[%d]: %w", i, err)
		}
		scope, err := scopeIDFor(mapped)
		if err != nil {
			return corecollector.ClusterTarget{}, ResourceUse{}, fmt.Errorf("targets[%d]: %w", i, err)
		}
		if scope == scopeID {
			return mapped, target.Limits.overlay(topLimits), nil
		}
	}
	return corecollector.ClusterTarget{}, ResourceUse{}, fmt.Errorf("no configured target matches scope_id %q", scopeID)
}

// decodeTargets decodes the activation config into its cluster targets plus
// the top-level host envelope limits. The config is either one target object
// or {"targets":[...]} carrying the envelope the component-extension host
// forwards verbatim: an optional top-level limits object and host-minted
// host_* keys, both accepted (the token ignored). Unknown keys still fail
// closed: the rejection never names the key, because an operator key can be
// a pasted credential.
func decodeTargets(raw map[string]any) ([]targetJSON, ResourceUse, error) {
	if raw == nil {
		return nil, ResourceUse{}, fmt.Errorf("collector configuration is required")
	}
	decode := func(cleaned map[string]any, target any) error {
		encoded, err := json.Marshal(cleaned)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		return decoder.Decode(target)
	}
	if _, ok := raw["targets"]; ok {
		topLimits, err := decodeTopLevelLimits(raw["limits"])
		if err != nil {
			return nil, ResourceUse{}, err
		}
		var decoded struct {
			Targets []targetJSON `json:"targets"`
		}
		if err := decode(withoutHostKeys(raw, "limits"), &decoded); err != nil {
			return nil, ResourceUse{}, fmt.Errorf("decode collector configuration targets: %s", decodeReason(err))
		}
		return decoded.Targets, topLimits, nil
	}
	var single targetJSON
	if err := decode(withoutHostKeys(raw), &single); err != nil {
		return nil, ResourceUse{}, fmt.Errorf("decode collector configuration: %s", decodeReason(err))
	}
	return []targetJSON{single}, ResourceUse{}, nil
}

// decodeTopLevelLimits parses the host envelope's top-level limits object in
// either key spelling. A missing key stays zero so the handler bounds apply;
// anything else must be the four documented budget bounds.
func decodeTopLevelLimits(value any) (ResourceUse, error) {
	if value == nil {
		return ResourceUse{}, nil
	}
	bounds, ok := value.(map[string]any)
	if !ok {
		return ResourceUse{}, fmt.Errorf("decode collector configuration limits: field limits has the wrong type")
	}
	encoded, err := json.Marshal(bounds)
	if err != nil {
		return ResourceUse{}, fmt.Errorf("decode collector configuration limits: malformed JSON")
	}
	var limits ResourceUse
	if err := json.Unmarshal(encoded, &limits); err != nil {
		return ResourceUse{}, fmt.Errorf("decode collector configuration limits: %s", decodeReason(err))
	}
	return limits, nil
}

// withoutHostKeys returns a copy of the top-level config without the named
// host envelope keys and the host-minted host_* keys, so strict decoding stays
// fail-closed for genuinely unknown keys while tolerating the documented
// host envelope. Values are never inspected or echoed.
func withoutHostKeys(raw map[string]any, keys ...string) map[string]any {
	skip := map[string]struct{}{}
	for _, key := range keys {
		skip[key] = struct{}{}
	}
	cleaned := make(map[string]any, len(raw))
	for key, value := range raw {
		if _, ok := skip[key]; ok {
			continue
		}
		if strings.HasPrefix(key, hostKeyPrefix) {
			continue
		}
		cleaned[key] = value
	}
	return cleaned
}

// scopeIDFor returns the durable scope ID for one mapped cluster target.
func scopeIDFor(target corecollector.ClusterTarget) (string, error) {
	return corecollector.ClusterScopeID(target.ClusterID)
}

// fencingToken parses the claim fencing token. Empty stays zero; anything
// else must be an integer, because the snapshot stamps it on every fact
// boundary.
func fencingToken(raw string) (int64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	token, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("claim fencing_token %q is not an integer", raw)
	}
	return token, nil
}

func mapTarget(target targetJSON) (corecollector.ClusterTarget, error) {
	clusterID := strings.TrimSpace(target.ClusterID)
	if clusterID == "" {
		return corecollector.ClusterTarget{}, fmt.Errorf("cluster_id is required")
	}
	// The host validator requires a source URI on every fact; fail fast on a
	// blank one instead of emitting facts the host must reject.
	if strings.TrimSpace(target.SourceURI) == "" {
		return corecollector.ClusterTarget{}, fmt.Errorf("source_uri is required")
	}
	return corecollector.ClusterTarget{
		ClusterID:       clusterID,
		DisplayName:     strings.TrimSpace(target.DisplayName),
		Provider:        strings.TrimSpace(target.Provider),
		GCPWorkloadPool: strings.TrimSpace(target.GCPWorkloadPool),
		Environment:     strings.TrimSpace(target.Environment),
		FencingToken:    target.FencingToken,
		SourceURI:       strings.TrimSpace(target.SourceURI),
	}, nil
}

// decodeReason keeps a JSON decode failure to its reason without echoing
// decoded values. An unknown key is reported without its name: the key comes
// from the operator or the host and can be a pasted credential, and the
// standard library's message would quote it.
func decodeReason(err error) string {
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.Is(err, errLimitsUnknownField):
		return "unknown field"
	case errors.As(err, &typeErr):
		return "field " + typeErr.Field + " has the wrong type"
	case strings.HasPrefix(err.Error(), "json: unknown field"):
		return "unknown field"
	case strings.HasPrefix(err.Error(), "field "):
		// The flexible limits decoder's bounded rejections name only
		// fixed-vocabulary fields, never values.
		return err.Error()
	default:
		return "malformed JSON"
	}
}
