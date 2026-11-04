// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Provenance: File/Scope/Fact, the schema_version "1" validation, and the
// envelope mapping are ported from go/internal/replay/cassette/format.go and
// go/internal/replay/cassette/source.go at core commit 95dfc56ebb54. The
// satellite replays one scope per claim (the claim selects the scope), so the
// multi-scope Next/drain cursor of the in-tree Source is replaced by
// ReplayClaimedScope. The in-tree Postgres commit boundary has no satellite
// analogue (the host commits); parity is proved at sdk.Result level.
//
// Deliberate deviations from the in-tree source, both dictated by the
// satellite contract:
//   - SourceConfidence defaults to reported (SourceConfidenceReported), not
//     the in-tree observed: the satellite contract declares only reported,
//     and the SDK validator rejects anything else.
//   - Partial derives from the replayed envelopes: the cassette schema
//     carries no partial bit, so a scope that replays warning facts maps to
//     a partial snapshot (the live builder emits warnings exactly when
//     evidence is degraded). A warning-free scope replays complete.

// CassetteSchemaVersion is the only cassette schema version this collector
// replays. It mirrors the in-tree cassette.SchemaVersionV1: cassettes are
// recorded and canonicalized in-tree (or by dev tooling) and only replayed
// here, so writer and reader must agree on one version literal.
const CassetteSchemaVersion = "1"

// File is the root document of a cassette JSON file. Each scope entry carries
// the scope identity, the generation metadata, and the pre-recorded fact
// envelopes of one collection run.
type File struct {
	// Collector names the collector kind that produced this cassette (e.g.
	// "kubernetes_live"). Informational; not validated at replay time.
	Collector string `json:"collector"`
	// SchemaVersion must equal "1".
	SchemaVersion string `json:"schema_version"`
	// Scopes is the ordered list of pre-recorded scope+generation batches.
	// One claim replays exactly one of them.
	Scopes []Scope `json:"scopes"`
	// PseudonymKeyFingerprint identifies the recording key a pseudonymized
	// recording was written under. Informational: replay ignores it.
	PseudonymKeyFingerprint string `json:"pseudonym_key_fingerprint,omitempty"`
}

// Scope is one pre-recorded scope+generation worth of facts.
type Scope struct {
	// ScopeID is the durable source-local scope identity (required).
	ScopeID string `json:"scope_id"`
	// SourceSystem names the collector family (e.g. "kubernetes_live").
	SourceSystem string `json:"source_system"`
	// ScopeKind is the scope classification (e.g. "cluster").
	ScopeKind string `json:"scope_kind"`
	// CollectorKind is the collector family label (e.g. "kubernetes_live").
	CollectorKind string `json:"collector_kind"`
	// PartitionKey is the partition routing key. Defaults to ScopeID when empty.
	PartitionKey string `json:"partition_key,omitempty"`
	// Metadata is an optional map of key-value pairs describing the scope.
	Metadata map[string]string `json:"metadata,omitempty"`
	// GenerationID is the durable generation identity (required).
	GenerationID string `json:"generation_id"`
	// ObservedAt is the observation timestamp for the generation (required).
	ObservedAt time.Time `json:"observed_at"`
	// TriggerKind is how the generation was produced. Defaults to "snapshot".
	TriggerKind string `json:"trigger_kind,omitempty"`
	// Facts is the ordered list of pre-recorded fact envelopes.
	Facts []Fact `json:"facts"`
}

// partitionKey returns the effective partition key for the scope.
func (s Scope) partitionKey() string {
	if pk := strings.TrimSpace(s.PartitionKey); pk != "" {
		return pk
	}
	return s.ScopeID
}

// triggerKind returns the effective trigger kind for the scope.
func (s Scope) triggerKind() string {
	if tk := strings.TrimSpace(s.TriggerKind); tk != "" {
		return tk
	}
	return "snapshot"
}

// Fact is one pre-recorded fact envelope. FactID is re-derived at replay time
// via DeriveFactID, so the cassette carries none.
type Fact struct {
	// FactKind is the durable fact type identifier (required).
	FactKind string `json:"fact_kind"`
	// StableFactKey is the durable deduplication key (required).
	StableFactKey string `json:"stable_fact_key"`
	// SchemaVersion is the payload schema version (required).
	SchemaVersion string `json:"schema_version"`
	// CollectorKind is the collector that produced the fact. Falls back to
	// the parent scope's CollectorKind when empty.
	CollectorKind string `json:"collector_kind,omitempty"`
	// FencingToken is the generation fencing token. Defaults to 1, matching
	// the in-tree replay when the cassette leaves it unset.
	FencingToken int64 `json:"fencing_token,omitempty"`
	// SourceConfidence is the evidence quality label. Defaults to reported:
	// the satellite contract declares no other confidence.
	SourceConfidence string `json:"source_confidence,omitempty"`
	// Payload is the fact-kind-specific data map (required).
	Payload map[string]any `json:"payload"`
	// IsTombstone marks this fact as a retraction.
	IsTombstone bool `json:"is_tombstone,omitempty"`
	// SourceURI is an optional provenance URI for the fact.
	SourceURI string `json:"source_uri,omitempty"`
	// SourceRecordID is the source-record identity for the fact. Defaults to
	// the stable fact key when empty.
	SourceRecordID string `json:"source_record_id,omitempty"`
}

// sourceRecordID returns the effective source-record id, defaulting to the
// stable fact key when the cassette does not carry one.
func (f Fact) sourceRecordID() string {
	if id := strings.TrimSpace(f.SourceRecordID); id != "" {
		return id
	}
	return f.StableFactKey
}

// fencingToken returns the effective fencing token, defaulting to 1 like the
// in-tree replay.
func (f Fact) fencingToken() int64 {
	if f.FencingToken > 0 {
		return f.FencingToken
	}
	return 1
}

// collectorKind returns the effective collector kind, falling back to the
// scope-level kind when the fact does not carry its own.
func (f Fact) collectorKind(scopeCollectorKind string) string {
	if ck := strings.TrimSpace(f.CollectorKind); ck != "" {
		return ck
	}
	return scopeCollectorKind
}

// sourceConfidence returns the effective source confidence label. Unlike the
// in-tree replay (which defaults to observed), the satellite defaults to
// reported: the satellite contract declares only reported and the SDK
// validator rejects anything else.
func (f Fact) sourceConfidence() string {
	if sc := strings.TrimSpace(f.SourceConfidence); sc != "" {
		return sc
	}
	return SourceConfidenceReported
}

// DeriveFactID returns the fact_id a cassette-replayed envelope carries. It
// ports the in-tree cassette.DeriveFactID verbatim: a StableID over the
// CassetteReplay namespace keyed by scope, generation, and stable fact key,
// so every replay of the same cassette stamps the same fact_ids.
func DeriveFactID(scopeID, generationID, stableFactKey string) string {
	return stableID("CassetteReplay", map[string]any{
		"scope_id":        scopeID,
		"generation_id":   generationID,
		"stable_fact_key": stableFactKey,
	})
}

// LoadFile reads and validates a cassette from the given file path.
func LoadFile(path string) (File, error) {
	// #nosec G304 -- path is an operator-supplied cassette location (the
	// activation cassette_file key or a repo-shipped test fixture), not
	// request-derived input.
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read cassette file %q: %w", path, err)
	}
	f, err := ParseAndValidate(data)
	if err != nil {
		return File{}, fmt.Errorf("cassette file %q: %w", path, err)
	}
	return f, nil
}

// ParseAndValidate decodes cassette bytes and runs the same structural
// validation LoadFile applies — required fields, the supported
// schema_version, and field types — without touching the filesystem.
func ParseAndValidate(data []byte) (File, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("parse cassette: %w", err)
	}
	if err := f.validate(); err != nil {
		return File{}, fmt.Errorf("invalid cassette: %w", err)
	}
	return f, nil
}

func (f File) validate() error {
	if f.SchemaVersion != CassetteSchemaVersion {
		return fmt.Errorf("unsupported schema_version %q (want %q)", f.SchemaVersion, CassetteSchemaVersion)
	}
	if len(f.Scopes) == 0 {
		return errors.New("cassette must contain at least one scope")
	}
	for i, s := range f.Scopes {
		if err := s.validate(); err != nil {
			return fmt.Errorf("scope[%d]: %w", i, err)
		}
	}
	return nil
}

func (s Scope) validate() error {
	if strings.TrimSpace(s.ScopeID) == "" {
		return errors.New("scope_id is required")
	}
	if strings.TrimSpace(s.SourceSystem) == "" {
		return errors.New("source_system is required")
	}
	if strings.TrimSpace(s.ScopeKind) == "" {
		return errors.New("scope_kind is required")
	}
	if strings.TrimSpace(s.CollectorKind) == "" {
		return errors.New("collector_kind is required")
	}
	if strings.TrimSpace(s.GenerationID) == "" {
		return errors.New("generation_id is required")
	}
	if s.ObservedAt.IsZero() {
		return errors.New("observed_at is required and must be non-zero")
	}
	for i, fct := range s.Facts {
		if err := fct.validate(); err != nil {
			return fmt.Errorf("fact[%d]: %w", i, err)
		}
	}
	return nil
}

func (f Fact) validate() error {
	if strings.TrimSpace(f.FactKind) == "" {
		return errors.New("fact_kind is required")
	}
	if strings.TrimSpace(f.StableFactKey) == "" {
		return errors.New("stable_fact_key is required")
	}
	if strings.TrimSpace(f.SchemaVersion) == "" {
		return errors.New("schema_version is required")
	}
	if f.Payload == nil {
		return errors.New("payload is required (use {} for an empty payload)")
	}
	return nil
}

// ReplayClaimedScope replays the one cassette scope whose scope ID matches the
// claim and returns it as a collected snapshot. It is the satellite analogue
// of the in-tree cassette Source.Next: one claim replays one scope, so the
// poll-loop drain cursor has no meaning here and an unmatched scope is an
// error instead of an empty batch.
func ReplayClaimedScope(file File, scopeID string) (CollectedSnapshot, error) {
	for _, scope := range file.Scopes {
		if scope.ScopeID != scopeID {
			continue
		}
		return replayScope(scope)
	}
	return CollectedSnapshot{}, fmt.Errorf("cassette has no scope matching %q", scopeID)
}

func replayScope(scope Scope) (CollectedSnapshot, error) {
	scopeValue := ScopeInfo{
		ScopeID:       scope.ScopeID,
		SourceSystem:  scope.SourceSystem,
		ScopeKind:     scope.ScopeKind,
		CollectorKind: scope.CollectorKind,
		PartitionKey:  scope.partitionKey(),
		Metadata:      scope.Metadata,
	}
	envelopes := make([]Envelope, 0, len(scope.Facts))
	for i, fct := range scope.Facts {
		envelope, err := replayEnvelope(scope, fct)
		if err != nil {
			return CollectedSnapshot{}, fmt.Errorf("scope %q fact[%d]: %w", scope.ScopeID, i, err)
		}
		envelopes = append(envelopes, envelope)
	}
	partial := countWarnings(envelopes) > 0
	freshness := "complete"
	if partial {
		freshness = "partial"
	}
	generationValue := GenerationInfo{
		ScopeID:       scope.ScopeID,
		GenerationID:  scope.GenerationID,
		Status:        "pending",
		ObservedAt:    scope.ObservedAt,
		IngestedAt:    scope.ObservedAt,
		TriggerKind:   scope.triggerKind(),
		FreshnessHint: freshness,
	}
	return CollectedSnapshot{
		Scope:      scopeValue,
		Generation: generationValue,
		Envelopes:  envelopes,
		Partial:    partial,
	}, nil
}

func replayEnvelope(scope Scope, fct Fact) (Envelope, error) {
	payload := fct.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	return Envelope{
		FactID:           DeriveFactID(scope.ScopeID, scope.GenerationID, fct.StableFactKey),
		ScopeID:          scope.ScopeID,
		GenerationID:     scope.GenerationID,
		FactKind:         fct.FactKind,
		StableFactKey:    fct.StableFactKey,
		SchemaVersion:    fct.SchemaVersion,
		CollectorKind:    strings.TrimSpace(fct.collectorKind(scope.CollectorKind)),
		FencingToken:     fct.fencingToken(),
		SourceConfidence: fct.sourceConfidence(),
		ObservedAt:       scope.ObservedAt,
		Payload:          payload,
		IsTombstone:      fct.IsTombstone,
		SourceRef: Ref{
			SourceSystem:   scope.SourceSystem,
			ScopeID:        scope.ScopeID,
			GenerationID:   scope.GenerationID,
			FactKey:        fct.StableFactKey,
			SourceURI:      strings.TrimSpace(fct.SourceURI),
			SourceRecordID: fct.sourceRecordID(),
		},
	}, nil
}
