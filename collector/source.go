// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Provenance: ported from go/internal/collector/kuberneteslive/source.go at
// core commit 95dfc56ebb54, with the host-owned seams exchanged for the
// published SDK contract:
//
//   - collector.CollectedGeneration -> local CollectedSnapshot (ScopeInfo +
//     GenerationInfo + Envelopes); the SDK wire form is built by
//     ToSDKResult in sdkresult.go.
//   - scope.IngestionScope / scope.ScopeGeneration -> local ScopeInfo /
//     GenerationInfo with identical literal values ("cluster", "pending",
//     "snapshot", freshness "complete"/"partial"). The in-tree
//     ValidateForScope consistency check is dropped: the values are built
//     from the same scope/generation IDs by construction, so it holds
//     vacuously; the proof asserts the shared IDs per fact.
//   - telemetry.Instruments record hooks -> dropped (host-side metrics with
//     no emission effect). OTel spans keep the in-tree span names
//     ("kubernetes_live.snapshot", "kubernetes_live.api_call") and the
//     cluster_id attribute.
//   - pkg/log attrs -> plain slog string attrs with the same keys
//     ("scope_id", "generation_id", "cluster_id") and phase ("discovery").
//
// Concurrency note (ported verbatim): a single Source instance is a serial
// producer; the durable conflict domain is the per-cluster scope id, and each
// cluster yields exactly one generation. Listing multiple clusters is
// intentionally one-cluster-per-Next so each generation commits atomically;
// parallel multi-cluster collection is a follow-up that must partition by the
// per-cluster scope id (its natural conflict key) rather than serialize.

// Config configures the snapshot Source with one or more cluster targets.
type Config struct {
	// CollectorInstanceID is the durable collector instance identity stamped on
	// every emitted fact.
	CollectorInstanceID string
	// Clusters is the set of configured read-only cluster targets.
	Clusters []ClusterTarget
}

func (c Config) validated() (Config, error) {
	if strings.TrimSpace(c.CollectorInstanceID) == "" {
		return Config{}, fmt.Errorf("kubernetes live collector instance id is required")
	}
	if len(c.Clusters) == 0 {
		return Config{}, fmt.Errorf("kubernetes live collector requires at least one cluster target")
	}
	seen := make(map[string]struct{}, len(c.Clusters))
	for i, cluster := range c.Clusters {
		id := strings.TrimSpace(cluster.ClusterID)
		if id == "" {
			return Config{}, fmt.Errorf("cluster[%d] cluster_id must not be blank", i)
		}
		if _, dup := seen[id]; dup {
			return Config{}, fmt.Errorf("duplicate cluster_id %q", id)
		}
		seen[id] = struct{}{}
	}
	return c, nil
}

// ScopeInfo is the collector-owned view of the ingestion scope for one
// cluster snapshot. Values mirror the in-tree scope.IngestionScope the host
// used to build.
type ScopeInfo struct {
	ScopeID       string
	SourceSystem  string
	ScopeKind     string
	CollectorKind string
	PartitionKey  string
	Metadata      map[string]string
}

// GenerationInfo is the collector-owned view of one snapshot generation.
type GenerationInfo struct {
	ScopeID       string
	GenerationID  string
	Status        string
	ObservedAt    time.Time
	IngestedAt    time.Time
	TriggerKind   string
	FreshnessHint string
}

// CollectedSnapshot is one cluster snapshot generation: its scope, its
// generation, and its envelopes in emission order.
type CollectedSnapshot struct {
	Scope      ScopeInfo
	Generation GenerationInfo
	Envelopes  []Envelope
	Partial    bool
}

// Source lists a configured core resource set from each cluster target and
// yields one snapshot generation per cluster. It is read-only and metadata-only.
type Source struct {
	Config        Config
	ClientFactory ClientFactory
	Tracer        trace.Tracer
	Logger        *slog.Logger
	Clock         func() time.Time

	next int
}

// Next returns the next configured cluster snapshot generation. It returns
// ok=false to signal the batch is drained, resetting for the next poll.
func (s *Source) Next(ctx context.Context) (CollectedSnapshot, bool, error) {
	config, err := s.Config.validated()
	if err != nil {
		return CollectedSnapshot{}, false, err
	}
	if s.ClientFactory == nil {
		return CollectedSnapshot{}, false, fmt.Errorf("kubernetes live client factory is required")
	}
	if s.next >= len(config.Clusters) {
		s.next = 0
		return CollectedSnapshot{}, false, nil
	}
	target := config.Clusters[s.next]
	s.next++
	collected, err := s.collectCluster(ctx, config, target)
	if err != nil {
		return CollectedSnapshot{}, false, err
	}
	return collected, true, nil
}

func (s *Source) collectCluster(ctx context.Context, config Config, target ClusterTarget) (CollectedSnapshot, error) {
	start := s.now()
	if s.Tracer != nil {
		var span trace.Span
		ctx, span = s.Tracer.Start(ctx, "kubernetes_live.snapshot")
		span.SetAttributes(attribute.String("cluster_id", target.ClusterID))
		defer span.End()
	}

	client, err := s.ClientFactory.Client(ctx, target)
	if err != nil {
		return CollectedSnapshot{}, fmt.Errorf("create kubernetes client: %w", err)
	}
	if err := s.recordAPICall(ctx, "ping", func(context.Context) error { return client.PingReadOnly(ctx) }); err != nil {
		return CollectedSnapshot{}, fmt.Errorf("ping kubernetes cluster: %w", err)
	}

	observedAt := s.now()
	builder := &generationBuilder{
		source:              s,
		target:              target,
		collectorInstanceID: config.CollectorInstanceID,
		observedAt:          observedAt,
	}
	if err := builder.run(ctx, client); err != nil {
		return CollectedSnapshot{}, err
	}

	scopeValue, generationValue := s.scopeAndGeneration(target, observedAt, builder.partial)
	envelopes := builder.envelopes
	if s.Logger != nil {
		s.Logger.InfoContext(
			ctx, "kubernetes live snapshot completed",
			slog.String("phase", "discovery"),
			slog.String("scope_id", scopeValue.ScopeID),
			slog.String("generation_id", generationValue.GenerationID),
			slog.String("cluster_id", target.ClusterID),
			slog.Bool("partial", builder.partial),
			slog.Int("fact_count", len(envelopes)),
			slog.Float64("duration_seconds", time.Since(start).Seconds()),
		)
	}
	return CollectedSnapshot{
		Scope:      scopeValue,
		Generation: generationValue,
		Envelopes:  envelopes,
		Partial:    builder.partial,
	}, nil
}

func (s *Source) scopeAndGeneration(target ClusterTarget, observedAt time.Time, partial bool) (ScopeInfo, GenerationInfo) {
	// ClusterScopeID only fails on a blank cluster id, which validated()
	// already rejects; the scope id is total here by construction.
	scopeID, _ := ClusterScopeID(target.ClusterID)
	freshness := "complete"
	if partial {
		freshness = "partial"
	}
	generationID := clusterGenerationID(target.ClusterID, observedAt)
	metadata := map[string]string{"cluster_id": target.ClusterID}
	if provider := strings.TrimSpace(target.Provider); provider != "" {
		metadata["provider"] = provider
	}
	if env := strings.TrimSpace(target.Environment); env != "" {
		metadata["environment"] = env
	}
	scopeValue := ScopeInfo{
		ScopeID:       scopeID,
		SourceSystem:  CollectorKind,
		ScopeKind:     "cluster",
		CollectorKind: CollectorKind,
		PartitionKey:  target.ClusterID,
		Metadata:      metadata,
	}
	generationValue := GenerationInfo{
		ScopeID:       scopeID,
		GenerationID:  generationID,
		Status:        "pending",
		ObservedAt:    observedAt,
		IngestedAt:    observedAt,
		TriggerKind:   "snapshot",
		FreshnessHint: freshness,
	}
	return scopeValue, generationValue
}

func (s *Source) recordAPICall(ctx context.Context, operation string, call func(context.Context) error) error {
	if s.Tracer != nil {
		var span trace.Span
		ctx, span = s.Tracer.Start(ctx, "kubernetes_live.api_call")
		span.SetAttributes(attribute.String("operation", operation))
		defer span.End()
	}
	return call(ctx)
}

func (s *Source) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}
