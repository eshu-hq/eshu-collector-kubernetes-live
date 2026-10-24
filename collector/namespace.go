// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"time"

	sdkfactschema "github.com/eshu-hq/eshu-sdk/factschema"
	kuberneteslivev1 "github.com/eshu-hq/eshu-sdk/factschema/kuberneteslive/v1"
)

// Provenance: ported from go/internal/collector/kuberneteslive/envelope_namespace.go
// at core commit 95dfc56ebb54. Import rewrites only (model, kinds, published
// factschema).

// NamespaceObservation is the input for one kubernetes_live.namespace fact.
// It carries only the namespace's labels (never annotations) so the reducer's
// environment-alias binding domain has evidence to decide, per namespace,
// whether a label declares a recognized environment.
type NamespaceObservation struct {
	Identity            ObjectIdentity
	Labels              map[string]string
	GenerationID        string
	CollectorInstanceID string
	FencingToken        int64
	ObservedAt          time.Time
	SourceURI           string
}

// NewNamespaceEnvelope builds the durable namespace fact. It redacts
// everything except metadata-only fields: the namespace's labels. It never
// carries annotations, ConfigMap-like data, or any other namespace object
// detail -- METADATA-ONLY per the package invariant.
func NewNamespaceEnvelope(observation NamespaceObservation) (Envelope, error) {
	if err := observation.Identity.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("namespace identity: %w", err)
	}
	if err := validateBoundary(observation.GenerationID, observation.CollectorInstanceID, "namespace observation"); err != nil {
		return Envelope{}, err
	}
	objectID := observation.Identity.ObjectID()
	anchors := []string{objectID}
	clusterID := observation.Identity.ClusterID
	// A Namespace object is cluster-scoped (ObjectIdentity.Namespace is
	// always blank for it, per Validate's allowance); the namespace's own
	// name -- the (cluster_id, namespace) identity the reducer binds
	// environment evidence against -- is ObjectIdentity.Name.
	namespaceName := observation.Identity.Name
	payload, err := sdkfactschema.EncodeKubernetesLiveNamespace(kuberneteslivev1.Namespace{
		ObjectID:           objectID,
		ClusterID:          &clusterID,
		Namespace:          &namespaceName,
		Labels:             sortedStringMap(observation.Labels),
		CorrelationAnchors: anchors,
	})
	if err != nil {
		return Envelope{}, fmt.Errorf("encode kubernetes_live.namespace payload: %w", err)
	}
	payload["collector_instance_id"] = observation.CollectorInstanceID
	return newEnvelope(
		observation.Identity.ClusterID,
		KubernetesNamespaceFactKind,
		KubernetesNamespaceSchemaVersion,
		objectID,
		observation.GenerationID,
		observation.CollectorInstanceID,
		observation.FencingToken,
		observation.ObservedAt,
		observation.SourceURI,
		objectID,
		payload,
	)
}
