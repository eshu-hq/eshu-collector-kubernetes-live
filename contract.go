// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

const (
	// ComponentID is the manifest identity of this collector. Keep it in sync
	// with metadata.id in manifest.yaml.
	ComponentID = "dev.eshu.collector.kubernetes-live"
	// CollectorKind is the durable collector family name for facts and scopes
	// emitted by the Kubernetes live collector.
	CollectorKind = corecollector.CollectorKind
	// SourceSystem is the source system name facts carry when the claim does
	// not name one. Hosted claims carry the activation's source system.
	SourceSystem = corecollector.CollectorKind
	// MetricsPrefix is the component-owned metric prefix the manifest declares.
	// Nothing in this repository emits a metric under it yet.
	MetricsPrefix = "eshu_dp_kubernetes_live_collector_"
)

// Schema versions mirror the emission core (kinds.go); the manifest and the
// contract below must agree with them.
const (
	// SchemaVersionPodTemplate is the schema version of every
	// kubernetes_live.pod_template fact.
	SchemaVersionPodTemplate = corecollector.KubernetesPodTemplateSchemaVersion
	// SchemaVersionV1 is the schema version of every other fact kind this
	// collector emits.
	SchemaVersionV1 = corecollector.KubernetesRelationshipSchemaVersion
)

// Fact kind aliases. They are core-owned: the host requires a producer grant
// for each before accepting them from this component.
const (
	// FactKindPodTemplate identifies one pod-template observation fact.
	FactKindPodTemplate = corecollector.KubernetesPodTemplateFactKind
	// FactKindRelationship identifies one directed object-edge fact.
	FactKindRelationship = corecollector.KubernetesRelationshipFactKind
	// FactKindWarning identifies one non-fatal collection warning fact.
	FactKindWarning = corecollector.KubernetesWarningFactKind
	// FactKindNamespace identifies one namespace observation fact.
	FactKindNamespace = corecollector.KubernetesNamespaceFactKind

	// FactKindServiceAccount identifies one Kubernetes ServiceAccount fact.
	FactKindServiceAccount = corecollector.KubernetesServiceAccountFactKind
	// FactKindRBACRole identifies one RBAC role fact.
	FactKindRBACRole = corecollector.KubernetesRBACRoleFactKind
	// FactKindRBACBinding identifies one RBAC binding fact.
	FactKindRBACBinding = corecollector.KubernetesRBACBindingFactKind
	// FactKindWorkloadIdentityUse identifies one workload identity use fact.
	FactKindWorkloadIdentityUse = corecollector.KubernetesWorkloadIdentityUseFactKind
	// FactKindGCPWorkloadIdentityBinding identifies one GCP workload identity
	// binding fact.
	FactKindGCPWorkloadIdentityBinding = corecollector.KubernetesGCPWorkloadIdentityBindingFactKind
	// FactKindServiceAccountTokenPosture identifies one ServiceAccount token
	// posture fact.
	FactKindServiceAccountTokenPosture = corecollector.KubernetesServiceAccountTokenPostureFactKind
	// FactKindEKSIRSAAnnotation identifies one EKS IRSA annotation fact.
	FactKindEKSIRSAAnnotation = corecollector.EKSIRSAAnnotationFactKind
	// FactKindEKSPodIdentityAssociation identifies one EKS pod identity
	// association fact.
	FactKindEKSPodIdentityAssociation = corecollector.EKSPodIdentityAssociationFactKind
	// FactKindSecretsIAMCoverageWarning identifies one secrets/IAM coverage
	// warning fact.
	FactKindSecretsIAMCoverageWarning = corecollector.SecretsIAMCoverageWarningFactKind
)

// FactKinds returns every fact kind this collector may emit, in the order the
// manifest declares them.
func FactKinds() []string {
	return []string{
		FactKindPodTemplate,
		FactKindRelationship,
		FactKindWarning,
		FactKindNamespace,
		FactKindServiceAccount,
		FactKindRBACRole,
		FactKindRBACBinding,
		FactKindWorkloadIdentityUse,
		FactKindGCPWorkloadIdentityBinding,
		FactKindServiceAccountTokenPosture,
		FactKindEKSIRSAAnnotation,
		FactKindEKSPodIdentityAssociation,
		FactKindSecretsIAMCoverageWarning,
	}
}

// schemaVersionFor returns the schema version of one emitted fact kind.
func schemaVersionFor(kind string) string {
	if kind == FactKindPodTemplate {
		return SchemaVersionPodTemplate
	}
	return SchemaVersionV1
}

// Contract returns the SDK fact families this collector may emit.
func Contract() sdk.Contract {
	kinds := FactKinds()
	facts := make([]sdk.FactDeclaration, 0, len(kinds))
	for _, kind := range kinds {
		facts = append(facts, sdk.FactDeclaration{
			Kind:             kind,
			SchemaVersions:   []string{schemaVersionFor(kind)},
			SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
		})
	}
	return sdk.Contract{ProtocolVersion: sdk.ProtocolVersionV1Alpha1, Facts: facts}
}
