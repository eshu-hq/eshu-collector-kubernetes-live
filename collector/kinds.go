// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

// Provenance: kind and schema-version constants ported from
// go/internal/facts/cloud/kubernetes_live.go and
// go/internal/facts/identity/iam.go at core commit 95dfc56ebb54. Values are
// pinned byte-exact by the parity proof test against the checked-in fixture
// pack; do not change them without a contract migration.

// Kubernetes live fact kinds and schema versions.
const (
	KubernetesPodTemplateFactKind  = "kubernetes_live.pod_template"
	KubernetesRelationshipFactKind = "kubernetes_live.relationship"
	KubernetesWarningFactKind      = "kubernetes_live.warning"
	KubernetesNamespaceFactKind    = "kubernetes_live.namespace"

	KubernetesPodTemplateSchemaVersion  = "1.3.0"
	KubernetesRelationshipSchemaVersion = "1.0.0"
	KubernetesWarningSchemaVersion      = "1.0.0"
	KubernetesNamespaceSchemaVersion    = "1.0.0"
)

// KubernetesLiveFactKinds lists every kubernetes_live.* kind this collector
// emits. The parity proof requires the fixture pack to span all of them.
func KubernetesLiveFactKinds() []string {
	return []string{
		KubernetesPodTemplateFactKind,
		KubernetesRelationshipFactKind,
		KubernetesWarningFactKind,
		KubernetesNamespaceFactKind,
	}
}

// Secrets/IAM posture fact kinds and schema version carried by this collector.
const (
	KubernetesServiceAccountFactKind             = "k8s_service_account"
	KubernetesRBACRoleFactKind                   = "k8s_rbac_role"
	KubernetesRBACBindingFactKind                = "k8s_rbac_binding"
	KubernetesWorkloadIdentityUseFactKind        = "k8s_workload_identity_use"
	KubernetesGCPWorkloadIdentityBindingFactKind = "k8s_gcp_workload_identity_binding" // #nosec G101 -- fact-kind schema identifier, not a credential
	KubernetesServiceAccountTokenPostureFactKind = "k8s_service_account_token_posture" // #nosec G101 -- fact-kind schema identifier, not a credential
	EKSIRSAAnnotationFactKind                    = "eks_irsa_annotation"
	EKSPodIdentityAssociationFactKind            = "eks_pod_identity_association"
	SecretsIAMCoverageWarningFactKind            = "secrets_iam_coverage_warning"

	SecretsIAMSchemaVersionV1 = "1.0.0"
)
