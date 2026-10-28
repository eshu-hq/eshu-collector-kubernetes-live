// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"strings"
)

// Provenance: secrets/IAM posture seam ported from
// go/internal/collector/access/posture/ (envelope.go shared core,
// kubernetes_envelope.go, kubernetes_types.go, kubernetes_gcp_envelope.go,
// kubernetes_rbac_validate.go, normalize.go, and the Kubernetes/GCP identity
// helpers from gcp_identity.go) at core commit 95dfc56ebb54.
//
// The in-tree posture package serves every collector family (AWS, GCP, vault,
// Kubernetes); only the Kubernetes-relevant subset travels with this
// extraction. AWS/vault constructors, payloads, and contexts stay in core.
// Import rewrites only: facts.Envelope/Ref/StableID -> local model/stable,
// factsidentity.*Kind/SecretsIAMSchemaVersionV1 -> kinds.go. The shared seam's
// known pre-extraction gap (posture SourceURI carried verbatim, not
// sanitized) travels verbatim and stays pinned by the proof test until the
// secrets-IAM lane fixes the shared seam.

// NewKubernetesServiceAccountEnvelope builds a k8s_service_account source fact.
// It fingerprints namespace and ServiceAccount names by default while
// preserving deterministic join keys for reducers.
func NewKubernetesServiceAccountEnvelope(observation KubernetesServiceAccountObservation) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	joinKey, err := serviceAccountJoinKey(observation.Context, observation.Namespace, observation.Name)
	if err != nil {
		return Envelope{}, err
	}
	stableKey := stableID(KubernetesServiceAccountFactKind, map[string]any{
		"cluster_id":               observation.Context.ClusterID,
		"service_account_join_key": joinKey,
		"uid":                      fingerprintKubernetesValue("uid", observation.UID),
	})
	payload := kubernetesPayload(observation.Context)
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", observation.Namespace)
	payload["service_account_fingerprint"] = fingerprintKubernetesValue("service_account", observation.Name)
	payload["service_account_join_key"] = joinKey
	payload["uid_fingerprint"] = fingerprintKubernetesValue("uid", observation.UID)
	payload["annotation_keys"] = normalizeKeyList(observation.AnnotationKeys)
	payload["annotation_count"] = len(normalizeKeyList(observation.AnnotationKeys))
	payload["automount_token"] = normalizeBoolState(observation.AutomountToken)
	payload["secret_ref_count"] = observation.SecretRefCount
	payload["image_pull_secret_ref_count"] = observation.ImagePullSecretRefCount
	payload["resource_version_fingerprint"] = fingerprintKubernetesValue("resource_version", observation.ResourceVersion)
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		KubernetesServiceAccountFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewKubernetesServiceAccountTokenPostureEnvelope builds a token posture source
// fact without carrying token, Secret, or projected volume values.
func NewKubernetesServiceAccountTokenPostureEnvelope(
	observation KubernetesServiceAccountTokenPostureObservation,
) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	joinKey, err := serviceAccountJoinKey(observation.Context, observation.Namespace, observation.ServiceAccountName)
	if err != nil {
		return Envelope{}, err
	}
	stableKey := stableID(KubernetesServiceAccountTokenPostureFactKind, map[string]any{
		"cluster_id":               observation.Context.ClusterID,
		"service_account_join_key": joinKey,
		"uid":                      fingerprintKubernetesValue("uid", observation.ServiceAccountUID),
	})
	payload := kubernetesPayload(observation.Context)
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", observation.Namespace)
	payload["service_account_fingerprint"] = fingerprintKubernetesValue("service_account", observation.ServiceAccountName)
	payload["service_account_join_key"] = joinKey
	payload["service_account_uid_fingerprint"] = fingerprintKubernetesValue("uid", observation.ServiceAccountUID)
	payload["automount_token"] = normalizeBoolState(observation.AutomountToken)
	payload["secret_ref_count"] = observation.SecretRefCount
	payload["image_pull_secret_ref_count"] = observation.ImagePullSecretRefCount
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		KubernetesServiceAccountTokenPostureFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewKubernetesRBACRoleEnvelope builds a k8s_rbac_role source fact for a Role
// or ClusterRole with bounded rule summaries.
func NewKubernetesRBACRoleEnvelope(observation KubernetesRBACRoleObservation) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	role, err := normalizeRBACRoleIdentity(observation.RoleKind, observation.Namespace, observation.Name)
	if err != nil {
		return Envelope{}, err
	}
	roleKey := rbacRoleJoinKey(observation.Context, role.kind, role.namespace, role.name)
	stableKey := stableID(KubernetesRBACRoleFactKind, map[string]any{
		"cluster_id": observation.Context.ClusterID,
		"role_key":   roleKey,
		"uid":        fingerprintKubernetesValue("uid", observation.UID),
	})
	payload := kubernetesPayload(observation.Context)
	payload["role_kind"] = role.kind
	payload["role_scope"] = role.scope
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", role.namespace)
	payload["role_name_fingerprint"] = fingerprintKubernetesValue("rbac_role", role.name)
	payload["role_join_key"] = roleKey
	payload["uid_fingerprint"] = fingerprintKubernetesValue("uid", observation.UID)
	payload["resource_version_fingerprint"] = fingerprintKubernetesValue("resource_version", observation.ResourceVersion)
	payload["rules"] = rbacRulePayloads(observation.Rules)
	payload["rule_count"] = len(observation.Rules)
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		KubernetesRBACRoleFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewKubernetesRBACBindingEnvelope builds a k8s_rbac_binding source fact. It
// distinguishes namespaced RoleBindings from cluster-wide ClusterRoleBindings.
func NewKubernetesRBACBindingEnvelope(observation KubernetesRBACBindingObservation) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	binding, err := normalizeRBACBindingIdentity(
		observation.BindingKind,
		observation.Namespace,
		observation.Name,
		observation.RoleRefKind,
		observation.RoleRefName,
	)
	if err != nil {
		return Envelope{}, err
	}
	roleRefKey := rbacRoleJoinKey(
		observation.Context,
		binding.roleRefKind,
		binding.roleRefNamespace,
		binding.roleRefName,
	)
	stableKey := stableID(KubernetesRBACBindingFactKind, map[string]any{
		"binding_kind": binding.kind,
		"cluster_id":   observation.Context.ClusterID,
		"name":         fingerprintKubernetesValue("rbac_binding", binding.name),
		"namespace":    fingerprintKubernetesValue("namespace", binding.namespace),
		"uid":          fingerprintKubernetesValue("uid", observation.UID),
	})
	payload := kubernetesPayload(observation.Context)
	payload["binding_kind"] = binding.kind
	payload["binding_scope"] = binding.scope
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", binding.namespace)
	payload["binding_name_fingerprint"] = fingerprintKubernetesValue("rbac_binding", binding.name)
	payload["uid_fingerprint"] = fingerprintKubernetesValue("uid", observation.UID)
	payload["resource_version_fingerprint"] = fingerprintKubernetesValue("resource_version", observation.ResourceVersion)
	payload["role_ref_kind"] = binding.roleRefKind
	payload["role_ref_api_group"] = strings.TrimSpace(observation.RoleRefAPIGroup)
	payload["role_ref_name_fingerprint"] = fingerprintKubernetesValue("rbac_role_ref", binding.roleRefName)
	payload["role_ref_join_key"] = roleRefKey
	payload["subject_count"] = maxInt(observation.SubjectCount, len(observation.Subjects))
	payload["subjects"] = rbacSubjectPayloads(observation.Context, observation.Subjects)
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		KubernetesRBACBindingFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewKubernetesWorkloadIdentityUseEnvelope builds a
// k8s_workload_identity_use source fact for one workload's ServiceAccount
// reference.
func NewKubernetesWorkloadIdentityUseEnvelope(
	observation KubernetesWorkloadIdentityUseObservation,
) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	workloadObjectID := strings.TrimSpace(observation.WorkloadObjectID)
	if workloadObjectID == "" {
		return Envelope{}, fmt.Errorf("kubernetes workload identity observation requires workload_object_id")
	}
	joinKey, err := serviceAccountJoinKey(observation.Context, observation.Namespace, observation.ServiceAccountName)
	if err != nil {
		return Envelope{}, err
	}
	stableKey := stableID(KubernetesWorkloadIdentityUseFactKind, map[string]any{
		"cluster_id":               observation.Context.ClusterID,
		"service_account_join_key": joinKey,
		"workload_object_id":       workloadObjectID,
	})
	payload := kubernetesPayload(observation.Context)
	payload["workload_object_id"] = workloadObjectID
	payload["workload_kind"] = strings.TrimSpace(observation.WorkloadKind)
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", observation.Namespace)
	payload["service_account_fingerprint"] = fingerprintKubernetesValue("service_account", observation.ServiceAccountName)
	payload["service_account_join_key"] = joinKey
	payload["service_account_uid_fingerprint"] = fingerprintKubernetesValue("uid", observation.ServiceAccountUID)
	payload["projected_service_account_token"] = observation.ProjectedServiceAccountToken
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		KubernetesWorkloadIdentityUseFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewEKSIRSAAnnotationEnvelope builds an eks_irsa_annotation source fact.
func NewEKSIRSAAnnotationEnvelope(observation EKSIRSAAnnotationObservation) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	roleARN := strings.TrimSpace(observation.RoleARN)
	if roleARN == "" {
		return Envelope{}, fmt.Errorf("eks irsa annotation observation requires role_arn")
	}
	joinKey, err := serviceAccountJoinKey(observation.Context, observation.Namespace, observation.ServiceAccountName)
	if err != nil {
		return Envelope{}, err
	}
	stableKey := stableID(EKSIRSAAnnotationFactKind, map[string]any{
		"cluster_id":               observation.Context.ClusterID,
		"role_arn":                 roleARN,
		"service_account_join_key": joinKey,
	})
	payload := kubernetesPayload(observation.Context)
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", observation.Namespace)
	payload["service_account_fingerprint"] = fingerprintKubernetesValue("service_account", observation.ServiceAccountName)
	payload["service_account_join_key"] = joinKey
	payload["service_account_uid_fingerprint"] = fingerprintKubernetesValue("uid", observation.ServiceAccountUID)
	payload["role_arn"] = roleARN
	payload["annotation_present"] = observation.AnnotationPresent
	payload["web_identity_subject_fingerprint"] = WebIdentitySubjectFingerprint(
		kubernetesWebIdentitySubject(observation.Namespace, observation.ServiceAccountName),
	)
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		EKSIRSAAnnotationFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewEKSPodIdentityAssociationEnvelope builds an
// eks_pod_identity_association source fact when association evidence exists.
// The in-tree lane never emits it today; the constructor travels with the
// seam so the cutover keeps the full posture surface.
func NewEKSPodIdentityAssociationEnvelope(observation EKSPodIdentityAssociationObservation) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	associationID := strings.TrimSpace(observation.AssociationID)
	roleARN := strings.TrimSpace(observation.RoleARN)
	if associationID == "" || roleARN == "" {
		return Envelope{}, fmt.Errorf("eks pod identity association observation requires association_id and role_arn")
	}
	joinKey, err := serviceAccountJoinKey(observation.Context, observation.Namespace, observation.ServiceAccountName)
	if err != nil {
		return Envelope{}, err
	}
	stableKey := stableID(EKSPodIdentityAssociationFactKind, map[string]any{
		"association_id":           associationID,
		"cluster_id":               observation.Context.ClusterID,
		"role_arn":                 roleARN,
		"service_account_join_key": joinKey,
	})
	payload := kubernetesPayload(observation.Context)
	payload["association_id"] = associationID
	payload["cluster_name_fingerprint"] = fingerprintKubernetesValue("eks_cluster_name", observation.ClusterName)
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", observation.Namespace)
	payload["service_account_fingerprint"] = fingerprintKubernetesValue("service_account", observation.ServiceAccountName)
	payload["service_account_join_key"] = joinKey
	payload["role_arn"] = roleARN
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		EKSPodIdentityAssociationFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewKubernetesGCPWorkloadIdentityBindingEnvelope builds the
// k8s_gcp_workload_identity_binding source fact for a ServiceAccount annotated
// with iam.gke.io/gcp-service-account under a configured GKE workload pool.
func NewKubernetesGCPWorkloadIdentityBindingEnvelope(
	observation KubernetesGCPWorkloadIdentityBindingObservation,
) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	emailDigest := GCPServiceAccountEmailDigest(observation.GCPServiceAccountEmail)
	if emailDigest == "" {
		return Envelope{}, fmt.Errorf("kubernetes GCP workload identity binding requires gcp service-account annotation")
	}
	workloadPool := strings.TrimSpace(observation.GCPWorkloadPool)
	if workloadPool == "" {
		return Envelope{}, fmt.Errorf("kubernetes GCP workload identity binding requires gcp workload pool")
	}
	joinKey, err := serviceAccountJoinKey(
		observation.Context,
		observation.Namespace,
		observation.ServiceAccountName,
	)
	if err != nil {
		return Envelope{}, err
	}
	subjectFingerprint := GCPWorkloadIdentitySubjectFingerprint(
		workloadPool,
		observation.Namespace,
		observation.ServiceAccountName,
	)
	if subjectFingerprint == "" {
		return Envelope{}, fmt.Errorf("kubernetes GCP workload identity binding requires subject identity")
	}
	stableKey := stableID(KubernetesGCPWorkloadIdentityBindingFactKind, map[string]any{
		"cluster_id":                                observation.Context.ClusterID,
		"gcp_service_account_email_digest":          emailDigest,
		"gcp_workload_identity_subject_fingerprint": subjectFingerprint,
		"service_account_join_key":                  joinKey,
		"service_account_uid_fingerprint":           fingerprintKubernetesValue("uid", observation.ServiceAccountUID),
	})
	payload := kubernetesPayload(observation.Context)
	payload["namespace_fingerprint"] = fingerprintKubernetesValue("namespace", observation.Namespace)
	payload["service_account_fingerprint"] = fingerprintKubernetesValue("service_account", observation.ServiceAccountName)
	payload["service_account_join_key"] = joinKey
	payload["service_account_uid_fingerprint"] = fingerprintKubernetesValue("uid", observation.ServiceAccountUID)
	payload["gcp_service_account_email_digest"] = emailDigest
	payload["gcp_workload_identity_pool_fingerprint"] = fingerprintKubernetesValue("gcp_workload_pool", workloadPool)
	payload["gcp_workload_identity_subject_fingerprint"] = subjectFingerprint
	payload["annotation_present"] = observation.AnnotationPresent
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		KubernetesGCPWorkloadIdentityBindingFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}

// NewKubernetesCoverageWarningEnvelope builds secrets_iam_coverage_warning
// evidence for partial or hidden Kubernetes source reads.
func NewKubernetesCoverageWarningEnvelope(observation KubernetesCoverageWarningObservation) (Envelope, error) {
	if err := validateKubernetesContext(observation.Context); err != nil {
		return Envelope{}, err
	}
	warningKind := strings.TrimSpace(observation.WarningKind)
	sourceState := strings.TrimSpace(observation.SourceState)
	if warningKind == "" || sourceState == "" {
		return Envelope{}, fmt.Errorf("kubernetes coverage warning requires warning_kind and source_state")
	}
	resourceScope := strings.TrimSpace(observation.ResourceScope)
	stableKey := stableID(SecretsIAMCoverageWarningFactKind, map[string]any{
		"cluster_id":     observation.Context.ClusterID,
		"generation":     observation.Context.GenerationID,
		"resource_scope": resourceScope,
		"source_state":   sourceState,
		"warning_kind":   warningKind,
	})
	payload := kubernetesPayload(observation.Context)
	payload["warning_kind"] = warningKind
	payload["source_state"] = sourceState
	payload["resource_scope"] = resourceScope
	payload["error_class"] = strings.TrimSpace(observation.ErrorClass)
	payload["message"] = strings.TrimSpace(observation.Message)
	payload["attributes"] = cloneAnyMap(observation.Attributes)
	return newPostureEnvelope(
		kubernetesEnvelopeContext(observation.Context),
		SecretsIAMCoverageWarningFactKind,
		stableKey,
		sourceRecordID(observation.SourceRecordID, stableKey),
		firstNonBlank(observation.SourceURI, observation.Context.SourceURI),
		payload,
	), nil
}
