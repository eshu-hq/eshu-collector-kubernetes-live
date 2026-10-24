// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"sort"
	"strings"
	"time"
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

const (
	// PostureCollectorKind is the durable collector_kind for secrets/IAM
	// posture facts (in-tree posture.CollectorKind).
	PostureCollectorKind = "secrets_iam_posture"
	// ProviderKubernetes identifies Kubernetes RBAC and service-account source
	// evidence in the secrets/IAM posture family.
	ProviderKubernetes = "kubernetes"
	// RedactionPolicyVersion identifies the redaction contract used for this
	// source fact family.
	RedactionPolicyVersion = "secrets_iam_posture_v1"

	// BoolStateTrue reports an observed true boolean.
	BoolStateTrue = "true"
	// BoolStateFalse reports an observed false boolean.
	BoolStateFalse = "false"
	// BoolStateUnknown reports a missing or unsupported boolean.
	BoolStateUnknown = "unknown"

	// SourceStateUnsupported marks evidence the collector cannot observe in the
	// current runtime slice.
	SourceStateUnsupported = "unsupported"
	// SourceStatePartial marks source evidence that was only partly observed.
	SourceStatePartial = "partial"
	// SourceStatePermissionHidden marks source evidence hidden by IAM
	// permissions.
	SourceStatePermissionHidden = "permission_hidden"
	// SourceStateRateLimited marks source evidence skipped because the provider
	// rate-limited the collector.
	SourceStateRateLimited = "rate_limited"
	// SourceStateStale marks source evidence known to be stale.
	SourceStateStale = "stale"
)

// EnvelopeContext carries fact boundary fields for one secrets/IAM source
// observation.
type EnvelopeContext struct {
	AccountID           string
	Region              string
	ScopeID             string
	GenerationID        string
	CollectorInstanceID string
	FencingToken        int64
	ObservedAt          time.Time
	SourceURI           string
}

// KubernetesContext carries source scope, generation, claim, and observation
// fields for Kubernetes secrets/IAM posture source facts.
type KubernetesContext struct {
	ClusterID           string
	ScopeID             string
	GenerationID        string
	CollectorInstanceID string
	FencingToken        int64
	ObservedAt          time.Time
	SourceURI           string
}

// KubernetesServiceAccountObservation describes one Kubernetes ServiceAccount
// source identity. Names and namespaces are fingerprinted by the envelope
// builder unless a future explicit safe-identity mode is added.
type KubernetesServiceAccountObservation struct {
	Context                 KubernetesContext
	Namespace               string
	Name                    string
	UID                     string
	AnnotationKeys          []string
	AutomountToken          string
	SecretRefCount          int
	ImagePullSecretRefCount int
	ResourceVersion         string
	SourceURI               string
	SourceRecordID          string
}

// KubernetesServiceAccountTokenPostureObservation describes token-related
// ServiceAccount posture without carrying token or Secret names.
type KubernetesServiceAccountTokenPostureObservation struct {
	Context                 KubernetesContext
	Namespace               string
	ServiceAccountName      string
	ServiceAccountUID       string
	AutomountToken          string
	SecretRefCount          int
	ImagePullSecretRefCount int
	SourceURI               string
	SourceRecordID          string
}

// KubernetesRBACRuleSummary carries bounded RBAC rule metadata. ResourceNames
// and non-resource URLs are represented by presence and counts only.
type KubernetesRBACRuleSummary struct {
	Verbs                  []string
	APIGroups              []string
	Resources              []string
	ResourceNameCount      int
	ResourceNamesPresent   bool
	NonResourceURLCount    int
	NonResourceURLsPresent bool
}

// KubernetesRBACRoleObservation describes one Role or ClusterRole and its
// summarized rules.
type KubernetesRBACRoleObservation struct {
	Context         KubernetesContext
	RoleKind        string
	Namespace       string
	Name            string
	UID             string
	ResourceVersion string
	Rules           []KubernetesRBACRuleSummary
	SourceURI       string
	SourceRecordID  string
}

// KubernetesRBACSubject describes one RoleBinding subject with names redacted by
// envelope construction.
type KubernetesRBACSubject struct {
	Kind      string
	APIGroup  string
	Namespace string
	Name      string
}

// KubernetesRBACBindingObservation describes one RoleBinding or
// ClusterRoleBinding.
type KubernetesRBACBindingObservation struct {
	Context         KubernetesContext
	BindingKind     string
	Namespace       string
	Name            string
	UID             string
	ResourceVersion string
	RoleRefKind     string
	RoleRefAPIGroup string
	RoleRefName     string
	SubjectCount    int
	Subjects        []KubernetesRBACSubject
	SourceURI       string
	SourceRecordID  string
}

// KubernetesWorkloadIdentityUseObservation describes one workload reference to
// a ServiceAccount.
type KubernetesWorkloadIdentityUseObservation struct {
	Context                      KubernetesContext
	WorkloadObjectID             string
	WorkloadKind                 string
	Namespace                    string
	ServiceAccountName           string
	ServiceAccountUID            string
	ProjectedServiceAccountToken bool
	SourceURI                    string
	SourceRecordID               string
}

// KubernetesGCPWorkloadIdentityBindingObservation describes a GKE Workload
// Identity ServiceAccount annotation joined to the configured workload pool.
// The builder turns the raw annotation target and Kubernetes identity into
// redaction-safe digests and fingerprints.
type KubernetesGCPWorkloadIdentityBindingObservation struct {
	Context                KubernetesContext
	Namespace              string
	ServiceAccountName     string
	ServiceAccountUID      string
	GCPServiceAccountEmail string
	GCPWorkloadPool        string
	AnnotationPresent      bool
	SourceURI              string
	SourceRecordID         string
}

// EKSIRSAAnnotationObservation describes the IRSA role annotation on a
// ServiceAccount. RoleARN is preserved as the IAM join anchor; Kubernetes names
// are fingerprinted.
type EKSIRSAAnnotationObservation struct {
	Context            KubernetesContext
	Namespace          string
	ServiceAccountName string
	ServiceAccountUID  string
	RoleARN            string
	AnnotationPresent  bool
	SourceURI          string
	SourceRecordID     string
}

// EKSPodIdentityAssociationObservation describes EKS Pod Identity association
// evidence when a source lane has it available.
type EKSPodIdentityAssociationObservation struct {
	Context            KubernetesContext
	AssociationID      string
	ClusterName        string
	Namespace          string
	ServiceAccountName string
	RoleARN            string
	SourceURI          string
	SourceRecordID     string
}

// KubernetesCoverageWarningObservation describes partial, hidden, unsupported,
// rate-limited, or stale Kubernetes source coverage.
type KubernetesCoverageWarningObservation struct {
	Context        KubernetesContext
	WarningKind    string
	SourceState    string
	ResourceScope  string
	ErrorClass     string
	Message        string
	Attributes     map[string]any
	SourceURI      string
	SourceRecordID string
}

func newPostureEnvelope(
	ctx EnvelopeContext,
	factKind string,
	stableKey string,
	sourceRecordID string,
	sourceURI string,
	payload map[string]any,
) Envelope {
	return Envelope{
		FactID:           secretsIAMFactID(factKind, stableKey, ctx.ScopeID, ctx.GenerationID),
		ScopeID:          strings.TrimSpace(ctx.ScopeID),
		GenerationID:     strings.TrimSpace(ctx.GenerationID),
		FactKind:         factKind,
		StableFactKey:    stableKey,
		SchemaVersion:    SecretsIAMSchemaVersionV1,
		CollectorKind:    PostureCollectorKind,
		FencingToken:     ctx.FencingToken,
		SourceConfidence: SourceConfidenceReported,
		ObservedAt:       normalizedObservedAt(ctx.ObservedAt),
		Payload:          payload,
		SourceRef: Ref{
			SourceSystem:   PostureCollectorKind,
			ScopeID:        strings.TrimSpace(ctx.ScopeID),
			GenerationID:   strings.TrimSpace(ctx.GenerationID),
			FactKey:        stableKey,
			SourceURI:      strings.TrimSpace(sourceURI),
			SourceRecordID: strings.TrimSpace(sourceRecordID),
		},
	}
}

func secretsIAMFactID(factKind, stableFactKey, scopeID, generationID string) string {
	return stableID("SecretsIAMFact", map[string]any{
		"fact_kind":       factKind,
		"generation_id":   generationID,
		"scope_id":        scopeID,
		"stable_fact_key": stableFactKey,
	})
}

// WebIdentitySubjectFingerprint returns the redaction-safe join fingerprint for
// an IAM web-identity subject such as system:serviceaccount:<ns>:<name>.
func WebIdentitySubjectFingerprint(subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ""
	}
	return "sha256:" + stableID("SecretsIAMWebIdentitySubject", map[string]any{
		"subject": subject,
	})
}

// GCPServiceAccountEmailDigest returns the redaction-safe digest of a GKE
// workload-identity service-account email.
func GCPServiceAccountEmailDigest(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return ""
	}
	return "sha256:" + stableID("SecretsIAMGCPServiceAccountEmail", map[string]any{
		"email": normalized,
	})
}

// GCPWorkloadIdentitySubjectFingerprint returns the redaction-safe join
// fingerprint for a GKE Workload Identity subject scoped by workload pool.
func GCPWorkloadIdentitySubjectFingerprint(pool, namespace, serviceAccount string) string {
	pool = strings.TrimSpace(pool)
	namespace = strings.TrimSpace(namespace)
	serviceAccount = strings.TrimSpace(serviceAccount)
	if pool == "" || namespace == "" || serviceAccount == "" {
		return ""
	}
	return "sha256:" + stableID("SecretsIAMGCPWorkloadIdentitySubject", map[string]any{
		"pool":            pool,
		"namespace":       namespace,
		"service_account": serviceAccount,
	})
}

func normalizeActionList(values []string) []string {
	return normalizeStrings(values, strings.ToLower)
}

func normalizePatternList(values []string) []string {
	return normalizeStrings(values, nil)
}

func normalizeKeyList(values []string) []string {
	return normalizeStrings(values, nil)
}

func normalizeStrings(values []string, mapFn func(string) string) []string {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if mapFn != nil {
			trimmed = mapFn(trimmed)
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		output = append(output, trimmed)
	}
	sort.Strings(output)
	return output
}

func sourceRecordID(candidate, fallback string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate != "" {
		return candidate
	}
	return strings.TrimSpace(fallback)
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func validateKubernetesContext(ctx KubernetesContext) error {
	switch {
	case strings.TrimSpace(ctx.ClusterID) == "":
		return fmt.Errorf("kubernetes secrets iam observation requires cluster_id")
	case strings.TrimSpace(ctx.ScopeID) == "":
		return fmt.Errorf("kubernetes secrets iam observation requires scope_id")
	case strings.TrimSpace(ctx.GenerationID) == "":
		return fmt.Errorf("kubernetes secrets iam observation requires generation_id")
	case strings.TrimSpace(ctx.CollectorInstanceID) == "":
		return fmt.Errorf("kubernetes secrets iam observation requires collector_instance_id")
	case ctx.FencingToken <= 0:
		return fmt.Errorf("kubernetes secrets iam observation fencing_token must be positive")
	default:
		return nil
	}
}

func kubernetesEnvelopeContext(ctx KubernetesContext) EnvelopeContext {
	return EnvelopeContext{
		AccountID:           "kubernetes",
		Region:              "cluster",
		ScopeID:             ctx.ScopeID,
		GenerationID:        ctx.GenerationID,
		CollectorInstanceID: ctx.CollectorInstanceID,
		FencingToken:        ctx.FencingToken,
		ObservedAt:          ctx.ObservedAt,
		SourceURI:           ctx.SourceURI,
	}
}

func kubernetesPayload(ctx KubernetesContext) map[string]any {
	return map[string]any{
		"cluster_id":               strings.TrimSpace(ctx.ClusterID),
		"provider":                 ProviderKubernetes,
		"collector_instance_id":    strings.TrimSpace(ctx.CollectorInstanceID),
		"redaction_policy_version": RedactionPolicyVersion,
	}
}

func serviceAccountJoinKey(ctx KubernetesContext, namespace, name string) (string, error) {
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" || name == "" {
		return "", fmt.Errorf("kubernetes service account join requires namespace and name")
	}
	return fingerprintKubernetesParts("service_account_join", ctx.ClusterID, namespace, name), nil
}

func kubernetesWebIdentitySubject(namespace, name string) string {
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" || name == "" {
		return ""
	}
	return "system:serviceaccount:" + namespace + ":" + name
}

func rbacRoleJoinKey(ctx KubernetesContext, kind, namespace, name string) string {
	return fingerprintKubernetesParts("rbac_role_join", ctx.ClusterID, kind, namespace, name)
}

func fingerprintKubernetesValue(kind, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return fingerprintKubernetesParts(kind, value)
}

func fingerprintKubernetesParts(kind string, parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized = append(normalized, strings.TrimSpace(part))
	}
	return "sha256:" + stableID("SecretsIAMKubernetesFingerprint", map[string]any{
		"kind":  strings.TrimSpace(kind),
		"parts": normalized,
	})
}

func rbacRulePayloads(rules []KubernetesRBACRuleSummary) []map[string]any {
	if len(rules) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		output = append(output, map[string]any{
			"verbs":                     normalizeActionList(rule.Verbs),
			"api_groups":                normalizeKeyList(rule.APIGroups),
			"resources":                 normalizeKeyList(rule.Resources),
			"resource_name_count":       rule.ResourceNameCount,
			"resource_names_present":    rule.ResourceNamesPresent,
			"non_resource_url_count":    rule.NonResourceURLCount,
			"non_resource_urls_present": rule.NonResourceURLsPresent,
		})
	}
	return output
}

func rbacSubjectPayloads(ctx KubernetesContext, subjects []KubernetesRBACSubject) []map[string]any {
	if len(subjects) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(subjects))
	for _, subject := range subjects {
		item := map[string]any{
			"kind":                  strings.TrimSpace(subject.Kind),
			"api_group":             strings.TrimSpace(subject.APIGroup),
			"namespace_fingerprint": fingerprintKubernetesValue("namespace", subject.Namespace),
			"name_fingerprint":      fingerprintKubernetesValue("rbac_subject", subject.Name),
		}
		if strings.TrimSpace(subject.Kind) == "ServiceAccount" && strings.TrimSpace(subject.Namespace) != "" {
			item["service_account_join_key"] = fingerprintKubernetesParts(
				"service_account_join",
				ctx.ClusterID,
				subject.Namespace,
				subject.Name,
			)
		}
		output = append(output, item)
	}
	return output
}

func normalizeBoolState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case BoolStateTrue:
		return BoolStateTrue
	case BoolStateFalse:
		return BoolStateFalse
	default:
		return BoolStateUnknown
	}
}

func maxInt(first, second int) int {
	if first > second {
		return first
	}
	return second
}

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

type normalizedRBACRole struct {
	kind      string
	namespace string
	name      string
	scope     string
}

type normalizedRBACBinding struct {
	kind             string
	namespace        string
	name             string
	scope            string
	roleRefKind      string
	roleRefNamespace string
	roleRefName      string
}

func normalizeRBACRoleIdentity(kind, namespace, name string) (normalizedRBACRole, error) {
	role := normalizedRBACRole{
		kind:      strings.TrimSpace(kind),
		namespace: strings.TrimSpace(namespace),
		name:      strings.TrimSpace(name),
	}
	if role.name == "" {
		return normalizedRBACRole{}, fmt.Errorf("kubernetes rbac role observation requires name")
	}
	switch role.kind {
	case RBACRoleKindRole:
		if role.namespace == "" {
			return normalizedRBACRole{}, fmt.Errorf("kubernetes role observation requires namespace")
		}
		role.scope = BindingScopeNamespace
	case RBACRoleKindClusterRole:
		role.namespace = ""
		role.scope = BindingScopeCluster
	default:
		return normalizedRBACRole{}, fmt.Errorf("kubernetes rbac role observation has unsupported role_kind %q", role.kind)
	}
	return role, nil
}

func normalizeRBACBindingIdentity(
	kind string,
	namespace string,
	name string,
	roleRefKind string,
	roleRefName string,
) (normalizedRBACBinding, error) {
	binding := normalizedRBACBinding{
		kind:        strings.TrimSpace(kind),
		namespace:   strings.TrimSpace(namespace),
		name:        strings.TrimSpace(name),
		roleRefKind: strings.TrimSpace(roleRefKind),
		roleRefName: strings.TrimSpace(roleRefName),
	}
	if binding.name == "" {
		return normalizedRBACBinding{}, fmt.Errorf("kubernetes rbac binding observation requires name")
	}
	switch binding.kind {
	case BindingKindRoleBinding:
		if binding.namespace == "" {
			return normalizedRBACBinding{}, fmt.Errorf("kubernetes rolebinding observation requires namespace")
		}
		binding.scope = BindingScopeNamespace
	case BindingKindClusterRoleBinding:
		binding.namespace = ""
		binding.scope = BindingScopeCluster
	default:
		return normalizedRBACBinding{}, fmt.Errorf("kubernetes rbac binding observation has unsupported binding_kind %q", binding.kind)
	}
	if binding.roleRefName == "" {
		return normalizedRBACBinding{}, fmt.Errorf("kubernetes rbac binding observation requires role_ref_name")
	}
	switch binding.roleRefKind {
	case RBACRoleKindRole:
		if binding.kind != BindingKindRoleBinding {
			return normalizedRBACBinding{}, fmt.Errorf("kubernetes clusterrolebinding observation cannot reference a Role")
		}
		binding.roleRefNamespace = binding.namespace
	case RBACRoleKindClusterRole:
		binding.roleRefNamespace = ""
	default:
		return normalizedRBACBinding{}, fmt.Errorf("kubernetes rbac binding observation has unsupported role_ref_kind %q", binding.kind)
	}
	return binding, nil
}
