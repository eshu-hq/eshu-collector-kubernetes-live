// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"sort"
	"strings"
)

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
