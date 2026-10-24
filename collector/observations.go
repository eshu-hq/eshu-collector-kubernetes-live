// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"strings"
)

// Provenance: ported from go/internal/collector/kuberneteslive/secrets_iam_observations.go
// at core commit 95dfc56ebb54. posture.* references resolve to the merged
// posture.go in this package.

func (b *generationBuilder) collectServiceAccounts(ctx context.Context, client Client) error {
	result, err := client.ListServiceAccounts(ctx)
	if err != nil {
		return err
	}
	b.markPartial(ctx, ResourceScopeServiceAccounts, result.Partial, result.Reason)
	for _, account := range result.Items {
		b.indexObject(account.Meta)
		b.serviceAccountIndex[namespacedName(account.Meta.Namespace, account.Meta.Name)] = account
		if err := b.addServiceAccountFacts(ctx, account); err != nil {
			return err
		}
	}
	return nil
}

func (b *generationBuilder) collectRBAC(ctx context.Context, client Client) error {
	roleLists := []struct {
		resourceScope string
		list          func(context.Context) (ListResult[RBACRoleObject], error)
	}{
		{ResourceScopeRoles, client.ListRoles},
		{ResourceScopeClusterRoles, client.ListClusterRoles},
	}
	for _, entry := range roleLists {
		result, err := entry.list(ctx)
		if err != nil {
			return err
		}
		b.markPartial(ctx, entry.resourceScope, result.Partial, result.Reason)
		for _, role := range result.Items {
			b.indexObject(role.Meta)
			if err := b.addRBACRoleFact(ctx, role); err != nil {
				return err
			}
		}
	}
	bindingLists := []struct {
		resourceScope string
		list          func(context.Context) (ListResult[RBACBindingObject], error)
	}{
		{ResourceScopeRoleBindings, client.ListRoleBindings},
		{ResourceScopeClusterRoleBindings, client.ListClusterRoleBindings},
	}
	for _, entry := range bindingLists {
		result, err := entry.list(ctx)
		if err != nil {
			return err
		}
		b.markPartial(ctx, entry.resourceScope, result.Partial, result.Reason)
		for _, binding := range result.Items {
			b.indexObject(binding.Meta)
			if err := b.addRBACBindingFact(ctx, binding); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *generationBuilder) addServiceAccountFacts(ctx context.Context, account ServiceAccountObject) error {
	automount := boolState(account.AutomountToken)
	envelope, err := NewKubernetesServiceAccountEnvelope(KubernetesServiceAccountObservation{
		Context:                 b.secretsIAMContext(),
		Namespace:               account.Meta.Namespace,
		Name:                    account.Meta.Name,
		UID:                     account.Meta.UID,
		AnnotationKeys:          account.AnnotationKeys,
		AutomountToken:          automount,
		SecretRefCount:          account.SecretRefCount,
		ImagePullSecretRefCount: account.ImagePullSecretRefCount,
		ResourceVersion:         account.Meta.ResourceVersion,
		SourceURI:               b.target.SourceURI,
	})
	if err != nil {
		return err
	}
	b.append(ctx, envelope)
	token, err := NewKubernetesServiceAccountTokenPostureEnvelope(
		KubernetesServiceAccountTokenPostureObservation{
			Context:                 b.secretsIAMContext(),
			Namespace:               account.Meta.Namespace,
			ServiceAccountName:      account.Meta.Name,
			ServiceAccountUID:       account.Meta.UID,
			AutomountToken:          automount,
			SecretRefCount:          account.SecretRefCount,
			ImagePullSecretRefCount: account.ImagePullSecretRefCount,
			SourceURI:               b.target.SourceURI,
		},
	)
	if err != nil {
		return err
	}
	b.append(ctx, token)
	if strings.TrimSpace(account.IRSAAnnotation) == "" {
		return b.addGCPWorkloadIdentityBinding(ctx, account)
	}
	irsa, err := NewEKSIRSAAnnotationEnvelope(EKSIRSAAnnotationObservation{
		Context:            b.secretsIAMContext(),
		Namespace:          account.Meta.Namespace,
		ServiceAccountName: account.Meta.Name,
		ServiceAccountUID:  account.Meta.UID,
		RoleARN:            account.IRSAAnnotation,
		AnnotationPresent:  true,
		SourceURI:          b.target.SourceURI,
	})
	if err != nil {
		return err
	}
	b.append(ctx, irsa)
	return b.addGCPWorkloadIdentityBinding(ctx, account)
}

func (b *generationBuilder) addGCPWorkloadIdentityBinding(ctx context.Context, account ServiceAccountObject) error {
	if strings.TrimSpace(account.GCPServiceAccountAnnotation) == "" || strings.TrimSpace(b.target.GCPWorkloadPool) == "" {
		return nil
	}
	binding, err := NewKubernetesGCPWorkloadIdentityBindingEnvelope(
		KubernetesGCPWorkloadIdentityBindingObservation{
			Context:                b.secretsIAMContext(),
			Namespace:              account.Meta.Namespace,
			ServiceAccountName:     account.Meta.Name,
			ServiceAccountUID:      account.Meta.UID,
			GCPServiceAccountEmail: account.GCPServiceAccountAnnotation,
			GCPWorkloadPool:        b.target.GCPWorkloadPool,
			AnnotationPresent:      true,
			SourceURI:              b.target.SourceURI,
		},
	)
	if err != nil {
		return err
	}
	b.append(ctx, binding)
	return nil
}

func (b *generationBuilder) addRBACRoleFact(ctx context.Context, role RBACRoleObject) error {
	envelope, err := NewKubernetesRBACRoleEnvelope(KubernetesRBACRoleObservation{
		Context:         b.secretsIAMContext(),
		RoleKind:        role.Kind,
		Namespace:       role.Meta.Namespace,
		Name:            role.Meta.Name,
		UID:             role.Meta.UID,
		ResourceVersion: role.Meta.ResourceVersion,
		Rules:           secretsRBACRules(role.Rules),
		SourceURI:       b.target.SourceURI,
	})
	if err != nil {
		return err
	}
	b.append(ctx, envelope)
	return nil
}

func (b *generationBuilder) addRBACBindingFact(ctx context.Context, binding RBACBindingObject) error {
	envelope, err := NewKubernetesRBACBindingEnvelope(KubernetesRBACBindingObservation{
		Context:         b.secretsIAMContext(),
		BindingKind:     binding.Kind,
		Namespace:       binding.Meta.Namespace,
		Name:            binding.Meta.Name,
		UID:             binding.Meta.UID,
		ResourceVersion: binding.Meta.ResourceVersion,
		RoleRefKind:     binding.RoleRefKind,
		RoleRefAPIGroup: binding.RoleRefAPIGroup,
		RoleRefName:     binding.RoleRefName,
		SubjectCount:    len(binding.Subjects),
		Subjects:        secretsRBACSubjects(binding.Subjects),
		SourceURI:       b.target.SourceURI,
	})
	if err != nil {
		return err
	}
	b.append(ctx, envelope)
	return nil
}

func (b *generationBuilder) addWorkloadIdentityUse(
	ctx context.Context,
	identity ObjectIdentity,
	workload WorkloadObject,
) error {
	serviceAccountName := strings.TrimSpace(workload.ServiceAccount)
	if serviceAccountName == "" {
		return nil
	}
	account := b.serviceAccountIndex[namespacedName(identity.Namespace, serviceAccountName)]
	envelope, err := NewKubernetesWorkloadIdentityUseEnvelope(
		KubernetesWorkloadIdentityUseObservation{
			Context:                      b.secretsIAMContext(),
			WorkloadObjectID:             identity.ObjectID(),
			WorkloadKind:                 strings.TrimSpace(identity.Resource),
			Namespace:                    identity.Namespace,
			ServiceAccountName:           serviceAccountName,
			ServiceAccountUID:            account.Meta.UID,
			ProjectedServiceAccountToken: workload.ProjectedServiceAccountToken,
			SourceURI:                    b.target.SourceURI,
		},
	)
	if err != nil {
		return err
	}
	b.append(ctx, envelope)
	return nil
}

func (b *generationBuilder) emitSecretsCoverageWarning(ctx context.Context, reason, resourceScope string) error {
	state := SourceStatePartial
	if strings.TrimSpace(reason) == WarningForbiddenResource {
		state = SourceStatePermissionHidden
	}
	envelope, err := NewKubernetesCoverageWarningEnvelope(KubernetesCoverageWarningObservation{
		Context:       b.secretsIAMContext(),
		WarningKind:   strings.TrimSpace(reason),
		SourceState:   state,
		ResourceScope: strings.TrimSpace(resourceScope),
		ErrorClass:    strings.TrimSpace(reason),
		SourceURI:     b.target.SourceURI,
	})
	if err != nil {
		return err
	}
	b.append(ctx, envelope)
	return nil
}

func (b *generationBuilder) secretsIAMContext() KubernetesContext {
	scopeID, _ := ClusterScopeID(b.target.ClusterID)
	return KubernetesContext{
		ClusterID:           b.target.ClusterID,
		ScopeID:             scopeID,
		GenerationID:        b.generationID(),
		CollectorInstanceID: b.collectorInstanceID,
		FencingToken:        b.target.FencingToken,
		ObservedAt:          b.observedAt,
		SourceURI:           b.target.SourceURI,
	}
}

func secretsRBACRules(rules []RBACRuleSummary) []KubernetesRBACRuleSummary {
	if len(rules) == 0 {
		return nil
	}
	output := make([]KubernetesRBACRuleSummary, 0, len(rules))
	for _, rule := range rules {
		output = append(output, KubernetesRBACRuleSummary{
			Verbs:                  rule.Verbs,
			APIGroups:              rule.APIGroups,
			Resources:              rule.Resources,
			ResourceNameCount:      rule.ResourceNameCount,
			ResourceNamesPresent:   rule.ResourceNamesPresent,
			NonResourceURLCount:    rule.NonResourceURLCount,
			NonResourceURLsPresent: rule.NonResourceURLsPresent,
		})
	}
	return output
}

func secretsRBACSubjects(subjects []RBACSubject) []KubernetesRBACSubject {
	if len(subjects) == 0 {
		return nil
	}
	output := make([]KubernetesRBACSubject, 0, len(subjects))
	for _, subject := range subjects {
		output = append(output, KubernetesRBACSubject{
			Kind:      subject.Kind,
			APIGroup:  subject.APIGroup,
			Namespace: subject.Namespace,
			Name:      subject.Name,
		})
	}
	return output
}

func boolState(value *bool) string {
	if value == nil {
		return BoolStateUnknown
	}
	if *value {
		return BoolStateTrue
	}
	return BoolStateFalse
}
