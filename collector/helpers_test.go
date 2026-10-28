// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"
)

func TestObjectIdentityValidateRequiresEveryField(t *testing.T) {
	t.Parallel()

	valid := portedSampleIdentity()
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want the ported identity accepted", err)
	}
	cases := map[string]func(*ObjectIdentity){
		"cluster_id": func(o *ObjectIdentity) { o.ClusterID = " " },
		"version":    func(o *ObjectIdentity) { o.Version = "" },
		"resource":   func(o *ObjectIdentity) { o.Resource = "" },
		"name":       func(o *ObjectIdentity) { o.Name = "" },
		"uid":        func(o *ObjectIdentity) { o.UID = "" },
	}
	for field, blank := range cases {
		identity := portedSampleIdentity()
		blank(&identity)
		if err := identity.Validate(); err == nil {
			t.Errorf("Validate() error = nil, want %s rejection", field)
		}
	}
}

func TestClusterScopeIDRejectsBlankCluster(t *testing.T) {
	t.Parallel()

	if _, err := ClusterScopeID("  "); err == nil {
		t.Fatal("ClusterScopeID(blank) error = nil, want rejection")
	}
	first, err := ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatalf("ClusterScopeID() error = %v", err)
	}
	second, err := ClusterScopeID("ops-qa-1")
	if err != nil {
		t.Fatalf("ClusterScopeID() error = %v", err)
	}
	if first != second || !strings.HasPrefix(first, "kubernetes_live:") {
		t.Fatalf("ClusterScopeID() = %q, want a stable scoped id", first)
	}
}

func TestSelectorMatchesLabelsNeedsANonEmptySubset(t *testing.T) {
	t.Parallel()

	labels := map[string]string{"app": "web", "tier": "front"}
	if selectorMatchesLabels(nil, labels) {
		t.Fatal("empty selector matched, want false")
	}
	if !selectorMatchesLabels(map[string]string{"app": "web"}, labels) {
		t.Fatal("subset selector did not match, want true")
	}
	if selectorMatchesLabels(map[string]string{"app": "api"}, labels) {
		t.Fatal("mismatched selector matched, want false")
	}
}

func TestNormalizeCRIImageIDCoversEveryBranch(t *testing.T) {
	t.Parallel()

	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := map[string]string{
		"":                                 "",
		"repo:tag":                         "",
		"sha256:abc":                       "",
		"docker-pullable://repo@" + digest: "repo@" + digest,
		"docker://repo@" + digest:          "repo@" + digest,
		"repo@" + digest:                   "repo@" + digest,
		"docker-pullable://":               "",
	}
	for raw, want := range cases {
		if got := NormalizeCRIImageID(raw); got != want {
			t.Errorf("NormalizeCRIImageID(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestNormalizedObservedAtDefaultsToNowUTC(t *testing.T) {
	t.Parallel()

	got := normalizedObservedAt(time.Time{})
	if time.Since(got) > time.Minute || got.Location() != time.UTC {
		t.Fatalf("zero observedAt = %v, want ~now in UTC", got)
	}
	fixed := time.Date(2026, 5, 31, 12, 0, 0, 0, time.FixedZone("x", 3600))
	if got := normalizedObservedAt(fixed); !got.Equal(fixed.UTC()) {
		t.Fatalf("observedAt = %v, want the UTC instant", got)
	}
}

func TestValidateBoundaryNamesTheNoun(t *testing.T) {
	t.Parallel()

	if err := validateBoundary("", "i", "pod"); err == nil {
		t.Fatal("blank generation accepted, want rejection")
	}
	if err := validateBoundary("g", "", "pod"); err == nil {
		t.Fatal("blank instance accepted, want rejection")
	}
	if err := validateBoundary("g", "i", "pod"); err != nil {
		t.Fatalf("validateBoundary() error = %v", err)
	}
}

func TestNewEnvelopeRejectsBlankCluster(t *testing.T) {
	t.Parallel()

	_, err := newEnvelope("", "k", "1.0.0", "key", "gen", "i", 1, time.Now().UTC(), "", "", nil)
	if err == nil {
		t.Fatal("newEnvelope(blank cluster) error = nil, want rejection")
	}
}

func validPostureContext() KubernetesContext {
	return KubernetesContext{
		ClusterID:           "ops-qa-1",
		ScopeID:             "scope-1",
		GenerationID:        "gen-1",
		CollectorInstanceID: "i-1",
		FencingToken:        7,
		ObservedAt:          time.Now().UTC(),
		SourceURI:           "https://kubernetes.default.svc",
	}
}

func TestValidateKubernetesContextRequiresEveryField(t *testing.T) {
	t.Parallel()

	if err := validateKubernetesContext(validPostureContext()); err != nil {
		t.Fatalf("validateKubernetesContext() error = %v", err)
	}
	cases := map[string]func(*KubernetesContext){
		"cluster_id":            func(c *KubernetesContext) { c.ClusterID = "" },
		"scope_id":              func(c *KubernetesContext) { c.ScopeID = "" },
		"generation_id":         func(c *KubernetesContext) { c.GenerationID = "" },
		"collector_instance_id": func(c *KubernetesContext) { c.CollectorInstanceID = "" },
		"fencing_token":         func(c *KubernetesContext) { c.FencingToken = 0 },
	}
	for field, blank := range cases {
		ctx := validPostureContext()
		blank(&ctx)
		if err := validateKubernetesContext(ctx); err == nil {
			t.Errorf("validateKubernetesContext() error = nil, want %s rejection", field)
		}
	}
}

func TestCloneAnyMapCopiesOrStaysNil(t *testing.T) {
	t.Parallel()

	if cloneAnyMap(nil) != nil {
		t.Fatal("cloneAnyMap(nil) != nil")
	}
	orig := map[string]any{"k": "v"}
	dup := cloneAnyMap(orig)
	dup["k"] = "changed"
	if orig["k"] != "v" {
		t.Fatal("clone shares the backing map with the original")
	}
}

func TestMaxIntPicksTheLarger(t *testing.T) {
	t.Parallel()

	if maxInt(1, 2) != 2 || maxInt(2, 1) != 2 || maxInt(2, 2) != 2 {
		t.Fatal("maxInt() picked the wrong side")
	}
}

func TestSourceRecordIDPrefersTheCandidate(t *testing.T) {
	t.Parallel()

	if got := sourceRecordID("c", "f"); got != "c" {
		t.Fatalf("sourceRecordID() = %q, want the candidate", got)
	}
	if got := sourceRecordID(" ", "f"); got != "f" {
		t.Fatalf("sourceRecordID() = %q, want the fallback", got)
	}
	if got := sourceRecordID("", ""); got != "" {
		t.Fatalf("sourceRecordID() = %q, want empty", got)
	}
}

func TestNormalizeRBACRoleIdentityScopesByKind(t *testing.T) {
	t.Parallel()

	role, err := normalizeRBACRoleIdentity(RBACRoleKindRole, "ns", "name")
	if err != nil || role.scope != BindingScopeNamespace {
		t.Fatalf("Role identity = (%+v, %v), want namespace scope", role, err)
	}
	cluster, err := normalizeRBACRoleIdentity(RBACRoleKindClusterRole, "ns", "name")
	if err != nil || cluster.scope != BindingScopeCluster || cluster.namespace != "" {
		t.Fatalf("ClusterRole identity = (%+v, %v), want cleared namespace", cluster, err)
	}
	for name, args := range map[string][3]string{
		"empty name":       {RBACRoleKindRole, "ns", ""},
		"namespaced role":  {RBACRoleKindRole, "", "name"},
		"unsupported kind": {"Root", "ns", "name"},
	} {
		if _, err := normalizeRBACRoleIdentity(args[0], args[1], args[2]); err == nil {
			t.Errorf("%s accepted, want rejection", name)
		}
	}
}

func TestNormalizeRBACBindingIdentityScopesByKind(t *testing.T) {
	t.Parallel()

	binding, err := normalizeRBACBindingIdentity(BindingKindRoleBinding, "ns", "name", RBACRoleKindRole, "role")
	if err != nil || binding.scope != BindingScopeNamespace || binding.roleRefNamespace != "ns" {
		t.Fatalf("RoleBinding identity = (%+v, %v)", binding, err)
	}
	cluster, err := normalizeRBACBindingIdentity(BindingKindClusterRoleBinding, "ns", "name", RBACRoleKindClusterRole, "role")
	if err != nil || cluster.scope != BindingScopeCluster {
		t.Fatalf("ClusterRoleBinding identity = (%+v, %v)", cluster, err)
	}
	for name, args := range map[string][5]string{
		"empty name":              {BindingKindRoleBinding, "ns", "", RBACRoleKindRole, "role"},
		"role without ns":         {BindingKindRoleBinding, "", "name", RBACRoleKindRole, "role"},
		"unsupported kind":        {"Root", "ns", "name", RBACRoleKindRole, "role"},
		"empty role ref":          {BindingKindRoleBinding, "ns", "name", RBACRoleKindRole, ""},
		"unsupported ref kind":    {BindingKindRoleBinding, "ns", "name", "Root", "role"},
		"cluster binding to Role": {BindingKindClusterRoleBinding, "", "name", RBACRoleKindRole, "role"},
	} {
		if _, err := normalizeRBACBindingIdentity(args[0], args[1], args[2], args[3], args[4]); err == nil {
			t.Errorf("%s accepted, want rejection", name)
		}
	}
}

func TestKubernetesWebIdentitySubjectFormats(t *testing.T) {
	t.Parallel()

	if got := kubernetesWebIdentitySubject("ns", "sa"); got != "system:serviceaccount:ns:sa" {
		t.Fatalf("subject = %q", got)
	}
	if got := kubernetesWebIdentitySubject("", "sa"); got != "" {
		t.Fatalf("blank namespace subject = %q, want empty", got)
	}
}

func TestSourceClockDefaultsToWallTime(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	got := (&Source{}).now()
	if got.Before(before) || time.Since(got) > time.Minute {
		t.Fatalf("Source{}.now() = %v, want ~wall time", got)
	}
}

func TestOwnerScopeMapsWorkloadKinds(t *testing.T) {
	t.Parallel()

	builder := &generationBuilder{}
	cases := map[string]string{
		"Deployment":  ResourceScopeDeployments,
		"ReplicaSet":  ResourceScopeReplicaSets,
		"StatefulSet": ResourceScopeStatefulSets,
		"DaemonSet":   ResourceScopeDaemonSets,
		"Job":         ResourceScopeJobs,
		"CronJob":     ResourceScopeCronJobs,
		"StrangeKind": "strangekind",
	}
	for kind, want := range cases {
		if got := builder.ownerScope(OwnerReference{Kind: kind}); got != want {
			t.Errorf("ownerScope(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestRecordAPICallTracesWhenConfigured(t *testing.T) {
	t.Parallel()

	source := &Source{Tracer: noop.NewTracerProvider().Tracer("test")}
	called := false
	err := source.recordAPICall(context.Background(), "ping", func(context.Context) error {
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("recordAPICall() = (%v, called=%v), want (nil, true)", err, called)
	}
}

func TestCollectClusterReportsAPingFailure(t *testing.T) {
	t.Parallel()

	source := portedNewSource(&fakeClient{pingErr: errors.New("connection refused")})
	_, _, err := source.Next(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ping") {
		t.Fatalf("Next(ping refused) error = %v, want the ping wrapped", err)
	}
}

func TestBuilderRunReportsANamespaceFailure(t *testing.T) {
	t.Parallel()

	source := portedNewSource(&fakeClient{namespacesErr: errors.New("forbidden")})
	_, _, err := source.Next(context.Background())
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("Next(namespaces forbidden) error = %v, want the list failure", err)
	}
}

func TestFingerprintHelpersAreStableAndBlankSafe(t *testing.T) {
	t.Parallel()

	if WebIdentitySubjectFingerprint(" ") != "" || GCPServiceAccountEmailDigest("") != "" {
		t.Fatal("blank fingerprint input did not return empty")
	}
	if GCPServiceAccountEmailDigest("Admin@Example.COM") != GCPServiceAccountEmailDigest("admin@example.com") {
		t.Fatal("email digest is case-sensitive, want lowercase normalization")
	}
	if GCPWorkloadIdentitySubjectFingerprint("", "ns", "sa") != "" {
		t.Fatal("blank pool fingerprint did not return empty")
	}
	first := GCPWorkloadIdentitySubjectFingerprint("pool", "ns", "sa")
	if first == "" || first != GCPWorkloadIdentitySubjectFingerprint("pool", "ns", "sa") {
		t.Fatal("subject fingerprint is unstable")
	}
}
