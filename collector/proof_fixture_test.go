// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"time"
)

// Provenance: fakeClient and the parity-full / parity-hostile fixture builders
// are ported from source_test.go (fakeClient) and source_parity_8859_test.go
// (parity8859LiveSource) at core commit 95dfc56ebb54. Only the assertions
// below are new: they compare the extracted producer against the copied
// fixture-pack oracle instead of the in-tree cassette reader.

// fakeClient is a read-only in-memory Kubernetes client for tests. Each field
// is the list result for one resource family; a nil Err returns the items.
type fakeClient struct {
	pingErr             error
	namespaces          ListResult[ObjectMeta]
	pods                ListResult[WorkloadObject]
	deployments         ListResult[WorkloadObject]
	replicasets         ListResult[WorkloadObject]
	statefulsets        ListResult[WorkloadObject]
	daemonsets          ListResult[WorkloadObject]
	jobs                ListResult[WorkloadObject]
	cronjobs            ListResult[WorkloadObject]
	services            ListResult[ServiceObject]
	ingresses           ListResult[IngressObject]
	serviceAccounts     ListResult[ServiceAccountObject]
	roles               ListResult[RBACRoleObject]
	clusterRoles        ListResult[RBACRoleObject]
	roleBindings        ListResult[RBACBindingObject]
	clusterRoleBindings ListResult[RBACBindingObject]
}

func (f *fakeClient) PingReadOnly(context.Context) error { return f.pingErr }
func (f *fakeClient) ListNamespaces(context.Context) (ListResult[ObjectMeta], error) {
	return f.namespaces, nil
}

func (f *fakeClient) ListPods(context.Context) (ListResult[WorkloadObject], error) {
	return f.pods, nil
}

func (f *fakeClient) ListDeployments(context.Context) (ListResult[WorkloadObject], error) {
	return f.deployments, nil
}

func (f *fakeClient) ListReplicaSets(context.Context) (ListResult[WorkloadObject], error) {
	return f.replicasets, nil
}

func (f *fakeClient) ListStatefulSets(context.Context) (ListResult[WorkloadObject], error) {
	return f.statefulsets, nil
}

func (f *fakeClient) ListDaemonSets(context.Context) (ListResult[WorkloadObject], error) {
	return f.daemonsets, nil
}

func (f *fakeClient) ListJobs(context.Context) (ListResult[WorkloadObject], error) {
	return f.jobs, nil
}

func (f *fakeClient) ListCronJobs(context.Context) (ListResult[WorkloadObject], error) {
	return f.cronjobs, nil
}

func (f *fakeClient) ListServices(context.Context) (ListResult[ServiceObject], error) {
	return f.services, nil
}

func (f *fakeClient) ListIngresses(context.Context) (ListResult[IngressObject], error) {
	return f.ingresses, nil
}

func (f *fakeClient) ListServiceAccounts(context.Context) (ListResult[ServiceAccountObject], error) {
	return f.serviceAccounts, nil
}

func (f *fakeClient) ListRoles(context.Context) (ListResult[RBACRoleObject], error) {
	return f.roles, nil
}

func (f *fakeClient) ListClusterRoles(context.Context) (ListResult[RBACRoleObject], error) {
	return f.clusterRoles, nil
}

func (f *fakeClient) ListRoleBindings(context.Context) (ListResult[RBACBindingObject], error) {
	return f.roleBindings, nil
}

func (f *fakeClient) ListClusterRoleBindings(context.Context) (ListResult[RBACBindingObject], error) {
	return f.clusterRoleBindings, nil
}

func factoryFor(client Client) ClientFactory {
	return ClientFactoryFunc(func(context.Context, ClusterTarget) (Client, error) {
		return client, nil
	})
}

var proofObservedAt = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func boolPtr(value bool) *bool { return &value }

// proofSource rebuilds the exact source the fixture pack was cut from: same
// targets, same fake evidence, same fixed clock, so scope IDs, generation
// IDs, and stable keys reproduce deterministically.
func proofSource() *Source {
	full := &fakeClient{
		namespaces: ListResult[ObjectMeta]{Items: []ObjectMeta{{
			Version: "v1", Resource: "namespaces",
			Name: "payments", UID: "uid-ns-payments",
			Labels: map[string]string{"environment": "staging"},
		}}},
		deployments: ListResult[WorkloadObject]{Items: []WorkloadObject{{
			Meta: ObjectMeta{
				APIGroup: "apps", Version: "v1", Resource: "deployments",
				Namespace: "payments", Name: "checkout", UID: "uid-deploy-full",
				Labels: map[string]string{"app": "checkout"},
			},
			ServiceAccount: "checkout-sa",
			Selector:       map[string]string{"app": "checkout"},
			Containers: []ContainerSummary{{
				Name: "app", Image: "ghcr.io/parity/checkout:1.2.3",
				Ports: []int32{8080}, EnvKeys: []string{"PORT", "DB_PASSWORD"},
			}},
		}}},
		replicasets: ListResult[WorkloadObject]{Items: []WorkloadObject{{
			Meta: ObjectMeta{
				APIGroup: "apps", Version: "v1", Resource: "replicasets",
				Namespace: "payments", Name: "checkout-rs", UID: "uid-rs-full",
				OwnerReferences: []OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "checkout", UID: "uid-deploy-full"}},
			},
			Containers: []ContainerSummary{{Name: "app", Image: "ghcr.io/parity/checkout:1.2.3"}},
		}}},
		statefulsets: ListResult[WorkloadObject]{Items: []WorkloadObject{{
			Meta: ObjectMeta{
				APIGroup: "apps", Version: "v1", Resource: "statefulsets",
				Namespace: "payments", Name: "checkout-db", UID: "uid-ss-full",
			},
			Containers: []ContainerSummary{{Name: "db", Image: "ghcr.io/parity/db:4.5.6"}},
		}}},
		pods: ListResult[WorkloadObject]{Items: []WorkloadObject{{
			Meta: ObjectMeta{
				Version: "v1", Resource: "pods",
				Namespace: "payments", Name: "checkout-pod", UID: "uid-pod-full",
				Labels:          map[string]string{"app": "checkout"},
				OwnerReferences: []OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "checkout-rs", UID: "uid-rs-full"}},
			},
			ServiceAccount: "checkout-sa",
			Containers: []ContainerSummary{{
				Name: "app", Image: "ghcr.io/parity/checkout:1.2.3",
				ResolvedImageDigest: "ghcr.io/parity/checkout@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			}},
		}}},
		services: ListResult[ServiceObject]{Items: []ServiceObject{{
			Meta: ObjectMeta{
				Version: "v1", Resource: "services",
				Namespace: "payments", Name: "checkout-svc", UID: "uid-svc-full",
			},
			Selector: map[string]string{"app": "checkout"},
		}}},
		// No ingresses: the ingress group (networking.k8s.io) is not a
		// documented safe host form, so the recorder's private-data belt
		// refuses a cassette containing it.
		serviceAccounts: ListResult[ServiceAccountObject]{Items: []ServiceAccountObject{{
			Meta: ObjectMeta{
				Version: "v1", Resource: "serviceaccounts",
				Namespace: "payments", Name: "checkout-sa", UID: "uid-sa-full",
			},
			AnnotationKeys:              []string{"eks.amazonaws.com/role-arn"},
			IRSAAnnotation:              "arn:aws:iam::123456789012:role/parity-role",
			GCPServiceAccountAnnotation: "parity-sa@parity-project.iam.gserviceaccount.com",
			AutomountToken:              boolPtr(true),
			SecretRefCount:              1,
		}}},
		// No roles, cluster roles, or bindings: the RBAC group
		// (rbac.authorization.k8s.io) is not a documented safe host form, so
		// the recorder's private-data belt refuses a cassette containing it.
	}

	hostile := &fakeClient{
		namespaces: ListResult[ObjectMeta]{Items: []ObjectMeta{{
			Version: "v1", Resource: "namespaces",
			Name: "default", UID: "uid-ns-default",
		}}},
		// Forbidden deployment list: the snapshot stays partial and carries
		// the in-band warning evidence instead of failing.
		deployments: ListResult[WorkloadObject]{Partial: true, Reason: WarningForbiddenResource},
		pods: ListResult[WorkloadObject]{Items: []WorkloadObject{{
			Meta: ObjectMeta{
				Version: "v1", Resource: "pods",
				Namespace: "default", Name: "orphan", UID: "uid-orphan",
				// The owner is outside the collected set: ambiguity evidence,
				// never an invented identity.
				OwnerReferences: []OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "gone", UID: "uid-gone"}},
			},
			// Env var NAMES only; the model has no field for values, so a
			// hostile name still cannot leak a value.
			Containers: []ContainerSummary{{Name: "app", Image: "ghcr.io/parity/orphan:0.0.1", EnvKeys: []string{"DB_PASSWORD"}}},
		}}},
	}

	clients := map[string]*fakeClient{
		"parity-full":    full,
		"parity-hostile": hostile,
	}
	return &Source{
		Config: Config{
			CollectorInstanceID: "k8s-parity-8859",
			Clusters: []ClusterTarget{
				{
					ClusterID:       "parity-full",
					Provider:        "eks",
					GCPWorkloadPool: "parity-project.svc.id.goog",
					Environment:     "staging",
					FencingToken:    7,
					SourceURI:       "https://api.parity-full.example.test:6443",
				},
				{
					ClusterID:    "parity-hostile",
					FencingToken: 9,
					// Credential-bearing URI: userinfo and secret query keys
					// must be sanitized before emission.
					SourceURI: "https://svc:HOSTILESECRET@api.parity-hostile.example.test/cluster?token=HOSTILETOKEN&region=us-east-1",
				},
			},
		},
		ClientFactory: ClientFactoryFunc(func(_ context.Context, target ClusterTarget) (Client, error) {
			client, ok := clients[target.ClusterID]
			if !ok {
				return nil, context.DeadlineExceeded
			}
			return client, nil
		}),
		Clock: func() time.Time { return proofObservedAt },
	}
}
