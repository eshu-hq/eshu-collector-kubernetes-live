# Facts

You'll be able to answer what is running where and which
identities those workloads use.

The table below mirrors `spec.emittedFacts` in
[manifest.yaml](../../manifest.yaml); update this table in the same
change as the manifest. That file declares 13 fact kinds with
`reported` confidence (the cluster API reported it).
`kubernetes_live.pod_template` is at schema `1.3.0`; the other
twelve are at `1.0.0`.

| Fact kind | What you get |
|---|---|
| `kubernetes_live.pod_template` | The pod shape a workload asks Kubernetes to run |
| `kubernetes_live.relationship` | One link between two Kubernetes objects |
| `kubernetes_live.warning` | Part of the cluster could not be read fully |
| `kubernetes_live.namespace` | One namespace seen in the cluster |
| `k8s_service_account` | One service account (a workload identity) |
| `k8s_rbac_role` | One RBAC role: a set of allowed actions |
| `k8s_rbac_binding` | One binding of a role to identities |
| `k8s_workload_identity_use` | A workload using a cloud identity |
| `k8s_gcp_workload_identity_binding` | A service account bound to a Google Cloud identity |
| `k8s_service_account_token_posture` | How a service account token is mounted and exposed |
| `eks_irsa_annotation` | An EKS annotation that links a service account to an AWS role |
| `eks_pod_identity_association` | An EKS Pod Identity link for a service account |
| `secrets_iam_coverage_warning` | Secrets or IAM coverage was partial for this scope |

New to the words *fact* and *claim*? [Concepts](../concepts/README.md) defines them in plain language.
