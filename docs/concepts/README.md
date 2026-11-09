# Concepts

Give this collector one Kubernetes cluster and it lists the
cluster's metadata, workload pod shapes, service accounts, RBAC,
namespaces, nothing more, and hands Eshu facts about what it
found. The host validates and commits. The collector never changes
the cluster and stores nothing itself.

Words to know. A *fact* is one small, typed piece of evidence.
A *claim* is one bounded request to collect one cluster. The
*host* is the Eshu process that starts this collector, sends it a
claim, and stores the result. Evidence here is metadata only:
names, shapes, and links, never secret values or config payloads.

## When to use it

Use it when Eshu needs current evidence about one Kubernetes
cluster: workloads and their pod shapes, namespaces, service
accounts, RBAC roles and bindings, and cloud identity links such
as EKS IRSA, EKS Pod Identity, and GKE Workload Identity.

## When not to use it

- Don't use it to change a cluster. It only lists objects.
- Don't use it to read Secret or ConfigMap contents.
  Those payloads are excluded by design.
- Don't use one activation for many clusters.
  One target covers one cluster; a claim whose scope matches no
  target is rejected instead of scanning the wrong cluster.
- Don't use cassette replay to prove live access.
  Replay needs no credentials and proves only the recorded shape.

## What you get

The full fact table lives in [Facts](../reference/facts.md), which
mirrors `spec.emittedFacts` in [manifest.yaml](../../manifest.yaml).

RBAC is Kubernetes role-based access control: rules that say who
may do what. IRSA is IAM Roles for Service Accounts, the EKS
feature that gives a pod an AWS identity.

The collector never emits Secret values, ConfigMap data payloads,
or environment variable values. `containers.env_from_secret` in a
pod template is only a yes/no flag that a container references
secret-backed environment; it never carries a value.

## Boundaries: what this never does

- It never writes to the Eshu graph, Postgres, or any queue.
  The host validates the result and owns claims and commits.
- It never creates, updates, or deletes a Kubernetes object.
- It never emits Secret values, ConfigMap data, or env var values.
- It never puts a credential in config, facts, logs, or statuses.

For the flow behind these boundaries, see
[Architecture](../architecture/README.md) and
[Diagrams](../diagrams/README.md).
