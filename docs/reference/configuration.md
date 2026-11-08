# Configuration

Start from [config.example.yaml](../../config.example.yaml), which
shows both the live and cassette forms. The host forwards the
activation `config` object as the request config, either one
target object or `{"targets":[...]}` matched by claim scope.
Host-minted `host_*` keys are accepted and ignored; any other
unknown top-level key fails closed without naming the key.

| Name | Required | Default | What it does |
|---|---|---|---|
| `host.sourceSystem` | Yes in the example | `kubernetes_live` | Source system recorded on facts |
| `host.scope.kind` | Yes in the example | `cluster` | Host scope kind; its ID derives from `cluster_id` |
| `process.stdout_limit_bytes` | No | Host default `4194304`; example `67108864` | Host cap on result size; raise with `max_result_bytes` |
| `config.cluster_id` | Yes per target | None | Durable cluster identity; part of every fact key, choose once |
| `config.source_uri` | Yes per target | None | Credential-free source address recorded on every fact |
| `config.display_name` | No | Empty | Operator-facing cluster label |
| `config.provider` | No | Empty | Provider label such as `eks`, `gke`, `aks`, or `kind` |
| `config.environment` | No | Empty | Operator-declared environment label |
| `config.gcp_workload_pool` | No | Empty | GKE Workload Identity pool; enables GCP binding facts |
| `config.fencing_token` | No | Claim token wins | Ordering token so a stale run can't replace newer facts |
| `config.cassette_file` | Alternative to targets | None | Recorded snapshot to replay; can't combine with live targets |
| `config.limits.max_records_per_claim` | No | `50000` | Maximum facts in one claim |
| `config.limits.max_payload_bytes` | No | `1048576` | Maximum bytes in one fact payload |
| `config.limits.max_result_bytes` | No | `3145728` | Maximum bytes in the result written to stdout |
| `config.limits.claim_timeout_seconds` | No | `300` | Maximum wall-clock seconds for one claim |

Limits accept `snake_case` or `camelCase` keys; the target's own
values win, then the top-level `limits` object, then the defaults.
Values are clamped to ceilings in code (1,000,000 records, 16 MiB
payload, 256 MiB result, 3,600 seconds).

One correction to an older claim in these docs: config holds no
secrets, but not every value stays out of facts. `cluster_id`
anchors the fact scope and forms part of every fact key, and
`source_uri` is recorded on facts after sanitization (credentials
are stripped first). What never appears in facts, logs, or
statuses is any credential or secret value, because config doesn't
carry one in the first place.

## Credentials and least privilege

Cluster credentials reach the process only from its environment:
the in-cluster service account token, or the file `KUBECONFIG`
points at. No secret travels in activation config, facts, source
URIs, logs, or statuses.

The live backend only lists objects: namespaces, pods, workloads
(Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs,
CronJobs), Services, Ingresses, ServiceAccounts, Roles,
ClusterRoles, RoleBindings, and ClusterRoleBindings. This repo
ships no RBAC manifest, so grant the collector identity only list
access to that read-only set and stop there; it needs no write
verbs and no access to Secret or ConfigMap contents.

## Claim budget

One claim is bounded by the limits above (defaults: 50,000
records, 1,048,576 payload bytes, 3,145,728 result bytes, 300
seconds). The collector stops starting work just before the
deadline and returns retryable `claim_deadline_exceeded` with no
facts. A result over budget fails terminal with
`result_budget_exceeded` instead of letting the host drop an
oversized result. If a big cluster keeps hitting the result
budget, raise `max_result_bytes` together with the host's
`process.stdout_limit_bytes`.

---

Looking for what comes out the other side? See [Facts](facts.md).
Stuck on a value? [Troubleshoot](../guides/troubleshoot.md) covers
the failures people hit most.
