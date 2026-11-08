# Operate

## How it gets run

The host runs one claim per process invocation. With no arguments
(or `--sdk-stdio`) the binary reads one `collector-sdk/v1alpha1`
request from stdin and writes one result to stdout. The host
validates the result and owns claims and commits.

Installing it first? See [Seed and install](seed-and-install.md).

## What to watch

Diagnostics go to stderr through the handler log. That's your
first stop when a claim misbehaves. The manifest declares metric
prefix `eshu_dp_kubernetes_live_collector_` as declared only: the
collector emits no metric under this prefix, so don't build
dashboards expecting it yet.

## Dependencies

| Dependency | Version or contract | Where it's pinned |
|---|---|---|
| `github.com/eshu-hq/eshu-sdk/collector` | `v0.1.0-rc.4` | `go.mod` |
| `github.com/eshu-hq/eshu-sdk/factschema` | `v0.1.0-rc.7` | `go.mod` |
| Host protocol | `collector-sdk/v1alpha1`, `process` adapter | [manifest.yaml](../../manifest.yaml) |
| Eshu core compatibility | `>=0.0.5 <0.2.0` | [manifest.yaml](../../manifest.yaml) |
| Producer identity | `dev.eshu.collector.kubernetes-live`, version `0.1.3` | [manifest.yaml](../../manifest.yaml) |

No `replace` directives, no core imports. Producer grants are
issued by Eshu core, not this repo.
[grant.example.json](../../grant.example.json) is the request shape:
one grant per declared kind for this producer and version.
