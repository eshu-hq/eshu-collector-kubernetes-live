# Architecture

Short version: the Eshu host hands this collector one bounded scope,
the collector reads it and hands typed facts back, and the host
validates and commits them to Eshu core. This collector stores
nothing itself. All diagrams live in
[Diagrams](../diagrams/README.md); this page is the words.

## Where it sits

Kubernetes API (or a recorded cassette file) -> this
collector -> Eshu host process -> Eshu core. A cassette is a
recorded cluster snapshot the collector can replay with no cluster
and no credentials, handy for tests.

Overview diagram: [Where it sits](../diagrams/README.md#1-where-it-sits).

## One claim, start to finish

Cluster access resolves in a fixed order: an explicit `KUBECONFIG`
file wins, otherwise the in-cluster service account. When neither
exists, the claim returns a bounded retryable error rather than
guessing.

Sequence diagram:
[One claim, start to finish](../diagrams/README.md#2-one-claim-start-to-finish).

## When something goes wrong

a claim whose scope matches no target is rejected
instead of scanning the wrong cluster. The collector stops
starting work just before the deadline and returns retryable
`claim_deadline_exceeded` with no facts. A result over budget
fails terminal with `result_budget_exceeded` instead of letting
the host drop an oversized result. A cluster that can't be reached
reports retryable `collection_failed`, never a silent empty
result.

Failure-flow diagram:
[When something goes wrong](../diagrams/README.md#3-when-something-goes-wrong).

## Trust boundary

- It never writes to the Eshu graph, Postgres, or any queue.
  The host validates the result and owns claims and commits.
- It never creates, updates, or deletes a Kubernetes object.
- It never emits Secret values, ConfigMap data, or env var values.
- It never puts a credential in config, facts, logs, or statuses.
