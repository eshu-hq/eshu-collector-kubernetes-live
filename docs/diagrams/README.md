# Diagrams

Every diagram for this collector lives on this page, each with a
caption and a plain-text version so nothing depends on rendering.
Other pages link here instead of copying a diagram. (The repo
[README](../../README.md) keeps the first one as its overview.)

## 1. Where it sits

*Caption: source data flows into this collector, then to the Eshu
host process, then to Eshu core. The collector itself stores
nothing.*

```mermaid
flowchart LR
    K[Kubernetes API, or a cassette file] --> C[This collector]
    C --> H[Eshu host process]
    H --> E[Eshu core]
```

Text version: Kubernetes API (or a recorded cassette file) -> this
collector -> Eshu host process -> Eshu core. A cassette is a
recorded cluster snapshot the collector can replay with no cluster
and no credentials, handy for tests.

## 2. One claim, start to finish

*Caption: one process invocation serves exactly one claim. The host
writes the request, the collector reads the claimed scope, facts
come back on stdout, and the host validates and commits.*

```mermaid
sequenceDiagram
    participant H as Eshu host process
    participant C as This collector
    participant K as Kubernetes API (or cassette file)
    participant E as Eshu core
    H->>C: one claim on stdin (--sdk-stdio)
    C->>K: list the read-only resource set for the cluster
    K-->>C: object metadata
    C-->>H: one result with facts on stdout
    H->>E: validate and commit the facts
```

Text version: the host writes one `collector-sdk/v1alpha1` request to
stdin, the collector lists the read-only resource set for the one
claimed cluster and builds facts, then writes one result to
stdout. The host validates and commits.

## 3. When something goes wrong

*Caption: the failure paths. Bounded, fail-closed outcomes are
preferred over late, oversized, or silently incomplete evidence;
partial reads say so instead of pretending.*

```mermaid
flowchart TD
    S[Claim arrives] --> T{Claim scope matches a configured target?}
    T -- no --> X[Rejected: never scan the wrong cluster]
    T -- yes --> L[List the read-only resource set]
    L --> D{Done before the deadline?}
    D -- no --> E1[Retryable claim_deadline_exceeded, no facts]
    D -- yes --> B{Result within byte budget?}
    B -- no --> E2[Terminal result_budget_exceeded]
    B -- yes --> O[Return facts on stdout]
```

Text version: a claim whose scope matches no target is rejected
instead of scanning the wrong cluster. The collector stops
starting work just before the deadline and returns retryable
`claim_deadline_exceeded` with no facts. A result over budget
fails terminal with `result_budget_exceeded` instead of letting
the host drop an oversized result. A cluster that can't be reached
reports retryable `collection_failed`, never a silent empty
result.
