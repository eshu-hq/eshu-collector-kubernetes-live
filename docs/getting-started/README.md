# Getting started

Hi! In about a minute you can watch this collector turn
live Kubernetes cluster metadata, or a recorded cassette file into facts for Eshu. It only collects and
returns evidence; the Eshu host validates the result and stores it.
Nothing is stored (or changed) here.

## Run it once

```bash
go build -o /tmp/collector ./cmd/collector
echo "$REQUEST" | /tmp/collector --sdk-stdio
```

No cluster handy? Cassette replay serves a recorded snapshot with no credentials; see [Configuration](../reference/configuration.md). Replay proves only the recorded shape, never live access.

## What just happened?

The host runs one *claim* (one bounded request to collect one scope)
per process invocation: one `collector-sdk/v1alpha1` request on
stdin, one result full of typed *facts* on stdout. Eshu can then
answer what is running where and which identities those workloads use. The picture and the step-by-step flow live
in [Diagrams](../diagrams/README.md) and
[Architecture](../architecture/README.md).

## Where next?

- Every knob: [Configuration](../reference/configuration.md)
- What comes out: [Facts](../reference/facts.md)
- Day-2 work: [Guides](../guides/README.md)
- New words and boundaries: [Concepts](../concepts/README.md)
