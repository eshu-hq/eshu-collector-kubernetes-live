# Seed and install

The binary is its own installer, so an init container (or you, by
hand) can lay down the component without a shell script.

```bash
go build -o /tmp/collector ./cmd/collector
echo "$REQUEST" | /tmp/collector --sdk-stdio
/tmp/collector seed --dest /component
```

`seed` writes `DIR/collector` (this binary, mode `0755`) and
`DIR/manifest.yaml` (mode `0644`) so an init container can install
the component without a shell. `--image-ref REF@sha256:<digest>`,
or `COLLECTOR_IMAGE_REF` when the flag is absent, stamps the
deployed digest into the seeded manifest; an image can't embed
its own digest, so [manifest.yaml](../../manifest.yaml) in this repo
keeps the all-zero placeholder digest. The image entrypoint is
`/usr/local/bin/collector` with default argument `--sdk-stdio`
(see [Dockerfile](../../Dockerfile)).

Image references stay digest-pinned (`@sha256:...`). After a
release, record the published digest as described in
[Release](release.md), then seed activations from that digest.
First run after install? [Getting started](../getting-started/README.md)
has the one-minute version.
