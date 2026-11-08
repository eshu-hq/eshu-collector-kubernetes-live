# Release

```bash
make ci
```

`make ci` runs `make lint`, `make test`, and `make race` (see
[Makefile](../../Makefile)): vet, lint and format checks, module
drift, no `replace` directives, the 500-line file cap, the full
test suite, and the race suite with the coverage floor read from
CI. Proof carried by the test suite includes full-harness
conformance for `kubernetes_live.*` facts including `pod_template`
(`TestExtractedPayloadsPassConformance`), pack-schema conformance
for all 13 emitted kinds, and synthetic-fixture conformance for
`k8s_rbac_role`, `k8s_rbac_binding`, and
`eks_pod_identity_association`.

Releases: push a `v*` tag that matches `metadata.version` in
[manifest.yaml](../../manifest.yaml) on the protected `main` head;
the release workflow builds, signs, and attests the image. A tag
on any other commit fails before anything builds or pushes.

Before tagging, run the local gate from
[Contributing](../contributing/README.md) and re-read
[manifest.yaml](../../manifest.yaml): the manifest version, the
git tag, and the pinned image digest must agree.
