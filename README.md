# eshu-collector-kubernetes-live

Eshu kubernetes live collector, extracted from the Eshu core repository.

**Pre-release. Holds no producer authority until its reviewed cutover
(eshu-hq/eshu#8859).**

Extraction tracking: [eshu-hq/eshu#8859](https://github.com/eshu-hq/eshu/issues/8859).
The in-tree extraction census, producer-grant draft, and parity proofs live
in the core repository until the cutover rehearsal lands them here.

## Serving shim (v0.1.0)

The root `collector` package (shim) serves one claim per process through the
Eshu component-extension host process runner:

```bash
go build -o /tmp/collector ./cmd/collector
echo "$REQUEST" | /tmp/collector --sdk-stdio   # one request in, one result out
/tmp/collector seed --dest /component          # install binary + manifest
```

`collector seed --dest DIR [--image-ref REF@sha256:<digest>]` writes
`DIR/collector` (this binary, mode 0755) and `DIR/manifest.yaml` (the embedded
manifest, mode 0644). `--image-ref`, or `COLLECTOR_IMAGE_REF` when the flag is
absent, stamps the digest-pinned image the operator deployed into the
manifest's artifact entry. The Dockerfile installs the binary at
`/usr/local/bin/collector`, which is the path the IaC seed step calls:
`ENTRYPOINT ["/usr/local/bin/collector"]`, `CMD ["--sdk-stdio"]`.

The component-extension host forwards the activation config subtree verbatim
as the SDK request `Config`, so a request may carry the standard host envelope
next to the targets: `{"targets":[...], "limits":{...},
"host_github_app_token":{...}}`. The shim maps the top-level `limits` object
in `snake_case` or `camelCase` (`claimTimeoutSeconds`, `maxPayloadBytes`,
`maxRecordsPerClaim`, `maxResultBytes`) onto the claim budgets — a target's
own bounds win where set, the envelope fills the gaps, then the handler
bounds, then the built-in defaults — and accepts and ignores `host_*` keys
(the host-minted per-claim credentials this satellite never reads). Any other
top-level key still fails closed without naming the key.

Config contract: every target needs a `cluster_id` (the durable scope anchor;
`ClusterScopeID` derives the scope id from it alone) and a `source_uri` (the
host validator requires one on every fact). A scan that cannot reach a cluster
reports terminal `collection_failed`, never `invalid_config`: reaching that
class proves the envelope decoded and the scope matched. The v0.1.0 image
ships no live cluster backend (the client-go adapter port needs a live
backend); `Handler.ClientFactory == nil` reports terminal `collection_failed`
so the missing backend is explicit, not a silent empty result.

`manifest.yaml` (`metadata.version: 0.1.0`) declares all 13 emitted kinds
with their schema versions and the placeholder artifact digest; deployments
stamp the pulled digest with `collector seed --image-ref`. `config.example.yaml`
is the cutover-shaped activation; `grant.example.json` is the producer-grant
request an operator submits (one grant per declared kind, bound to this
producer and version). Releasing: push a `v*` tag matching
`manifest.yaml metadata.version` and `.github/workflows/release.yml` builds,
signs, and attests the image.

## Extracted-path proof (`collector/`)

This branch ports the in-tree emission core onto the published SDK contracts
and proves byte-exact emission against the fixture pack the in-tree parity pin
was cut from (`collector/testdata/8859-parity-kubernetes-live.json`, copied
verbatim from core):

```go
require (
	github.com/eshu-hq/eshu-sdk/collector v0.1.0-rc.3
	github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.6
)
```

No `replace` directives, no core imports. Run the proof:

```bash
go build ./...
go vet ./...
go test ./... -count=1
```

What is proven: scope/kind/stable-key/attribute/payload parity per scope,
duplicate-delivery stability, hostile inputs (partial freshness, in-band
warnings, URI sanitization), the SDK Result boundary (state mapping, 1:1 fact
mapping, fencing round-trip, credential-free wire URIs), full-harness
conformance for `kubernetes_live.*` facts except `pod_template`
(schema-only, see the SDK handoff below), full-harness conformance for the
three declared kinds the fixture pack does not span (`k8s_rbac_role`,
`k8s_rbac_binding`, `eks_pod_identity_association`, via synthetic fixtures),
pack-schema conformance for all 13 emitted kinds, and ported unit tests with
verbatim in-tree expectations for the paths the fixture pack cannot carry
(RBAC, ingress edges, pool gating, canaries).

What stays open for cutover (not this proof): the client-go adapter port
(needs a live backend), claim-driven collection (mapped, not pinned), grant
enforcement (fails closed per the grant draft), per-target `source_uri`
configuration (the SDK requires a non-empty wire URI), the posture SourceURI
shared-seam fix (owned by the secrets-IAM lane; the boundary sanitizes),
the SDK payload-key allowlist handoff below, release artifact, and rehearsed
rollback.

SDK handoff: the published collector's fail-closed payload-key heuristic
rejects legacy field names that are provably not credentials. For posture:
`secret_ref_count`, `image_pull_secret_ref_count`, `automount_token`,
`projected_service_account_token` (integer counts and closed-enum strings
the cutover contract pins byte-exact). For `kubernetes_live.pod_template`:
`containers.env_from_secret`, a boolean that records only whether a
container references secret-backed env (`collector/envelope.go`
`ContainerSummary.EnvFromSecret`) and never carries a value. Renaming either
set would break the byte-pinned cutover contract, so the fix belongs to the
SDK. Tracked on
[eshu-hq/eshu#8851](https://github.com/eshu-hq/eshu/issues/8851) as a
`redactionSafePayloadKeys` allowlist request; the posture half of the proof
runs schema-only until the SDK release carries it, and `pod_template` runs
schema-only (`TestExtractedPodTemplatePayloadsMatchPackSchemas`) with the
full-harness block pinned (`TestExtractedPodTemplateFullHarnessStillBlocked`)
until the same allowlist covers `env_from_secret`. Do not push a `v0.1.0`
tag until the SDK allowlist lands or the owner records a waiver.
