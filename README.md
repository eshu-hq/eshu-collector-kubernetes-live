# eshu-collector-kubernetes-live

Eshu kubernetes live collector, extracted from the Eshu core repository.

**Pre-release. Holds no producer authority until its reviewed cutover
(eshu-hq/eshu#8859).**

Extraction tracking: [eshu-hq/eshu#8859](https://github.com/eshu-hq/eshu/issues/8859).
The in-tree extraction census, producer-grant draft, and parity proofs live
in the core repository until the cutover rehearsal lands them here.

## Extracted-path proof (`collector/`)

This branch ports the in-tree emission core onto the published SDK contracts
and proves byte-exact emission against the fixture pack the in-tree parity pin
was cut from (`collector/testdata/8859-parity-kubernetes-live.json`, copied
verbatim from core):

```go
require (
	github.com/eshu-hq/eshu-sdk/collector v0.1.0-rc.2
	github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.2
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
conformance for `kubernetes_live.*` facts, pack-schema conformance for all 10
emitted kinds, and ported unit tests with verbatim in-tree expectations for
the paths the fixture pack cannot carry (RBAC, ingress edges, pool gating,
canaries).

What stays open for cutover (not this proof): the client-go adapter port
(needs a live backend), claim-driven collection (mapped, not pinned), grant
enforcement (fails closed per the grant draft), per-target `source_uri`
configuration (the SDK requires a non-empty wire URI), the posture SourceURI
shared-seam fix (owned by the secrets-IAM lane; the boundary sanitizes),
the SDK payload-key allowlist handoff below, release artifact, and rehearsed
rollback.

SDK handoff: the published collector's fail-closed payload-key heuristic
rejects legacy posture field names that are provably not credentials
(`secret_ref_count`, `image_pull_secret_ref_count`, `automount_token`,
`projected_service_account_token` — integer counts and closed-enum strings
the cutover contract pins byte-exact). Tracked on
[eshu-hq/eshu#8851](https://github.com/eshu-hq/eshu/issues/8851) as a
`redactionSafePayloadKeys` allowlist request; the posture half of the proof
runs schema-only until the SDK release carries it.
