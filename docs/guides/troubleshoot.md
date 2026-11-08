# Troubleshoot

Start with the symptom you have. Most of these end at a config
value, so keep [Configuration](../reference/configuration.md) open
in another tab.

- Retryable error about cluster access? Neither `KUBECONFIG` nor
  an in-cluster service account was available. Fix the
  environment; the collector won't guess at credentials.
- `claim_deadline_exceeded`, retryable, no facts? The cluster scan
  ran out of its 300-second default. Raise
  `claim_timeout_seconds` (ceiling 3,600) for very large clusters.
- `result_budget_exceeded`, terminal? The result outgrew
  `max_result_bytes`. Raise it together with the host's
  `process.stdout_limit_bytes`, or the host will drop the result
  anyway.
- Claim rejected outright? Its scope matched no configured target.
  One target covers one cluster; add a target instead of reusing
  another cluster's activation.
- Cassette replay passed but live fails? Replay needs no
  credentials and proves only the recorded shape. It says nothing
  about live access.

## Still stuck?

Re-read the failure flow in
[Diagrams](../diagrams/README.md#3-when-something-goes-wrong) and
check which branch your run took. If the result looks complete but
wrong, compare it against [Facts](../reference/facts.md) before
suspecting the source.
