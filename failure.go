// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"errors"
	"math"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

const (
	// FailureInvalidConfig marks an activation config the collector cannot run.
	FailureInvalidConfig = "invalid_config"
	// FailureClaimDeadline marks a claim whose lease deadline has passed.
	FailureClaimDeadline = "claim_deadline_exceeded"
	// FailureRecordBudget marks a claim past its fact-count bound.
	FailureRecordBudget = "record_budget_exceeded"
	// FailurePayloadBudget marks a fact past its payload-size bound.
	FailurePayloadBudget = "payload_budget_exceeded"
	// FailureResultBudget marks an encoded result past its size bound.
	FailureResultBudget = "result_budget_exceeded"
	// FailureCollection marks a scan that failed after the config was
	// accepted: the cluster was unreachable, the client factory is not
	// configured, or listing failed. Terminal when retrying cannot help,
	// retryable otherwise. It is never invalid_config: a request that reaches
	// this class proves the host envelope decoded and the scope matched.
	FailureCollection = "collection_failed"

	defaultRetryAfterSeconds = 30
)

// Failure describes one bounded claim failure: the class token is a fixed
// vocabulary and never carries URLs, bodies, or credentials.
type Failure struct {
	Class      string
	Terminal   bool
	RetryAfter time.Duration
}

// failureResult builds the SDK result for a failed claim: terminal when
// retrying cannot help, retryable otherwise. Neither carries facts.
func failureResult(claim sdk.Claim, observedAt time.Time, failure Failure, latency time.Duration) sdk.Result {
	state := sdk.ResultRetryable
	status := sdk.Status{
		Class:           sdk.StatusFailure,
		FailureClass:    failure.Class,
		SourceLatencyMS: latencyMillis(latency),
	}
	if failure.Terminal {
		state = sdk.ResultTerminal
	} else {
		status.RetryAfterSeconds = retryAfterSeconds(failure)
	}
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           state,
		Claim:           claim,
		Generation: sdk.Generation{
			ID:         claim.GenerationID,
			ObservedAt: observedAt.UTC(),
		},
		Statuses: []sdk.Status{status},
	}
}

// budgetResult is the bounded terminal shape for exhausted budgets and bad
// configuration: an explicit terminal state with a named class.
func budgetResult(claim sdk.Claim, observedAt time.Time, class string) sdk.Result {
	return failureResult(claim, observedAt, Failure{Class: class, Terminal: true}, 0)
}

func retryAfterSeconds(failure Failure) int {
	if failure.RetryAfter > 0 {
		return int(math.Ceil(failure.RetryAfter.Seconds()))
	}
	return defaultRetryAfterSeconds
}

func latencyMillis(latency time.Duration) int {
	if latency <= 0 {
		return 0
	}
	return int(latency.Milliseconds())
}

// errClaimDeadline is the cancellation cause of a context that ended because
// the claim lease deadline (less its margin) was reached. It tells that stop
// apart from a host cancel and from the configured claim timeout.
var errClaimDeadline = errors.New("claim lease deadline reached")

const (
	maxDeadlineMargin     = 2 * time.Second
	deadlineMarginDivisor = 20
)

// clampedDeadlineTimeout returns how long the collector may work on a claim:
// the time left until deadline minus a safety margin of min(2s, 5% of the time
// left). The host kills the process at the deadline, so the collector stops
// starting provider calls a little earlier and ends with a retryable result
// of its own instead of being killed mid-request.
func clampedDeadlineTimeout(now, deadline time.Time, budget time.Duration) (time.Duration, bool) {
	if deadline.IsZero() {
		return budget, true
	}
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return 0, false
	}
	margin := min(maxDeadlineMargin, remaining/deadlineMarginDivisor)
	if timeout := remaining - margin; timeout < budget {
		return timeout, true
	}
	return budget, true
}

// claimContext bounds the collection by the claim lease deadline (less its
// margin) and the configured claim timeout, whichever is shorter. A context
// that ends at the lease bound carries errClaimDeadline as its cause. ok is
// false when the lease is already spent.
func claimContext(
	ctx context.Context,
	claim sdk.Claim,
	now time.Time,
	limits ResourceUse,
) (context.Context, context.CancelFunc, bool) {
	budget := time.Duration(limits.ClaimTimeoutSeconds) * time.Second
	var cause error
	timeout := budget
	if !claim.Deadline.IsZero() {
		deadline := claim.Deadline.UTC()
		if !deadline.After(now) {
			return ctx, func() {}, false
		}
		var bounded bool
		timeout, bounded = clampedDeadlineTimeout(now, deadline, budget)
		if !bounded {
			return ctx, func() {}, false
		}
		if timeout < budget {
			cause = errClaimDeadline
		}
	}
	runCtx, cancel := context.WithTimeoutCause(ctx, timeout, cause)
	return runCtx, cancel, true
}

// stoppedAtClaimDeadline reports whether ctx ended because the claim lease
// deadline was reached, as opposed to a host cancel or the claim timeout.
func stoppedAtClaimDeadline(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errClaimDeadline)
}
