// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// blockingClient stalls PingReadOnly until the claim context ends, so the
// handler's deadline/timeout mapping executes instead of the fast stub path.
type blockingClient struct {
	stubLiveClient
}

func (c *blockingClient) PingReadOnly(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func blockingHandler(limits ResourceUse) Handler {
	return Handler{
		ClientFactory: corecollector.ClientFactoryFunc(func(context.Context, corecollector.ClusterTarget) (corecollector.Client, error) {
			return &blockingClient{}, nil
		}),
		Limits: limits,
	}
}

// TestHandleMapsSpentDeadlineToRetryableClaimDeadline proves an already-spent
// lease deadline never scans: the claim ends retryable
// claim_deadline_exceeded with no facts, so the host re-plans it.
func TestHandleMapsSpentDeadlineToRetryableClaimDeadline(t *testing.T) {
	t.Parallel()

	claim := handlerClaim()
	claim.Deadline = time.Now().Add(-time.Minute).UTC()
	result, err := handlerWith(&stubLiveClient{}).Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v, want a retryable result", err)
	}
	if result.State != sdk.ResultRetryable {
		t.Fatalf("State = %q, want retryable", result.State)
	}
	if len(result.Statuses) != 1 || result.Statuses[0].FailureClass != FailureClaimDeadline {
		t.Fatalf("Statuses = %+v, want one claim_deadline_exceeded", result.Statuses)
	}
	if result.Statuses[0].RetryAfterSeconds <= 0 {
		t.Fatalf("RetryAfterSeconds = %d, want a positive host retry hint", result.Statuses[0].RetryAfterSeconds)
	}
	if len(result.Facts) != 0 {
		t.Fatal("failed result carries facts")
	}
}

// TestHandleReturnsHostCancelAsError proves a host cancellation returns an
// error instead of a result, so nothing commits for a dead claim.
func TestHandleReturnsHostCancelAsError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := blockingHandler(ResourceUse{}).Handle(ctx, Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           handlerClaim(),
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Handle() error = %v, want context.Canceled", err)
	}
}

// TestHandleMapsExhaustedClaimTimeoutToRetryableCollectionFailed proves the
// configured claim timeout bounds a stalled scan: the claim ends retryable
// collection_failed (never invalid_config, never terminal) with no facts.
func TestHandleMapsExhaustedClaimTimeoutToRetryableCollectionFailed(t *testing.T) {
	t.Parallel()

	handler := blockingHandler(ResourceUse{
		MaxRecordsPerClaim:  50_000,
		MaxPayloadBytes:     1 << 20,
		MaxResultBytes:      3 << 20,
		ClaimTimeoutSeconds: 1,
	})
	result, err := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           handlerClaim(),
		Contract:        Contract(),
		Config:          handlerTargetConfig(),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v, want a retryable result", err)
	}
	if result.State != sdk.ResultRetryable {
		t.Fatalf("State = %q, want retryable", result.State)
	}
	if len(result.Statuses) != 1 || result.Statuses[0].FailureClass != FailureCollection {
		t.Fatalf("Statuses = %+v, want one collection_failed", result.Statuses)
	}
	if len(result.Facts) != 0 {
		t.Fatal("failed result carries facts")
	}
}
