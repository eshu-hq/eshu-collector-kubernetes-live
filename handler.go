// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	corecollector "github.com/eshu-hq/eshu-collector-kubernetes-live/collector"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// Handler runs one claim. The zero value is usable: it reads the wall clock
// and the activation config carries the cluster target, so no environment
// lookup happens on the config path (cluster auth stays behind the client
// factory seam). The client factory has no default: without a live cluster
// backend the handler reports terminal collection_failed, never
// invalid_config, so a request that reaches that class proves the host
// envelope decoded and the scope matched. The binary wires
// clientgo.DefaultFactory as the live backend; a directly built Handler
// keeps the terminal guard until a factory is set.
type Handler struct {
	// Now supplies the clock; nil selects time.Now.
	Now func() time.Time
	// ClientFactory builds read-only cluster clients; nil reports terminal
	// collection_failed. Tests inject fakes here.
	ClientFactory corecollector.ClientFactory
	// Log receives one bounded JSON diagnostic line per claim; nil discards
	// it. The binary points it at stderr, which the extension host's process
	// runner does not surface (it keeps only a byte count), so the line helps
	// a local run and a test, not an operator in production.
	Log io.Writer
	// Limits bounds one claim's emission; the zero value selects defaults.
	Limits ResourceUse
}

func (h Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h Handler) limits() ResourceUse {
	return h.Limits.withDefaults()
}

// Handle collects the cluster named by the claim and returns the SDK result
// the host validates and commits. It never returns facts together with a
// failure state, never lets a credential into a result, and echoes the claim
// unchanged so the host's identity check passes. A host cancellation returns
// an error instead of a result so nothing commits for a dead claim.
func (h Handler) Handle(ctx context.Context, request Request) (sdk.Result, error) {
	started := h.now()
	claim := request.Claim
	target, configLimits, err := resolveTarget(request.Config, claim.Scope.ID)
	if err != nil {
		h.logConfigFailure(claim, err)
		return budgetResult(claim, started, FailureInvalidConfig), nil
	}
	// The activation's limits win where set; the handler value fills the
	// gaps, then the built-in defaults.
	limits := configLimits.overlay(h.limits())
	token, err := fencingToken(claim.FencingToken)
	if err != nil {
		h.logConfigFailure(claim, err)
		return budgetResult(claim, started, FailureInvalidConfig), nil
	}
	if token == 0 {
		token = target.FencingToken
	}
	// The snapshot stamps the target fencing token; the claim token wins when
	// the activation left the target at zero.
	target.FencingToken = token
	runCtx, cancel, ok := claimContext(ctx, claim, started, limits)
	defer cancel()
	if !ok {
		h.logFailure(claim, FailureClaimDeadline)
		return failureResult(claim, started, Failure{Class: FailureClaimDeadline}, 0), nil
	}
	if h.ClientFactory == nil {
		h.logFailure(claim, FailureCollection)
		return failureResult(claim, started, Failure{Class: FailureCollection, Terminal: true}, 0), nil
	}
	source := corecollector.Source{
		Config: corecollector.Config{
			CollectorInstanceID: claim.InstanceID,
			Clusters:            []corecollector.ClusterTarget{target},
		},
		ClientFactory: h.ClientFactory,
		Clock:         h.Now,
	}
	collected, matched, err := source.Next(runCtx)
	if err != nil || stoppedAtClaimDeadline(runCtx) {
		if runCtx.Err() != nil && !stoppedAtClaimDeadline(runCtx) && ctx.Err() != nil {
			return sdk.Result{}, ctx.Err()
		}
		failure := Failure{Class: FailureCollection}
		if stoppedAtClaimDeadline(runCtx) {
			failure = Failure{Class: FailureClaimDeadline}
		}
		latency := h.now().Sub(started)
		h.logFailure(claim, failure.Class)
		return failureResult(claim, started, failure, latency), nil
	}
	if !matched {
		h.logConfigFailure(claim, fmt.Errorf("source drained without yielding the claimed cluster"))
		return budgetResult(claim, started, FailureInvalidConfig), nil
	}
	return h.completeResult(claim, collected, started, limits), nil
}

func (h Handler) completeResult(claim sdk.Claim, collected corecollector.CollectedSnapshot, started time.Time, limits ResourceUse) sdk.Result {
	result, err := corecollector.ToSDKResult(claim, collected)
	if err != nil {
		h.logConfigFailure(claim, err)
		return budgetResult(claim, started, FailureInvalidConfig)
	}
	// The claim owns the generation at the satellite boundary: the host
	// plans the claim before the scan, so the result echoes the claim
	// generation on itself and on every fact ref (the SDK validator
	// requires both). The snapshot's internal generation
	// (cluster+observedAt) is the evidence timestamp, kept as ObservedAt.
	// Stable keys are unaffected: they derive from object identity, never
	// the generation.
	result.Generation.ID = claim.GenerationID
	for i := range result.Facts {
		result.Facts[i].SourceRef.GenerationID = claim.GenerationID
	}
	facts := result.Facts
	if class := checkBudgets(facts, limits); class != "" {
		h.logFailure(claim, class)
		return budgetResult(claim, started, class)
	}
	latency := h.now().Sub(started)
	if collected.Partial {
		result.State = sdk.ResultPartial
		result.Statuses = []sdk.Status{{
			Class: sdk.StatusWarning, Partial: true,
			WarningCount: countWarnings(collected.Envelopes), FactCount: len(facts),
		}}
	} else {
		result.Statuses = []sdk.Status{{
			Class: sdk.StatusComplete, FactCount: len(facts),
			SourceLatencyMS: latencyMillis(latency),
		}}
	}
	if encoded, err := json.Marshal(result); err != nil || len(encoded) > limits.MaxResultBytes {
		h.logFailure(claim, FailureResultBudget)
		return budgetResult(claim, started, FailureResultBudget)
	}
	h.logSuccess(claim, result)
	return result
}

// checkBudgets returns the failure class of the first exhausted bound, or "".
func checkBudgets(facts []sdk.Fact, limits ResourceUse) string {
	if len(facts) > limits.MaxRecordsPerClaim {
		return FailureRecordBudget
	}
	for _, fact := range facts {
		encoded, err := json.Marshal(fact.Payload)
		if err != nil || len(encoded) > limits.MaxPayloadBytes {
			return FailurePayloadBudget
		}
	}
	return ""
}

// countWarnings counts warning facts in one snapshot for the partial status.
func countWarnings(envelopes []corecollector.Envelope) int {
	warnings := 0
	for _, envelope := range envelopes {
		if envelope.FactKind == FactKindWarning {
			warnings++
		}
	}
	return warnings
}

// logLine is the bounded diagnostic record written to stderr. Every field is
// a counter or a fixed-vocabulary token; none carries a URL, a body, or a
// secret.
type logLine struct {
	Event        string `json:"event"`
	Outcome      string `json:"outcome"`
	ScopeID      string `json:"scope_id"`
	GenerationID string `json:"generation_id"`
	WorkItemID   string `json:"work_item_id"`
	Attempt      int    `json:"attempt"`
	FailureClass string `json:"failure_class,omitempty"`
	Detail       string `json:"detail,omitempty"`
	Facts        int    `json:"facts,omitempty"`
}

func (h Handler) logFailure(claim sdk.Claim, class string) {
	h.emit(logLine{
		Event: "kubernetes_live.claim", Outcome: "failure", ScopeID: claim.Scope.ID, GenerationID: claim.GenerationID,
		WorkItemID: claim.WorkItemID, Attempt: claim.Attempt, FailureClass: class,
	})
}

func (h Handler) logConfigFailure(claim sdk.Claim, err error) {
	h.emit(logLine{
		Event: "kubernetes_live.claim", Outcome: "failure", ScopeID: claim.Scope.ID, GenerationID: claim.GenerationID,
		WorkItemID: claim.WorkItemID, Attempt: claim.Attempt, FailureClass: FailureInvalidConfig,
		Detail: err.Error(),
	})
}

func (h Handler) logSuccess(claim sdk.Claim, result sdk.Result) {
	h.emit(logLine{
		Event: "kubernetes_live.claim", Outcome: string(result.State), ScopeID: claim.Scope.ID, GenerationID: claim.GenerationID,
		WorkItemID: claim.WorkItemID, Attempt: claim.Attempt, Facts: len(result.Facts),
	})
}

func (h Handler) emit(line logLine) {
	if h.Log == nil {
		return
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(h.Log, "%s\n", strings.TrimSpace(string(encoded)))
}
