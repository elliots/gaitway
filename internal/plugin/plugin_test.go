package plugin

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type panicPlugin struct{}

func (panicPlugin) Name() string                               { return "panic" }
func (panicPlugin) Validate() error                            { return nil }
func (panicPlugin) Evaluate(context.Context, Request) Decision { panic("boom") }

func TestSecretScannerRejectsAndMasks(t *testing.T) {
	secret := "AKIA1234567890ABCDEF"
	decision := NewSecretScanner(Reject).Evaluate(context.Background(), Request{Body: []byte("use " + secret)})
	if decision.Action != Reject || len(decision.Findings) != 1 {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if strings.Contains(decision.Findings[0].Masked, secret) || decision.Findings[0].Masked != "AKIA…CDEF" {
		t.Fatalf("unsafe mask: %q", decision.Findings[0].Masked)
	}
}

func TestModelPolicy(t *testing.T) {
	policy := NewModelPolicy([]string{"claude-approved"}, nil)
	if got := policy.Evaluate(context.Background(), Request{Route: "messages", Model: "claude-other"}); got.Action != Reject {
		t.Fatalf("disallowed model accepted: %+v", got)
	}
	if got := policy.Evaluate(context.Background(), Request{Route: "messages", Model: "claude-approved"}); got.Action != Allow {
		t.Fatalf("approved model rejected: %+v", got)
	}
}

func TestModelPolicyBlocksFamily(t *testing.T) {
	policy := NewModelPolicy(nil, []string{"haiku"})
	if got := policy.Evaluate(context.Background(), Request{Route: "messages", Model: "claude-HAIKU-4-5"}); got.Action != Reject || got.Findings[0].Rule != "blocked-family" {
		t.Fatalf("blocked family accepted: %+v", got)
	}
	if got := policy.Evaluate(context.Background(), Request{Route: "messages", Model: "claude-sonnet-5"}); got.Action != Allow {
		t.Fatalf("unblocked family rejected: %+v", got)
	}
}

func TestBudgetAllowsConcurrentRequestsBeforeRecordedLimit(t *testing.T) {
	policy := NewBudgetPolicy(time.Hour, 0, 100, "")
	now := time.Now()
	var allowed atomic.Int32
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			if policy.Evaluate(context.Background(), Request{Principal: "p", Route: "messages", Body: []byte(strings.Repeat("x", 36)), Now: now}).Action == Allow {
				allowed.Add(1)
			}
		}()
	}
	group.Wait()
	if allowed.Load() != 20 {
		t.Fatalf("allowed %d reservations, want 20", allowed.Load())
	}
}

func TestBudgetRejectsRequestAfterRecordedLimit(t *testing.T) {
	policy := NewBudgetPolicy(4*time.Hour, 0, 100, "Company Claude allowance exhausted")
	now := time.Now()
	request := Request{ID: "one", Principal: "p", Route: "messages", Body: []byte("x"), Now: now}
	if got := policy.Evaluate(context.Background(), request); got.Action != Allow {
		t.Fatalf("request before limit rejected: %+v", got)
	}
	policy.Reconcile("p", "one", 101, true, now.Add(2*time.Hour))
	request.ID = "two"
	request.Now = now.Add(2 * time.Hour)
	if got := policy.Evaluate(context.Background(), request); got.Action != Reject || got.Code != "usage_limit" || got.Status != http.StatusPaymentRequired {
		t.Fatalf("request after limit accepted: %+v", got)
	} else if !strings.Contains(got.Message, "Company Claude allowance exhausted: 101/100 tokens used in the 4-hour window; resets in 2 hours") {
		t.Fatalf("limit message is not useful: %q", got.Message)
	}
}

func TestBudgetReconcilesEstimateToProviderUsage(t *testing.T) {
	policy := NewBudgetPolicy(time.Hour, 0, 20, "")
	now := time.Now()
	request := Request{ID: "one", Principal: "p", Route: "messages", Body: []byte(strings.Repeat("x", 36)), Now: now}
	if decision := policy.Evaluate(context.Background(), request); decision.Action != Allow {
		t.Fatalf("initial reservation failed: %+v", decision)
	}
	policy.Reconcile("p", "one", 3, true, now)
	request.ID = "a"
	if decision := policy.Evaluate(context.Background(), request); decision.Action != Allow {
		t.Fatalf("reconciled capacity was not released: %+v", decision)
	}
	policy.Reconcile("p", "a", 0, false, now)
	request.ID = "last"
	if decision := policy.Evaluate(context.Background(), request); decision.Action != Allow {
		t.Fatalf("failed request reservation was not released: %+v", decision)
	}
}

func TestPluginPanicFailsClosed(t *testing.T) {
	engine, _ := NewEngine(time.Second, panicPlugin{})
	decision := engine.Evaluate(context.Background(), Request{})
	if decision.Action != Reject || decision.Code != "plugin_failure" {
		t.Fatalf("plugin panic did not fail closed: %+v", decision)
	}
}

func TestBudgetAcknowledgementLastsForWindow(t *testing.T) {
	policy := NewBudgetPolicy(time.Hour, 1, 1000, "")
	now := time.Now()
	first := Request{ID: "one", Principal: "p", Route: "messages", Body: []byte("x"), Now: now}
	if decision := policy.Evaluate(context.Background(), first); decision.Action != Warn {
		t.Fatalf("warning was not raised: %+v", decision)
	}
	policy.Reconcile("p", "one", 0, false, now)
	first.ID = "two"
	first.Acknowledged = true
	if decision := policy.Evaluate(context.Background(), first); decision.Action != Allow {
		t.Fatalf("acknowledged request was not allowed: %+v", decision)
	}
	policy.Reconcile("p", "two", 0, false, now)
	first.ID = "three"
	first.Acknowledged = false
	if decision := policy.Evaluate(context.Background(), first); decision.Action != Allow {
		t.Fatalf("acknowledgement did not last for window: %+v", decision)
	}
}
