package plugin

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	policy := NewModelPolicy([]string{"claude-approved"})
	if got := policy.Evaluate(context.Background(), Request{Route: "messages", Model: "claude-other"}); got.Action != Reject {
		t.Fatalf("disallowed model accepted: %+v", got)
	}
	if got := policy.Evaluate(context.Background(), Request{Route: "messages", Model: "claude-approved"}); got.Action != Allow {
		t.Fatalf("approved model rejected: %+v", got)
	}
}

func TestBudgetReservationsAreAtomic(t *testing.T) {
	policy := NewBudgetPolicy(time.Hour, 0, 100)
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
	if allowed.Load() != 10 {
		t.Fatalf("allowed %d reservations, want 10", allowed.Load())
	}
}
