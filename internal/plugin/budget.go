package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type BudgetPolicy struct {
	mu      sync.Mutex
	window  time.Duration
	warning int64
	hard    int64
	usage   map[string]budgetWindow
}

type budgetWindow struct {
	started      time.Time
	used         int64
	reserved     int64
	reservations map[string]int64
	acknowledged bool
}

func NewBudgetPolicy(window time.Duration, warning, hard int64) *BudgetPolicy {
	return &BudgetPolicy{window: window, warning: warning, hard: hard, usage: make(map[string]budgetWindow)}
}

func (*BudgetPolicy) Name() string { return "usage-budget" }

func (b *BudgetPolicy) Validate() error {
	if b.hard < 0 || b.warning < 0 || (b.hard > 0 && b.warning > b.hard) || b.window <= 0 {
		return fmt.Errorf("invalid budget window or limits")
	}
	return nil
}

func (b *BudgetPolicy) Evaluate(_ context.Context, request Request) Decision {
	if b.hard == 0 || request.Route != "messages" {
		return Decision{Action: Allow}
	}
	units := estimatedUnits(request.Body)
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.usage[request.Principal]
	if entry.started.IsZero() || request.Now.Sub(entry.started) >= b.window {
		entry = budgetWindow{started: request.Now, reservations: make(map[string]int64)}
	}
	if entry.used+entry.reserved+units > b.hard {
		return Decision{Action: Reject, Status: 429, Code: "usage_limit", Message: "usage hard limit reached", Findings: []Finding{{Plugin: b.Name(), Rule: "hard-cap", Message: "request reservation rejected"}}}
	}
	entry.reserved += units
	if request.Acknowledged {
		entry.acknowledged = true
	}
	if request.ID != "" {
		entry.reservations[request.ID] = units
	}
	b.usage[request.Principal] = entry
	if b.warning > 0 && entry.used+entry.reserved >= b.warning && !entry.acknowledged {
		return Decision{Action: Warn, Code: "usage_warning", Message: "usage warning threshold reached", Findings: []Finding{{Plugin: b.Name(), Rule: "warning", Message: "usage warning threshold reached"}}}
	}
	return Decision{Action: Allow}
}

func (b *BudgetPolicy) Reconcile(principal, requestID string, actual int64, completed bool, now time.Time) {
	if requestID == "" || b.hard == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.usage[principal]
	if !ok || (!entry.started.IsZero() && now.Sub(entry.started) >= b.window) {
		return
	}
	estimate, ok := entry.reservations[requestID]
	if !ok {
		return
	}
	delete(entry.reservations, requestID)
	entry.reserved -= estimate
	if completed && actual > 0 {
		entry.used += actual
	}
	b.usage[principal] = entry
}

func estimatedUnits(body []byte) int64 {
	// This is deliberately conservative until provider-reported usage is
	// reconciled by the durable Postgres budget ledger.
	units := int64(len(body)/4 + 1)
	if units < 1 {
		return 1
	}
	return units
}
