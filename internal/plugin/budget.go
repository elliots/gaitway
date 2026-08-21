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
	started  time.Time
	reserved int64
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
		entry = budgetWindow{started: request.Now}
	}
	if entry.reserved+units > b.hard {
		return Decision{Action: Reject, Status: 429, Code: "usage_limit", Message: "usage hard limit reached", Findings: []Finding{{Plugin: b.Name(), Rule: "hard-cap", Message: "request reservation rejected"}}}
	}
	entry.reserved += units
	b.usage[request.Principal] = entry
	if b.warning > 0 && entry.reserved >= b.warning {
		return Decision{Action: Warn, Code: "usage_warning", Message: "usage warning threshold reached", Findings: []Finding{{Plugin: b.Name(), Rule: "warning", Message: "usage warning threshold reached"}}}
	}
	return Decision{Action: Allow}
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
