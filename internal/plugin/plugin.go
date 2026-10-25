package plugin

import (
	"context"
	"fmt"
	"slices"
	"time"
)

type Action string

const (
	Allow  Action = "allow"
	Reject Action = "reject"
	Warn   Action = "warn"
)

type Request struct {
	ID           string
	Principal    string
	Session      string
	Route        string
	Model        string
	Body         []byte
	Now          time.Time
	Acknowledged bool
	// Background marks an invisible Claude Code request, such as session
	// title generation, whose errors are never shown to the user.
	Background bool
}

type UsageReconciler interface {
	Reconcile(principal, requestID string, actual int64, completed bool, now time.Time)
}

type Finding struct {
	Plugin  string `json:"plugin"`
	Rule    string `json:"rule"`
	Masked  string `json:"masked,omitempty"`
	Message string `json:"message"`
}

type Decision struct {
	Action   Action
	Status   int
	Code     string
	Message  string
	Findings []Finding
	// Body replaces the request body for later plugins and upstream; nil
	// leaves it unchanged.
	Body []byte
	// Notices are sentences shown to the user at the start of the response.
	Notices []string
}

type RequestPlugin interface {
	Name() string
	Validate() error
	Evaluate(context.Context, Request) Decision
}

type Engine struct {
	timeout time.Duration
	plugins []RequestPlugin
}

func NewEngine(timeout time.Duration, plugins ...RequestPlugin) (*Engine, error) {
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	for _, item := range plugins {
		if item == nil {
			return nil, fmt.Errorf("nil plugin")
		}
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("plugin %s: %w", item.Name(), err)
		}
	}
	return &Engine{timeout: timeout, plugins: slices.Clone(plugins)}, nil
}

func (e *Engine) Evaluate(ctx context.Context, request Request) Decision {
	combined := Decision{Action: Allow}
	request.Body = slices.Clone(request.Body)
	for _, item := range e.plugins {
		decision := e.evaluateOne(ctx, item, request)
		combined.Findings = append(combined.Findings, decision.Findings...)
		combined.Notices = append(combined.Notices, decision.Notices...)
		if decision.Body != nil {
			request.Body = decision.Body
			combined.Body = decision.Body
		}
		if decision.Action == Reject {
			decision.Findings = combined.Findings
			return decision
		}
		if decision.Action == Warn {
			combined.Action = Warn
			combined.Code = decision.Code
			combined.Message = decision.Message
		}
	}
	return combined
}

func (e *Engine) Reconcile(principal, requestID string, actual int64, completed bool, now time.Time) {
	for _, item := range e.plugins {
		if reconciler, ok := item.(UsageReconciler); ok {
			reconciler.Reconcile(principal, requestID, actual, completed, now)
		}
	}
}

func (e *Engine) evaluateOne(ctx context.Context, item RequestPlugin, request Request) Decision {
	pluginContext, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	type response struct{ decision Decision }
	done := make(chan response, 1)
	go func() {
		result := Decision{}
		func() {
			defer func() {
				if recover() != nil {
					result = Decision{Action: Reject, Status: 500, Code: "plugin_failure", Message: "request policy failed closed"}
				}
			}()
			result = item.Evaluate(pluginContext, request)
		}()
		done <- response{decision: result}
	}()
	select {
	case output := <-done:
		return output.decision
	case <-pluginContext.Done():
		return Decision{Action: Reject, Status: 503, Code: "plugin_timeout", Message: "request policy timed out"}
	}
}
