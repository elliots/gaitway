package plugin

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type ModelPolicy struct {
	allowed         map[string]struct{}
	blockedFamilies []string
}

func NewModelPolicy(models, blockedFamilies []string) *ModelPolicy {
	allowed := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model = strings.TrimSpace(model); model != "" {
			allowed[model] = struct{}{}
		}
	}
	blocked := make([]string, 0, len(blockedFamilies))
	for _, family := range blockedFamilies {
		if family = strings.ToLower(strings.TrimSpace(family)); family != "" {
			blocked = append(blocked, family)
		}
	}
	return &ModelPolicy{allowed: allowed, blockedFamilies: blocked}
}

func (*ModelPolicy) Name() string    { return "approved-models" }
func (*ModelPolicy) Validate() error { return nil }

func (p *ModelPolicy) Evaluate(_ context.Context, request Request) Decision {
	if request.Route != "messages" {
		return Decision{Action: Allow}
	}
	model := strings.ToLower(request.Model)
	for _, family := range p.blockedFamilies {
		if strings.Contains(model, family) {
			return Decision{
				Action:   Reject,
				Status:   403,
				Code:     "model_not_approved",
				Message:  fmt.Sprintf("requested Claude model family is blocked: %s", family),
				Findings: []Finding{{Plugin: p.Name(), Rule: "blocked-family", Message: "requested model rejected"}},
			}
		}
	}
	if len(p.allowed) == 0 {
		return Decision{Action: Allow}
	}
	if _, ok := p.allowed[request.Model]; ok {
		return Decision{Action: Allow}
	}
	models := make([]string, 0, len(p.allowed))
	for model := range p.allowed {
		models = append(models, model)
	}
	sort.Strings(models)
	return Decision{
		Action:   Reject,
		Status:   403,
		Code:     "model_not_approved",
		Message:  fmt.Sprintf("requested Claude model is not approved; allowed: %s", strings.Join(models, ", ")),
		Findings: []Finding{{Plugin: p.Name(), Rule: "allowlist", Message: "requested model rejected"}},
	}
}

var errInvalidAction = fmt.Errorf("action must be allow or reject")
