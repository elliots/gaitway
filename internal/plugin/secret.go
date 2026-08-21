package plugin

import (
	"context"
	"regexp"
)

type SecretScanner struct {
	action Action
	rules  []secretRule
}

type secretRule struct {
	name    string
	pattern *regexp.Regexp
}

func NewSecretScanner(action Action) *SecretScanner {
	return &SecretScanner{action: action, rules: []secretRule{
		{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`)},
		{"anthropic_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{16,}`)},
		{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	}}
}

func (*SecretScanner) Name() string { return "secret-scanner" }

func (s *SecretScanner) Validate() error {
	if s.action != Allow && s.action != Reject {
		return errInvalidAction
	}
	return nil
}

func (s *SecretScanner) Evaluate(_ context.Context, request Request) Decision {
	var findings []Finding
	for _, rule := range s.rules {
		for _, match := range rule.pattern.FindAll(request.Body, -1) {
			findings = append(findings, Finding{Plugin: s.Name(), Rule: rule.name, Masked: mask(match), Message: "possible secret detected"})
		}
	}
	if len(findings) == 0 {
		return Decision{Action: Allow}
	}
	if s.action == Reject {
		return Decision{Action: Reject, Status: 422, Code: "secret_detected", Message: "request blocked by secret policy", Findings: findings}
	}
	return Decision{Action: Allow, Findings: findings}
}

func mask(value []byte) string {
	if len(value) <= 8 {
		return "********"
	}
	return string(value[:4]) + "…" + string(value[len(value)-4:])
}
