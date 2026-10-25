package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCardScannerRejectsRealCardAndMasks(t *testing.T) {
	card := "4539 1488 0343 6467"
	decision := NewCardScanner(Reject, DefaultTestCards).Evaluate(context.Background(), Request{Body: []byte(`{"text":"pay with ` + card + ` please"}`)})
	if decision.Action != Reject || decision.Code != "payment_card_detected" || len(decision.Findings) != 1 {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.Findings[0].Masked != "4539…6467" {
		t.Fatalf("unsafe mask: %q", decision.Findings[0].Masked)
	}
}

func TestCardScannerAllowsConfiguredTestCards(t *testing.T) {
	body := []byte(`{"text":"use 4111-1111-1111-1111 or 3782 822463 10005\n5555555555554444"}`)
	if got := NewCardScanner(Reject, DefaultTestCards).Evaluate(context.Background(), Request{Body: body}); got.Action != Allow || len(got.Findings) != 0 {
		t.Fatalf("test cards rejected: %+v", got)
	}
	if got := NewCardScanner(Reject, nil).Evaluate(context.Background(), Request{Body: body}); got.Action != Reject || len(got.Findings) != 3 {
		t.Fatalf("cards accepted without test list: %+v", got)
	}
	if got := NewCardScanner(Reject, []string{"4111 1111 1111 1111"}).Evaluate(context.Background(), Request{Body: []byte("4111111111111111")}); got.Action != Allow {
		t.Fatalf("formatted test card not normalized: %+v", got)
	}
}

func TestCardScannerAllowActionRecordsFindings(t *testing.T) {
	body := []byte("4539148803436467 and again 4539148803436467")
	got := NewCardScanner(Allow, nil).Evaluate(context.Background(), Request{Body: body})
	if got.Action != Allow || len(got.Findings) != 1 {
		t.Fatalf("expected one deduplicated finding: %+v", got)
	}
}

func TestFindCardNumbers(t *testing.T) {
	cases := []struct {
		body string
		want []string
	}{
		{"4539148803436467", []string{"4539148803436467"}},
		{`"\n4539148803436467\t"`, []string{"4539148803436467"}},
		{"card: 4539-1488-0343-6467.", []string{"4539148803436467"}},
		{"4539148803436468", nil},                // fails Luhn
		{"1539148803436461", nil},                // not an issuer prefix
		{"id4539148803436467", nil},              // embedded in word
		{"45391488034364670", nil},               // longer run fails Luhn
		{"0.4539148803436467", nil},              // decimal fraction
		{"4539 1488-0343 6467", nil},             // mixed separators
		{"4 5 3 9 1 4 8 8 0 3 4 3 6 4 6 7", nil}, // single-digit groups
		{"1700000000000 4539148803436467", []string{"4539148803436467"}},
		{"1234 4539148803436467", []string{"4539148803436467"}},
		{"4539 1488 0343 6467 12", []string{"4539148803436467"}},
		{"4539 1488 0343 6467 2024", []string{"4539148803436467"}},       // trailing group
		{"4539 1488 0343 6467 1234567890", []string{"4539148803436467"}}, // trailing number
		{"12 4539 1488 0343 6467", []string{"4539148803436467"}},         // leading short group
		{"4539 1488 0343 6467 4111 1111 1111 1111", []string{"4539148803436467", "4111111111111111"}},
		{`{"id":4539148803436467,"text":"4539148803436467"}`, []string{"4539148803436467"}}, // JSON numbers ignored
		{`{"text":"say \"4539148803436467\"","n":4111111111111111}`, []string{"4539148803436467"}},
		{`["4539148803436467"]`, []string{"4539148803436467"}},
	}
	for _, tc := range cases {
		var got []string
		for _, match := range findCardNumbers([]byte(tc.body)) {
			got = append(got, match.digits)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("findCardNumbers(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

func TestDefaultTestCardsPassLuhn(t *testing.T) {
	for _, card := range DefaultTestCards {
		if !luhn([]byte(card)) {
			t.Errorf("default test card %s fails Luhn", card)
		}
	}
}

func TestCardScannerValidate(t *testing.T) {
	if err := NewCardScanner(Warn, nil).Validate(); err == nil {
		t.Fatal("warn action accepted")
	}
	if err := NewCardScanner(Reject, []string{"4111x"}).Validate(); err == nil || !strings.Contains(err.Error(), "4111x") {
		t.Fatalf("invalid test card accepted: %v", err)
	}
}

func FuzzFindCardNumbers(f *testing.F) {
	f.Add([]byte("4539 1488 0343 6467 12"))
	f.Add([]byte(`"\n4111-1111-1111-1111"`))
	f.Add([]byte(`{"a":"x\"4539148803436467","b":4539148803436467}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		matches := findCardNumbers(body)
		original := map[string]bool{}
		for _, match := range matches {
			if len(match.digits) < 12 || len(match.digits) > 19 || !luhn([]byte(match.digits)) {
				t.Fatalf("invalid card reported: %q", match.digits)
			}
			original[match.digits] = true
		}
		redacted := redactCards(body, matches)
		for _, match := range findCardNumbers(redacted) {
			if original[match.digits] {
				t.Fatalf("redaction left card %s in %q", match.digits, redacted)
			}
		}
		trimmed := bytes.TrimSpace(body)
		if json.Valid(body) && (trimmed[0] == '{' || trimmed[0] == '[') && !json.Valid(redacted) {
			t.Fatalf("redaction broke JSON: %q", redacted)
		}
	})
}

func TestEngineForwardsRewrittenBody(t *testing.T) {
	engine, err := NewEngine(time.Second, NewCardScanner(Redact, nil), NewSecretScanner(Reject))
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Evaluate(context.Background(), Request{Body: []byte("4539148803436467"), Now: time.Now()})
	if got.Action != Allow || string(got.Body) != "[REDACTED: real card number ending 6467]" {
		t.Fatalf("rewritten body not returned: %+v", got)
	}
}

func TestCardScannerRedactAnnouncesCardsInNewestMessage(t *testing.T) {
	scanner := NewCardScanner(Redact, DefaultTestCards)
	notice := "Credit card number ending in 6467 was redacted before sending to the model"
	first := `{"messages":[{"role":"user","content":"card 4539 1488 0343 6467 and 4111111111111111"}]}`
	got := scanner.Evaluate(context.Background(), Request{Body: []byte(first)})
	want := `{"messages":[{"role":"user","content":"card [REDACTED: real card number ending 6467] and 4111111111111111"}]}`
	if got.Action != Allow || string(got.Body) != want || !slices.Equal(got.Notices, []string{notice}) || len(got.Findings) != 1 {
		t.Fatalf("first mention not redacted and announced: %+v body=%s", got, got.Body)
	}

	// The card is only in history now, so it is redacted without a notice.
	followUp := `{"messages":[{"role":"user","content":"card 4539148803436467"},{"role":"assistant","content":"ok"},{"role":"user","content":"thanks"}]}`
	if got := scanner.Evaluate(context.Background(), Request{Body: []byte(followUp)}); got.Action != Allow || len(got.Notices) != 0 || strings.Contains(string(got.Body), "4539") {
		t.Fatalf("history-only card announced or left in body: %+v", got)
	}

	// Mentioning it again, here through a tool result, announces it again.
	again := `{"messages":[{"role":"user","content":"card 4539148803436467"},{"role":"assistant","content":"ok"},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"4539-1488-0343-6467 and 5425 2334 3010 9903"}]}]}`
	got = scanner.Evaluate(context.Background(), Request{Body: []byte(again)})
	if !slices.Equal(got.Notices, []string{notice, "Credit card number ending in 9903 was redacted before sending to the model"}) {
		t.Fatalf("repeated mention not announced: %q", got.Notices)
	}
}

func TestCardScannerBackgroundRequestIsRedactedQuietly(t *testing.T) {
	got := NewCardScanner(Redact, nil).Evaluate(context.Background(), Request{Body: []byte(`{"messages":[{"role":"user","content":"4539148803436467"}]}`), Background: true})
	if got.Action != Allow || len(got.Notices) != 0 || !strings.Contains(string(got.Body), "[REDACTED") {
		t.Fatalf("background request not quietly redacted: %+v", got)
	}
}

func TestCardScannerRedactsPlainBody(t *testing.T) {
	got := NewCardScanner(Redact, nil).Evaluate(context.Background(), Request{Body: []byte("4539148803436467")})
	if got.Action != Allow || string(got.Body) != "[REDACTED: real card number ending 6467]" || len(got.Notices) != 1 {
		t.Fatalf("plain body not redacted and announced: %+v body=%s", got, got.Body)
	}
}
