package plugin

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
)

// DefaultTestCards are widely published processor test numbers that never
// identify a real account.
var DefaultTestCards = []string{
	"4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556",
	"5555555555554444", "5105105105105100", "2223003122003222",
	"378282246310005", "371449635398431",
	"6011111111111117", "6011000990139424",
	"3530111333300000", "3566002020360505",
	"30569309025904", "38520000023237",
}

// Redact is a CardScanner action: every request is forwarded with each card
// replaced by a placeholder that tells the model a real card number was
// removed, and the user is told whenever the newest message brings a card in.
const Redact Action = "redact"

// CardScanner rejects or masks Luhn-valid payment card numbers unless the
// number is a configured test card.
type CardScanner struct {
	action    Action
	testCards map[string]struct{}
	invalid   []string
}

func NewCardScanner(action Action, testCards []string) *CardScanner {
	scanner := &CardScanner{action: action, testCards: make(map[string]struct{}, len(testCards))}
	for _, raw := range testCards {
		digits := strings.Map(func(r rune) rune {
			if r == ' ' || r == '-' {
				return -1
			}
			return r
		}, strings.TrimSpace(raw))
		if len(digits) < 12 || len(digits) > 19 || strings.Trim(digits, "0123456789") != "" {
			scanner.invalid = append(scanner.invalid, raw)
			continue
		}
		scanner.testCards[digits] = struct{}{}
	}
	return scanner
}

func (*CardScanner) Name() string { return "card-scanner" }

func (s *CardScanner) Validate() error {
	if s.action != Allow && s.action != Reject && s.action != Redact {
		return fmt.Errorf("action must be allow, reject, or redact")
	}
	if len(s.invalid) > 0 {
		return fmt.Errorf("test card numbers must be 12-19 digits: %q", s.invalid)
	}
	return nil
}

func (s *CardScanner) Evaluate(ctx context.Context, request Request) Decision {
	var matches []cardMatch
	var findings []Finding
	seen := map[string]struct{}{}
	for _, match := range findCardNumbers(request.Body) {
		if ctx.Err() != nil {
			break
		}
		if _, ok := s.testCards[match.digits]; ok {
			continue
		}
		matches = append(matches, match)
		if _, ok := seen[match.digits]; ok {
			continue
		}
		seen[match.digits] = struct{}{}
		findings = append(findings, Finding{Plugin: s.Name(), Rule: "payment_card", Masked: mask([]byte(match.digits)), Message: "possible payment card number detected"})
	}
	if len(findings) == 0 {
		return Decision{Action: Allow}
	}
	switch s.action {
	case Reject:
		return Decision{Action: Reject, Status: 422, Code: "payment_card_detected", Message: "request blocked by payment card policy", Findings: findings}
	case Redact:
		// Only cards the newest message brings in are announced; history
		// repeats earlier cards on every request and is redacted quietly.
		// Background requests, such as session titles, are never announced.
		var notices []string
		newest := latestUserMessage(request.Body)
		for _, match := range matches {
			notice := fmt.Sprintf("Credit card number ending in %s was redacted before sending to the model", match.digits[len(match.digits)-4:])
			if !request.Background && match.start >= newest && !slices.Contains(notices, notice) {
				notices = append(notices, notice)
			}
		}
		for index := range findings {
			findings[index].Message = "payment card number redacted"
		}
		return Decision{Action: Allow, Findings: findings, Body: redactCards(request.Body, matches), Notices: notices}
	}
	return Decision{Action: Allow, Findings: findings}
}

// latestUserMessage returns the offset of the last user message in a
// Messages API body, or 0 when there is none, so the whole body counts as
// new. Inside JSON strings quotes are escaped, so the raw key only matches
// message structure.
func latestUserMessage(body []byte) int {
	return max(bytes.LastIndex(body, []byte(`"role":"user"`)), 0)
}

// cardPlaceholder is JSON-string safe and keeps the last four digits so the
// user and model can still tell cards apart.
func cardPlaceholder(digits string) string {
	return "[REDACTED: real card number ending " + digits[len(digits)-4:] + "]"
}

func redactCards(body []byte, matches []cardMatch) []byte {
	redacted := make([]byte, 0, len(body)+len(matches)*24)
	last := 0
	for _, match := range matches {
		redacted = append(redacted, body[last:match.start]...)
		redacted = append(redacted, cardPlaceholder(match.digits)...)
		last = match.end
	}
	return append(redacted, body[last:]...)
}

type cardMatch struct {
	start, end int
	digits     string
}

// findCardNumbers returns every 12-19 digit run that passes the Luhn check
// and looks like a card: it starts with a 2-6 issuer digit, is not embedded
// in a longer word or decimal, and if grouped uses a single space or dash
// separator with groups of 3-6 digits. A card may sit beside other numbers in
// the same run, such as "4539 1488 0343 6467 2024". In a JSON body only string
// values are scanned, so a match can always be replaced with text.
func findCardNumbers(body []byte) []cardMatch {
	var matches []cardMatch
	jsonBody := false
	for _, b := range body {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			jsonBody = b == '{' || b == '['
			break
		}
	}
	inString, escaped := false, false
	var groups [][2]int
	for i := 0; i < len(body); {
		if b := body[i]; !isDigit(b) || (jsonBody && (escaped || !inString)) {
			if jsonBody {
				switch {
				case escaped:
					escaped = false
				case inString && b == '\\':
					escaped = true
				case b == '"':
					inString = !inString
				}
			}
			i++
			continue
		}
		// Collect a run of digit groups joined by one repeated separator.
		groups = groups[:0]
		var separator byte
		for {
			start := i
			for i < len(body) && isDigit(body[i]) {
				i++
			}
			groups = append(groups, [2]int{start, i})
			if i+1 < len(body) && (body[i] == ' ' || body[i] == '-') && (separator == 0 || separator == body[i]) && isDigit(body[i+1]) {
				separator = body[i]
				i++
				continue
			}
			break
		}
		matches = appendCards(matches, body, groups)
	}
	return matches
}

// appendCards finds the leftmost-longest card in each stretch of groups: a
// single 12-19 digit group, or consecutive groups of 3-6 digits.
func appendCards(matches []cardMatch, body []byte, groups [][2]int) []cardMatch {
	last := len(groups) - 1
	digits := make([]byte, 0, 19)
	for first := 0; first <= last; first++ {
		if body[groups[first][0]] < '2' || body[groups[first][0]] > '6' || (first == 0 && !cardBoundary(body, groups[0][0]-1, true)) {
			continue
		}
		digits = digits[:0]
		best, bestDigits := -1, ""
		for end := first; end <= last; end++ {
			if end > first && (!cardGroup(groups[first]) || !cardGroup(groups[end])) {
				break
			}
			if digits = append(digits, body[groups[end][0]:groups[end][1]]...); len(digits) > 19 {
				break
			}
			if len(digits) >= 12 && luhn(digits) && (end < last || cardBoundary(body, groups[last][1], false)) {
				best, bestDigits = end, string(digits)
			}
		}
		if best >= 0 {
			matches = append(matches, cardMatch{start: groups[first][0], end: groups[best][1], digits: bestDigits})
			first = best
		}
	}
	return matches
}

func cardGroup(group [2]int) bool { return group[1]-group[0] >= 3 && group[1]-group[0] <= 6 }

// cardBoundary reports whether the byte at index does not continue the
// number. JSON escapes such as \n count as boundaries.
func cardBoundary(body []byte, index int, before bool) bool {
	if index < 0 || index >= len(body) {
		return true
	}
	b := body[index]
	if before && b == '.' {
		return false
	}
	if before && index > 0 && body[index-1] == '\\' && strings.IndexByte("nrtbf/", b) >= 0 {
		return true
	}
	return !(isDigit(b) || b == '_' || (b|0x20 >= 'a' && b|0x20 <= 'z'))
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func luhn(digits []byte) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
