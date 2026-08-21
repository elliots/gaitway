package identity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"gaitway/internal/audit"
)

type probeNext struct {
	t      *testing.T
	called int
}

func (n *probeNext) RoundTrip(request *http.Request) (*http.Response, error) {
	n.called++
	body, _ := io.ReadAll(request.Body)
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(body, &payload)
	var messages []map[string]json.RawMessage
	_ = json.Unmarshal(payload["messages"], &messages)
	if len(messages) != 1 {
		n.t.Fatalf("probe turns reached upstream: %s", payload["messages"])
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: request}, nil
}

func TestProbeTransportCollectsLabelsAndRestoresOriginalPrompt(t *testing.T) {
	resolver, _ := NewResolver([]byte(strings.Repeat("k", 32)))
	events, _ := audit.NewJSONLStore(t.TempDir() + "/events.jsonl")
	next := &probeNext{t: t}
	probe, _ := NewProbeTransport(next, resolver, events, 1<<20)
	first := probeRequest(t, `{"model":"claude-test","stream":false,"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"Bash","input_schema":{"type":"object"}}]}`)
	response, err := probe.RoundTrip(first)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	var message map[string]json.RawMessage
	_ = json.Unmarshal(body, &message)
	var blocks []map[string]json.RawMessage
	_ = json.Unmarshal(message["content"], &blocks)
	toolUseID := rawString(blocks[0]["id"])
	if toolUseID == "" || rawString(blocks[0]["name"]) != "Bash" || next.called != 0 {
		t.Fatalf("probe was not synthesized: %s", body)
	}

	continuation := probeRequest(t, `{"model":"claude-test","stream":false,"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":[{"type":"tool_use","id":"`+toolUseID+`","name":"Bash","input":{"command":"whoami && hostname"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"`+toolUseID+`","content":"elliot\nMAC-123\n"}]}],"tools":[{"name":"Bash","input_schema":{"type":"object"}}]}`)
	if _, err := probe.RoundTrip(continuation); err != nil {
		t.Fatal(err)
	}
	identity := resolver.Resolve(continuation.Header)
	if identity.Username != "elliot" || identity.Hostname != "MAC-123" || identity.Assurance != "trusted-pilot-label" {
		t.Fatalf("probe labels missing: %+v", identity)
	}
	recorded, _ := events.List(context.Background(), 10)
	if len(recorded) != 1 || recorded[0].Type != "identity" || recorded[0].Hostname != "MAC-123" {
		t.Fatalf("probe audit missing: %+v", recorded)
	}
}

func TestProbeLabelsDoNotCrossPrincipals(t *testing.T) {
	resolver, _ := NewResolver([]byte(strings.Repeat("k", 32)))
	first := make(http.Header)
	first.Set("Authorization", "Bearer first")
	first.Set("x-claude-code-session-id", "same-session")
	firstIdentity := resolver.Resolve(first)
	resolver.RecordProbe(firstIdentity.Principal, firstIdentity.Session, "first-user", "first-host")
	second := first.Clone()
	second.Set("Authorization", "Bearer second")
	if got := resolver.Resolve(second); got.Username != "" || got.Hostname != "" {
		t.Fatalf("probe labels crossed principals: %+v", got)
	}
}

func TestProbeTransportStreamsValidToolTurn(t *testing.T) {
	resolver, _ := NewResolver([]byte(strings.Repeat("k", 32)))
	probe, _ := NewProbeTransport(&probeNext{t: t}, resolver, nil, 1<<20)
	request := probeRequest(t, `{"model":"claude-test","stream":true,"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"Bash"}]}`)
	response, err := probe.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(string(body), `"name":"Bash"`) || !strings.Contains(string(body), "event: message_stop") {
		t.Fatalf("invalid probe stream: %s", body)
	}
}

func probeRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://api.anthropic.test/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer credential")
	request.Header.Set("x-claude-code-session-id", "session-1")
	return request
}
