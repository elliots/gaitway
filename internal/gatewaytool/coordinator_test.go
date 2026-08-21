package gatewaytool

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type scriptedTransport struct {
	t       *testing.T
	mu      sync.Mutex
	steps   []func(map[string]json.RawMessage) string
	request int
}

func (s *scriptedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		s.t.Fatal(err)
	}
	s.mu.Lock()
	if s.request >= len(s.steps) {
		s.mu.Unlock()
		s.t.Fatalf("unexpected upstream request %d", s.request+1)
	}
	step := s.steps[s.request]
	s.request++
	s.mu.Unlock()
	responseBody := step(payload)
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

func TestCoordinatorCompletesGatewayOnlyLoopWithoutTranscriptReceipt(t *testing.T) {
	tool := &testTool{}
	registry, _ := NewRegistry(tool)
	fingerprinter, _ := NewFingerprinter([]byte(strings.Repeat("k", 32)))
	transport := &scriptedTransport{t: t}
	transport.steps = []func(map[string]json.RawMessage) string{
		func(payload map[string]json.RawMessage) string {
			assertInjectedTool(t, payload)
			if !rawBool(payload["stream"]) {
				t.Fatal("coordinated upstream request does not stream")
			}
			return messageJSON(`[ {"type":"tool_use","id":"call-1","name":"gaitway__test","input":{"q":1}} ]`, "tool_use")
		},
		func(payload map[string]json.RawMessage) string {
			var messages []map[string]json.RawMessage
			_ = json.Unmarshal(payload["messages"], &messages)
			if len(messages) != 3 || rawString(messages[1]["role"]) != "assistant" || rawString(messages[2]["role"]) != "user" {
				t.Fatalf("internal tool turn not appended: %s", payload["messages"])
			}
			return messageJSON(`[ {"type":"text","text":"done"} ]`, "end_turn")
		},
		func(payload map[string]json.RawMessage) string {
			var messages []map[string]json.RawMessage
			_ = json.Unmarshal(payload["messages"], &messages)
			if len(messages) != 3 {
				t.Fatalf("visible history was not preserved: %s", payload["messages"])
			}
			return messageJSON(`[ {"type":"text","text":"continued"} ]`, "end_turn")
		},
	}
	coordinator, _ := NewCoordinator(CoordinatorConfig{Next: transport, Registry: registry, Fingerprinter: fingerprinter})

	first := newMessagesRequest(t, `{"model":"claude-test","max_tokens":10,"stream":false,"messages":[{"role":"user","content":"go"}]}`)
	response, err := coordinator.RoundTrip(first)
	if err != nil {
		t.Fatal(err)
	}
	firstBody, _ := io.ReadAll(response.Body)
	var firstMessage map[string]json.RawMessage
	_ = json.Unmarshal(firstBody, &firstMessage)
	var usage map[string]int64
	_ = json.Unmarshal(firstMessage["usage"], &usage)
	if usage["input_tokens"] != 2 || usage["output_tokens"] != 2 {
		t.Fatalf("internal usage was not aggregated: %s", firstMessage["usage"])
	}
	blocks, _ := decodeBlocks(firstMessage["content"])
	if len(blocks) != 1 || rawString(blocks[0]["text"]) != "done" || strings.Contains(string(firstBody), "GAITWAY:") {
		t.Fatalf("gateway receipt leaked into the transcript: %s", firstBody)
	}

	history, _ := json.Marshal(blocks)
	second := newMessagesRequest(t, `{"model":"claude-test","max_tokens":10,"stream":false,"messages":[{"role":"user","content":"go"},{"role":"assistant","content":`+string(history)+`},{"role":"user","content":"next"}]}`)
	if _, err := coordinator.RoundTrip(second); err != nil {
		t.Fatal(err)
	}
	if tool.calls.Load() != 1 {
		t.Fatalf("history replay reran tool: %d calls", tool.calls.Load())
	}
}

func TestCoordinatorHandlesMixedLocalAndGatewayTools(t *testing.T) {
	tool := &testTool{}
	registry, _ := NewRegistry(tool)
	fingerprinter, _ := NewFingerprinter([]byte(strings.Repeat("m", 32)))
	transport := &scriptedTransport{t: t}
	transport.steps = []func(map[string]json.RawMessage) string{
		func(map[string]json.RawMessage) string {
			return messageJSON(`[
				{"type":"tool_use","id":"gateway-1","name":"gaitway__test","input":{"q":1}},
				{"type":"tool_use","id":"local-1","name":"Bash","input":{"command":"true"}}
			]`, "tool_use")
		},
		func(payload map[string]json.RawMessage) string {
			var messages []map[string]json.RawMessage
			_ = json.Unmarshal(payload["messages"], &messages)
			assistant, _ := decodeBlocks(messages[1]["content"])
			results, _ := decodeBlocks(messages[2]["content"])
			if len(assistant) != 2 || rawString(assistant[0]["name"]) != "gaitway__test" || rawString(assistant[1]["name"]) != "Bash" {
				t.Fatalf("mixed assistant turn was not reconstructed: %s", messages[1]["content"])
			}
			if len(results) != 2 || rawString(results[1]["tool_use_id"]) != "gateway-1" {
				t.Fatalf("gateway result was not merged: %s", messages[2]["content"])
			}
			return messageJSON(`[ {"type":"text","text":"mixed done"} ]`, "end_turn")
		},
	}
	coordinator, _ := NewCoordinator(CoordinatorConfig{Next: transport, Registry: registry, Fingerprinter: fingerprinter})
	first := newMessagesRequest(t, `{"model":"claude-test","max_tokens":10,"stream":false,"messages":[{"role":"user","content":"go"}],"tools":[{"name":"Bash","description":"run","input_schema":{"type":"object"}}]}`)
	response, err := coordinator.RoundTrip(first)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	var visible map[string]json.RawMessage
	_ = json.Unmarshal(body, &visible)
	visibleBlocks, _ := decodeBlocks(visible["content"])
	if len(visibleBlocks) != 1 || rawString(visibleBlocks[0]["name"]) != "Bash" || strings.Contains(string(body), "GAITWAY:") {
		t.Fatalf("gateway call was not hidden from client: %s", body)
	}
	if response.Header.Get(deferActivationHeader) != "1" {
		t.Fatal("mixed-tool response did not defer the activation marker")
	}
	content, _ := json.Marshal(visibleBlocks)
	continuation := newMessagesRequest(t, `{"model":"claude-test","max_tokens":10,"stream":false,"messages":[{"role":"user","content":"go"},{"role":"assistant","content":`+string(content)+`},{"role":"user","content":[{"type":"tool_result","tool_use_id":"local-1","content":"ok"}]}],"tools":[{"name":"Bash","description":"run","input_schema":{"type":"object"}}]}`)
	final, err := coordinator.RoundTrip(continuation)
	if err != nil {
		t.Fatal(err)
	}
	finalBody, _ := io.ReadAll(final.Body)
	if !strings.Contains(string(finalBody), "mixed done") || strings.Contains(string(finalBody), "GAITWAY:") {
		t.Fatalf("mixed response leaked gateway state: %s", finalBody)
	}
}

func TestCoordinatorConvertsToolResponseToSSE(t *testing.T) {
	registry, _ := NewRegistry(&testTool{})
	fingerprinter, _ := NewFingerprinter([]byte(strings.Repeat("s", 32)))
	transport := &scriptedTransport{t: t, steps: []func(map[string]json.RawMessage) string{
		func(map[string]json.RawMessage) string {
			return messageJSON(`[ {"type":"text","text":"hello"} ]`, "end_turn")
		},
	}}
	coordinator, _ := NewCoordinator(CoordinatorConfig{Next: transport, Registry: registry, Fingerprinter: fingerprinter})
	request := newMessagesRequest(t, `{"model":"claude-test","max_tokens":10,"stream":true,"messages":[{"role":"user","content":"go"}]}`)
	response, err := coordinator.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(string(body), `"text":"hello"`) || !strings.Contains(string(body), `"type":"text_delta"`) || !strings.Contains(string(body), "event: message_stop") {
		t.Fatalf("invalid synthetic stream: %s", body)
	}
}

func TestDecodeMessageSSEPreservesUsageAndToolInput(t *testing.T) {
	body := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg-1","type":"message","role":"assistant","content":[],"model":"claude-test","stop_reason":null,"usage":{"input_tokens":3,"cache_read_input_tokens":5,"output_tokens":0,"output_tokens_details":{"thinking_tokens":0}}}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call-1","name":"gaitway__test","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"q\":1}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":7}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")
	message, err := decodeUpstreamMessage([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var usage map[string]json.RawMessage
	_ = json.Unmarshal(message["usage"], &usage)
	if rawInt(usage["input_tokens"]) != 3 || rawInt(usage["cache_read_input_tokens"]) != 5 || rawInt(usage["output_tokens"]) != 7 {
		t.Fatalf("usage was not reconstructed: %s", message["usage"])
	}
	blocks, _ := decodeBlocks(message["content"])
	if len(blocks) != 1 || string(blocks[0]["input"]) != `{"q":1}` {
		t.Fatalf("tool input was not reconstructed: %s", message["content"])
	}
}

func TestAccumulateUsageSkipsNestedMetadata(t *testing.T) {
	total := make(map[string]int64)
	accumulateUsage(total, json.RawMessage(`{"input_tokens":3,"output_tokens":7,"output_tokens_details":{"thinking_tokens":2}}`))
	if total["input_tokens"] != 3 || total["output_tokens"] != 7 {
		t.Fatalf("numeric usage was lost: %+v", total)
	}
}

func TestMixedStateIsBoundToPrincipalAndSession(t *testing.T) {
	registry, _ := NewRegistry(&testTool{})
	fingerprinter, _ := NewFingerprinter([]byte(strings.Repeat("p", 32)))
	coordinator, _ := NewCoordinator(CoordinatorConfig{Registry: registry, Fingerprinter: fingerprinter})
	blocks, _ := decodeBlocks(json.RawMessage(`[
		{"type":"tool_use","id":"gateway-1","name":"gaitway__test","input":{}},
		{"type":"tool_use","id":"local-1","name":"Bash","input":{}}
	]`))
	calls, _ := coordinator.partition(blocks)
	content, _ := json.Marshal(blocks)
	if err := coordinator.rememberMixed("principal", "session", content, calls, blocks); err != nil {
		t.Fatal(err)
	}
	messages := []map[string]json.RawMessage{{
		"role":    json.RawMessage(`"assistant"`),
		"content": json.RawMessage(`[{"type":"tool_use","id":"local-1","name":"Bash","input":{}}]`),
	}}
	if _, index := coordinator.findPending("another", "session", messages); index >= 0 {
		t.Fatal("pending state crossed principals")
	}
	if _, index := coordinator.findPending("principal", "another", messages); index >= 0 {
		t.Fatal("pending state crossed sessions")
	}
	if _, index := coordinator.findPending("principal", "session", messages); index != 0 {
		t.Fatal("pending state was not found for its owner")
	}
}

func TestLegacyReceiptIsRemovedFromHistory(t *testing.T) {
	raw := json.RawMessage(`[
		{"type":"text","text":"[Gaitway] completed an internal gateway-tool turn\n<<<GAITWAY:old>>>"},
		{"type":"text","text":"actual answer"}
	]`)
	cleaned, keep, err := stripLegacyReceipts(raw)
	if err != nil || !keep {
		t.Fatalf("receipt cleanup failed: keep=%v err=%v", keep, err)
	}
	blocks, _ := decodeBlocks(cleaned)
	if len(blocks) != 1 || rawString(blocks[0]["text"]) != "actual answer" || strings.Contains(string(cleaned), "GAITWAY:") {
		t.Fatalf("receipt was not removed: %s", cleaned)
	}
}

func assertInjectedTool(t *testing.T, payload map[string]json.RawMessage) {
	t.Helper()
	var tools []map[string]json.RawMessage
	_ = json.Unmarshal(payload["tools"], &tools)
	if len(tools) != 1 || rawString(tools[0]["name"]) != "gaitway__test" {
		t.Fatalf("gateway tool not injected: %s", payload["tools"])
	}
}

func newMessagesRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://api.anthropic.test/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(sessionHeader, "session-1")
	request.Header.Set("Content-Type", "application/json")
	return request
}

func messageJSON(content, stopReason string) string {
	return `{"id":"msg-1","type":"message","role":"assistant","content":` + content + `,"model":"claude-test","stop_reason":"` + stopReason + `","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`
}
