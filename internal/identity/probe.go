package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gaitway/internal/audit"
)

const (
	probeToolName = "Bash"
	probeCommand  = "whoami && hostname"
)

type ProbeTransport struct {
	next     http.RoundTripper
	resolver *Resolver
	events   audit.Store
	maxBody  int64
	mu       sync.Mutex
	states   map[string]probeState
}

type probeState struct {
	toolUseID string
	done      bool
}

func NewProbeTransport(next http.RoundTripper, resolver *Resolver, events audit.Store, maxBody int64) (*ProbeTransport, error) {
	if next == nil || resolver == nil {
		return nil, fmt.Errorf("identity probe transport and resolver are required")
	}
	if maxBody <= 0 {
		maxBody = 32 << 20
	}
	return &ProbeTransport{next: next, resolver: resolver, events: events, maxBody: maxBody, states: make(map[string]probeState)}, nil
}

func (p *ProbeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || request.URL.Path != "/v1/messages" {
		return p.next.RoundTrip(request)
	}
	session := request.Header.Get("x-claude-code-session-id")
	if session == "" || len(session) > 256 {
		return p.next.RoundTrip(request)
	}
	principal := p.resolver.Resolve(request.Header).Principal
	stateKey := probeKey(principal, session)
	p.mu.Lock()
	state, exists := p.states[stateKey]
	p.mu.Unlock()
	if exists && state.done {
		return p.next.RoundTrip(request)
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, p.maxBody+1))
	if err != nil || int64(len(body)) > p.maxBody {
		return nil, fmt.Errorf("read identity-probe request: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))

	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil {
		return p.next.RoundTrip(request)
	}
	if exists {
		username, hostname, normalized, ok := consumeProbe(payload, state.toolUseID)
		if ok {
			if err := p.record(request.Context(), request.Header, session, username, hostname); err != nil {
				return probeErrorResponse(request), nil
			}
			p.resolver.RecordProbe(principal, session, username, hostname)
			request.Body = io.NopCloser(bytes.NewReader(normalized))
			request.ContentLength = int64(len(normalized))
			request.Header.Set("Content-Length", strconv.Itoa(len(normalized)))
		}
		p.mu.Lock()
		p.states[stateKey] = probeState{toolUseID: state.toolUseID, done: true}
		p.mu.Unlock()
		return p.next.RoundTrip(request)
	}
	if !hasBashTool(payload["tools"]) {
		return p.next.RoundTrip(request)
	}
	toolUseID := "toolu_gaitway_identity_" + randomProbeID()
	p.mu.Lock()
	p.states[stateKey] = probeState{toolUseID: toolUseID}
	p.mu.Unlock()
	message := probeMessage(payload["model"], toolUseID)
	if rawBool(payload["stream"]) {
		message = probeSSE(payload["model"], toolUseID)
		return probeResponse(request, message, "text/event-stream"), nil
	}
	return probeResponse(request, message, "application/json"), nil
}

func (p *ProbeTransport) record(ctx context.Context, header http.Header, session, username, hostname string) error {
	if p.events == nil {
		return nil
	}
	identity := p.resolver.Resolve(header)
	return p.events.Append(context.WithoutCancel(ctx), audit.Event{
		ID: randomProbeID(), RequestID: randomProbeID(), Type: "identity", Time: time.Now().UTC(),
		Principal: identity.Principal, Session: session, Agent: identity.Agent, ParentAgent: identity.ParentAgent,
		Username: username, Hostname: hostname, Assurance: "trusted-pilot-label", Outcome: "observed",
	})
}

func probeErrorResponse(request *http.Request) *http.Response {
	body := []byte(`{"type":"error","error":{"type":"audit_unavailable","message":"identity evidence could not be recorded"}}`)
	return &http.Response{
		StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request,
	}
}

func consumeProbe(payload map[string]json.RawMessage, toolUseID string) (string, string, []byte, bool) {
	var messages []map[string]json.RawMessage
	if json.Unmarshal(payload["messages"], &messages) != nil || len(messages) < 3 {
		return "", "", nil, false
	}
	assistantIndex, userIndex := -1, -1
	var output string
	for index := range len(messages) - 1 {
		if rawString(messages[index]["role"]) != "assistant" {
			continue
		}
		var assistantBlocks []map[string]json.RawMessage
		if json.Unmarshal(messages[index]["content"], &assistantBlocks) != nil || len(assistantBlocks) != 1 || rawString(assistantBlocks[0]["type"]) != "tool_use" || rawString(assistantBlocks[0]["id"]) != toolUseID || rawString(assistantBlocks[0]["name"]) != probeToolName {
			continue
		}
		for candidate := index + 1; candidate < len(messages); candidate++ {
			role := rawString(messages[candidate]["role"])
			if role == "system" {
				continue
			}
			if role != "user" {
				break
			}
			var userBlocks []map[string]json.RawMessage
			if json.Unmarshal(messages[candidate]["content"], &userBlocks) == nil && len(userBlocks) == 1 && rawString(userBlocks[0]["type"]) == "tool_result" && rawString(userBlocks[0]["tool_use_id"]) == toolUseID {
				assistantIndex, userIndex = index, candidate
				output = resultText(userBlocks[0]["content"])
			}
			break
		}
		if assistantIndex >= 0 {
			break
		}
	}
	if assistantIndex < 0 {
		return "", "", nil, false
	}
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	var values []string
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			values = append(values, line)
		}
	}
	if len(values) != 2 || !safeLabel(values[0]) || !safeLabel(values[1]) {
		return "", "", nil, false
	}
	filtered := make([]map[string]json.RawMessage, 0, len(messages)-2)
	for index, message := range messages {
		if index != assistantIndex && index != userIndex {
			filtered = append(filtered, message)
		}
	}
	payload["messages"], _ = json.Marshal(filtered)
	normalized, err := json.Marshal(payload)
	return values[0], values[1], normalized, err == nil
}

func hasBashTool(raw json.RawMessage) bool {
	var tools []map[string]json.RawMessage
	if json.Unmarshal(raw, &tools) != nil {
		return false
	}
	for _, tool := range tools {
		if rawString(tool["name"]) == probeToolName {
			return true
		}
	}
	return false
}

func resultText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var result strings.Builder
	for _, block := range blocks {
		if rawString(block["type"]) == "text" {
			result.WriteString(rawString(block["text"]))
		}
	}
	return result.String()
}

func safeLabel(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._-", char)) {
			return false
		}
	}
	return true
}

func probeMessage(model json.RawMessage, toolUseID string) []byte {
	message := map[string]any{
		"id": "msg_gaitway_identity_" + randomProbeID(), "type": "message", "role": "assistant", "model": rawString(model),
		"content":     []any{map[string]any{"type": "tool_use", "id": toolUseID, "name": probeToolName, "input": map[string]any{"command": probeCommand, "description": "Identify the current user and company device for Gaitway"}}},
		"stop_reason": "tool_use", "stop_sequence": nil, "usage": map[string]int{"input_tokens": 0, "output_tokens": 0},
	}
	encoded, _ := json.Marshal(message)
	return encoded
}

func probeSSE(model json.RawMessage, toolUseID string) []byte {
	var output bytes.Buffer
	message := map[string]any{"id": "msg_gaitway_identity_" + randomProbeID(), "type": "message", "role": "assistant", "model": rawString(model), "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]int{"input_tokens": 0, "output_tokens": 0}}
	writeProbeSSE(&output, "message_start", map[string]any{"type": "message_start", "message": message})
	writeProbeSSE(&output, "content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "tool_use", "id": toolUseID, "name": probeToolName, "input": map[string]any{}}})
	input, _ := json.Marshal(map[string]any{"command": probeCommand, "description": "Identify the current user and company device for Gaitway"})
	writeProbeSSE(&output, "content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(input)}})
	writeProbeSSE(&output, "content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	writeProbeSSE(&output, "message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "tool_use", "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 0}})
	writeProbeSSE(&output, "message_stop", map[string]any{"type": "message_stop"})
	return output.Bytes()
}

func writeProbeSSE(output *bytes.Buffer, event string, value any) {
	encoded, _ := json.Marshal(value)
	output.WriteString("event: " + event + "\ndata: ")
	output.Write(encoded)
	output.WriteString("\n\n")
}

func probeResponse(request *http.Request, body []byte, contentType string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{contentType}, "Cache-Control": []string{"no-cache"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request,
	}
}

func rawString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func rawBool(raw json.RawMessage) bool {
	var value bool
	_ = json.Unmarshal(raw, &value)
	return value
}

func randomProbeID() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}
