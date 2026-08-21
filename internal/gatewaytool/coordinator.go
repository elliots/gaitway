package gatewaytool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sessionHeader = "x-claude-code-session-id"

// deferActivationHeader is an internal response marker consumed by the proxy.
// It prevents a synthetic mixed-tool response from consuming the once-per-
// session banner before Claude Code has a visible text answer to render.
const deferActivationHeader = "X-Gaitway-Defer-Activation"

const (
	pendingMixedLimit = 10_000
	pendingMixedTTL   = 10 * time.Minute
)

type Coordinator struct {
	next          http.RoundTripper
	registry      *Registry
	fingerprinter *Fingerprinter
	maxLoops      int
	maxBody       int64
	observer      Observer
	pending       map[string]pendingMixed
	pendingMu     sync.Mutex
}

type pendingMixed struct {
	assistantContent json.RawMessage
	calls            []toolCall
	localToolIDs     map[string]struct{}
	expiresAt        time.Time
}

type Observer interface {
	RecordTool(context.Context, string, string, json.RawMessage, Result, time.Duration) error
}

type CoordinatorConfig struct {
	Next          http.RoundTripper
	Registry      *Registry
	Fingerprinter *Fingerprinter
	MaxLoops      int
	MaxBody       int64
	Observer      Observer
}

func NewCoordinator(config CoordinatorConfig) (*Coordinator, error) {
	if config.Registry == nil || config.Fingerprinter == nil {
		return nil, fmt.Errorf("gateway tool registry and fingerprinter are required")
	}
	if config.Next == nil {
		config.Next = http.DefaultTransport
	}
	if config.MaxLoops <= 0 {
		config.MaxLoops = 4
	}
	if config.MaxBody <= 0 {
		config.MaxBody = 32 << 20
	}
	return &Coordinator{
		next: config.Next, registry: config.Registry, fingerprinter: config.Fingerprinter,
		maxLoops: config.MaxLoops, maxBody: config.MaxBody, observer: config.Observer,
		pending: make(map[string]pendingMixed),
	}, nil
}

func (c *Coordinator) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || (request.URL.Path != "/v1/messages" && request.URL.Path != "/v1/messages/count_tokens") {
		return c.next.RoundTrip(request)
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, c.maxBody+1))
	if err != nil || int64(len(body)) > c.maxBody {
		return localError(request, http.StatusRequestEntityTooLarge, "request_too_large", "tool-enabled request exceeds gateway limit"), nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return c.send(request, body)
	}
	principal := c.fingerprinter.Fingerprint(request.Header.Get("Authorization"))
	session := request.Header.Get(sessionHeader)
	if err := c.normalizeHistory(request.Context(), principal, session, payload); err != nil {
		return localError(request, http.StatusBadRequest, "invalid_gateway_history", err.Error()), nil
	}
	if err := c.injectTools(payload); err != nil {
		return localError(request, http.StatusBadRequest, "gateway_tool_collision", err.Error()), nil
	}
	clientStreams := rawBool(payload["stream"])
	if request.URL.Path == "/v1/messages/count_tokens" {
		transformed, _ := json.Marshal(payload)
		return c.send(request, transformed)
	}
	payload["stream"] = json.RawMessage("false")

	usageTotals := make(map[string]int64)
	for loop := 0; loop <= c.maxLoops; loop++ {
		transformed, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return nil, marshalErr
		}
		response, roundTripErr := c.send(request, transformed)
		if roundTripErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
			return response, roundTripErr
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxBody+1))
		_ = response.Body.Close()
		if readErr != nil || int64(len(responseBody)) > c.maxBody {
			return nil, fmt.Errorf("read tool-enabled upstream response: %w", readErr)
		}
		var message map[string]json.RawMessage
		if err := json.Unmarshal(responseBody, &message); err != nil {
			return nil, fmt.Errorf("decode tool-enabled upstream response: %w", err)
		}
		accumulateUsage(usageTotals, message["usage"])
		blocks, err := decodeBlocks(message["content"])
		if err != nil {
			return nil, err
		}
		calls, hasLocal := c.partition(blocks)
		if len(calls) == 0 {
			message["usage"], _ = json.Marshal(usageTotals)
			finalBody, _ := json.Marshal(message)
			return clientResponse(request, response, finalBody, clientStreams)
		}
		if hasLocal {
			message["usage"], _ = json.Marshal(usageTotals)
			if err := c.rememberMixed(principal, session, message["content"], calls, blocks); err != nil {
				return localError(request, http.StatusBadRequest, "mixed_tool_state", err.Error()), nil
			}
			for _, call := range calls {
				c.registry.Start(call.name, call.id, call.input)
			}
			if err := c.rewriteMixed(blocks, message); err != nil {
				return nil, err
			}
			finalBody, _ := json.Marshal(message)
			client, clientErr := clientResponse(request, response, finalBody, clientStreams)
			if clientErr == nil {
				client.Header.Set(deferActivationHeader, "1")
			}
			return client, clientErr
		}
		if loop == c.maxLoops {
			return localError(request, http.StatusBadGateway, "gateway_tool_loop_limit", "gateway tool loop limit reached"), nil
		}

		results := c.executeAll(request.Context(), calls)
		if err := appendToolTurn(payload, message["content"], results); err != nil {
			return nil, err
		}
	}
	panic("unreachable")
}

func accumulateUsage(total map[string]int64, raw json.RawMessage) {
	var current map[string]int64
	if json.Unmarshal(raw, &current) != nil {
		return
	}
	for name, value := range current {
		total[name] += value
	}
}

type toolCall struct {
	id    string
	name  string
	input json.RawMessage
}

func (c *Coordinator) partition(blocks []map[string]json.RawMessage) ([]toolCall, bool) {
	var calls []toolCall
	hasLocal := false
	for _, block := range blocks {
		if rawString(block["type"]) != "tool_use" {
			continue
		}
		name := rawString(block["name"])
		if !c.registry.Contains(name) {
			hasLocal = true
			continue
		}
		calls = append(calls, toolCall{id: rawString(block["id"]), name: name, input: append(json.RawMessage(nil), block["input"]...)})
	}
	return calls, hasLocal
}

func (c *Coordinator) executeAll(ctx context.Context, calls []toolCall) []ToolResult {
	results := make([]ToolResult, len(calls))
	done := make(chan int, len(calls))
	for index, call := range calls {
		go func() {
			started := time.Now()
			results[index] = ToolResult{ToolUseID: call.id, ToolName: call.name, Result: c.registry.Execute(ctx, call.name, call.id, call.input)}
			if err := c.record(ctx, call.input, results[index], time.Since(started)); err != nil {
				results[index].Result = Result{Content: "gateway tool evidence could not be recorded", IsError: true, Classification: "internal"}
			}
			done <- index
		}()
	}
	for range calls {
		<-done
	}
	return results
}

func (c *Coordinator) rewriteMixed(blocks []map[string]json.RawMessage, message map[string]json.RawMessage) error {
	visible := make([]map[string]json.RawMessage, 0, len(blocks))
	for _, block := range blocks {
		if rawString(block["type"]) == "tool_use" && c.registry.Contains(rawString(block["name"])) {
			continue
		}
		visible = append(visible, block)
	}
	encoded, err := json.Marshal(visible)
	if err == nil {
		message["content"] = encoded
	}
	return err
}

func (c *Coordinator) rememberMixed(principal, session string, assistantContent json.RawMessage, calls []toolCall, blocks []map[string]json.RawMessage) error {
	if session == "" {
		return fmt.Errorf("mixed local and gateway tools require a Claude session id")
	}
	localToolIDs := make(map[string]struct{})
	for _, block := range blocks {
		if rawString(block["type"]) != "tool_use" || c.registry.Contains(rawString(block["name"])) {
			continue
		}
		id := rawString(block["id"])
		if id == "" {
			return fmt.Errorf("local tool request has no id")
		}
		localToolIDs[id] = struct{}{}
	}
	if len(localToolIDs) == 0 {
		return fmt.Errorf("mixed tool response has no local tool request")
	}
	clonedCalls := make([]toolCall, len(calls))
	for index, call := range calls {
		clonedCalls[index] = call
		clonedCalls[index].input = append(json.RawMessage(nil), call.input...)
	}
	key := pendingKey(principal, session)
	now := time.Now()
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	for candidate, state := range c.pending {
		if !state.expiresAt.After(now) {
			delete(c.pending, candidate)
		}
	}
	if _, exists := c.pending[key]; exists {
		return fmt.Errorf("session already has a pending mixed-tool turn")
	}
	if len(c.pending) >= pendingMixedLimit {
		return fmt.Errorf("pending mixed-tool capacity reached")
	}
	c.pending[key] = pendingMixed{
		assistantContent: append(json.RawMessage(nil), assistantContent...),
		calls:            clonedCalls,
		localToolIDs:     localToolIDs,
		expiresAt:        now.Add(pendingMixedTTL),
	}
	return nil
}

func (c *Coordinator) findPending(principal, session string, messages []map[string]json.RawMessage) (pendingMixed, int) {
	if session == "" {
		return pendingMixed{}, -1
	}
	key := pendingKey(principal, session)
	c.pendingMu.Lock()
	state, exists := c.pending[key]
	if exists && !state.expiresAt.After(time.Now()) {
		delete(c.pending, key)
		exists = false
	}
	c.pendingMu.Unlock()
	if !exists {
		return pendingMixed{}, -1
	}
	for index := len(messages) - 1; index >= 0; index-- {
		if rawString(messages[index]["role"]) == "assistant" && matchesLocalTools(messages[index]["content"], state.localToolIDs) {
			return state, index
		}
	}
	return pendingMixed{}, -1
}

func matchesLocalTools(content json.RawMessage, expected map[string]struct{}) bool {
	blocks, err := decodeBlocks(content)
	if err != nil {
		return false
	}
	found := make(map[string]struct{})
	for _, block := range blocks {
		if rawString(block["type"]) != "tool_use" {
			continue
		}
		id := rawString(block["id"])
		if _, ok := expected[id]; !ok {
			return false
		}
		found[id] = struct{}{}
	}
	return len(found) == len(expected)
}

func hasToolResults(content json.RawMessage, expected map[string]struct{}) bool {
	blocks, err := decodeBlocks(content)
	if err != nil {
		return false
	}
	found := make(map[string]struct{})
	for _, block := range blocks {
		if rawString(block["type"]) != "tool_result" {
			continue
		}
		id := rawString(block["tool_use_id"])
		if _, ok := expected[id]; ok {
			found[id] = struct{}{}
		}
	}
	return len(found) == len(expected)
}

func (c *Coordinator) clearPending(principal, session string) {
	c.pendingMu.Lock()
	delete(c.pending, pendingKey(principal, session))
	c.pendingMu.Unlock()
}

func pendingKey(principal, session string) string { return principal + "\x00" + session }

func (c *Coordinator) normalizeHistory(ctx context.Context, principal, session string, payload map[string]json.RawMessage) error {
	var messages []map[string]json.RawMessage
	if len(payload["messages"]) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload["messages"], &messages); err != nil {
		return fmt.Errorf("decode messages: %w", err)
	}
	pendingState, pendingIndex := c.findPending(principal, session, messages)
	var normalized []map[string]json.RawMessage
	var pendingResults []ToolResult
	for messageIndex, message := range messages {
		role := rawString(message["role"])
		if role == "user" {
			if len(pendingResults) > 0 {
				if pendingIndex >= 0 && !hasToolResults(message["content"], pendingState.localToolIDs) {
					return fmt.Errorf("pending mixed-tool turn has no matching local tool results")
				}
				if err := addToolResults(message, pendingResults); err != nil {
					return err
				}
				pendingResults = nil
			}
			normalized = append(normalized, message)
			continue
		}
		if role != "assistant" {
			normalized = append(normalized, message)
			continue
		}
		if messageIndex == pendingIndex {
			message["content"] = append(json.RawMessage(nil), pendingState.assistantContent...)
			normalized = append(normalized, message)
			pendingResults = c.executeAll(ctx, pendingState.calls)
			continue
		}
		content, keep, err := stripLegacyReceipts(message["content"])
		if err != nil {
			return err
		}
		if keep {
			message["content"] = content
			normalized = append(normalized, message)
		}
	}
	if len(pendingResults) > 0 {
		return fmt.Errorf("gateway tool request has no following user tool-result turn")
	}
	encoded, err := json.Marshal(normalized)
	if err == nil {
		payload["messages"] = encoded
	}
	if err == nil && pendingIndex >= 0 {
		c.clearPending(principal, session)
	}
	return err
}

func stripLegacyReceipts(content json.RawMessage) (json.RawMessage, bool, error) {
	blocks, err := decodeBlocks(content)
	if err != nil {
		return nil, false, err
	}
	visible := make([]map[string]json.RawMessage, 0, len(blocks))
	for _, block := range blocks {
		text := rawString(block["text"])
		if rawString(block["type"]) == "text" && strings.HasPrefix(text, "[Gaitway] ") {
			if _, ok := envelopeToken(text); ok {
				continue
			}
		}
		visible = append(visible, block)
	}
	if len(visible) == 0 {
		return nil, false, nil
	}
	encoded, err := json.Marshal(visible)
	return encoded, true, err
}

func (c *Coordinator) record(ctx context.Context, input json.RawMessage, result ToolResult, duration time.Duration) error {
	if c.observer != nil {
		return c.observer.RecordTool(ctx, result.ToolName, result.ToolUseID, append(json.RawMessage(nil), input...), result.Result, duration)
	}
	return nil
}

func (c *Coordinator) injectTools(payload map[string]json.RawMessage) error {
	var existing []json.RawMessage
	if raw := payload["tools"]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("decode tools: %w", err)
		}
	}
	seen := make(map[string]struct{}, len(existing))
	for _, raw := range existing {
		var item struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &item) == nil {
			seen[item.Name] = struct{}{}
		}
	}
	for _, descriptor := range c.registry.Descriptors() {
		if _, exists := seen[descriptor.Name]; exists {
			return fmt.Errorf("client tool %q collides with a gateway tool", descriptor.Name)
		}
		encoded, _ := json.Marshal(map[string]any{"name": descriptor.Name, "description": descriptor.Description, "input_schema": descriptor.InputSchema})
		existing = append(existing, encoded)
	}
	encoded, err := json.Marshal(existing)
	if err == nil {
		payload["tools"] = encoded
	}
	return err
}

func (c *Coordinator) send(request *http.Request, body []byte) (*http.Response, error) {
	outbound := request.Clone(request.Context())
	outbound.Body = io.NopCloser(bytes.NewReader(body))
	outbound.GetBody = nil
	outbound.ContentLength = int64(len(body))
	outbound.Header = request.Header.Clone()
	outbound.Header.Del("Accept-Encoding")
	outbound.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return c.next.RoundTrip(outbound)
}

func appendToolTurn(payload map[string]json.RawMessage, assistantContent json.RawMessage, results []ToolResult) error {
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(payload["messages"], &messages); err != nil {
		return err
	}
	messages = append(messages,
		map[string]json.RawMessage{"role": json.RawMessage(`"assistant"`), "content": append(json.RawMessage(nil), assistantContent...)},
		toolResultMessage(results),
	)
	encoded, err := json.Marshal(messages)
	if err == nil {
		payload["messages"] = encoded
	}
	return err
}

func toolResultMessage(results []ToolResult) map[string]json.RawMessage {
	blocks := make([]map[string]json.RawMessage, 0, len(results))
	for _, result := range results {
		blocks = append(blocks, toolResultBlock(result))
	}
	encoded, _ := json.Marshal(blocks)
	return map[string]json.RawMessage{"role": json.RawMessage(`"user"`), "content": encoded}
}

func addToolResults(message map[string]json.RawMessage, results []ToolResult) error {
	blocks, err := decodeBlocks(message["content"])
	if err != nil {
		var text string
		if json.Unmarshal(message["content"], &text) != nil {
			return err
		}
		blocks = []map[string]json.RawMessage{textBlock(text)}
	}
	for _, result := range results {
		blocks = append(blocks, toolResultBlock(result))
	}
	encoded, err := json.Marshal(blocks)
	if err == nil {
		message["content"] = encoded
	}
	return err
}

func toolResultBlock(result ToolResult) map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"type": json.RawMessage(`"tool_result"`), "tool_use_id": mustJSON(result.ToolUseID), "content": mustJSON(result.Result.Content), "is_error": json.RawMessage(strconv.FormatBool(result.Result.IsError)),
	}
}

func textBlock(value string) map[string]json.RawMessage {
	return map[string]json.RawMessage{"type": json.RawMessage(`"text"`), "text": mustJSON(value)}
}

func decodeBlocks(raw json.RawMessage) ([]map[string]json.RawMessage, error) {
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("decode message content: %w", err)
	}
	return blocks, nil
}

func envelopeToken(text string) (string, bool) {
	start := strings.LastIndex(text, "<<<GAITWAY:")
	if start < 0 {
		return "", false
	}
	end := strings.Index(text[start:], ">>>")
	if end < 0 || strings.TrimSpace(text[start+end+3:]) != "" {
		return "", false
	}
	return text[start : start+end+3], true
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

func mustJSON(value string) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

func localError(request *http.Request, status int, kind, message string) *http.Response {
	body, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": kind, "message": message}})
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request}
}

func clientResponse(request *http.Request, upstream *http.Response, body []byte, stream bool) (*http.Response, error) {
	upstream.Request = request
	upstream.Header = upstream.Header.Clone()
	if stream {
		streamBody, err := messageSSE(body)
		if err != nil {
			return nil, err
		}
		body = streamBody
		upstream.Header.Set("Content-Type", "text/event-stream")
		upstream.Header.Set("Cache-Control", "no-cache")
	} else {
		upstream.Header.Set("Content-Type", "application/json")
	}
	upstream.Header.Del("Content-Encoding")
	upstream.Header.Del("Content-Length")
	upstream.ContentLength = int64(len(body))
	upstream.Body = io.NopCloser(bytes.NewReader(body))
	return upstream, nil
}

func messageSSE(raw []byte) ([]byte, error) {
	var message map[string]json.RawMessage
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, err
	}
	blocks, err := decodeBlocks(message["content"])
	if err != nil {
		return nil, err
	}
	start := make(map[string]json.RawMessage, len(message))
	for key, value := range message {
		start[key] = value
	}
	start["content"] = json.RawMessage(`[]`)
	start["stop_reason"] = json.RawMessage(`null`)
	start["stop_sequence"] = json.RawMessage(`null`)
	var output bytes.Buffer
	writeSSE(&output, "message_start", map[string]any{"type": "message_start", "message": start})
	for index, block := range blocks {
		typeName := rawString(block["type"])
		switch typeName {
		case "text":
			writeSSE(&output, "content_block_start", map[string]any{"type": "content_block_start", "index": index, "content_block": map[string]any{"type": "text", "text": ""}})
			writeSSE(&output, "content_block_delta", map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]any{"type": "text_delta", "text": rawString(block["text"])}})
		case "tool_use":
			writeSSE(&output, "content_block_start", map[string]any{"type": "content_block_start", "index": index, "content_block": map[string]any{"type": "tool_use", "id": rawString(block["id"]), "name": rawString(block["name"]), "input": map[string]any{}}})
			writeSSE(&output, "content_block_delta", map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(block["input"])}})
		case "thinking":
			writeSSE(&output, "content_block_start", map[string]any{"type": "content_block_start", "index": index, "content_block": map[string]any{"type": "thinking", "thinking": "", "signature": ""}})
			if value := rawString(block["thinking"]); value != "" {
				writeSSE(&output, "content_block_delta", map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]any{"type": "thinking_delta", "thinking": value}})
			}
			if value := rawString(block["signature"]); value != "" {
				writeSSE(&output, "content_block_delta", map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]any{"type": "signature_delta", "signature": value}})
			}
		default:
			writeSSE(&output, "content_block_start", map[string]any{"type": "content_block_start", "index": index, "content_block": block})
		}
		writeSSE(&output, "content_block_stop", map[string]any{"type": "content_block_stop", "index": index})
	}
	delta := map[string]json.RawMessage{"stop_reason": message["stop_reason"], "stop_sequence": message["stop_sequence"]}
	writeSSE(&output, "message_delta", map[string]any{"type": "message_delta", "delta": delta, "usage": message["usage"]})
	writeSSE(&output, "message_stop", map[string]any{"type": "message_stop"})
	return output.Bytes(), nil
}

func writeSSE(writer *bytes.Buffer, event string, value any) {
	encoded, _ := json.Marshal(value)
	writer.WriteString("event: ")
	writer.WriteString(event)
	writer.WriteString("\ndata: ")
	writer.Write(encoded)
	writer.WriteString("\n\n")
}
