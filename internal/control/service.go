package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"gaitway/internal/archive"
	"gaitway/internal/audit"
	"gaitway/internal/gatewaytool"
	"gaitway/internal/identity"
	"gaitway/internal/plugin"
)

var errResponseCaptureLimit = fmt.Errorf("response exceeded archive capture limit")

type Service struct {
	archive   archive.Store
	audit     audit.Store
	identity  *identity.Resolver
	policies  *plugin.Engine
	maxBody   int64
	telemetry Telemetry
	ackMu     sync.Mutex
	acks      map[string]ackState
}

type ackState struct {
	marker  string
	message string
}

type Telemetry interface {
	Begin(context.Context, string) context.Context
	Finish(context.Context, string, int, time.Duration)
}

type transactionKey struct{}

type transaction struct {
	once       sync.Once
	id         string
	identity   identity.Identity
	route      string
	model      string
	started    time.Time
	requestRef archive.Object
}

func NewService(objects archive.Store, events audit.Store, resolver *identity.Resolver, policies *plugin.Engine, maxBody int64, telemetry ...Telemetry) *Service {
	service := &Service{archive: objects, audit: events, identity: resolver, policies: policies, maxBody: maxBody, acks: make(map[string]ackState)}
	if len(telemetry) > 0 {
		service.telemetry = telemetry[0]
	}
	return service
}

func (s *Service) Prepare(writer http.ResponseWriter, request *http.Request) (*http.Request, bool) {
	body, err := io.ReadAll(io.LimitReader(request.Body, s.maxBody+1))
	if err != nil || int64(len(body)) > s.maxBody {
		writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "request exceeds gateway limit")
		return request, false
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	identityValue := s.identity.Resolve(request.Header)
	body, acknowledged, pending := s.consumeAcknowledgement(body, identityValue.Principal, identityValue.Session)
	if pending && !acknowledged {
		object, archiveErr := s.archive.Put(request.Context(), "acknowledgement", body)
		if archiveErr != nil || s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: randomID(), Type: "acknowledgement", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Username: identityValue.Username, Hostname: identityValue.Hostname, Assurance: identityValue.Assurance, Outcome: "required", ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size}) != nil {
			writeError(writer, http.StatusServiceUnavailable, "evidence_unavailable", "acknowledgement evidence could not be recorded")
			return request, false
		}
		s.writePendingWarning(writer, request, identityValue.Principal, identityValue.Session)
		return request, false
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	model := requestModel(body)
	route := routeName(request.URL.Path)
	id := randomID()
	decision := s.policies.Evaluate(request.Context(), plugin.Request{ID: id, Principal: identityValue.Principal, Session: identityValue.Session, Route: route, Model: model, Body: body, Now: time.Now().UTC(), Acknowledged: acknowledged})
	if acknowledged {
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "acknowledgement", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Username: identityValue.Username, Hostname: identityValue.Hostname, Assurance: identityValue.Assurance, Outcome: "accepted", Policy: "usage-budget"}) != nil {
			s.policies.Reconcile(identityValue.Principal, id, 0, false, time.Now().UTC())
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "request audit could not be recorded")
			return request, false
		}
	}
	for _, finding := range decision.Findings {
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "policy", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Route: route, Model: model, Policy: finding.Plugin, Rule: finding.Rule, Finding: finding.Masked}) != nil {
			s.policies.Reconcile(identityValue.Principal, id, 0, false, time.Now().UTC())
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "policy audit could not be recorded")
			return request, false
		}
	}
	if decision.Action == plugin.Reject {
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, Username: identityValue.Username, Hostname: identityValue.Hostname, Assurance: identityValue.Assurance, Route: route, Model: model, Outcome: "rejected", Policy: decision.Code}) != nil {
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "rejection audit could not be recorded")
			return request, false
		}
		writeError(writer, decision.Status, decision.Code, decision.Message)
		return request, false
	}
	object, err := s.archive.Put(request.Context(), "request", body)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "archive_unavailable", "request evidence could not be recorded")
		return request, false
	}
	if decision.Action == plugin.Warn {
		s.policies.Reconcile(identityValue.Principal, id, 0, false, time.Now().UTC())
		if identityValue.Session == "" {
			writeError(writer, http.StatusPreconditionRequired, "usage_acknowledgement_required", decision.Message)
			return request, false
		}
		state := ackState{marker: randomID(), message: decision.Message}
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, Username: identityValue.Username, Hostname: identityValue.Hostname, Assurance: identityValue.Assurance, Route: route, Model: model, Outcome: "warning", ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size, Policy: decision.Code}) != nil {
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "warning audit could not be recorded")
			return request, false
		}
		s.ackMu.Lock()
		s.acks[ackKey(identityValue.Principal, identityValue.Session)] = state
		s.ackMu.Unlock()
		s.writeWarning(writer, request, state)
		return request, false
	}
	requestContext := request.Context()
	if s.telemetry != nil {
		requestContext = s.telemetry.Begin(requestContext, route)
	}
	tx := &transaction{id: id, identity: identityValue, route: route, model: model, started: time.Now().UTC(), requestRef: object}
	if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: tx.started, Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, Username: identityValue.Username, Hostname: identityValue.Hostname, Assurance: identityValue.Assurance, Route: route, Model: model, Outcome: string(decision.Action), ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size, Policy: decision.Code}) != nil {
		s.policies.Reconcile(identityValue.Principal, id, 0, false, time.Now().UTC())
		writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "request audit could not be recorded")
		return request, false
	}
	return request.WithContext(context.WithValue(requestContext, transactionKey{}, tx)), true
}

func (s *Service) consumeAcknowledgement(body []byte, principal, session string) ([]byte, bool, bool) {
	s.ackMu.Lock()
	key := ackKey(principal, session)
	state, pending := s.acks[key]
	s.ackMu.Unlock()
	if !pending {
		return body, false, false
	}
	var payload map[string]json.RawMessage
	var messages []map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil || json.Unmarshal(payload["messages"], &messages) != nil {
		return body, false, true
	}
	assistantIndex, userIndex := -1, -1
	for index, message := range messages {
		if rawRole(message) != "assistant" || !strings.Contains(messageText(message["content"]), "[gaitway-ack:"+state.marker+"]") {
			continue
		}
		for candidate := index + 1; candidate < len(messages); candidate++ {
			role := rawRole(messages[candidate])
			if role == "system" {
				continue
			}
			if role == "user" && strings.EqualFold(strings.TrimSpace(messageText(messages[candidate]["content"])), "ACKNOWLEDGE") {
				assistantIndex, userIndex = index, candidate
			}
			break
		}
		break
	}
	if assistantIndex < 0 {
		return body, false, true
	}
	filtered := make([]map[string]json.RawMessage, 0, len(messages)-2)
	for index, message := range messages {
		if index != assistantIndex && index != userIndex {
			filtered = append(filtered, message)
		}
	}
	payload["messages"], _ = json.Marshal(filtered)
	normalized, err := json.Marshal(payload)
	if err != nil {
		return body, false, true
	}
	s.ackMu.Lock()
	delete(s.acks, key)
	s.ackMu.Unlock()
	return normalized, true, true
}

func (s *Service) writePendingWarning(writer http.ResponseWriter, request *http.Request, principal, session string) {
	s.ackMu.Lock()
	state := s.acks[ackKey(principal, session)]
	s.ackMu.Unlock()
	s.writeWarning(writer, request, state)
}

func ackKey(principal, session string) string { return principal + "\x00" + session }

func (s *Service) writeWarning(writer http.ResponseWriter, request *http.Request, state ackState) {
	text := "*** Gaitway usage warning ***\n\n" + state.message + " Reply with exactly `ACKNOWLEDGE` to continue.\n\n[gaitway-ack:" + state.marker + "]"
	body, _ := io.ReadAll(request.Body)
	request.Body = io.NopCloser(bytes.NewReader(body))
	model := requestModel(body)
	message := map[string]any{"id": "msg_gaitway_warning_" + randomID(), "type": "message", "role": "assistant", "model": model, "content": []any{map[string]any{"type": "text", "text": text}}, "stop_reason": "end_turn", "stop_sequence": nil, "usage": map[string]int{"input_tokens": 0, "output_tokens": 0}}
	encoded, _ := json.Marshal(message)
	contentType := "application/json"
	if requestStreams(body) {
		encoded = warningSSE(message, text)
		contentType = "text/event-stream"
	}
	identityValue := s.identity.Resolve(request.Header)
	object, archiveErr := s.archive.Put(context.WithoutCancel(request.Context()), "response", encoded)
	if archiveErr != nil || s.audit.Append(context.WithoutCancel(request.Context()), audit.Event{ID: randomID(), RequestID: randomID(), Type: "response", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Username: identityValue.Username, Hostname: identityValue.Hostname, Assurance: identityValue.Assurance, Route: "messages", Model: model, Status: http.StatusOK, Outcome: "warning", ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size, Policy: "usage_warning"}) != nil {
		writeError(writer, http.StatusServiceUnavailable, "evidence_unavailable", "warning response could not be recorded")
		return
	}
	writer.Header().Set("Content-Type", contentType)
	if contentType == "text/event-stream" {
		writer.Header().Set("Cache-Control", "no-cache")
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func rawRole(message map[string]json.RawMessage) string {
	var role string
	_ = json.Unmarshal(message["role"], &role)
	return role
}

func messageText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var combined strings.Builder
	for _, block := range blocks {
		var typeName, value string
		_ = json.Unmarshal(block["type"], &typeName)
		_ = json.Unmarshal(block["text"], &value)
		if typeName == "text" {
			combined.WriteString(value)
		}
	}
	return combined.String()
}

func requestStreams(body []byte) bool {
	var payload struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &payload)
	return payload.Stream
}

func warningSSE(message map[string]any, text string) []byte {
	start := make(map[string]any, len(message))
	for key, value := range message {
		start[key] = value
	}
	start["content"] = []any{}
	start["stop_reason"] = nil
	var output bytes.Buffer
	writeEvent := func(event string, value any) {
		encoded, _ := json.Marshal(value)
		output.WriteString("event: " + event + "\ndata: ")
		output.Write(encoded)
		output.WriteString("\n\n")
	}
	writeEvent("message_start", map[string]any{"type": "message_start", "message": start})
	writeEvent("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
	writeEvent("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text}})
	writeEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	writeEvent("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 0}})
	writeEvent("message_stop", map[string]any{"type": "message_stop"})
	return output.Bytes()
}

func (s *Service) WrapResponse(request *http.Request, response *http.Response) {
	tx, _ := request.Context().Value(transactionKey{}).(*transaction)
	if tx == nil {
		return
	}
	response.Body = &captureBody{source: response.Body, max: s.maxBody, finish: func(body []byte, readErr error) {
		outcome := "completed"
		if readErr != nil {
			outcome = "failed"
		}
		s.finish(request.Context(), tx, response.StatusCode, outcome, body)
	}}
}

func (s *Service) Fail(request *http.Request, _ error) {
	if tx, _ := request.Context().Value(transactionKey{}).(*transaction); tx != nil {
		s.finish(request.Context(), tx, 0, "failed", nil)
	}
}

func (s *Service) RecordTool(ctx context.Context, name, toolUseID string, input json.RawMessage, result gatewaytool.Result, duration time.Duration) error {
	tx, _ := ctx.Value(transactionKey{}).(*transaction)
	if tx == nil {
		return fmt.Errorf("tool transaction is missing")
	}
	outcome := "completed"
	if result.IsError {
		outcome = "failed"
	}
	payload, _ := json.Marshal(map[string]any{"input": input, "result": result})
	object, err := s.archive.Put(context.WithoutCancel(ctx), "tool", payload)
	if err != nil {
		return err
	}
	return s.audit.Append(context.WithoutCancel(ctx), audit.Event{
		ID: randomID(), RequestID: tx.id, Type: "tool", Time: time.Now().UTC(), Principal: tx.identity.Principal,
		Session: tx.identity.Session, Agent: tx.identity.Agent, ParentAgent: tx.identity.ParentAgent,
		Username: tx.identity.Username, Hostname: tx.identity.Hostname, Assurance: tx.identity.Assurance,
		Route: tx.route, Model: tx.model, Outcome: outcome, Status: result.Status, LatencyMS: duration.Milliseconds(),
		ToolName: name, ToolUseID: toolUseID, Classification: result.Classification,
		ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size,
	})
}

func (s *Service) finish(ctx context.Context, tx *transaction, status int, outcome string, body []byte) {
	tx.once.Do(func() {
		latency := time.Since(tx.started)
		var object archive.Object
		if len(body) > 0 {
			var archiveErr error
			object, archiveErr = s.archive.Put(context.WithoutCancel(ctx), "response", body)
			if archiveErr != nil {
				outcome = "archive_failed"
			}
		}
		usage := responseUsage(body)
		s.policies.Reconcile(tx.identity.Principal, tx.id, usage.Input+usage.Output+usage.CacheRead+usage.CacheWrite, outcome == "completed" && status >= 200 && status < 300, time.Now().UTC())
		_ = s.audit.Append(context.WithoutCancel(ctx), audit.Event{
			ID: randomID(), RequestID: tx.id, Type: "response", Time: time.Now().UTC(), Principal: tx.identity.Principal,
			Session: tx.identity.Session, Agent: tx.identity.Agent, ParentAgent: tx.identity.ParentAgent,
			Username: tx.identity.Username, Hostname: tx.identity.Hostname, Assurance: tx.identity.Assurance, Route: tx.route,
			Model: tx.model, Status: status, Outcome: outcome, InputTokens: usage.Input, OutputTokens: usage.Output,
			CacheRead: usage.CacheRead, CacheWrite: usage.CacheWrite, LatencyMS: latency.Milliseconds(),
			ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size,
		})
		if s.telemetry != nil {
			s.telemetry.Finish(ctx, outcome, status, latency)
		}
	})
}

type captureBody struct {
	source   io.ReadCloser
	buffer   bytes.Buffer
	max      int64
	once     sync.Once
	overflow bool
	finish   func([]byte, error)
}

func (b *captureBody) Read(target []byte) (int, error) {
	n, err := b.source.Read(target)
	if !b.overflow {
		remaining := b.max - int64(b.buffer.Len())
		keep := int64(n)
		if keep > remaining {
			keep = remaining
			b.overflow = true
		}
		if keep > 0 {
			_, _ = b.buffer.Write(target[:keep])
		}
	}
	if err != nil {
		finishErr := err
		if finishErr == io.EOF {
			finishErr = nil
		}
		if b.overflow {
			finishErr = errResponseCaptureLimit
		}
		b.done(finishErr)
	}
	return n, err
}

func (b *captureBody) Close() error {
	err := b.source.Close()
	finishErr := err
	if b.overflow {
		finishErr = errResponseCaptureLimit
	}
	b.done(finishErr)
	return err
}

func (b *captureBody) done(err error) {
	b.once.Do(func() { b.finish(append([]byte(nil), b.buffer.Bytes()...), err) })
}

type usage struct{ Input, Output, CacheRead, CacheWrite int64 }

func responseUsage(body []byte) usage {
	var result usage
	var payload struct {
		Usage struct {
			Input      int64 `json:"input_tokens"`
			Output     int64 `json:"output_tokens"`
			CacheRead  int64 `json:"cache_read_input_tokens"`
			CacheWrite int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &payload) == nil {
		result = usage{payload.Usage.Input, payload.Usage.Output, payload.Usage.CacheRead, payload.Usage.CacheWrite}
		return result
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if json.Unmarshal(data, &payload) == nil {
			if payload.Usage.Input != 0 {
				result.Input = payload.Usage.Input
			}
			if payload.Usage.Output != 0 {
				result.Output = payload.Usage.Output
			}
			result.CacheRead = payload.Usage.CacheRead
			result.CacheWrite = payload.Usage.CacheWrite
		}
	}
	return result
}

func requestModel(body []byte) string {
	var payload struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &payload)
	if len(payload.Model) > 128 {
		return ""
	}
	return payload.Model
}

func routeName(path string) string {
	if path == "/v1/messages/count_tokens" {
		return "count_tokens"
	}
	return "messages"
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"type": "error", "error": map[string]string{"type": code, "message": message}})
}

func randomID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(fmt.Sprintf("random id: %v", err))
	}
	return hex.EncodeToString(value)
}
