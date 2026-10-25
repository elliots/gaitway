package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"gaitway/internal/archive"
	"gaitway/internal/audit"
	"gaitway/internal/banner"
	"gaitway/internal/gatewaytool"
	"gaitway/internal/identity"
	"gaitway/internal/plugin"
)

var errResponseCaptureLimit = fmt.Errorf("response exceeded archive capture limit")

const (
	defaultMaxAcknowledgements = 10_000
	defaultAcknowledgementTTL  = 10 * time.Minute
	defaultMaxNotices          = 10_000
	defaultNoticeTTL           = time.Hour
)

type Service struct {
	archive   archive.Store
	audit     audit.Store
	identity  *identity.Resolver
	profiles  *identity.ProfileLookup
	banner    *banner.Transformer
	policies  *plugin.Engine
	maxBody   int64
	telemetry Telemetry
	ackMu     sync.Mutex
	acks      map[string]ackState
	maxAcks   int
	ackTTL    time.Duration
	noticeMu  sync.Mutex
	notices   map[string]pendingNotice
	now       func() time.Time
}

// pendingNotice holds policy notices until a response shows them to the user.
type pendingNotice struct {
	texts     []string
	expiresAt time.Time
}

func (s *Service) SetProfileLookup(profiles *identity.ProfileLookup) { s.profiles = profiles }

// SetBanner lets the service strip text the banner injected into earlier
// responses before history is evaluated and sent upstream.
func (s *Service) SetBanner(transformer *banner.Transformer) { s.banner = transformer }

type ackState struct {
	marker    string
	message   string
	expiresAt time.Time
}

type Telemetry interface {
	Begin(context.Context, string) context.Context
	Finish(context.Context, string, int, time.Duration)
}

type transactionKey struct{}

type transaction struct {
	once               sync.Once
	id                 string
	identity           identity.Identity
	route              string
	model              string
	started            time.Time
	requestRef         archive.Object
	activationEligible bool
	noticeKey          string
}

func NewService(objects archive.Store, events audit.Store, resolver *identity.Resolver, policies *plugin.Engine, maxBody int64, telemetry ...Telemetry) *Service {
	service := &Service{
		archive: objects, audit: events, identity: resolver, policies: policies, maxBody: maxBody,
		acks: make(map[string]ackState), maxAcks: defaultMaxAcknowledgements,
		notices: make(map[string]pendingNotice),
		ackTTL:  defaultAcknowledgementTTL, now: time.Now,
	}
	if len(telemetry) > 0 {
		service.telemetry = telemetry[0]
	}
	return service
}

func (s *Service) Prepare(writer http.ResponseWriter, request *http.Request) (*http.Request, bool) {
	requestBody := io.Reader(http.NoBody)
	if request.Body != nil {
		requestBody = request.Body
	}
	body, readErr := io.ReadAll(io.LimitReader(requestBody, s.maxBody+1))
	var closeErr error
	if request.Body != nil {
		closeErr = request.Body.Close()
	}
	var maxBytesErr *http.MaxBytesError
	if errors.As(readErr, &maxBytesErr) || int64(len(body)) > s.maxBody {
		writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "request exceeds gateway limit")
		return request, false
	}
	if readErr != nil || closeErr != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request body could not be read")
		return request, false
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if s.profiles != nil {
		if err := s.profiles.Enrich(request.Context(), request.Header); err != nil {
			writeError(writer, http.StatusServiceUnavailable, "identity_unavailable", "Anthropic identity could not be recorded")
			return request, false
		}
	}
	identityValue := s.identity.Resolve(request.Header)
	body, acknowledged, pending := s.consumeAcknowledgement(body, identityValue.Principal, identityValue.Session)
	if pending != nil && !acknowledged {
		object, archiveErr := s.archive.Put(request.Context(), "acknowledgement", body)
		if archiveErr != nil || s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: randomID(), Type: "acknowledgement", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, AccountID: identityValue.AccountID, OrganizationID: identityValue.OrganizationID, Email: identityValue.Email, DisplayName: identityValue.DisplayName, FullName: identityValue.FullName, Assurance: identityValue.Assurance, Outcome: "required", ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size}) != nil {
			writeError(writer, http.StatusServiceUnavailable, "evidence_unavailable", "acknowledgement evidence could not be recorded")
			return request, false
		}
		s.writeWarning(writer, request, *pending)
		return request, false
	}
	if s.banner != nil {
		body = s.banner.StripInjected(body)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	model := requestModel(body)
	route := routeName(request.URL.Path)
	id := randomID()
	eligible := activationEligible(body)
	decision := s.policies.Evaluate(request.Context(), plugin.Request{ID: id, Principal: identityValue.Principal, Session: identityValue.Session, Route: route, Model: model, Body: body, Now: time.Now().UTC(), Acknowledged: acknowledged, Background: !eligible})
	if acknowledged {
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "acknowledgement", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, AccountID: identityValue.AccountID, OrganizationID: identityValue.OrganizationID, Email: identityValue.Email, DisplayName: identityValue.DisplayName, FullName: identityValue.FullName, Assurance: identityValue.Assurance, Outcome: "accepted", Policy: "usage-budget"}) != nil {
			s.policies.Reconcile(identityValue.Principal, id, 0, false, time.Now().UTC())
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "request audit could not be recorded")
			return request, false
		}
	}
	for _, finding := range decision.Findings {
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "policy", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, AccountID: identityValue.AccountID, OrganizationID: identityValue.OrganizationID, Email: identityValue.Email, DisplayName: identityValue.DisplayName, FullName: identityValue.FullName, Route: route, Model: model, Policy: finding.Plugin, Rule: finding.Rule, Finding: finding.Masked}) != nil {
			s.policies.Reconcile(identityValue.Principal, id, 0, false, time.Now().UTC())
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "policy audit could not be recorded")
			return request, false
		}
	}
	if decision.Action == plugin.Reject {
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, AccountID: identityValue.AccountID, OrganizationID: identityValue.OrganizationID, Email: identityValue.Email, DisplayName: identityValue.DisplayName, FullName: identityValue.FullName, Assurance: identityValue.Assurance, Route: route, Model: model, Outcome: "rejected", Policy: decision.Code}) != nil {
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "rejection audit could not be recorded")
			return request, false
		}
		writeError(writer, decision.Status, decision.Code, decision.Message)
		return request, false
	}
	if decision.Body != nil {
		body = decision.Body
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
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
		key := ackKey(identityValue.Principal, identityValue.Session)
		if !s.rememberAcknowledgement(key, state) {
			writeError(writer, http.StatusServiceUnavailable, "acknowledgement_capacity", "usage acknowledgement capacity reached")
			return request, false
		}
		if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, AccountID: identityValue.AccountID, OrganizationID: identityValue.OrganizationID, Email: identityValue.Email, DisplayName: identityValue.DisplayName, FullName: identityValue.FullName, Assurance: identityValue.Assurance, Route: route, Model: model, Outcome: "warning", ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size, Policy: decision.Code}) != nil {
			s.forgetAcknowledgement(key, state.marker)
			writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "warning audit could not be recorded")
			return request, false
		}
		s.writeWarning(writer, request, state)
		return request, false
	}
	requestContext := request.Context()
	if s.telemetry != nil {
		requestContext = s.telemetry.Begin(requestContext, route)
	}
	tx := &transaction{
		id: id, identity: identityValue, route: route, model: model,
		started: time.Now().UTC(), requestRef: object,
		activationEligible: eligible,
		noticeKey:          "\x00" + id,
	}
	if identityValue.Session != "" {
		tx.noticeKey = ackKey(identityValue.Principal, identityValue.Session)
	}
	s.queueNotices(tx.noticeKey, decision.Notices)
	if s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: tx.started, Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, AccountID: identityValue.AccountID, OrganizationID: identityValue.OrganizationID, Email: identityValue.Email, DisplayName: identityValue.DisplayName, FullName: identityValue.FullName, Assurance: identityValue.Assurance, Route: route, Model: model, Outcome: string(decision.Action), ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size, Policy: decision.Code}) != nil {
		s.policies.Reconcile(identityValue.Principal, id, 0, false, time.Now().UTC())
		writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "request audit could not be recorded")
		return request, false
	}
	return request.WithContext(context.WithValue(requestContext, transactionKey{}, tx)), true
}

// NoticePending reports whether the response to this request should carry
// policy notices, so the proxy can request an uncompressed body.
func (s *Service) NoticePending(request *http.Request) bool {
	_, pending := s.pendingNotice(request)
	return pending
}

// ResponseNotice returns pending policy notices for the user-facing response
// to this request. Notices stay pending until done reports them written, so
// a response without a text block passes them to the next one.
func (s *Service) ResponseNotice(request *http.Request) (string, func(bool)) {
	pending, ok := s.pendingNotice(request)
	if !ok {
		return "", nil
	}
	tx := request.Context().Value(transactionKey{}).(*transaction)
	texts := slices.Clone(pending.texts)
	return banner.Notice(texts), func(emitted bool) {
		if !emitted {
			return
		}
		s.noticeMu.Lock()
		defer s.noticeMu.Unlock()
		if current, ok := s.notices[tx.noticeKey]; ok {
			current.texts = slices.DeleteFunc(current.texts, func(text string) bool { return slices.Contains(texts, text) })
			if len(current.texts) == 0 {
				delete(s.notices, tx.noticeKey)
			} else {
				s.notices[tx.noticeKey] = current
			}
		}
	}
}

func (s *Service) pendingNotice(request *http.Request) (pendingNotice, bool) {
	tx, _ := request.Context().Value(transactionKey{}).(*transaction)
	if tx == nil || tx.route != "messages" || !tx.activationEligible {
		return pendingNotice{}, false
	}
	s.noticeMu.Lock()
	pending, ok := s.notices[tx.noticeKey]
	s.noticeMu.Unlock()
	return pending, ok && pending.expiresAt.After(s.now())
}

func (s *Service) queueNotices(key string, texts []string) {
	if len(texts) == 0 {
		return
	}
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	if s.notices == nil {
		s.notices = make(map[string]pendingNotice)
	}
	now := s.now()
	pending, exists := s.notices[key]
	if !exists && len(s.notices) >= defaultMaxNotices {
		maps.DeleteFunc(s.notices, func(_ string, current pendingNotice) bool { return !current.expiresAt.After(now) })
		if len(s.notices) >= defaultMaxNotices {
			return
		}
	}
	for _, text := range texts {
		if !slices.Contains(pending.texts, text) {
			pending.texts = append(pending.texts, text)
		}
	}
	pending.expiresAt = now.Add(defaultNoticeTTL)
	s.notices[key] = pending
}

// ActivationEligible distinguishes user-facing Claude work from invisible
// metadata calls that share the same Claude session header.
func (s *Service) ActivationEligible(request *http.Request) bool {
	tx, _ := request.Context().Value(transactionKey{}).(*transaction)
	return tx == nil || tx.activationEligible
}

func activationEligible(body []byte) bool {
	const titleInstruction = "You are naming a coding session"
	var payload struct {
		System json.RawMessage `json:"system"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return true
	}
	var plain string
	if json.Unmarshal(payload.System, &plain) == nil {
		return !strings.Contains(plain, titleInstruction)
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(payload.System, &blocks) != nil {
		return true
	}
	for _, block := range blocks {
		if block.Type == "text" && strings.Contains(block.Text, titleInstruction) {
			return false
		}
	}
	return true
}

func (s *Service) consumeAcknowledgement(body []byte, principal, session string) ([]byte, bool, *ackState) {
	s.ackMu.Lock()
	key := ackKey(principal, session)
	state, pending := s.acks[key]
	if pending && !state.expiresAt.After(s.now()) {
		delete(s.acks, key)
		pending = false
	}
	s.ackMu.Unlock()
	if !pending {
		return body, false, nil
	}
	var payload map[string]json.RawMessage
	var messages []map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil || json.Unmarshal(payload["messages"], &messages) != nil {
		return body, false, &state
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
		return body, false, &state
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
		return body, false, &state
	}
	s.ackMu.Lock()
	delete(s.acks, key)
	s.ackMu.Unlock()
	return normalized, true, &state
}

func (s *Service) rememberAcknowledgement(key string, state ackState) bool {
	s.ackMu.Lock()
	defer s.ackMu.Unlock()
	now := s.now()
	if _, exists := s.acks[key]; !exists && len(s.acks) >= s.maxAcks {
		maps.DeleteFunc(s.acks, func(_ string, current ackState) bool { return !current.expiresAt.After(now) })
		if len(s.acks) >= s.maxAcks {
			return false
		}
	}
	state.expiresAt = now.Add(s.ackTTL)
	s.acks[key] = state
	return true
}

func (s *Service) forgetAcknowledgement(key, marker string) {
	s.ackMu.Lock()
	if state, exists := s.acks[key]; exists && state.marker == marker {
		delete(s.acks, key)
	}
	s.ackMu.Unlock()
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
	if archiveErr != nil || s.audit.Append(context.WithoutCancel(request.Context()), audit.Event{ID: randomID(), RequestID: randomID(), Type: "response", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, AccountID: identityValue.AccountID, OrganizationID: identityValue.OrganizationID, Email: identityValue.Email, DisplayName: identityValue.DisplayName, FullName: identityValue.FullName, Assurance: identityValue.Assurance, Route: "messages", Model: model, Status: http.StatusOK, Outcome: "warning", ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size, Policy: "usage_warning"}) != nil {
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
	start := maps.Clone(message)
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
		Assurance: tx.identity.Assurance, AccountID: tx.identity.AccountID, OrganizationID: tx.identity.OrganizationID,
		Email: tx.identity.Email, DisplayName: tx.identity.DisplayName, FullName: tx.identity.FullName,
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
			AccountID: tx.identity.AccountID, OrganizationID: tx.identity.OrganizationID,
			Email: tx.identity.Email, DisplayName: tx.identity.DisplayName, FullName: tx.identity.FullName, Assurance: tx.identity.Assurance, Route: tx.route,
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
		if errors.Is(finishErr, io.EOF) {
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
	b.once.Do(func() { b.finish(slices.Clone(b.buffer.Bytes()), err) })
}

type usage struct{ Input, Output, CacheRead, CacheWrite int64 }

type usagePayload struct {
	Input      int64 `json:"input_tokens"`
	Output     int64 `json:"output_tokens"`
	CacheRead  int64 `json:"cache_read_input_tokens"`
	CacheWrite int64 `json:"cache_creation_input_tokens"`
}

func responseUsage(body []byte) usage {
	var result usage
	var payload struct {
		Usage   usagePayload `json:"usage"`
		Message struct {
			Usage usagePayload `json:"usage"`
		} `json:"message"`
	}
	if json.Unmarshal(body, &payload) == nil {
		mergeUsage(&result, payload.Message.Usage)
		mergeUsage(&result, payload.Usage)
		return result
	}
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if json.Unmarshal(data, &payload) == nil {
			mergeUsage(&result, payload.Message.Usage)
			mergeUsage(&result, payload.Usage)
		}
	}
	return result
}

func mergeUsage(result *usage, current usagePayload) {
	if current.Input != 0 {
		result.Input = current.Input
	}
	if current.Output != 0 {
		result.Output = current.Output
	}
	if current.CacheRead != 0 {
		result.CacheRead = current.CacheRead
	}
	if current.CacheWrite != 0 {
		result.CacheWrite = current.CacheWrite
	}
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
	return rand.Text()
}
