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
	"sync"
	"time"

	"gaitway/internal/archive"
	"gaitway/internal/audit"
	"gaitway/internal/identity"
	"gaitway/internal/plugin"
)

type Service struct {
	archive  archive.Store
	audit    audit.Store
	identity *identity.Resolver
	policies *plugin.Engine
	maxBody  int64
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

func NewService(objects archive.Store, events audit.Store, resolver *identity.Resolver, policies *plugin.Engine, maxBody int64) *Service {
	return &Service{archive: objects, audit: events, identity: resolver, policies: policies, maxBody: maxBody}
}

func (s *Service) Prepare(writer http.ResponseWriter, request *http.Request) (*http.Request, bool) {
	body, err := io.ReadAll(io.LimitReader(request.Body, s.maxBody+1))
	if err != nil || int64(len(body)) > s.maxBody {
		writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "request exceeds gateway limit")
		return request, false
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	identityValue := s.identity.Resolve(request.Header)
	model := requestModel(body)
	route := routeName(request.URL.Path)
	decision := s.policies.Evaluate(request.Context(), plugin.Request{Principal: identityValue.Principal, Route: route, Model: model, Body: body, Now: time.Now().UTC()})
	id := randomID()
	for _, finding := range decision.Findings {
		_ = s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "policy", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Route: route, Model: model, Policy: finding.Plugin, Rule: finding.Rule, Finding: finding.Masked})
	}
	if decision.Action == plugin.Reject {
		_ = s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: time.Now().UTC(), Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, Route: route, Model: model, Outcome: "rejected", Policy: decision.Code})
		writeError(writer, decision.Status, decision.Code, decision.Message)
		return request, false
	}
	object, err := s.archive.Put(request.Context(), "request", body)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "archive_unavailable", "request evidence could not be recorded")
		return request, false
	}
	tx := &transaction{id: id, identity: identityValue, route: route, model: model, started: time.Now().UTC(), requestRef: object}
	_ = s.audit.Append(request.Context(), audit.Event{ID: randomID(), RequestID: id, Type: "request", Time: tx.started, Principal: identityValue.Principal, Session: identityValue.Session, Agent: identityValue.Agent, ParentAgent: identityValue.ParentAgent, Route: route, Model: model, Outcome: string(decision.Action), ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size, Policy: decision.Code})
	return request.WithContext(context.WithValue(request.Context(), transactionKey{}, tx)), true
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

func (s *Service) finish(ctx context.Context, tx *transaction, status int, outcome string, body []byte) {
	tx.once.Do(func() {
		var object archive.Object
		if len(body) > 0 {
			object, _ = s.archive.Put(context.WithoutCancel(ctx), "response", body)
		}
		usage := responseUsage(body)
		_ = s.audit.Append(context.WithoutCancel(ctx), audit.Event{
			ID: randomID(), RequestID: tx.id, Type: "response", Time: time.Now().UTC(), Principal: tx.identity.Principal,
			Session: tx.identity.Session, Agent: tx.identity.Agent, ParentAgent: tx.identity.ParentAgent, Route: tx.route,
			Model: tx.model, Status: status, Outcome: outcome, InputTokens: usage.Input, OutputTokens: usage.Output,
			CacheRead: usage.CacheRead, CacheWrite: usage.CacheWrite, LatencyMS: time.Since(tx.started).Milliseconds(),
			ContentRef: object.Ref, ContentSHA: object.SHA256, ContentSize: object.Size,
		})
	})
}

type captureBody struct {
	source io.ReadCloser
	buffer bytes.Buffer
	max    int64
	once   sync.Once
	finish func([]byte, error)
}

func (b *captureBody) Read(target []byte) (int, error) {
	n, err := b.source.Read(target)
	if int64(b.buffer.Len()+n) <= b.max {
		_, _ = b.buffer.Write(target[:n])
	}
	if err != nil {
		finishErr := err
		if finishErr == io.EOF {
			finishErr = nil
		}
		b.done(finishErr)
	}
	return n, err
}

func (b *captureBody) Close() error {
	err := b.source.Close()
	b.done(err)
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
