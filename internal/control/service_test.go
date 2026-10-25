package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gaitway/internal/archive"
	"gaitway/internal/audit"
	"gaitway/internal/banner"
	"gaitway/internal/identity"
	"gaitway/internal/plugin"
	"gaitway/internal/proxy"
)

type failingAudit struct{}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func (failingAudit) Append(context.Context, audit.Event) error {
	return errors.New("audit unavailable")
}
func (failingAudit) List(context.Context, int) ([]audit.Event, error) {
	return nil, errors.New("audit unavailable")
}

func TestServiceArchivesAndAuditsWithoutCredential(t *testing.T) {
	root := t.TempDir()
	objects, _ := archive.NewFilesystem(filepath.Join(root, "content"))
	events, _ := audit.NewJSONLStore(filepath.Join(root, "audit.jsonl"))
	resolver, _ := identity.NewResolver([]byte(strings.Repeat("k", 32)))
	policies, _ := plugin.NewEngine(time.Second, plugin.NewSecretScanner(plugin.Reject))
	controller := NewService(objects, events, resolver, policies, 1<<20)

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"content":[{"type":"text","text":"OK"}],"usage":{"input_tokens":3,"output_tokens":1}}`)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	handler, err := proxy.NewHandler(proxy.Config{
		Upstream: upstreamURL,
		Banner:   banner.NewTransformer("active", banner.NewRegistry(10), 1<<20, 8<<20),
		Hooks:    controller,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(handler)
	defer gateway.Close()

	body := []byte(`{"model":"claude-test","messages":[]}`)
	request, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/messages", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer credential-canary")
	request.Header.Set("x-claude-code-session-id", "session")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()

	var listed []audit.Event
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		listed, err = events.List(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(listed) != 2 || listed[0].Type != "response" || listed[0].InputTokens != 3 || listed[0].OutputTokens != 1 {
		t.Fatalf("unexpected audit events: %+v", listed)
	}
	logBytes, _ := os.ReadFile(filepath.Join(root, "audit.jsonl"))
	if bytes.Contains(logBytes, []byte("credential-canary")) {
		t.Fatal("credential leaked to audit log")
	}
	requestBytes, err := objects.Read(context.Background(), listed[1].ContentRef)
	if err != nil || !bytes.Equal(requestBytes, body) {
		t.Fatalf("request archive mismatch: %q %v", requestBytes, err)
	}
}

func TestResponseUsageReadsStreamingStartAndEnd(t *testing.T) {
	body := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"usage":{"input_tokens":7,"cache_read_input_tokens":11,"cache_creation_input_tokens":13}}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":17}}` + "\n\n")
	got := responseUsage(body)
	want := usage{Input: 7, Output: 17, CacheRead: 11, CacheWrite: 13}
	if got != want {
		t.Fatalf("usage = %+v, want %+v", got, want)
	}
}

func TestServiceRejectsSecretWithoutArchivingBody(t *testing.T) {
	root := t.TempDir()
	objects, _ := archive.NewFilesystem(filepath.Join(root, "content"))
	events, _ := audit.NewJSONLStore(filepath.Join(root, "audit.jsonl"))
	resolver, _ := identity.NewResolver([]byte(strings.Repeat("k", 32)))
	policies, _ := plugin.NewEngine(time.Second, plugin.NewSecretScanner(plugin.Reject))
	service := NewService(objects, events, resolver, policies, 1<<20)
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"message":"AKIA1234567890ABCDEF"}`))
	response := httptest.NewRecorder()
	_, ok := service.Prepare(response, request)
	if ok || response.Code != 422 {
		t.Fatalf("secret request not rejected: %d", response.Code)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "content", "*", "*", "*.bin"))
	if len(matches) != 0 {
		t.Fatal("prohibited request body was archived")
	}
}

func TestServiceForwardsAndArchivesRedactedCard(t *testing.T) {
	root := t.TempDir()
	objects, _ := archive.NewFilesystem(filepath.Join(root, "content"))
	events, _ := audit.NewJSONLStore(filepath.Join(root, "audit.jsonl"))
	resolver, _ := identity.NewResolver([]byte(strings.Repeat("k", 32)))
	policies, _ := plugin.NewEngine(time.Second, plugin.NewCardScanner(plugin.Redact, nil))
	service := NewService(objects, events, resolver, policies, 1<<20)
	send := func() (*http.Request, *httptest.ResponseRecorder, bool) {
		request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"message":"4539148803436467"}`))
		request.Header.Set("x-claude-code-session-id", "session")
		response := httptest.NewRecorder()
		prepared, ok := service.Prepare(response, request)
		return prepared, response, ok
	}
	prepared, _, ok := send()
	if !ok {
		t.Fatal("card request rejected")
	}
	forwarded, _ := io.ReadAll(prepared.Body)
	if string(forwarded) != `{"message":"[REDACTED: real card number ending 6467]"}` || prepared.ContentLength != int64(len(forwarded)) {
		t.Fatalf("forwarded body not masked: %q length=%d", forwarded, prepared.ContentLength)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "content", "*", "*", "*.bin"))
	for _, match := range matches {
		if contents, _ := os.ReadFile(match); bytes.Contains(contents, []byte("4539148803436467")) {
			t.Fatal("unmasked card was archived")
		}
	}
	if len(matches) == 0 {
		t.Fatal("masked request was not archived")
	}
}

func TestCardRedactionNoticeReachesUser(t *testing.T) {
	root := t.TempDir()
	objects, _ := archive.NewFilesystem(filepath.Join(root, "content"))
	events, _ := audit.NewJSONLStore(filepath.Join(root, "audit.jsonl"))
	resolver, _ := identity.NewResolver([]byte(strings.Repeat("k", 32)))
	policies, _ := plugin.NewEngine(time.Second, plugin.NewCardScanner(plugin.Redact, nil))
	controller := NewService(objects, events, resolver, policies, 1<<20)

	responses := []string{
		`{"content":[{"type":"tool_use","id":"t","name":"Read","input":{}}],"usage":{"input_tokens":1,"output_tokens":1}}`,
		`{"content":[{"type":"text","text":"OK"}],"usage":{"input_tokens":1,"output_tokens":1}}`,
		`{"content":[{"type":"text","text":"OK"}],"usage":{"input_tokens":1,"output_tokens":1}}`,
	}
	var forwarded []string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		forwarded = append(forwarded, string(body))
		writer.Header().Set("Content-Type", "application/json")
		// Claude Code accepts gzip, and Anthropic uses it when allowed.
		if strings.Contains(request.Header.Get("Accept-Encoding"), "gzip") {
			writer.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(writer)
			_, _ = io.WriteString(compressed, responses[len(forwarded)-1])
			_ = compressed.Close()
			return
		}
		_, _ = io.WriteString(writer, responses[len(forwarded)-1])
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	transformer := banner.NewTransformer("", banner.NewRegistry(10), 1<<20, 8<<20)
	controller.SetBanner(transformer)
	handler, err := proxy.NewHandler(proxy.Config{
		Upstream: upstreamURL,
		Banner:   transformer,
		Hooks:    controller,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(handler)
	defer gateway.Close()
	send := func(messages string) (int, string) {
		body := `{"model":"claude-test","messages":[` + messages + `]}`
		request, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/messages", strings.NewReader(body))
		request.Header.Set("x-claude-code-session-id", "session")
		request.Header.Set("Accept-Encoding", "gzip")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		reader := io.Reader(response.Body)
		if response.Header.Get("Content-Encoding") == "gzip" {
			if reader, err = gzip.NewReader(response.Body); err != nil {
				t.Fatal(err)
			}
		}
		text, _ := io.ReadAll(reader)
		return response.StatusCode, string(text)
	}

	notice := `{"type":"text","text":"> **⚠ Gaitway:** ` + "`Credit card number ending in 6467 was redacted before sending to the model`" + `"}`
	first := `{"role":"user","content":"card 4539148803436467"}`
	// The notice is its own first block, so even a tool-only reply carries it.
	if status, body := send(first); status != 200 || !strings.HasPrefix(body, `{"content":[`+notice+`,{"type":"tool_use"`) {
		t.Fatalf("notice missing from tool response: %d %s", status, body)
	}
	// History replays the annotated reply, as Claude Code does; the card is
	// no longer in the newest message, so nothing is announced.
	history := first + `,{"role":"assistant","content":[` + notice + `,{"type":"text","text":"OK"}]}`
	if _, body := send(history + `,{"role":"user","content":"next"}`); strings.Contains(body, "Gaitway") {
		t.Fatalf("history-only card announced: %s", body)
	}
	if _, body := send(history + `,{"role":"user","content":"again 4539148803436467"}`); !strings.Contains(body, notice) {
		t.Fatalf("repeated card not announced: %s", body)
	}
	for _, body := range forwarded {
		if strings.Contains(body, "4539148803436467") || !strings.Contains(body, "[REDACTED: real card number ending 6467]") {
			t.Fatalf("card not redacted upstream: %s", body)
		}
		if strings.Contains(body, "Gaitway") {
			t.Fatalf("injected notice sent upstream: %s", body)
		}
	}
}

func TestServiceClosesConsumedRequestBody(t *testing.T) {
	service := &Service{maxBody: 1}
	body := &closeTrackingBody{Reader: strings.NewReader(`{}`)}
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	request.Body = body
	response := httptest.NewRecorder()
	if _, ok := service.Prepare(response, request); ok || response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request was not rejected: status=%d", response.Code)
	}
	if !body.closed {
		t.Fatal("consumed request body was not closed")
	}
}

func TestAcknowledgementStateIsBoundedAndExpires(t *testing.T) {
	service := &Service{
		acks: make(map[string]ackState), maxAcks: 1,
		ackTTL: time.Minute, now: time.Now,
	}
	now := time.Now()
	service.now = func() time.Time { return now }
	if !service.rememberAcknowledgement("first", ackState{marker: "one"}) {
		t.Fatal("first acknowledgement was rejected")
	}
	if service.rememberAcknowledgement("second", ackState{marker: "two"}) {
		t.Fatal("acknowledgement state exceeded its capacity")
	}
	now = now.Add(time.Minute + 1)
	if !service.rememberAcknowledgement("second", ackState{marker: "two"}) {
		t.Fatal("expired acknowledgement did not release capacity")
	}
}

func TestUsageWarningRequiresVisibleAcknowledgement(t *testing.T) {
	root := t.TempDir()
	objects, _ := archive.NewFilesystem(filepath.Join(root, "content"))
	events, _ := audit.NewJSONLStore(filepath.Join(root, "audit.jsonl"))
	resolver, _ := identity.NewResolver([]byte(strings.Repeat("k", 32)))
	policies, _ := plugin.NewEngine(time.Second, plugin.NewBudgetPolicy(time.Hour, 1, 10_000, ""))
	service := NewService(objects, events, resolver, policies, 1<<20)
	body := `{"model":"claude-test","stream":false,"messages":[{"role":"user","content":"hello"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer credential")
	request.Header.Set("x-claude-code-session-id", "session")
	response := httptest.NewRecorder()
	if _, ok := service.Prepare(response, request); ok || response.Code != http.StatusOK {
		t.Fatalf("warning did not pause request: status=%d", response.Code)
	}
	var warning map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &warning); err != nil {
		t.Fatal(err)
	}
	var warningBlocks []map[string]json.RawMessage
	_ = json.Unmarshal(warning["content"], &warningBlocks)
	warningText := messageText(warning["content"])
	if !strings.Contains(warningText, "ACKNOWLEDGE") {
		t.Fatalf("warning is not visible: %s", response.Body.Bytes())
	}
	warningContent, _ := json.Marshal(warningBlocks)
	continuationBody := `{"model":"claude-test","stream":false,"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":` + string(warningContent) + `},{"role":"user","content":"ACKNOWLEDGE"}]}`
	continuation := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(continuationBody))
	continuation.Header = request.Header.Clone()
	continued := httptest.NewRecorder()
	normalized, ok := service.Prepare(continued, continuation)
	if !ok {
		t.Fatalf("acknowledgement was not accepted: %s", continued.Body.String())
	}
	normalizedBody, _ := io.ReadAll(normalized.Body)
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(normalizedBody, &payload)
	var messages []map[string]json.RawMessage
	_ = json.Unmarshal(payload["messages"], &messages)
	if len(messages) != 1 || rawRole(messages[0]) != "user" {
		t.Fatalf("warning exchange reached upstream: %s", payload["messages"])
	}
}

func TestAllowedRequestFailsClosedWhenAuditIsUnavailable(t *testing.T) {
	objects, _ := archive.NewFilesystem(t.TempDir())
	resolver, _ := identity.NewResolver([]byte(strings.Repeat("k", 32)))
	policies, _ := plugin.NewEngine(time.Second)
	service := NewService(objects, failingAudit{}, resolver, policies, 1<<20)
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"claude-test","messages":[]}`))
	request.Header.Set("Authorization", "Bearer credential")
	response := httptest.NewRecorder()
	if _, ok := service.Prepare(response, request); ok || response.Code != http.StatusServiceUnavailable {
		t.Fatalf("request escaped failed audit store: status=%d", response.Code)
	}
}

func TestActivationEligibilityExcludesClaudeSessionTitles(t *testing.T) {
	title := []byte(`{"system":[{"type":"text","text":"You are Claude Code."},{"type":"text","text":"You are naming a coding session so the user can pick it out of a long list of sessions."}],"messages":[]}`)
	if activationEligible(title) {
		t.Fatal("session-title request could consume the visible activation marker")
	}
	main := []byte(`{"system":[{"type":"text","text":"You are Claude Code, an interactive coding agent."}],"messages":[]}`)
	if !activationEligible(main) {
		t.Fatal("user-facing request was excluded from activation")
	}
	if !activationEligible([]byte(`{"future":true}`)) {
		t.Fatal("unknown future request shape was excluded from activation")
	}
}
