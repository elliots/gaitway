package control

import (
	"bytes"
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
	matches, _ := filepath.Glob(filepath.Join(root, "content", "*", "*", "*", "*.bin"))
	if len(matches) != 0 {
		t.Fatal("prohibited request body was archived")
	}
}

func TestUsageWarningRequiresVisibleAcknowledgement(t *testing.T) {
	root := t.TempDir()
	objects, _ := archive.NewFilesystem(filepath.Join(root, "content"))
	events, _ := audit.NewJSONLStore(filepath.Join(root, "audit.jsonl"))
	resolver, _ := identity.NewResolver([]byte(strings.Repeat("k", 32)))
	policies, _ := plugin.NewEngine(time.Second, plugin.NewBudgetPolicy(time.Hour, 1, 10_000))
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
