package control

import (
	"bytes"
	"context"
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
