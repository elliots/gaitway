package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"gaitway/internal/banner"
)

func TestStreamingMessagesPassesThroughAndActivatesOnce(t *testing.T) {
	var attempts atomic.Int32
	requestBody := []byte(`{"model":"claude-test","unknown":{"future":true}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		if request.Method != http.MethodPost || request.URL.RequestURI() != "/v1/messages?beta=true" {
			t.Errorf("unexpected upstream request: %s %s", request.Method, request.URL.RequestURI())
		}
		if request.Header.Get("Authorization") != "Bearer secret-canary" {
			t.Error("authorization was not forwarded")
		}
		body, _ := io.ReadAll(request.Body)
		if !bytes.Equal(body, requestBody) {
			t.Errorf("request body changed: %s", body)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("X-Future-Header", "kept")
		_, _ = io.WriteString(writer, testSSE)
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL, "*** Gaitway Active ***")
	defer gateway.Close()

	for run := range 2 {
		request, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/messages?beta=true", bytes.NewReader(requestBody))
		request.Header.Set("Authorization", "Bearer secret-canary")
		request.Header.Set("x-claude-code-session-id", "11111111-1111-1111-1111-111111111111")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		count := strings.Count(string(body), `"text":"*** Gaitway Active ***\n\n"`)
		if run == 0 && count != 1 {
			t.Fatalf("first response marker count %d: %s", count, body)
		}
		if run == 1 && count != 0 {
			t.Fatalf("second response marker count %d: %s", count, body)
		}
		if response.Header.Get("X-Future-Header") != "kept" {
			t.Fatal("unknown response header was lost")
		}
	}
	if attempts.Load() != 2 {
		t.Fatalf("upstream attempts = %d, want 2", attempts.Load())
	}
}

func TestCountTokensIsAlwaysPassive(t *testing.T) {
	original := `{"input_tokens":7,"future":true}`
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, original)
	}))
	defer upstream.Close()
	gateway := newTestGateway(t, upstream.URL, "active")
	defer gateway.Close()

	request, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/messages/count_tokens", strings.NewReader(`{"messages":[]}`))
	request.Header.Set("x-claude-code-session-id", "session")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != original {
		t.Fatalf("count response changed: %s", body)
	}
}

func TestUpstreamErrorIsUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(writer, `{"type":"error","future":"keep me"}`)
	}))
	defer upstream.Close()
	gateway := newTestGateway(t, upstream.URL, "active")
	defer gateway.Close()

	request, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/messages", strings.NewReader(`{}`))
	request.Header.Set("x-claude-code-session-id", "session")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests || string(body) != `{"type":"error","future":"keep me"}` {
		t.Fatalf("upstream error changed: %d %s", response.StatusCode, body)
	}
}

func TestLocalRoutes(t *testing.T) {
	var attempts atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { attempts.Add(1) }))
	defer upstream.Close()
	gateway := newTestGateway(t, upstream.URL, "")
	defer gateway.Close()

	checks := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodHead, "/api/hello", http.StatusNoContent},
		{http.MethodGet, "/v1/messages", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/models", http.StatusNotFound},
	}
	for _, check := range checks {
		request, _ := http.NewRequest(check.method, gateway.URL+check.path, nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != check.status {
			t.Errorf("%s %s status = %d, want %d", check.method, check.path, response.StatusCode, check.status)
		}
	}
	if attempts.Load() != 0 {
		t.Fatalf("unsupported routes reached upstream %d times", attempts.Load())
	}
}

func newTestGateway(t *testing.T, upstreamURL, message string) *httptest.Server {
	t.Helper()
	parsed, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(Config{
		Upstream:        parsed,
		Banner:          banner.NewTransformer(message, banner.NewRegistry(100), 1<<20, 8<<20),
		MaxRequestBytes: 32 << 20,
		MaxSessionBytes: 256,
		Logger:          logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(handler)
}

const testSSE = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{}}\n\n" +
	"event: content_block_start\n" +
	"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"OK\"}}\n\n" +
	"event: message_stop\n" +
	"data: {\"type\":\"message_stop\"}\n\n"
