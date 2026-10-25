package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gaitway/internal/audit"
)

func TestProfileLookupRunsOncePerTokenAndStoresProfileWithoutToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/api/oauth/profile" || !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
			t.Fatalf("unexpected profile request: %s %s", request.Method, request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"account":{"uuid":"account-123","email":"private@example.com","display_name":"Private Person","full_name":"Private Person Example"},"organization":{"uuid":"org-456"}}`))
	}))
	defer server.Close()

	upstream, _ := url.Parse(server.URL)
	resolver, _ := NewResolver([]byte(strings.Repeat("k", 32)))
	events, _ := audit.NewJSONLStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	lookup, err := NewProfileLookup(upstream, nil, resolver, events)
	if err != nil {
		t.Fatal(err)
	}

	header := make(http.Header)
	header.Set("Authorization", "Bearer token-one")
	header.Set("x-claude-code-session-id", "session-one")
	if err := lookup.Enrich(t.Context(), header); err != nil {
		t.Fatal(err)
	}
	header.Set("x-claude-code-session-id", "session-two")
	if err := lookup.Enrich(t.Context(), header); err != nil {
		t.Fatal(err)
	}
	identity := resolver.Resolve(header)
	if identity.AccountID != "account-123" || identity.OrganizationID != "org-456" || identity.Email != "private@example.com" || identity.DisplayName != "Private Person" || identity.FullName != "Private Person Example" || identity.Assurance != "anthropic-oauth-profile" {
		t.Fatalf("profile was not attached: %+v", identity)
	}
	if calls.Load() != 1 {
		t.Fatalf("profile endpoint called %d times for one token", calls.Load())
	}

	header.Set("Authorization", "Bearer token-two")
	if err := lookup.Enrich(t.Context(), header); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("second token did not get its own lookup: %d", calls.Load())
	}
	recorded, _ := events.List(t.Context(), 10)
	encoded, _ := json.Marshal(recorded)
	if len(recorded) != 2 || !strings.Contains(string(encoded), "private@example.com") || !strings.Contains(string(encoded), "Private Person") || strings.Contains(string(encoded), "token-one") {
		t.Fatalf("unsafe profile evidence: %s", encoded)
	}
}

func TestProfileLookupCoalescesConcurrentRequestsForOneToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = writer.Write([]byte(`{"account":{"uuid":"account-123","email":"person@example.com"},"organization":{"uuid":"org-456"}}`))
	}))
	defer server.Close()

	upstream, _ := url.Parse(server.URL)
	resolver, _ := NewResolver([]byte(strings.Repeat("k", 32)))
	events, _ := audit.NewJSONLStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	lookup, err := NewProfileLookup(upstream, nil, resolver, events)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 20
	start := make(chan struct{})
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			<-start
			header := make(http.Header)
			header.Set("Authorization", "Bearer shared-token")
			errors <- lookup.Enrich(t.Context(), header)
		})
	}
	close(start)
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("profile endpoint called %d times for concurrent requests", calls.Load())
	}
}

func TestProfileLookupExpiresNegativeResult(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	upstream, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	events, err := audit.NewJSONLStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := NewProfileLookup(upstream, nil, resolver, events)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	lookup.now = func() time.Time { return now }
	lookup.negativeTTL = time.Minute
	header := http.Header{"Authorization": {"Bearer unavailable-token"}}

	if err := lookup.Enrich(t.Context(), header); err != nil {
		t.Fatal(err)
	}
	if err := lookup.Enrich(t.Context(), header); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("negative result was not cached: %d calls", calls.Load())
	}
	now = now.Add(time.Minute + 1)
	if err := lookup.Enrich(t.Context(), header); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expired negative result was not retried: %d calls", calls.Load())
	}
}
