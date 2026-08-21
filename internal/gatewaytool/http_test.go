package gatewaytool

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func TestHTTPToolUsesAllowlistAndBounds(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Error("credential missing")
		}
		_, _ = writer.Write([]byte("trusted transport, untrusted content"))
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tool := NewHTTPTool(HTTPConfig{
		AllowedHosts: []string{parsed.Hostname()}, PathPrefixes: []string{"/api"}, BearerToken: "token", AllowPrivate: true,
		Timeout: time.Second, MaxResultBytes: 20, RootCAs: roots,
	})
	if err := tool.Validate(); err != nil {
		t.Fatal(err)
	}
	result := tool.Execute(context.Background(), json.RawMessage(`{"url":"`+server.URL+`/api/data"}`))
	if !result.IsError || result.Classification != "truncated" || len(result.Content) != 20 {
		t.Fatalf("unexpected bounded result: %+v", result)
	}
	blocked := tool.Execute(context.Background(), json.RawMessage(`{"url":"https://example.com/api/data"}`))
	if !blocked.IsError || blocked.Classification != "policy" {
		t.Fatalf("unapproved host was not blocked: %+v", blocked)
	}
	lookalike := tool.Execute(context.Background(), json.RawMessage(`{"url":"`+server.URL+`/apievil"}`))
	if !lookalike.IsError || lookalike.Classification != "policy" {
		t.Fatalf("path-prefix lookalike was not blocked: %+v", lookalike)
	}
}

func TestUnsafeAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "ff02::1"} {
		if !unsafeAddress(netip.MustParseAddr(raw)) {
			t.Errorf("address %s was considered public", raw)
		}
	}
	if unsafeAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address was blocked")
	}
}
