package identity

import (
	"net/http"
	"strings"
	"testing"
)

func TestResolverFingerprintsWithoutRetainingCredential(t *testing.T) {
	resolver, err := NewResolver([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer top-secret")
	header.Set("x-claude-code-session-id", "session")
	header.Set("x-claude-code-agent-id", "agent")
	header.Set("x-claude-code-parent-agent-id", "parent")
	first := resolver.Resolve(header)
	second := resolver.Resolve(header)
	if first.Principal != second.Principal || first.Principal == "" || strings.Contains(first.Principal, "secret") {
		t.Fatalf("unsafe or unstable principal: %q", first.Principal)
	}
	if first.Session != "session" || first.Agent != "agent" || first.ParentAgent != "parent" {
		t.Fatalf("lineage not captured: %+v", first)
	}
	resolver.RecordProfile(first.Principal, Profile{AccountID: "account-123", OrganizationID: "org-456", Email: "person@example.com", DisplayName: "Person", FullName: "Person Example"})
	profiled := resolver.Resolve(header)
	if profiled.AccountID != "account-123" || profiled.OrganizationID != "org-456" || profiled.Email != "person@example.com" || profiled.DisplayName != "Person" || profiled.FullName != "Person Example" || profiled.Assurance != "anthropic-oauth-profile" {
		t.Fatalf("profile mapping missing: %+v", profiled)
	}
	header.Set("Authorization", "Bearer another-secret")
	if resolver.Resolve(header).Principal == first.Principal {
		t.Fatal("different credentials produced same test fingerprint")
	}
}
