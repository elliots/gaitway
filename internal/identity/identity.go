package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"sync"
)

type Resolver struct {
	key      []byte
	mu       sync.RWMutex
	profiles map[string]Profile
}

type Profile struct {
	AccountID      string
	OrganizationID string
	Email          string
	DisplayName    string
	FullName       string
}

type Identity struct {
	Principal      string
	Session        string
	Agent          string
	ParentAgent    string
	AccountID      string
	OrganizationID string
	Email          string
	DisplayName    string
	FullName       string
	Assurance      string
}

func NewResolver(key []byte) (*Resolver, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("identity HMAC key must contain at least 32 bytes")
	}
	return &Resolver{key: slices.Clone(key), profiles: make(map[string]Profile)}, nil
}

func (r *Resolver) Resolve(header http.Header) Identity {
	authorization := header.Get("Authorization")
	principal := "anonymous"
	if authorization != "" {
		mac := hmac.New(sha256.New, r.key)
		_, _ = mac.Write([]byte(authorization))
		principal = hex.EncodeToString(mac.Sum(nil)[:16])
	}
	identity := Identity{
		Principal:   principal,
		Session:     boundedHeader(header.Get("x-claude-code-session-id")),
		Agent:       boundedHeader(header.Get("x-claude-code-agent-id")),
		ParentAgent: boundedHeader(header.Get("x-claude-code-parent-agent-id")),
	}
	r.mu.RLock()
	profile, hasProfile := r.profiles[identity.Principal]
	r.mu.RUnlock()
	if hasProfile {
		identity.AccountID = profile.AccountID
		identity.OrganizationID = profile.OrganizationID
		identity.Email = profile.Email
		identity.DisplayName = profile.DisplayName
		identity.FullName = profile.FullName
		identity.Assurance = "anthropic-oauth-profile"
	}
	return identity
}

func (r *Resolver) RecordProfile(principal string, profile Profile) {
	if principal == "" || profile.AccountID == "" || profile.OrganizationID == "" {
		return
	}
	r.mu.Lock()
	r.profiles[principal] = profile
	r.mu.Unlock()
}

func (r *Resolver) HasProfile(principal string) bool {
	r.mu.RLock()
	_, ok := r.profiles[principal]
	r.mu.RUnlock()
	return ok
}

func boundedHeader(value string) string {
	if len(value) > 256 {
		return ""
	}
	return value
}
