package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
)

type Resolver struct {
	key    []byte
	mu     sync.RWMutex
	probes map[string]Probe
}

type Probe struct {
	Username string
	Hostname string
}

type Identity struct {
	Principal   string
	Session     string
	Agent       string
	ParentAgent string
	Username    string
	Hostname    string
	Assurance   string
}

func NewResolver(key []byte) (*Resolver, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("identity HMAC key must contain at least 32 bytes")
	}
	return &Resolver{key: append([]byte(nil), key...), probes: make(map[string]Probe)}, nil
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
	probe, ok := r.probes[probeKey(identity.Principal, identity.Session)]
	r.mu.RUnlock()
	if ok {
		identity.Username = probe.Username
		identity.Hostname = probe.Hostname
		identity.Assurance = "trusted-pilot-label"
	}
	return identity
}

func (r *Resolver) RecordProbe(principal, session, username, hostname string) {
	if principal == "" || session == "" {
		return
	}
	r.mu.Lock()
	r.probes[probeKey(principal, session)] = Probe{Username: username, Hostname: hostname}
	r.mu.Unlock()
}

func probeKey(principal, session string) string { return principal + "\x00" + session }

func boundedHeader(value string) string {
	if len(value) > 256 {
		return ""
	}
	return value
}
