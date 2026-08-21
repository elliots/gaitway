package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
)

type Resolver struct{ key []byte }

type Identity struct {
	Principal   string
	Session     string
	Agent       string
	ParentAgent string
}

func NewResolver(key []byte) (*Resolver, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("identity HMAC key must contain at least 32 bytes")
	}
	return &Resolver{key: append([]byte(nil), key...)}, nil
}

func (r *Resolver) Resolve(header http.Header) Identity {
	authorization := header.Get("Authorization")
	principal := "anonymous"
	if authorization != "" {
		mac := hmac.New(sha256.New, r.key)
		_, _ = mac.Write([]byte(authorization))
		principal = hex.EncodeToString(mac.Sum(nil)[:16])
	}
	return Identity{
		Principal:   principal,
		Session:     boundedHeader(header.Get("x-claude-code-session-id")),
		Agent:       boundedHeader(header.Get("x-claude-code-agent-id")),
		ParentAgent: boundedHeader(header.Get("x-claude-code-parent-agent-id")),
	}
}

func boundedHeader(value string) string {
	if len(value) > 256 {
		return ""
	}
	return value
}
