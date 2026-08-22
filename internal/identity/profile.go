package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gaitway/internal/audit"
)

const maxProfileResponseBytes = 64 << 10

type ProfileLookup struct {
	client   *http.Client
	endpoint string
	resolver *Resolver
	events   audit.Store
	mu       sync.Mutex
	attempts map[string]*profileAttempt
}

type profileAttempt struct {
	done chan struct{}
	err  error
}

func NewProfileLookup(upstream *url.URL, transport http.RoundTripper, resolver *Resolver, events audit.Store) (*ProfileLookup, error) {
	if upstream == nil || resolver == nil || events == nil {
		return nil, fmt.Errorf("profile upstream, identity resolver, and audit store are required")
	}
	endpoint := upstream.ResolveReference(&url.URL{Path: "/api/oauth/profile"})
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &ProfileLookup{
		client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		endpoint: endpoint.String(), resolver: resolver, events: events, attempts: make(map[string]*profileAttempt),
	}, nil
}

func (l *ProfileLookup) Enrich(ctx context.Context, header http.Header) error {
	authorization := header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil
	}
	identity := l.resolver.Resolve(header)
	if l.resolver.HasProfile(identity.Principal) {
		return nil
	}

	l.mu.Lock()
	if attempt, exists := l.attempts[identity.Principal]; exists {
		l.mu.Unlock()
		select {
		case <-attempt.done:
			return attempt.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	attempt := &profileAttempt{done: make(chan struct{})}
	l.attempts[identity.Principal] = attempt
	l.mu.Unlock()

	attempt.err = l.lookup(ctx, authorization, identity)
	close(attempt.done)
	return attempt.err
}

func (l *ProfileLookup) lookup(ctx context.Context, authorization string, identity Identity) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, l.endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-cache")
	response, err := l.client.Do(request)
	if err != nil {
		return l.record(ctx, identity, Profile{}, 0, "unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProfileResponseBytes))
		return l.record(ctx, identity, Profile{}, response.StatusCode, "unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProfileResponseBytes+1))
	if err != nil || len(body) > maxProfileResponseBytes {
		return l.record(ctx, identity, Profile{}, response.StatusCode, "unavailable")
	}
	var payload struct {
		Account struct {
			UUID        string `json:"uuid"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			FullName    string `json:"full_name"`
		} `json:"account"`
		Organization struct {
			UUID string `json:"uuid"`
		} `json:"organization"`
	}
	if json.Unmarshal(body, &payload) != nil || !safeProfileID(payload.Account.UUID) || !safeProfileID(payload.Organization.UUID) {
		return l.record(ctx, identity, Profile{}, response.StatusCode, "unavailable")
	}
	profile := Profile{
		AccountID: payload.Account.UUID, OrganizationID: payload.Organization.UUID,
		Email: boundedProfileText(payload.Account.Email, 320), DisplayName: boundedProfileText(payload.Account.DisplayName, 256), FullName: boundedProfileText(payload.Account.FullName, 256),
	}
	if err := l.record(ctx, identity, profile, response.StatusCode, "observed"); err != nil {
		return err
	}
	l.resolver.RecordProfile(identity.Principal, profile)
	return nil
}

func (l *ProfileLookup) record(ctx context.Context, identity Identity, profile Profile, status int, outcome string) error {
	return l.events.Append(context.WithoutCancel(ctx), audit.Event{
		ID: randomProfileID(), RequestID: randomProfileID(), Type: "identity", Time: time.Now().UTC(),
		Principal: identity.Principal, Session: identity.Session, Agent: identity.Agent, ParentAgent: identity.ParentAgent,
		AccountID: profile.AccountID, OrganizationID: profile.OrganizationID, Email: profile.Email,
		DisplayName: profile.DisplayName, FullName: profile.FullName,
		Assurance: "anthropic-oauth-profile", Status: status, Outcome: outcome,
	})
}

func randomProfileID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

func boundedProfileText(value string, limit int) string {
	if value == "" || len(value) > limit {
		return ""
	}
	for _, char := range value {
		if char < ' ' || char == '\u007f' {
			return ""
		}
	}
	return value
}

func safeProfileID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}
