package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type Event struct {
	ID             string    `json:"id"`
	RequestID      string    `json:"request_id"`
	Type           string    `json:"type"`
	Time           time.Time `json:"time"`
	Principal      string    `json:"principal,omitempty"`
	Session        string    `json:"session,omitempty"`
	Agent          string    `json:"agent,omitempty"`
	ParentAgent    string    `json:"parent_agent,omitempty"`
	AccountID      string    `json:"anthropic_account_id,omitempty"`
	OrganizationID string    `json:"anthropic_organization_id,omitempty"`
	Email          string    `json:"anthropic_email,omitempty"`
	DisplayName    string    `json:"anthropic_display_name,omitempty"`
	FullName       string    `json:"anthropic_full_name,omitempty"`
	Assurance      string    `json:"identity_assurance,omitempty"`
	Route          string    `json:"route,omitempty"`
	Model          string    `json:"model,omitempty"`
	Status         int       `json:"status,omitempty"`
	Outcome        string    `json:"outcome,omitempty"`
	InputTokens    int64     `json:"input_tokens,omitempty"`
	OutputTokens   int64     `json:"output_tokens,omitempty"`
	CacheRead      int64     `json:"cache_read_tokens,omitempty"`
	CacheWrite     int64     `json:"cache_write_tokens,omitempty"`
	LatencyMS      int64     `json:"latency_ms,omitempty"`
	ContentRef     string    `json:"content_ref,omitempty"`
	ContentSHA     string    `json:"content_sha256,omitempty"`
	ContentSize    int64     `json:"content_size,omitempty"`
	Policy         string    `json:"policy,omitempty"`
	Rule           string    `json:"rule,omitempty"`
	Finding        string    `json:"finding,omitempty"`
	ToolName       string    `json:"tool_name,omitempty"`
	ToolUseID      string    `json:"tool_use_id,omitempty"`
	Classification string    `json:"classification,omitempty"`
}

type Store interface {
	Append(context.Context, Event) error
	List(context.Context, int) ([]Event, error)
}

type JSONLStore struct {
	mu   sync.Mutex
	path string
}

func NewJSONLStore(path string) (*JSONLStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &JSONLStore{path: path}, file.Close()
}

func (s *JSONLStore) Append(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func (s *JSONLStore) List(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	s.mu.Lock()
	data, err := os.ReadFile(s.path)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	lines := bytesLines(data)
	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}
	result := make([]Event, 0, len(lines)-start)
	for _, line := range lines[start:] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("decode audit log: %w", err)
		}
		result = append(result, event)
	}
	slices.Reverse(result)
	return result, nil
}

func bytesLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for index, value := range data {
		if value == '\n' {
			if index > start {
				lines = append(lines, data[start:index])
			}
			start = index + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
