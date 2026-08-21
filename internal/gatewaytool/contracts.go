package gatewaytool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Descriptor struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	InputSchema    json.RawMessage `json:"input_schema"`
	Access         string          `json:"access"`
	Timeout        time.Duration   `json:"-"`
	MaxResultBytes int64           `json:"-"`
}

type Result struct {
	Content        string `json:"content"`
	IsError        bool   `json:"is_error"`
	Classification string `json:"classification"`
	Status         int    `json:"status,omitempty"`
}

type ToolResult struct {
	ToolUseID string `json:"tool_use_id"`
	ToolName  string `json:"tool_name"`
	Result    Result `json:"result"`
}

type Tool interface {
	Descriptor() Descriptor
	Validate() error
	Execute(context.Context, json.RawMessage) Result
}

type Registry struct {
	tools map[string]Tool
	names []string
	mu    sync.Mutex
	runs  map[string]*toolRun
}

type toolRun struct {
	done   chan struct{}
	result Result
}

func NewRegistry(tools ...Tool) (*Registry, error) {
	registry := &Registry{tools: make(map[string]Tool), runs: make(map[string]*toolRun)}
	for _, tool := range tools {
		if tool == nil {
			return nil, fmt.Errorf("nil gateway tool")
		}
		descriptor := tool.Descriptor()
		if !strings.HasPrefix(descriptor.Name, "gaitway__") {
			return nil, fmt.Errorf("gateway tool %q must use gaitway__ prefix", descriptor.Name)
		}
		if _, exists := registry.tools[descriptor.Name]; exists {
			return nil, fmt.Errorf("duplicate gateway tool %q", descriptor.Name)
		}
		if descriptor.Access != "read-only" || descriptor.Timeout <= 0 || descriptor.MaxResultBytes <= 0 {
			return nil, fmt.Errorf("gateway tool %q has unsafe descriptor", descriptor.Name)
		}
		if err := tool.Validate(); err != nil {
			return nil, fmt.Errorf("gateway tool %q: %w", descriptor.Name, err)
		}
		registry.tools[descriptor.Name] = tool
		registry.names = append(registry.names, descriptor.Name)
	}
	sort.Strings(registry.names)
	return registry, nil
}

func (r *Registry) Descriptors() []Descriptor {
	result := make([]Descriptor, 0, len(r.names))
	for _, name := range r.names {
		descriptor := r.tools[name].Descriptor()
		descriptor.InputSchema = append(json.RawMessage(nil), descriptor.InputSchema...)
		result = append(result, descriptor)
	}
	return result
}

func (r *Registry) Contains(name string) bool {
	_, ok := r.tools[name]
	return ok
}

// Start begins a replay-safe execution without delaying the caller. A later
// Execute with the same inputs waits for and reuses this result.
func (r *Registry) Start(name, idempotencyKey string, input json.RawMessage) {
	go r.Execute(context.Background(), name, idempotencyKey, input)
}

func (r *Registry) Execute(ctx context.Context, name, idempotencyKey string, input json.RawMessage) Result {
	tool, exists := r.tools[name]
	if !exists {
		return Result{Content: "gateway tool is not registered", IsError: true, Classification: "internal"}
	}
	if idempotencyKey == "" {
		return Result{Content: "gateway tool idempotency key is required", IsError: true, Classification: "internal"}
	}
	digest := sha256.Sum256(append([]byte(name+"\x00"+idempotencyKey+"\x00"), input...))
	key := hex.EncodeToString(digest[:])
	r.mu.Lock()
	if existing, ok := r.runs[key]; ok {
		r.mu.Unlock()
		select {
		case <-existing.done:
			return existing.result
		case <-ctx.Done():
			return Result{Content: "gateway tool request was cancelled", IsError: true, Classification: "internal"}
		}
	}
	run := &toolRun{done: make(chan struct{})}
	r.runs[key] = run
	r.mu.Unlock()

	descriptor := tool.Descriptor()
	toolContext, cancel := context.WithTimeout(ctx, descriptor.Timeout)
	defer cancel()
	resultChannel := make(chan Result, 1)
	go func() {
		defer func() {
			if recover() != nil {
				resultChannel <- Result{Content: "gateway tool failed", IsError: true, Classification: "internal"}
			}
		}()
		resultChannel <- tool.Execute(toolContext, append(json.RawMessage(nil), input...))
	}()
	var result Result
	select {
	case result = <-resultChannel:
	case <-toolContext.Done():
		result = Result{Content: "gateway tool timed out", IsError: true, Classification: "internal"}
	}
	if int64(len(result.Content)) > descriptor.MaxResultBytes {
		result.Content = result.Content[:descriptor.MaxResultBytes]
		result.IsError = true
		result.Classification = "truncated"
	}
	r.mu.Lock()
	run.result = result
	close(run.done)
	r.mu.Unlock()
	return result
}
