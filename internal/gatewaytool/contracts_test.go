package gatewaytool

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testTool struct{ calls atomic.Int32 }

func (*testTool) Descriptor() Descriptor {
	return Descriptor{Name: "gaitway__test", Description: "test", InputSchema: json.RawMessage(`{"type":"object"}`), Access: "read-only", Timeout: time.Second, MaxResultBytes: 100}
}

func TestRegistryCoalescesConcurrentExecutions(t *testing.T) {
	tool := &testTool{}
	registry, err := NewRegistry(tool)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 20
	start := make(chan struct{})
	var group sync.WaitGroup
	for range callers {
		group.Go(func() {
			<-start
			result := registry.Execute(t.Context(), "gaitway__test", "same", json.RawMessage(`{"x":1}`))
			if result.IsError || result.Content != "ok" {
				t.Errorf("unexpected result: %+v", result)
			}
		})
	}
	close(start)
	group.Wait()
	if calls := tool.calls.Load(); calls != 1 {
		t.Fatalf("tool executed %d times", calls)
	}
}
func (*testTool) Validate() error { return nil }
func (t *testTool) Execute(context.Context, json.RawMessage) Result {
	t.calls.Add(1)
	return Result{Content: "ok", Classification: "untrusted"}
}

func TestRegistryIsDeterministicAndIdempotent(t *testing.T) {
	tool := &testTool{}
	registry, err := NewRegistry(tool)
	if err != nil {
		t.Fatal(err)
	}
	first := registry.Execute(t.Context(), "gaitway__test", "id", json.RawMessage(`{"x":1}`))
	second := registry.Execute(t.Context(), "gaitway__test", "id", json.RawMessage(`{"x":1}`))
	if first != second || tool.calls.Load() != 1 {
		t.Fatalf("tool was not idempotent: %+v %+v calls=%d", first, second, tool.calls.Load())
	}
	if registry.Descriptors()[0].Name != "gaitway__test" {
		t.Fatal("descriptor ordering changed")
	}
}

func TestRegistryBoundsAndExpiresCompletedRuns(t *testing.T) {
	tool := &testTool{}
	registry, err := NewRegistry(tool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	registry.maxRuns = 1
	registry.runTTL = time.Minute
	registry.now = func() time.Time { return now }

	if result := registry.Execute(t.Context(), "gaitway__test", "first", json.RawMessage(`{"x":1}`)); result.IsError {
		t.Fatalf("first execution failed: %+v", result)
	}
	if result := registry.Execute(t.Context(), "gaitway__test", "second", json.RawMessage(`{"x":2}`)); !result.IsError || result.Classification != "capacity" {
		t.Fatalf("full registry accepted a new execution: %+v", result)
	}
	now = now.Add(time.Minute + 1)
	if result := registry.Execute(t.Context(), "gaitway__test", "second", json.RawMessage(`{"x":2}`)); result.IsError {
		t.Fatalf("expired execution did not free capacity: %+v", result)
	}
}

func TestFingerprinterIsStableAndKeyed(t *testing.T) {
	first, _ := NewFingerprinter([]byte(strings.Repeat("a", 32)))
	second, _ := NewFingerprinter([]byte(strings.Repeat("b", 32)))
	want := first.Fingerprint("Bearer credential")
	if want == "" || first.Fingerprint("Bearer credential") != want {
		t.Fatal("fingerprint is not stable")
	}
	if first.Fingerprint("Bearer another") == want || second.Fingerprint("Bearer credential") == want {
		t.Fatal("fingerprint is not bound to the credential and key")
	}
	if _, err := NewFingerprinter(make([]byte, 31)); err == nil {
		t.Fatal("short fingerprint key was accepted")
	}
}
