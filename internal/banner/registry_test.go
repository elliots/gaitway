package banner

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestRegistryClaimsOnce(t *testing.T) {
	registry := NewRegistry(10)
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 50 {
		group.Add(1)
		go func() {
			defer group.Done()
			if registry.Claim("session") {
				winners.Add(1)
			}
		}()
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("got %d claim winners, want 1", winners.Load())
	}
	registry.MarkEmitted("session")
	registry.Release("session")
	if registry.Claim("session") {
		t.Fatal("emitted session became claimable")
	}
}

func TestRegistryReleaseAndCapacity(t *testing.T) {
	registry := NewRegistry(1)
	if !registry.Claim("first") {
		t.Fatal("first claim failed")
	}
	if registry.Claim("second") {
		t.Fatal("capacity limit was ignored")
	}
	registry.Release("first")
	if !registry.Claim("second") {
		t.Fatal("released claim did not free capacity")
	}
}
