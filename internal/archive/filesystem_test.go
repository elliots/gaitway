package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemRoundTrip(t *testing.T) {
	store, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("raw prompt bytes")
	object, err := store.Put(t.Context(), "request", body)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if object.SHA256 != hex.EncodeToString(digest[:]) || object.Size != int64(len(body)) {
		t.Fatalf("bad metadata: %+v", object)
	}
	wantPath := filepath.Join(store.root, object.Ref[:2], object.Ref[2:4], object.Ref+".bin")
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("object was not written to its directly addressable path: %v", err)
	}
	got, err := store.Read(t.Context(), object.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q", got)
	}
	if _, err := store.Read(t.Context(), "../../etc/passwd"); err == nil {
		t.Fatal("unsafe reference was accepted")
	}
}

func TestFilesystemReadsLegacyDatePartition(t *testing.T) {
	store, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.Repeat("a", 32)
	legacyDirectory := filepath.Join(store.root, "2026", "08", "23")
	if err := os.MkdirAll(legacyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDirectory, ref+".bin"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := store.Read(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "legacy" {
		t.Fatalf("legacy body = %q", body)
	}
}
