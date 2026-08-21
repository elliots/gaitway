package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFilesystemRoundTrip(t *testing.T) {
	store, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("raw prompt bytes")
	object, err := store.Put(context.Background(), "request", body)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if object.SHA256 != hex.EncodeToString(digest[:]) || object.Size != int64(len(body)) {
		t.Fatalf("bad metadata: %+v", object)
	}
	got, err := store.Read(context.Background(), object.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q", got)
	}
	if _, err := store.Read(context.Background(), "../../etc/passwd"); err == nil {
		t.Fatal("unsafe reference was accepted")
	}
}
