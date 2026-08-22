package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gaitway/internal/archive"
	"gaitway/internal/audit"
)

func TestDashboardEscapesDataAndWarnsAboutAuth(t *testing.T) {
	server, events, _ := testServer(t)
	_ = events.Append(context.Background(), audit.Event{ID: "1", Type: "request", Time: time.Now(), Email: "person@example.com", FullName: "Person Example", Model: `<script>alert(1)</script>`, Outcome: "allow"})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	body := response.Body.String()
	if strings.Contains(body, `<script>alert(1)</script>`) || !strings.Contains(body, "No application authentication") || !strings.Contains(body, "person@example.com") || !strings.Contains(body, "Person Example") {
		t.Fatalf("unsafe or missing warning: %s", body)
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
}

func TestRawContentIsInertAndAudited(t *testing.T) {
	server, events, objects := testServer(t)
	object, _ := objects.Put(context.Background(), "response", []byte(`<script>alert(1)</script>`))
	request := httptest.NewRequest(http.MethodGet, "/api/content/"+object.Ref, nil)
	request.SetPathValue("ref", object.Ref)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Header().Get("Content-Type") != "text/plain; charset=utf-8" || response.Body.String() != `<script>alert(1)</script>` {
		t.Fatal("raw content was not rendered inertly")
	}
	listed, _ := events.List(context.Background(), 10)
	if len(listed) != 1 || listed[0].Type != "raw_access" {
		t.Fatalf("raw access not audited: %+v", listed)
	}
}

func TestDashboardRejectsWrites(t *testing.T) {
	server, _, _ := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader("x"))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("write status = %d", response.Code)
	}
}

func testServer(t *testing.T) (*Server, *audit.JSONLStore, *archive.Filesystem) {
	t.Helper()
	root := t.TempDir()
	events, err := audit.NewJSONLStore(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := archive.NewFilesystem(filepath.Join(root, "content"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(events, objects)
	if err != nil {
		t.Fatal(err)
	}
	return server, events, objects
}
