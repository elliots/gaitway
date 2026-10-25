package postgres

import (
	"os"
	"strings"
	"testing"
	"time"

	"gaitway/internal/audit"
)

func TestMigrationDefinesSearchIndexes(t *testing.T) {
	for _, required := range []string{
		"gaitway_audit_events", "occurred_at DESC", "principal", "session_id", "request_id", "jsonb",
	} {
		if !strings.Contains(migration, required) {
			t.Fatalf("migration missing %q", required)
		}
	}
}

func TestPostgresIntegration(t *testing.T) {
	databaseURL := os.Getenv("GAITWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set GAITWAY_TEST_DATABASE_URL to run the PostgreSQL test")
	}
	store, err := New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := "test-" + time.Now().UTC().Format("20060102150405.000000000")
	event := audit.Event{ID: id, RequestID: id, Type: "identity", Time: time.Now().UTC(), Principal: "principal", Session: "session", AccountID: "account", OrganizationID: "organization", Email: "person@example.com", DisplayName: "Person", FullName: "Person Example", Assurance: "test", Outcome: "observed"}
	if err := store.Append(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	events, err := store.List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range events {
		if candidate.ID == id {
			if candidate.AccountID != "account" || candidate.OrganizationID != "organization" || candidate.Email != "person@example.com" || candidate.DisplayName != "Person" || candidate.FullName != "Person Example" {
				t.Fatalf("identity projection lost: %+v", candidate)
			}
			return
		}
	}
	t.Fatal("inserted event not found")
}
