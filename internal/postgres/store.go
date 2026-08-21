package postgres

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"gaitway/internal/audit"
)

//go:embed migrations/001_init.sql
var migration string

type Store struct{ pool *pgxpool.Pool }

func New(ctx context.Context, databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	config.MaxConns = 10
	config.MinIdleConns = 1
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 15 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, migration); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Append(ctx context.Context, event audit.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
        INSERT INTO gaitway_audit_events
			(id, request_id, event_type, occurred_at, principal, session_id, route, model, outcome, content_ref, username, hostname, identity_assurance, data)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ON CONFLICT (id) DO NOTHING`,
		event.ID, event.RequestID, event.Type, event.Time, event.Principal, event.Session,
		event.Route, event.Model, event.Outcome, event.ContentRef, event.Username, event.Hostname, event.Assurance, data)
	return err
}

func (s *Store) List(ctx context.Context, limit int) ([]audit.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT data FROM gaitway_audit_events ORDER BY occurred_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]audit.Event, 0, limit)
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var event audit.Event
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

var _ audit.Store = (*Store)(nil)
