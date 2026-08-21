CREATE TABLE IF NOT EXISTS gaitway_audit_events (
    id text PRIMARY KEY,
    request_id text NOT NULL,
    event_type text NOT NULL,
    occurred_at timestamptz NOT NULL,
    principal text NOT NULL DEFAULT '',
    session_id text NOT NULL DEFAULT '',
    route text NOT NULL DEFAULT '',
    model text NOT NULL DEFAULT '',
    outcome text NOT NULL DEFAULT '',
    content_ref text NOT NULL DEFAULT '',
	username text NOT NULL DEFAULT '',
	hostname text NOT NULL DEFAULT '',
	identity_assurance text NOT NULL DEFAULT '',
    data jsonb NOT NULL
);

ALTER TABLE gaitway_audit_events ADD COLUMN IF NOT EXISTS username text NOT NULL DEFAULT '';
ALTER TABLE gaitway_audit_events ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT '';
ALTER TABLE gaitway_audit_events ADD COLUMN IF NOT EXISTS identity_assurance text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS gaitway_audit_events_time_idx
    ON gaitway_audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS gaitway_audit_events_principal_time_idx
    ON gaitway_audit_events (principal, occurred_at DESC);
CREATE INDEX IF NOT EXISTS gaitway_audit_events_session_time_idx
    ON gaitway_audit_events (session_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS gaitway_audit_events_request_idx
    ON gaitway_audit_events (request_id, occurred_at);
CREATE INDEX IF NOT EXISTS gaitway_audit_events_username_time_idx
    ON gaitway_audit_events (username, occurred_at DESC);
CREATE INDEX IF NOT EXISTS gaitway_audit_events_hostname_time_idx
    ON gaitway_audit_events (hostname, occurred_at DESC);
