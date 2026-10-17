-- Operator web sessions. Only the SHA-256 of the session id is stored, so a
-- database dump cannot be used to hijack sessions.
CREATE TABLE web_sessions (
    id_hash    bytea PRIMARY KEY CHECK (length(id_hash) = 32),
    data       jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX web_sessions_expiry ON web_sessions (expires_at);
