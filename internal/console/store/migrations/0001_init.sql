-- open-rmm initial schema.
--
-- Tenant isolation: tables holding tenant data enable and FORCE row-level
-- security, so even the table owner only sees rows of the tenant set with
--   SELECT set_config('openrmm.tenant_id', '<uuid>', true)
-- inside the current transaction.

CREATE TABLE tenants (
    id          uuid PRIMARY KEY,
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Enrollment tokens are looked up by hash before the tenant is known, so this
-- table is not under RLS. The clear-text token is never stored.
CREATE TABLE enrollment_tokens (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    token_hash  bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    description text NOT NULL DEFAULT '',
    max_uses    integer NOT NULL CHECK (max_uses > 0),
    uses        integer NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    tenant_id          uuid NOT NULL REFERENCES tenants(id),
    id                 uuid NOT NULL,
    status             text NOT NULL CHECK (status IN ('active', 'revoked')),
    hostname           text NOT NULL DEFAULT '',
    os                 text NOT NULL DEFAULT '',
    os_version         text NOT NULL DEFAULT '',
    arch               text NOT NULL DEFAULT '',
    agent_version      text NOT NULL DEFAULT '',
    machine_id         text NOT NULL DEFAULT '',
    cert_fingerprint   text NOT NULL,
    cert_not_after     timestamptz NOT NULL,
    enrolled_at        timestamptz NOT NULL DEFAULT now(),
    enrolled_token_id  uuid REFERENCES enrollment_tokens(id),
    last_seen_at       timestamptz,
    last_seen_ip       inet,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX agents_machine_id ON agents (tenant_id, machine_id);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);

-- Append-only audit log with a per-tenant hash chain:
--   hash = SHA-256(prev_hash || canonical event bytes)
-- computed by the application. UPDATE and DELETE are rejected by trigger.
CREATE TABLE audit_log (
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    seq         bigint NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor       text NOT NULL,
    action      text NOT NULL,
    target      text NOT NULL DEFAULT '',
    details     jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   bytea NOT NULL CHECK (length(prev_hash) = 32),
    hash        bytea NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (tenant_id, seq)
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_log
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);

CREATE FUNCTION audit_log_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();
