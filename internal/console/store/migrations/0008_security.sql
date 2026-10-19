-- Tenant settings, check results reported by modules, alerts and logon events.

CREATE TABLE tenant_settings (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants(id),
    settings   jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL
);

CREATE TABLE agent_checks (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    agent_id   uuid NOT NULL,
    check_id   text NOT NULL,
    status     text NOT NULL CHECK (status IN ('ok', 'warning', 'failing')),
    summary    text NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, check_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

CREATE TABLE alerts (
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    id              uuid NOT NULL,
    agent_id        uuid NOT NULL,
    severity        text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    kind            text NOT NULL,
    summary         text NOT NULL,
    -- Open alerts with the same key are merged (count, last_seen).
    dedupe_key      text NOT NULL,
    count           integer NOT NULL DEFAULT 1,
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    acknowledged_at timestamptz,
    acknowledged_by text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

CREATE UNIQUE INDEX alerts_open_key ON alerts (tenant_id, dedupe_key) WHERE acknowledged_at IS NULL;
CREATE INDEX alerts_recent ON alerts (tenant_id, last_seen DESC);

CREATE TABLE logon_events (
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    agent_id    uuid NOT NULL,
    channel     text NOT NULL,
    record_id   bigint NOT NULL,
    at          timestamptz NOT NULL,
    event_id    integer NOT NULL,
    kind        text NOT NULL,
    username    text NOT NULL,
    domain      text NOT NULL,
    logon_type  integer NOT NULL,
    source_ip   text NOT NULL,
    source_host text NOT NULL,
    status      text NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, channel, record_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

CREATE INDEX logon_events_recent ON logon_events (tenant_id, agent_id, at DESC);
CREATE INDEX logon_events_source ON logon_events (tenant_id, agent_id, username, source_ip);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_settings', 'agent_checks', 'alerts', 'logon_events'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)$p$, t);
    END LOOP;
END $$;
