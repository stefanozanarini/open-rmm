-- Latest inventory per agent and the history of its changes.

CREATE TABLE inventories (
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    agent_id       uuid NOT NULL,
    collected_at   timestamptz NOT NULL,
    received_at    timestamptz NOT NULL DEFAULT now(),
    data           jsonb NOT NULL,
    -- Columns shown in agent lists, extracted from data.
    manufacturer   text NOT NULL DEFAULT '',
    model          text NOT NULL DEFAULT '',
    serial         text NOT NULL DEFAULT '',
    logged_on_user text NOT NULL DEFAULT '',
    supremo_id     text NOT NULL DEFAULT '',
    anydesk_id     text NOT NULL DEFAULT '',
    teamviewer_id  text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

ALTER TABLE inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventories FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON inventories
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);

CREATE TABLE inventory_changes (
    seq        bigserial PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    agent_id   uuid NOT NULL,
    at         timestamptz NOT NULL,
    kind       text NOT NULL,
    detail     text NOT NULL,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

CREATE INDEX inventory_changes_agent ON inventory_changes (tenant_id, agent_id, seq DESC);

ALTER TABLE inventory_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON inventory_changes
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
