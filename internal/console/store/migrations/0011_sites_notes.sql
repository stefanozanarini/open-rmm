-- Sites (recognized by subnet) and operator notes on agents.

CREATE TABLE sites (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    id         uuid NOT NULL,
    name       text NOT NULL,
    subnets    text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE agent_notes (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    id         uuid NOT NULL,
    agent_id   uuid NOT NULL,
    body       text NOT NULL,
    author     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

CREATE INDEX agent_notes_agent ON agent_notes (tenant_id, agent_id, created_at DESC);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sites', 'agent_notes'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)$p$, t);
    END LOOP;
END $$;

-- IPv4 addresses of the agent's adapters, from the inventory (site matching).
ALTER TABLE inventories ADD COLUMN ipv4 text[] NOT NULL DEFAULT '{}';
