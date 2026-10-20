-- Manual site assignment: it takes precedence over subnet matching. Deleting
-- the site puts the agent back on automatic assignment.

CREATE TABLE agent_sites (
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    agent_id    uuid NOT NULL,
    site_id     uuid NOT NULL,
    assigned_by text NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES sites (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE agent_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sites FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_sites
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
