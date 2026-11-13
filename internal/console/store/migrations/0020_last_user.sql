-- Last user seen on each agent (inventory or interactive logon), kept while
-- nobody is logged on or the computer is offline.

CREATE TABLE agent_last_user (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    agent_id  uuid NOT NULL,
    username  text NOT NULL,
    seen_at   timestamptz NOT NULL,
    source    text NOT NULL CHECK (source IN ('inventory', 'logon')),
    PRIMARY KEY (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

ALTER TABLE agent_last_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_last_user FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_last_user
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
