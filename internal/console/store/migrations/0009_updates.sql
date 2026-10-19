-- Latest update report per agent and source (windows, winget).

CREATE TABLE update_status (
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    agent_id     uuid NOT NULL,
    source       text NOT NULL CHECK (source IN ('windows', 'winget')),
    scanned_at   timestamptz NOT NULL,
    data         jsonb NOT NULL,
    managed_by   text NOT NULL DEFAULT 'none',
    important    integer NOT NULL DEFAULT 0,
    other        integer NOT NULL DEFAULT 0,
    oldest_days  integer NOT NULL DEFAULT 0,
    behind       integer NOT NULL DEFAULT 0,
    reboot       boolean NOT NULL DEFAULT false,
    reboot_since timestamptz,
    third_party  integer NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, agent_id, source),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

ALTER TABLE update_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE update_status FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON update_status
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
