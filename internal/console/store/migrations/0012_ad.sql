-- Active Directory computer lists, one per domain, reported by the
-- adinventory module.

CREATE TABLE ad_domains (
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    domain       text NOT NULL,
    agent_id     uuid NOT NULL,
    collected_at timestamptz NOT NULL,
    data         jsonb NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

ALTER TABLE ad_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE ad_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ad_domains
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
