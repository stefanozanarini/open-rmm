-- Policies (one row per version) and their latest results per agent.

ALTER TABLE agents ADD COLUMN os_family text NOT NULL DEFAULT 'unknown';

CREATE TABLE policies (
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    id          uuid NOT NULL,
    version     bigint NOT NULL CHECK (version > 0),
    name        text NOT NULL,
    applies_to  text NOT NULL,
    -- Canonical document as approved, and its signed envelope. A deletion is
    -- a version with deleted = true and no envelope.
    document    bytea,
    envelope    bytea,
    deleted     boolean NOT NULL DEFAULT false,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id, version),
    CHECK (deleted OR (document IS NOT NULL AND envelope IS NOT NULL))
);

CREATE TRIGGER policies_no_update BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION releases_immutable();

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policies
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);

CREATE TABLE policy_results (
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    agent_id       uuid NOT NULL,
    policy_id      uuid NOT NULL,
    rule_id        text NOT NULL,
    policy_version bigint NOT NULL,
    run_id         uuid NOT NULL,
    state          text NOT NULL,
    result         jsonb,
    error          text NOT NULL DEFAULT '',
    started_at     timestamptz NOT NULL,
    finished_at    timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, policy_id, rule_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

ALTER TABLE policy_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policy_results
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
