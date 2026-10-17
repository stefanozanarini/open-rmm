-- Signed modules and the job queue.

-- Modules are global, signed artifacts with no tenant data, hence no RLS.
-- A published (id, version) is immutable.
CREATE TABLE modules (
    id              text NOT NULL,
    version         text NOT NULL,
    description     text NOT NULL DEFAULT '',
    key_id          text NOT NULL,
    manifest        bytea NOT NULL,
    signature       bytea NOT NULL,
    manifest_sha256 bytea NOT NULL CHECK (length(manifest_sha256) = 32),
    archive         bytea NOT NULL,
    uploaded_at     timestamptz NOT NULL DEFAULT now(),
    uploaded_by     text NOT NULL DEFAULT '',
    PRIMARY KEY (id, version)
);

CREATE FUNCTION modules_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'published modules are immutable; publish a new version';
END;
$$;
CREATE TRIGGER modules_no_update BEFORE UPDATE ON modules
    FOR EACH ROW EXECUTE FUNCTION modules_immutable();

CREATE TABLE jobs (
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    id             uuid NOT NULL,
    agent_id       uuid NOT NULL,
    module         text NOT NULL,
    module_version text NOT NULL,
    action         text NOT NULL,
    params         jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Serialized SignedEnvelope, delivered to the agent as is.
    envelope       bytea NOT NULL,
    state          text NOT NULL CHECK (state IN
                     ('queued', 'sent', 'accepted', 'running', 'succeeded', 'failed', 'rejected', 'expired')),
    progress       smallint NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    message        text NOT NULL DEFAULT '',
    result         jsonb,
    error          text NOT NULL DEFAULT '',
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    sent_at        timestamptz,
    finished_at    timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
    FOREIGN KEY (module, module_version) REFERENCES modules (id, version)
);
CREATE INDEX jobs_dispatch ON jobs (tenant_id, agent_id, created_at) WHERE state IN ('queued', 'sent');
CREATE INDEX jobs_agent ON jobs (tenant_id, agent_id, created_at DESC);

ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON jobs
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
