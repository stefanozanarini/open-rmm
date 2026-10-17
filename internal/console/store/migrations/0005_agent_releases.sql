-- Signed agent releases and rollout by ring.

CREATE TABLE agent_releases (
    version      text NOT NULL,
    platform     text NOT NULL,
    key_id       text NOT NULL,
    manifest     bytea NOT NULL,
    signature    bytea NOT NULL,
    notes        text NOT NULL DEFAULT '',
    published_at timestamptz NOT NULL DEFAULT now(),
    published_by text NOT NULL DEFAULT '',
    PRIMARY KEY (version, platform)
);

CREATE TABLE agent_release_files (
    version  text NOT NULL,
    platform text NOT NULL,
    name     text NOT NULL,
    data     bytea NOT NULL,
    PRIMARY KEY (version, platform, name),
    FOREIGN KEY (version, platform) REFERENCES agent_releases (version, platform)
);

CREATE FUNCTION releases_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'published releases are immutable';
END;
$$;
CREATE TRIGGER agent_releases_no_update BEFORE UPDATE ON agent_releases
    FOR EACH ROW EXECUTE FUNCTION releases_immutable();
CREATE TRIGGER agent_release_files_no_update BEFORE UPDATE ON agent_release_files
    FOR EACH ROW EXECUTE FUNCTION releases_immutable();

-- Which version each ring of a tenant should run, per platform.
CREATE TABLE release_targets (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    ring       text NOT NULL CHECK (ring IN ('pilot', 'broad')),
    platform   text NOT NULL,
    version    text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, ring, platform),
    FOREIGN KEY (version, platform) REFERENCES agent_releases (version, platform)
);
ALTER TABLE release_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON release_targets
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);

ALTER TABLE agents ADD COLUMN update_ring text NOT NULL DEFAULT 'broad' CHECK (update_ring IN ('pilot', 'broad'));
ALTER TABLE agents ADD COLUMN update_state text NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN update_version text NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN update_error text NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN update_at timestamptz;
