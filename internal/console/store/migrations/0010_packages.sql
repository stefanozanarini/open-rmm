-- Software package library (files are stored outside the database, by
-- SHA-256) and the packages each job may download.

ALTER TABLE jobs ADD COLUMN packages text[] NOT NULL DEFAULT '{}';

CREATE TABLE packages (
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    sha256       text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    name         text NOT NULL,
    version      text NOT NULL,
    publisher    text NOT NULL DEFAULT '',
    file_name    text NOT NULL,
    size         bigint NOT NULL CHECK (size > 0),
    kind         text NOT NULL,
    silent_args  text NOT NULL DEFAULT '',
    product_code text NOT NULL DEFAULT '',
    allow_unsigned boolean NOT NULL DEFAULT false,
    source       text NOT NULL CHECK (source IN ('upload', 'winget')),
    winget_id    text NOT NULL DEFAULT '',
    source_url   text NOT NULL DEFAULT '',
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sha256)
);

ALTER TABLE packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE packages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON packages
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);

-- Applications followed in the winget catalog, with their latest release.
CREATE TABLE catalog_apps (
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    winget_id       text NOT NULL,
    name            text NOT NULL,
    publisher       text NOT NULL DEFAULT '',
    version         text NOT NULL,
    display_version text NOT NULL,
    match_name      text NOT NULL,
    product_codes   text[] NOT NULL DEFAULT '{}',
    release         jsonb NOT NULL,
    checked_at      timestamptz NOT NULL,
    added_by        text NOT NULL,
    PRIMARY KEY (tenant_id, winget_id)
);

ALTER TABLE catalog_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_apps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON catalog_apps
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
