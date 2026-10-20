-- Agent installers (MSI) built and signed by openrmm-builder, preconfigured
-- for this console. The file is in the package store, by SHA-256.

CREATE TABLE agent_installers (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    id         uuid NOT NULL,
    version    text NOT NULL,
    sha256     text NOT NULL,
    size       bigint NOT NULL,
    token_id   uuid NOT NULL REFERENCES enrollment_tokens(id),
    signer     text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE agent_installers ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_installers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_installers
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
