-- Software distribution workflows. Each save adds a revision, never changed
-- afterwards: a job names the revision it ran.

CREATE TABLE workflows (
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    id          uuid NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE workflow_revisions (
    tenant_id   uuid NOT NULL,
    workflow_id uuid NOT NULL,
    revision    integer NOT NULL CHECK (revision > 0),
    document    jsonb NOT NULL,
    comment     text NOT NULL DEFAULT '',
    author      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workflow_id, revision),
    FOREIGN KEY (tenant_id, workflow_id) REFERENCES workflows (tenant_id, id) ON DELETE CASCADE
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['workflows', 'workflow_revisions'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)$p$, t);
    END LOOP;
END $$;
