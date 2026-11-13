-- Groups of computers or of users, to filter the agent list and act on
-- many computers at once. A personal group belongs to one operator (owner);
-- a public one (owner '') to everybody. Members are agent ids for a
-- computer group, user names (DOMAIN\user) for a user group.

CREATE TABLE target_groups (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    id         uuid NOT NULL,
    name       text NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('computer', 'user')),
    owner      text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, owner, name)
);

CREATE TABLE target_group_members (
    tenant_id uuid NOT NULL,
    group_id  uuid NOT NULL,
    member    text NOT NULL,
    PRIMARY KEY (tenant_id, group_id, member),
    FOREIGN KEY (tenant_id, group_id) REFERENCES target_groups (tenant_id, id) ON DELETE CASCADE
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['target_groups', 'target_group_members'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)$p$, t);
    END LOOP;
END $$;
