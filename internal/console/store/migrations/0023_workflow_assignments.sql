-- Permanent workflow assignments: a workflow revision approved once by an
-- administrator (signed envelope, see internal/console/assignreq) to run
-- automatically on a group's computers until it expires or is revoked.

CREATE TABLE workflow_assignments (
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    id              uuid NOT NULL,
    workflow_id     uuid NOT NULL,
    revision        integer NOT NULL,
    group_id        uuid NOT NULL,
    envelope        bytea NOT NULL, -- serialized SignedEnvelope (AssignmentRequest)
    max_ttl_seconds integer NOT NULL,
    expires_at      timestamptz NOT NULL,
    active          boolean NOT NULL DEFAULT true,
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_by      text NOT NULL DEFAULT '',
    revoked_at      timestamptz,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, workflow_id) REFERENCES workflows (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id) REFERENCES target_groups (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX workflow_assignments_workflow ON workflow_assignments (tenant_id, workflow_id);
CREATE INDEX workflow_assignments_group ON workflow_assignments (tenant_id, group_id);

ALTER TABLE workflow_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workflow_assignments
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
