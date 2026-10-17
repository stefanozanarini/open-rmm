-- Agent approval and certificate renewal.

-- New agents start as 'pending' unless their enrollment token auto-approves.
ALTER TABLE agents DROP CONSTRAINT agents_status_check;
ALTER TABLE agents ADD CONSTRAINT agents_status_check
    CHECK (status IN ('pending', 'active', 'revoked'));
ALTER TABLE agents ADD COLUMN approved_at timestamptz;
ALTER TABLE agents ADD COLUMN approved_by text NOT NULL DEFAULT '';

-- Agents enrolled before approval existed were already trusted.
UPDATE agents SET approved_at = enrolled_at, approved_by = 'migration' WHERE status = 'active';

ALTER TABLE enrollment_tokens ADD COLUMN auto_approve boolean NOT NULL DEFAULT false;

-- During a renewal the previous certificate stays valid until the agent
-- connects with the new one.
ALTER TABLE agents ADD COLUMN prev_cert_fingerprint text;
