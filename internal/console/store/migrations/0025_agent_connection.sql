-- When the agent's current (or last) session with the console began and,
-- once it ended, when: the console shows an agent offline as soon as its
-- session closes instead of waiting for last_seen_at to grow stale.

ALTER TABLE agents ADD COLUMN connected_at timestamptz;
ALTER TABLE agents ADD COLUMN disconnected_at timestamptz;
