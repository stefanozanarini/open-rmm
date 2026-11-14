-- Whether the lock screen (or a UAC prompt) was showing at the last
-- inventory, so the console can warn before a remote-control session that
-- would only see a black secure desktop.

ALTER TABLE inventories ADD COLUMN screen_locked boolean NOT NULL DEFAULT false;
