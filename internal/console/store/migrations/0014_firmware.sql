-- Firmware, BIOS and driver reports (firmware module).

ALTER TABLE update_status DROP CONSTRAINT update_status_source_check;
ALTER TABLE update_status ADD CONSTRAINT update_status_source_check
    CHECK (source IN ('windows', 'winget', 'firmware'));
