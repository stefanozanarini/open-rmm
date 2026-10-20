-- Parameter description of a module's actions (params.json), for the
-- console's forms. Not signed and not sent to agents.
ALTER TABLE modules ADD COLUMN params bytea;
