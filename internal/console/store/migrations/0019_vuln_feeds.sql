-- Vulnerability data downloaded by the console (Microsoft security updates,
-- CISA Known Exploited Vulnerabilities, NVD, OSV), kept as compact extracts.
-- Public data shared by every tenant: no row level security.

CREATE TABLE vuln_feeds (
    key        text PRIMARY KEY,
    version    text NOT NULL DEFAULT '',
    data       bytea NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now()
);
