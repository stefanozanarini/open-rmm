-- Federation. Looked up by token hash or certificate fingerprint before the
-- tenant is known (like enrollment_tokens): no row-level security, every
-- tenant-facing query filters on tenant_id.

-- Central side: customer consoles linked to this console. tenant_id is the
-- central tenant whose operators use the link.
CREATE TABLE federation_links (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    name             text NOT NULL,
    token_hash       bytea UNIQUE CHECK (length(token_hash) = 32),
    token_expires_at timestamptz,
    cert_fingerprint text UNIQUE,
    status           text NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    created_by       text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    enrolled_at      timestamptz,
    last_seen_at     timestamptz,
    summary          jsonb,
    summary_at       timestamptz,
    UNIQUE (tenant_id, name)
);

-- Customer side: the link to a central console (at most one).
CREATE TABLE federation_uplink (
    singleton           boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    link_id             uuid NOT NULL,
    central_addr        text NOT NULL,
    central_fingerprint text NOT NULL,
    cert_pem            text NOT NULL,
    key_pem             text NOT NULL,
    suspended           boolean NOT NULL DEFAULT false,
    created_by          text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- Long-lived key material of the console itself (federation listener).
CREATE TABLE console_keys (
    name       text PRIMARY KEY,
    cert_pem   text NOT NULL,
    key_pem    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
