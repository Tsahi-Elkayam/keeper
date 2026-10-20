-- Integrations, version 1: how Keeper reaches each system, and the encrypted secrets it needs.
-- No plaintext secret is ever stored: integration_secret holds AES-256-GCM ciphertext only.

CREATE TABLE integration (
    integration_id TEXT PRIMARY KEY CHECK (integration_id GLOB '[a-z]*' AND integration_id NOT GLOB '*[^a-z0-9-]*'),
    type           TEXT NOT NULL,
    endpoint       TEXT NOT NULL DEFAULT '',
    auth_kind      TEXT NOT NULL,
    identity       TEXT,                                -- the account or application it reads as; not a secret
    options        TEXT NOT NULL DEFAULT '{}',          -- JSON: scopes, targets, header names, TLS mode ...
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    changed_by     TEXT NOT NULL,
    changed_at     TEXT NOT NULL,
    why            TEXT NOT NULL
) STRICT;

CREATE TABLE integration_secret (
    integration_id TEXT NOT NULL REFERENCES integration (integration_id) ON DELETE CASCADE,
    name           TEXT NOT NULL,                       -- password, token, clientSecret
    key_id         TEXT NOT NULL REFERENCES vault_key (key_id),
    nonce          BLOB NOT NULL,
    ciphertext     BLOB NOT NULL,
    tag            BLOB NOT NULL,
    bound_to       TEXT NOT NULL,                       -- the endpoint the secret was sealed for
    set_by         TEXT NOT NULL,
    set_at         TEXT NOT NULL,
    expires_on     TEXT,                                -- when the credential itself expires: a rule warns before
    PRIMARY KEY (integration_id, name)
) STRICT;

CREATE TABLE integration_test (
    test_id        INTEGER PRIMARY KEY,
    integration_id TEXT NOT NULL REFERENCES integration (integration_id) ON DELETE CASCADE,
    at             TEXT NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('ok', 'partial', 'failed')),
    detail         TEXT
) STRICT;

-- What rules may read about integrations (store protocol): never the secret columns.
CREATE VIEW integration_status AS
SELECT i.integration_id, i.type, i.endpoint, i.auth_kind, i.identity, i.enabled,
       s.name AS secret_name, s.set_at AS secret_set_at, s.expires_on AS secret_expires_on
FROM integration i
LEFT JOIN integration_secret s ON s.integration_id = i.integration_id;
