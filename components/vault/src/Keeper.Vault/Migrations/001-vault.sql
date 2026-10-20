-- Vault, version 1: the data key that encrypts secrets, itself protected by the operating system.
-- The wrapped key is useless without the OS account that wrapped it (DPAPI on Windows).

CREATE TABLE vault_key (
    key_id     TEXT PRIMARY KEY,
    protector  TEXT NOT NULL,                           -- dpapi-user
    wrapped    BLOB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT
) STRICT;
