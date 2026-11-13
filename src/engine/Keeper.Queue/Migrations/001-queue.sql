-- Queue, version 1: the audit trail of every write the queue manager processed.

CREATE TABLE request (
    request_id      TEXT PRIMARY KEY,                   -- the envelope's guid
    kind            TEXT NOT NULL,                      -- namespaced: <component>.<action>
    submitted_by    TEXT NOT NULL,
    submitted_at    TEXT NOT NULL,
    reason          TEXT NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    envelope        TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('done', 'failed')),
    error           TEXT,
    applied_at      TEXT NOT NULL,
    applied_by      TEXT NOT NULL
) STRICT;
CREATE INDEX request_by_applied ON request (applied_at);
