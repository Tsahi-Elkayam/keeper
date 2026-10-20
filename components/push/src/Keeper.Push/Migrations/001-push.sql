-- Push, version 1: every ticket Keeper asked an outside tracker to open, and what happened.

CREATE TABLE outbound (
    outbound_id  INTEGER PRIMARY KEY,
    finding_key  TEXT REFERENCES finding (finding_key) ON DELETE SET NULL,
    tracker      TEXT NOT NULL,
    integration  TEXT NOT NULL,
    op           TEXT NOT NULL CHECK (op IN ('open', 'status')),
    ext_id       TEXT,
    url          TEXT,
    status       TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
    detail       TEXT,
    actor        TEXT NOT NULL,
    at           TEXT NOT NULL
) STRICT;
CREATE INDEX outbound_by_finding ON outbound (finding_key);
