-- Rank, version 1: what to do today, one ranking per pipeline run.

CREATE TABLE ranking (
    build_id    TEXT NOT NULL,
    finding_key TEXT NOT NULL REFERENCES finding (finding_key) ON DELETE CASCADE,
    list        TEXT NOT NULL CHECK (list IN ('today', 'waiting', 'later', 'snoozed')),
    position    INTEGER NOT NULL,
    score       REAL NOT NULL,
    minutes     INTEGER NOT NULL,
    reasons     TEXT NOT NULL DEFAULT '[]',             -- JSON array: why it is where it is
    at          TEXT NOT NULL,
    PRIMARY KEY (build_id, finding_key)
) STRICT;
CREATE INDEX ranking_by_build ON ranking (build_id, list, position);

CREATE VIEW latest_ranking AS
SELECT r.* FROM ranking r WHERE r.build_id = (SELECT MAX(build_id) FROM ranking);
