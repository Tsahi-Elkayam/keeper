-- Review, version 5: two more kinds of key date - 'support-end' (a vendor stops supporting a product or
-- version) and 'payment' (a payment falls due). SQLite cannot change a CHECK constraint, so the table is
-- rebuilt with the same rows; nothing references it.

CREATE TABLE key_date_v5 (
    key_date_id TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('contract', 'renewal', 'licence', 'certificate', 'report', 'maintenance',
                                              'price-change', 'support-end', 'payment', 'other')),
    title       TEXT NOT NULL,
    due_on      TEXT NOT NULL,
    notice_days INTEGER NOT NULL DEFAULT 14,
    system_id   TEXT REFERENCES system (system_id),
    owner       TEXT,
    notes       TEXT,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

INSERT INTO key_date_v5 (key_date_id, kind, title, due_on, notice_days, system_id, owner, notes, updated_by, updated_at)
SELECT key_date_id, kind, title, due_on, notice_days, system_id, owner, notes, updated_by, updated_at FROM key_date;

DROP TABLE key_date;
ALTER TABLE key_date_v5 RENAME TO key_date;
CREATE INDEX key_date_by_due ON key_date (due_on);
