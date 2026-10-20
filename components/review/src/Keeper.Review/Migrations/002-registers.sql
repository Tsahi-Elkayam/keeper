-- Review, version 2: registers people keep - the dates and decisions no scan can see, but that
-- decide what is urgent. Rules read them through the store protocol (rules/registers.yaml).

CREATE TABLE vendor (
    vendor_id          TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    state              TEXT NOT NULL DEFAULT 'confirmed' CHECK (state IN ('candidate', 'confirmed', 'rejected')),
    sole_vendor        INTEGER NOT NULL DEFAULT 0 CHECK (sole_vendor IN (0, 1)),
    exit_plan          TEXT,
    sla                TEXT,
    data_handled       TEXT,
    sensitive          INTEGER NOT NULL DEFAULT 0 CHECK (sensitive IN (0, 1)),
    security_review_on TEXT,                            -- date of the last security review
    notes              TEXT,
    updated_by         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
) STRICT;

CREATE TABLE contract (
    contract_id TEXT PRIMARY KEY,
    vendor_id   TEXT REFERENCES vendor (vendor_id),
    system_id   TEXT REFERENCES system (system_id),
    title       TEXT NOT NULL,
    start_on    TEXT,
    end_on      TEXT,
    notice_days INTEGER NOT NULL DEFAULT 90,            -- how long before the end a decision is needed
    value       REAL,
    currency    TEXT,
    decision    TEXT CHECK (decision IN ('renew', 'replace', 'end', 'undecided')),
    owner       TEXT,
    notes       TEXT,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

-- Licences with no API to read them from: the expiry and the lead time procurement needs.
CREATE TABLE licence (
    licence_id  TEXT PRIMARY KEY,
    product     TEXT NOT NULL,
    vendor_id   TEXT REFERENCES vendor (vendor_id),
    system_id   TEXT REFERENCES system (system_id),
    seats       INTEGER,
    seats_used  INTEGER,
    expires_on  TEXT,
    notice_days INTEGER NOT NULL DEFAULT 60,            -- start the renewal this many days before expiry
    auto_renews INTEGER NOT NULL DEFAULT 0 CHECK (auto_renews IN (0, 1)),
    cost        REAL,
    currency    TEXT,
    owner       TEXT,
    notes       TEXT,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

-- Fixed dates: report due dates, maintenance windows, price changes, certificates no scan can reach.
CREATE TABLE key_date (
    key_date_id TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('contract', 'renewal', 'licence', 'certificate', 'report', 'maintenance', 'price-change', 'other')),
    title       TEXT NOT NULL,
    due_on      TEXT NOT NULL,
    notice_days INTEGER NOT NULL DEFAULT 14,
    system_id   TEXT REFERENCES system (system_id),
    owner       TEXT,
    notes       TEXT,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
CREATE INDEX key_date_by_due ON key_date (due_on);

CREATE TABLE initiative (
    initiative_id  TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    owner          TEXT,
    status         TEXT NOT NULL CHECK (status IN ('proposed', 'approved', 'in-progress', 'done', 'dropped')),
    saving_monthly REAL,
    currency       TEXT,
    measured       TEXT CHECK (measured IN ('bill', 'estimate')),
    notes          TEXT,
    updated_by     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
) STRICT;
