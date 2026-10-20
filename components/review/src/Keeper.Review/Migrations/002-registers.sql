-- Keeper store, version 2: registers people keep - vendors, contracts, key dates, saving initiatives.
-- These are the dates and decisions no scan can see, but that decide what is urgent.

CREATE TABLE vendor (
    vendor_id          TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('candidate', 'confirmed', 'rejected')),
    sole_vendor        INTEGER NOT NULL DEFAULT 0 CHECK (sole_vendor IN (0, 1)),
    exit_plan          TEXT,
    sla                TEXT,
    data_handled       TEXT,
    sensitive          INTEGER NOT NULL DEFAULT 0 CHECK (sensitive IN (0, 1)),
    security_review_on TEXT,                            -- date of the last security review
    updated_by         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
) STRICT;

CREATE TABLE vendor_system (
    vendor_id TEXT NOT NULL REFERENCES vendor (vendor_id) ON DELETE CASCADE,
    system_id TEXT NOT NULL REFERENCES system (system_id) ON DELETE CASCADE,
    PRIMARY KEY (vendor_id, system_id)
) STRICT;

CREATE TABLE contract (
    contract_id TEXT PRIMARY KEY,
    vendor_id   TEXT REFERENCES vendor (vendor_id),
    title       TEXT NOT NULL,
    start_on    TEXT,
    end_on      TEXT,
    value       REAL,
    currency    TEXT,
    decision    TEXT CHECK (decision IN ('renew', 'replace', 'end', 'undecided')),
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

-- Fixed dates: report due dates, maintenance windows, renewals, price changes.
CREATE TABLE key_date (
    key_date_id TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('contract', 'renewal', 'report', 'maintenance', 'price-change', 'other')),
    title       TEXT NOT NULL,
    due_on      TEXT NOT NULL,
    system_id   TEXT REFERENCES system (system_id),
    contract_id TEXT REFERENCES contract (contract_id),
    owner       TEXT,
    notes       TEXT,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
CREATE INDEX key_date_by_due ON key_date (due_on);

-- Cost-saving initiatives, tracked against a target.
CREATE TABLE initiative (
    initiative_id  TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    owner          TEXT,
    status         TEXT NOT NULL CHECK (status IN ('proposed', 'approved', 'in-progress', 'done', 'dropped')),
    saving_monthly REAL,
    currency       TEXT,
    measured       TEXT CHECK (measured IN ('bill', 'estimate')),
    note           TEXT,
    updated_by     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
) STRICT;
