-- Keeper store, version 1: the review system.
-- Generic: no tenant data in this file. Times are ISO 8601 UTC text; booleans are 0/1.
-- Only keeper-qm writes this database (keeper-db for migrations and backups).

-- Lookups ---------------------------------------------------------------------

CREATE TABLE severity (
    code TEXT PRIMARY KEY,
    rank INTEGER NOT NULL UNIQUE                        -- 0 = most severe
) STRICT;
INSERT INTO severity (code, rank) VALUES
    ('critical', 0), ('high', 1), ('medium', 2), ('low', 3), ('info', 4);

CREATE TABLE category (
    code     TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    security INTEGER NOT NULL CHECK (security IN (0, 1)) -- part of the security tier
) STRICT;
INSERT INTO category (code, name, security) VALUES
    ('HLT', 'Health and capacity', 0),
    ('LCM', 'OS, versions, lifecycle and patching', 0),
    ('LOG', 'Logs and recurring errors', 0),
    ('AVL', 'Availability, replication and disconnections', 0),
    ('CFG', 'Configuration and structure', 0),
    ('IAM', 'Identity, privileged access and permissions', 1),
    ('AUT', 'Authentication and protocol hardening', 1),
    ('PKI', 'Certificates and PKI', 1),
    ('BCK', 'Backup and recovery', 0),
    ('MON', 'Monitoring and audit', 0),
    ('HYG', 'Hygiene and best practice', 0),
    ('CST', 'Licensing and cost', 0);

-- Runs: every collector, importer and engine run that was loaded ---------------

CREATE TABLE run (
    run_id      TEXT PRIMARY KEY,                       -- yyyyMMdd-HHmmss-<slug>
    source      TEXT NOT NULL,                          -- collector or importer id
    kind        TEXT NOT NULL CHECK (kind IN ('collector', 'importer', 'engine')),
    title       TEXT,
    identity    TEXT,                                   -- the account it read as
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    evidence_at TEXT,                                   -- when the evidence was taken, if older than the run
    status      TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'failed')),
    folder      TEXT,
    manifest    TEXT,                                   -- run.json as loaded
    loaded_at   TEXT NOT NULL
) STRICT;
CREATE INDEX run_by_source ON run (source, started_at);

-- Catalog: generic per technology, loaded from catalog files --------------------

CREATE TABLE technology (
    technology_id TEXT PRIMARY KEY,                     -- lower-case, e.g. activedirectory, windows-server
    name          TEXT NOT NULL,
    module_id     TEXT NOT NULL,                        -- the plugin that collects it
    entity_types  TEXT NOT NULL DEFAULT '[]'            -- JSON array
) STRICT;

CREATE TABLE control (
    control_id       TEXT PRIMARY KEY,
    entity_type      TEXT NOT NULL,
    applies_to       TEXT,
    name             TEXT NOT NULL,
    why              TEXT,
    proved_by        TEXT,
    missing_severity TEXT NOT NULL REFERENCES severity (code),
    category         TEXT NOT NULL REFERENCES category (code),
    framework        TEXT
) STRICT;

-- Recurring duties: restore tests, access reviews, DR drills. Overdue = a 'missing' finding.
CREATE TABLE obligation (
    obligation_id    TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    interval_days    INTEGER NOT NULL CHECK (interval_days > 0),
    why              TEXT,
    proved_by        TEXT,
    overdue_severity TEXT NOT NULL REFERENCES severity (code),
    category         TEXT NOT NULL REFERENCES category (code),
    framework        TEXT
) STRICT;

-- The tenant's estate ----------------------------------------------------------

CREATE TABLE system (
    system_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    team         TEXT,                                  -- who looks after it
    estate_area  TEXT,
    purpose      TEXT,
    hosting      TEXT,
    owner        TEXT,                                  -- department
    owner_person TEXT,
    route        TEXT,                                  -- where its findings go: a tracker id, or triage
    source       TEXT NOT NULL,                         -- seed | manual | rule:<id> | integration:<collector>
    active       INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    proposed     INTEGER NOT NULL DEFAULT 0 CHECK (proposed IN (0, 1)),
    criticality  INTEGER CHECK (criticality IN (1, 2, 3)), -- 1 = the organisation stops
    to_confirm   TEXT NOT NULL DEFAULT '[]',            -- JSON array of columns that are best guesses
    notes        TEXT
) STRICT;

-- Keeper itself: holds coverage gaps, one NODATA finding per control nobody can see.
INSERT INTO system (system_id, name, source, notes)
VALUES ('KEEPER', 'Keeper', 'seed', 'Synthetic system for coverage gaps.');

CREATE TABLE system_technology (
    system_id     TEXT NOT NULL REFERENCES system (system_id) ON DELETE CASCADE,
    technology_id TEXT NOT NULL REFERENCES technology (technology_id),
    PRIMARY KEY (system_id, technology_id)
) STRICT;

CREATE TABLE system_dependency (
    system_id  TEXT NOT NULL REFERENCES system (system_id) ON DELETE CASCADE,
    depends_on TEXT NOT NULL REFERENCES system (system_id),
    PRIMARY KEY (system_id, depends_on)
) STRICT;

CREATE TABLE system_obligation (
    system_id     TEXT NOT NULL REFERENCES system (system_id) ON DELETE CASCADE,
    obligation_id TEXT NOT NULL REFERENCES obligation (obligation_id),
    PRIMARY KEY (system_id, obligation_id)
) STRICT;

-- Discovery by rule: entities are matched to systems in rule order, first match wins.
CREATE TABLE system_rule (
    rule_id     TEXT PRIMARY KEY,
    ord         INTEGER NOT NULL,
    entity_type TEXT NOT NULL,                          -- an entity type, or '*'
    field       TEXT NOT NULL,                          -- name | ou | dn | os | attr:<name>
    pattern     TEXT NOT NULL,                          -- .NET regex, case-insensitive
    system_id   TEXT NOT NULL REFERENCES system (system_id),
    managed     INTEGER NOT NULL CHECK (managed IN (0, 1)) -- 0 = platform fallback, still an unmanaged asset
) STRICT;

-- Checks: generic ones per technology, plus known-issue re-checks bound to one system.
CREATE TABLE check_def (
    check_id        TEXT PRIMARY KEY,
    technology_id   TEXT NOT NULL REFERENCES technology (technology_id),
    system_id       TEXT REFERENCES system (system_id),  -- set only for known-issue re-checks
    kind            TEXT NOT NULL CHECK (kind IN ('broken', 'misconfigured', 'missing')),
    lens            TEXT NOT NULL CHECK (lens IN ('maintenance', 'security', 'both')),
    category        TEXT NOT NULL REFERENCES category (code),
    subcategory     TEXT,
    title           TEXT NOT NULL,
    why             TEXT,
    method          TEXT,
    pass_criteria   TEXT,
    fail_severity   TEXT NOT NULL REFERENCES severity (code),
    fix             TEXT,
    effort          TEXT,
    reference       TEXT,                               -- standard ids, e.g. NIST-800-53:SI-2
    fact_type       TEXT,                               -- NULL = no evaluator yet
    rule            TEXT,
    threshold_key   TEXT,
    refresh_minutes INTEGER NOT NULL CHECK (refresh_minutes > 0),
    ttl_minutes     INTEGER,                            -- NULL = 3 x refresh
    origin          TEXT NOT NULL DEFAULT 'catalog'     -- catalog | known | <catalog folder>
) STRICT;
CREATE INDEX check_by_technology ON check_def (technology_id);

-- Everything Keeper has seen: servers, PCs, users, apps, licences, certificates ...
CREATE TABLE entity (
    entity_type TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    entity_name TEXT,
    system_id   TEXT REFERENCES system (system_id),
    mapped_by   TEXT,                                   -- hosts | rule:<id> | integration:<collector> | observation | fallback
    managed     INTEGER NOT NULL DEFAULT 0 CHECK (managed IN (0, 1)),
    active      INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    attrs       TEXT NOT NULL DEFAULT '{}',             -- JSON object
    PRIMARY KEY (entity_type, entity_key)
) STRICT;
CREATE INDEX entity_by_system ON entity (system_id);

-- Evidence ---------------------------------------------------------------------

CREATE TABLE fact (
    run_id       TEXT NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    entity_type  TEXT NOT NULL,
    entity_key   TEXT NOT NULL,
    fact_type    TEXT NOT NULL,
    fact_key     TEXT NOT NULL DEFAULT '',
    value        TEXT,
    unit         TEXT,
    collected_at TEXT NOT NULL,
    PRIMARY KEY (run_id, entity_type, entity_key, fact_type, fact_key)
) STRICT;
CREATE INDEX fact_by_type ON fact (fact_type, entity_type, entity_key);

-- What a run could not see. A gap makes coverage unknown, never ok.
CREATE TABLE gap (
    run_id     TEXT NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('check', 'fact_type', 'module')),
    scope_key  TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL CHECK (state IN ('not-active', 'no-data', 'failed', 'not-applicable')),
    reason     TEXT NOT NULL,
    PRIMARY KEY (run_id, scope_type, scope_key, target)
) STRICT;

-- Recurring log signatures from server event logs, summed per signature.
CREATE TABLE signal (
    signal_key  TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    system_id   TEXT REFERENCES system (system_id),
    log         TEXT NOT NULL,
    provider    TEXT NOT NULL,
    event_id    INTEGER NOT NULL,
    level       TEXT,
    occurrences INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    sample      TEXT,
    problem     TEXT,
    cause       TEXT,
    fix         TEXT,
    severity    TEXT REFERENCES severity (code)
) STRICT;

-- The should layer: what must exist, and what people state ----------------------

CREATE TABLE control_reading (
    run_id      TEXT NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    control_id  TEXT NOT NULL REFERENCES control (control_id),
    state       TEXT NOT NULL CHECK (state IN ('yes', 'no', 'unknown', 'na')),
    evidence    TEXT,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, entity_type, entity_key, control_id)
) STRICT;

CREATE TABLE obligation_reading (
    run_id        TEXT NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    obligation_id TEXT NOT NULL REFERENCES obligation (obligation_id),
    target        TEXT NOT NULL DEFAULT '-',
    last_done     TEXT,
    evidence      TEXT,
    observed_at   TEXT NOT NULL,
    PRIMARY KEY (run_id, obligation_id, target)
) STRICT;

-- Evidence no machine has: a person states it, with an expiry.
CREATE TABLE attestation (
    attestation_id INTEGER PRIMARY KEY,
    obligation_id  TEXT REFERENCES obligation (obligation_id),
    control_id     TEXT REFERENCES control (control_id),
    entity_key     TEXT NOT NULL DEFAULT '-',
    state          TEXT NOT NULL CHECK (state IN ('yes', 'no', 'na')),
    done_on        TEXT,
    evidence       TEXT NOT NULL,
    expires_on     TEXT,
    actor          TEXT NOT NULL,
    recorded_at    TEXT NOT NULL,
    CHECK ((obligation_id IS NULL) <> (control_id IS NULL))
) STRICT;

-- Evaluation -------------------------------------------------------------------

-- The latest result of each check on each entity.
CREATE TABLE result (
    check_id    TEXT NOT NULL REFERENCES check_def (check_id) ON DELETE CASCADE,
    system_id   TEXT NOT NULL REFERENCES system (system_id),
    entity_type TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('pass', 'fail', 'n-a', 'unknown', 'blocked')),
    value       TEXT,
    operand     TEXT,
    at          TEXT NOT NULL,
    run_id      TEXT REFERENCES run (run_id) ON DELETE SET NULL,
    ttl_minutes INTEGER NOT NULL,
    why         TEXT,
    PRIMARY KEY (check_id, system_id, entity_type, entity_key)
) STRICT;

CREATE TABLE finding (
    finding_key TEXT PRIMARY KEY,                       -- sha256(system|check|target), lower-case hex
    system_id   TEXT NOT NULL REFERENCES system (system_id),
    check_id    TEXT NOT NULL,                          -- catalog id or an importer's id, so no foreign key
    target      TEXT NOT NULL,                          -- entity key, '-' = the whole system
    kind        TEXT NOT NULL CHECK (kind IN ('broken', 'misconfigured', 'missing')),
    category    TEXT NOT NULL REFERENCES category (code),
    subcategory TEXT,
    severity    TEXT NOT NULL REFERENCES severity (code),
    security    INTEGER NOT NULL DEFAULT 0 CHECK (security IN (0, 1)),
    problem     TEXT NOT NULL,
    evidence    TEXT,
    fix         TEXT,
    reference   TEXT,
    status      TEXT NOT NULL CHECK (status IN ('open', 'unverified', 'blocked', 'ok', 'info', 'resolved', 'disabled', 'exception')),
    lifecycle   TEXT NOT NULL CHECK (lifecycle IN ('new', 'open', 'reopened', 'resolved', 'disabled', 'claimed-fixed', 'stale', 'na')),
    origin      TEXT NOT NULL CHECK (origin IN ('evaluate', 'import', 'should', 'map')),
    source      TEXT NOT NULL,
    confidence  TEXT,
    deadline    TEXT,                                   -- date: when it breaks or falls due
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    evidence_at TEXT,
    resolved_at TEXT,
    run_id      TEXT REFERENCES run (run_id) ON DELETE SET NULL
) STRICT;
CREATE INDEX finding_by_status ON finding (status, severity);
CREATE INDEX finding_by_system ON finding (system_id, status);
CREATE INDEX finding_by_check ON finding (check_id);

CREATE TABLE finding_event (
    event_id    INTEGER PRIMARY KEY,
    finding_key TEXT NOT NULL REFERENCES finding (finding_key) ON DELETE CASCADE,
    at          TEXT NOT NULL,
    event       TEXT NOT NULL CHECK (event IN ('new', 'reopened', 'resolved', 'disabled', 'exception', 'claimed-fixed',
                                               'claim-rejected', 'stale', 'imported', 'severity-changed', 'snoozed', 'delegated')),
    run_id      TEXT,
    actor       TEXT,
    note        TEXT
) STRICT;
CREATE INDEX finding_event_by_finding ON finding_event (finding_key, at);

-- Tickets in other systems. A closed ticket makes a finding claimed-fixed; only a passing check resolves it.
CREATE TABLE finding_ref (
    finding_key TEXT NOT NULL REFERENCES finding (finding_key) ON DELETE CASCADE,
    tracker     TEXT NOT NULL,                          -- servicenow | monday | ...
    ext_id      TEXT NOT NULL,
    status      TEXT NOT NULL,
    url         TEXT,
    opened_at   TEXT,
    closed_at   TEXT,
    PRIMARY KEY (finding_key, tracker, ext_id)
) STRICT;

-- Decisions --------------------------------------------------------------------

-- Disable a check, change its threshold, or accept one entity as it is.
-- Removing keeps the row (active = 0) so the audit trail stays.
CREATE TABLE override (
    override_id TEXT PRIMARY KEY,                       -- OVR-0001
    check_id    TEXT NOT NULL,                          -- may end in '*'
    decision    TEXT NOT NULL CHECK (decision IN ('disable', 'threshold', 'exception')),
    entity      TEXT NOT NULL DEFAULT '',
    value       TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL,
    at          TEXT NOT NULL,
    why         TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    removed_by  TEXT,
    removed_at  TEXT,
    removed_why TEXT
) STRICT;

-- Today's triage: snooze a finding or hand it to someone. Append-only; the newest row wins.
CREATE TABLE triage (
    triage_id   INTEGER PRIMARY KEY,
    finding_key TEXT NOT NULL REFERENCES finding (finding_key) ON DELETE CASCADE,
    decision    TEXT NOT NULL CHECK (decision IN ('snooze', 'delegate', 'clear')),
    owner       TEXT,
    until       TEXT,
    actor       TEXT NOT NULL,
    at          TEXT NOT NULL,
    why         TEXT NOT NULL
) STRICT;

-- Operations -------------------------------------------------------------------

-- Every request keeper-qm processed: the audit trail of every write.
CREATE TABLE request (
    request_id      TEXT PRIMARY KEY,                   -- the envelope's guid
    kind            TEXT NOT NULL,
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

-- Writes to other systems. Dry-run unless the tracker is enabled and the request says otherwise.
CREATE TABLE outbound (
    outbound_id  INTEGER PRIMARY KEY,
    finding_key  TEXT REFERENCES finding (finding_key) ON DELETE SET NULL,
    tracker      TEXT NOT NULL,
    op           TEXT NOT NULL CHECK (op IN ('open', 'update', 'close')),
    dry_run      INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
    ext_id       TEXT,
    status       TEXT NOT NULL CHECK (status IN ('requested', 'sent', 'failed', 'skipped')),
    note         TEXT,
    requested_at TEXT NOT NULL,
    sent_at      TEXT
) STRICT;

CREATE TABLE build (
    build_id    TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL CHECK (status IN ('running', 'ok', 'partial', 'failed')),
    counts      TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE TABLE daily_metric (
    day    TEXT NOT NULL,
    metric TEXT NOT NULL,
    value  REAL NOT NULL,
    PRIMARY KEY (day, metric)
) STRICT;

-- Views the queries build on ------------------------------------------------------

CREATE VIEW latest_triage AS
SELECT finding_key, decision, owner, until, actor, at, why
FROM (SELECT t.*, ROW_NUMBER() OVER (PARTITION BY t.finding_key ORDER BY t.triage_id DESC) AS rn
      FROM triage t)
WHERE rn = 1;

CREATE VIEW active_finding AS
SELECT f.*,
       s.rank AS severity_rank,
       CASE WHEN lt.decision = 'snooze' AND julianday(lt.until) > julianday('now') THEN lt.until END AS snoozed_until,
       CASE WHEN lt.decision = 'delegate' THEN lt.owner END AS delegated_to
FROM finding f
JOIN severity s ON s.code = f.severity
LEFT JOIN latest_triage lt ON lt.finding_key = f.finding_key
WHERE f.status IN ('open', 'unverified', 'blocked');
