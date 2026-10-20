-- Review, version 1: what scans saw, what is wrong, its history, and people's decisions.
-- Generic: no tenant data in this file. Times are ISO 8601 UTC text; dates yyyy-MM-dd; booleans 0/1.

-- Lookups ---------------------------------------------------------------------

CREATE TABLE severity (
    code TEXT PRIMARY KEY,
    rank INTEGER NOT NULL UNIQUE                        -- 0 = most severe
) STRICT;
INSERT INTO severity (code, rank) VALUES ('critical', 0), ('high', 1), ('medium', 2), ('low', 3), ('info', 4);

CREATE TABLE category (
    code     TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    security INTEGER NOT NULL CHECK (security IN (0, 1))
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

-- Settings people change: thresholds (threshold.<name>), the daily time budget, routing.
CREATE TABLE setting (
    key   TEXT PRIMARY KEY CHECK (key GLOB '[a-z]*' AND key NOT GLOB '*[^a-z0-9.-]*'),
    value TEXT NOT NULL,
    actor TEXT NOT NULL,
    at    TEXT NOT NULL,
    why   TEXT NOT NULL
) STRICT;

-- Rules: the catalogue as last loaded from the rule files -------------------

CREATE TABLE rule (
    rule_id      TEXT PRIMARY KEY,
    system       TEXT NOT NULL,                         -- rule file's system type, e.g. active-directory
    title        TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('broken', 'misconfigured', 'missing')),
    lens         TEXT NOT NULL CHECK (lens IN ('maintenance', 'security', 'both')),
    category     TEXT NOT NULL REFERENCES category (code),
    severity     TEXT NOT NULL REFERENCES severity (code),
    entity_type  TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    refresh_min  INTEGER NOT NULL CHECK (refresh_min > 0),
    why          TEXT,
    fix          TEXT,
    refs         TEXT NOT NULL DEFAULT '[]',            -- JSON array
    source_file  TEXT NOT NULL,                         -- builtin:<file> or tenant:<file>
    loaded_at    TEXT NOT NULL
) STRICT;

-- Scans: every run folder that was loaded -----------------------------------

CREATE TABLE run (
    run_id      TEXT PRIMARY KEY,
    instance    TEXT NOT NULL,                          -- the integration scanned
    system      TEXT NOT NULL,                          -- rule file's system type
    identity    TEXT,
    host        TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'failed')),
    folder      TEXT NOT NULL,
    manifest    TEXT NOT NULL,
    loaded_at   TEXT NOT NULL
) STRICT;
CREATE INDEX run_by_instance ON run (instance, started_at);

-- What each query returned. Kept per run; the newest run per instance is the inventory.
CREATE TABLE row_seen (
    run_id      TEXT NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    query       TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    entity_name TEXT,
    target      TEXT,
    attrs       TEXT NOT NULL,                          -- JSON object
    observed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, query, entity_type, entity_key)
) STRICT;
CREATE INDEX row_seen_by_entity ON row_seen (entity_type, entity_key);

CREATE TABLE coverage (
    run_id      TEXT NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    scope       TEXT NOT NULL CHECK (scope IN ('rule', 'query', 'target')),
    item        TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('ok', 'partial', 'failed', 'not-applicable')),
    reason      TEXT,
    count       INTEGER,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, scope, item)
) STRICT;

-- The latest result of each rule on each entity of each instance.
CREATE TABLE result (
    instance    TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('pass', 'fail', 'n-a', 'unknown')),
    value       TEXT,
    operand     TEXT,
    why         TEXT,
    ttl_minutes INTEGER NOT NULL,
    at          TEXT NOT NULL,
    run_id      TEXT REFERENCES run (run_id) ON DELETE SET NULL, -- the run may age out; the result stays
    PRIMARY KEY (instance, rule_id, entity_type, entity_key)
) STRICT;

-- Findings exactly as a scan reported them, per run. keeper-track turns them into the register.
CREATE TABLE reported (
    run_id      TEXT NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    record      TEXT NOT NULL,                          -- the keeper.finding/1 record
    PRIMARY KEY (run_id, finding_key)
) STRICT;

-- The tenant's estate --------------------------------------------------------

CREATE TABLE system (
    system_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    team         TEXT,                                  -- who looks after it
    purpose      TEXT,
    owner        TEXT,                                  -- department
    owner_person TEXT,
    route        TEXT,                                  -- where its findings go: a tracker, or triage
    criticality  INTEGER CHECK (criticality IN (1, 2, 3)), -- 1 = the organisation stops
    active       INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    notes        TEXT,
    updated_by   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;
INSERT INTO system (system_id, name, notes, updated_by, updated_at) VALUES
    ('KEEPER', 'Keeper', 'Synthetic: Keeper''s own gaps and integration problems.', 'seed', '1970-01-01T00:00:00Z'),
    ('UNMAPPED', 'Not mapped to a system', 'Synthetic: entities no system rule claims yet.', 'seed', '1970-01-01T00:00:00Z');

CREATE TABLE system_dependency (
    system_id  TEXT NOT NULL REFERENCES system (system_id) ON DELETE CASCADE,
    depends_on TEXT NOT NULL REFERENCES system (system_id),
    PRIMARY KEY (system_id, depends_on)
) STRICT;

-- Which entities belong to which system: applied in order, first match wins.
CREATE TABLE system_rule (
    rule_id     TEXT PRIMARY KEY,
    ord         INTEGER NOT NULL,
    instance    TEXT NOT NULL DEFAULT '*',              -- an integration id, or '*'
    entity_type TEXT NOT NULL DEFAULT '*',
    field       TEXT NOT NULL,                          -- key | name | <attribute path>
    pattern     TEXT NOT NULL,                          -- .NET regex, case-insensitive
    system_id   TEXT NOT NULL REFERENCES system (system_id) ON DELETE CASCADE,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

-- Everything Keeper has seen, with the system it belongs to. Written by keeper-track.
CREATE TABLE entity (
    instance    TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    entity_name TEXT,
    system_id   TEXT NOT NULL REFERENCES system (system_id),
    mapped_by   TEXT NOT NULL,                          -- rule:<id> | unmapped
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    gone_since  TEXT,                                   -- no longer returned by its query
    PRIMARY KEY (instance, entity_type, entity_key)
) STRICT;
CREATE INDEX entity_by_system ON entity (system_id);

-- The register: one row per problem, with its lifecycle -----------------

CREATE TABLE finding (
    finding_key TEXT PRIMARY KEY,                       -- sha256(instance|check|target)
    instance    TEXT NOT NULL,
    system      TEXT NOT NULL,                          -- rule file's system type
    system_id   TEXT NOT NULL REFERENCES system (system_id),
    rule_id     TEXT NOT NULL,
    check_id    TEXT NOT NULL,                          -- the rule id, or an imported tool's own id
    entity_type TEXT NOT NULL,
    target      TEXT NOT NULL,                          -- entity key, '-' = the whole system
    entity_name TEXT,
    kind        TEXT NOT NULL CHECK (kind IN ('broken', 'misconfigured', 'missing')),
    lens        TEXT NOT NULL CHECK (lens IN ('maintenance', 'security', 'both')),
    category    TEXT NOT NULL REFERENCES category (code),
    severity    TEXT NOT NULL REFERENCES severity (code),
    security    INTEGER NOT NULL DEFAULT 0 CHECK (security IN (0, 1)),
    title       TEXT NOT NULL,
    evidence    TEXT,
    why         TEXT,
    fix         TEXT,
    refs        TEXT NOT NULL DEFAULT '[]',
    deadline    TEXT,                                   -- date: when it breaks or falls due
    status      TEXT NOT NULL CHECK (status IN ('open', 'resolved', 'disabled', 'exception')),
    lifecycle   TEXT NOT NULL CHECK (lifecycle IN ('new', 'open', 'reopened', 'resolved', 'disabled', 'claimed-fixed', 'stale')),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    resolved_at TEXT,
    run_id      TEXT
) STRICT;
CREATE INDEX finding_by_status ON finding (status, severity);
CREATE INDEX finding_by_system ON finding (system_id, status);
CREATE INDEX finding_by_rule ON finding (rule_id);

CREATE TABLE finding_event (
    event_id    INTEGER PRIMARY KEY,
    finding_key TEXT NOT NULL REFERENCES finding (finding_key) ON DELETE CASCADE,
    at          TEXT NOT NULL,
    event       TEXT NOT NULL CHECK (event IN ('new', 'reopened', 'resolved', 'disabled', 'exception', 'claimed-fixed',
                                               'claim-rejected', 'stale', 'severity-changed', 'snoozed', 'delegated')),
    run_id      TEXT,
    actor       TEXT,
    note        TEXT
) STRICT;
CREATE INDEX finding_event_by_finding ON finding_event (finding_key, at);
CREATE INDEX finding_event_by_at ON finding_event (at);

-- Tickets in other systems. A closed ticket makes a finding claimed-fixed; only a passing check resolves it.
CREATE TABLE finding_ref (
    finding_key TEXT NOT NULL REFERENCES finding (finding_key) ON DELETE CASCADE,
    tracker     TEXT NOT NULL,
    ext_id      TEXT NOT NULL,
    status      TEXT NOT NULL,
    url         TEXT,
    opened_at   TEXT,
    closed_at   TEXT,
    PRIMARY KEY (finding_key, tracker, ext_id)
) STRICT;

-- Decisions ----------------------------------------------------------------

-- Disable a rule, change its threshold, or accept one entity as it is.
-- Removing keeps the row (active = 0) so the audit trail stays.
CREATE TABLE override (
    override_id TEXT PRIMARY KEY,                       -- OVR-0001
    check_id    TEXT NOT NULL,                          -- rule or check id; may end in '*'
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

-- Evidence no machine has: a person states it (a restore test, a DR drill), with an expiry.
-- Rules read it through the store protocol, so obligations are rules too.
CREATE TABLE attestation (
    attestation_id INTEGER PRIMARY KEY,
    obligation     TEXT NOT NULL,                       -- e.g. backup.restore-test
    target         TEXT NOT NULL DEFAULT '-',
    state          TEXT NOT NULL CHECK (state IN ('yes', 'no', 'na')),
    done_on        TEXT,
    evidence       TEXT NOT NULL,
    expires_on     TEXT,
    actor          TEXT NOT NULL,
    recorded_at    TEXT NOT NULL
) STRICT;
CREATE INDEX attestation_by_obligation ON attestation (obligation, target, recorded_at);

-- Pipeline runs ---------------------------------------------------------------

CREATE TABLE build (
    build_id    TEXT PRIMARY KEY,
    stage       TEXT NOT NULL,
    at          TEXT NOT NULL,
    counts      TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE TABLE daily_metric (
    day    TEXT NOT NULL,
    metric TEXT NOT NULL,
    value  REAL NOT NULL,
    PRIMARY KEY (day, metric)
) STRICT;

-- Views the questions build on ----------------------------------------------

CREATE VIEW latest_run AS
SELECT r.* FROM run r
WHERE r.started_at = (SELECT MAX(r2.started_at) FROM run r2 WHERE r2.instance = r.instance AND r2.system = r.system);

CREATE VIEW latest_triage AS
SELECT finding_key, decision, owner, until, actor, at, why
FROM (SELECT t.*, ROW_NUMBER() OVER (PARTITION BY t.finding_key ORDER BY t.triage_id DESC) AS rn FROM triage t)
WHERE rn = 1;

CREATE VIEW active_finding AS
SELECT f.*,
       s.rank AS severity_rank,
       CASE WHEN f.deadline IS NOT NULL THEN CAST(julianday(f.deadline) - julianday(date('now')) AS INTEGER) END AS days_left,
       CASE WHEN lt.decision = 'snooze' AND julianday(lt.until) > julianday('now') THEN lt.until END AS snoozed_until,
       CASE WHEN lt.decision = 'delegate' THEN lt.owner END AS delegated_to
FROM finding f
JOIN severity s ON s.code = f.severity
LEFT JOIN latest_triage lt ON lt.finding_key = f.finding_key
WHERE f.status = 'open';

CREATE VIEW latest_attestation AS
SELECT * FROM (SELECT a.*, ROW_NUMBER() OVER (PARTITION BY a.obligation, a.target ORDER BY a.recorded_at DESC, a.attestation_id DESC) AS rn
               FROM attestation a)
WHERE rn = 1;
