-- Review, version 9: how each rule stands on each instance it ran on, judged from that instance's newest
-- scan only. Keeper answers three questions from it - what is configured correctly, what should be
-- configured, what is configured but broken - and a fourth that keeps the first one honest: what could not
-- be checked. A pass counts as correct only when the read behind it was clean and fresh and nothing in it
-- was unknown; no data, a partial read or an old result is never correct.

CREATE VIEW rule_standing AS
WITH newest AS (
    -- Results of the newest scan only: a result left from an older run (an entity since gone) says nothing now.
    SELECT res.instance, res.rule_id, res.state, res.at, res.ttl_minutes, lr.run_id, lr.started_at
    FROM result res
    JOIN rule r ON r.rule_id = res.rule_id
    JOIN latest_run lr ON lr.instance = res.instance AND lr.system = r.system AND lr.run_id = res.run_id
),
per_rule AS (
    SELECT instance, rule_id, run_id, MIN(started_at) AS scanned_at,
           SUM(state = 'pass') AS passed, SUM(state = 'fail') AS failed,
           SUM(state = 'unknown') AS unknown, SUM(state = 'n-a') AS not_applicable,
           SUM(julianday('now') - julianday(at) > ttl_minutes / 1440.0) AS stale,
           MIN(at) AS tested_at
    FROM newest
    GROUP BY instance, rule_id
)
SELECT p.instance, p.rule_id, r.system, r.kind, r.lens, r.category, r.severity, r.title, r.refs,
       p.passed, p.failed, p.unknown, p.not_applicable, p.stale, p.tested_at, p.run_id,
       c.state AS coverage, c.reason AS coverage_reason,
       (cat.security = 1 OR r.lens = 'security') AS security,
       -- A pass against a threshold someone changed: correct by the tenant's own measure, worth knowing.
       (SELECT o.override_id FROM override o
        WHERE o.active = 1 AND o.decision = 'threshold' AND (o.until IS NULL OR o.until >= date('now'))
          AND (o.check_id = p.rule_id OR (o.check_id LIKE '%*' AND p.rule_id LIKE substr(o.check_id, 1, length(o.check_id) - 1) || '%'))
        ORDER BY o.override_id LIMIT 1) AS threshold_override,
       CASE
           WHEN p.failed > 0 THEN CASE r.kind WHEN 'broken' THEN 'broken' ELSE 'should-configure' END
           WHEN p.unknown > 0 OR p.stale > 0 OR c.state IS NULL OR c.state <> 'ok' THEN 'not-checked'
           WHEN p.passed = 0 THEN 'not-applicable'
           ELSE 'correct'
       END AS standing,
       CASE
           WHEN p.failed > 0 THEN NULL
           WHEN p.unknown > 0 THEN p.unknown || ' result(s) unknown: the data could not be read'
           WHEN c.state IS NULL THEN 'the scan recorded no coverage for this rule'
           WHEN c.state <> 'ok' THEN 'read ' || c.state || COALESCE(': ' || c.reason, '')
           WHEN p.stale > 0 THEN 'the newest result is older than the rule''s refresh interval: scan again'
           WHEN p.passed = 0 THEN 'nothing to judge: no target this rule applies to'
       END AS why_not_correct
FROM per_rule p
JOIN rule r ON r.rule_id = p.rule_id
JOIN category cat ON cat.code = r.category
LEFT JOIN coverage c ON c.run_id = p.run_id AND c.scope = 'rule' AND c.item = p.rule_id;
