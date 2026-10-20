-- name: controls
-- description: Every framework control the rules cite (refs) and how it stands now: rules, results, accepted risks, last tested.
-- param: framework optional
-- A control passes only when every rule citing it ran and every result passed; a failure accepted as an
-- exception is counted apart, so the control reads "failing, risk accepted" rather than "passing".
WITH refs AS (
    SELECT r.rule_id, j.value AS ref,
           CASE WHEN instr(j.value, ':') > 0 THEN substr(j.value, 1, instr(j.value, ':') - 1) ELSE j.value END AS framework,
           CASE WHEN instr(j.value, ':') > 0 THEN substr(j.value, instr(j.value, ':') + 1) ELSE '-' END AS control
    FROM rule r, json_each(r.refs) j
),
res AS (
    SELECT rule_id,
           SUM(state = 'pass') AS pass, SUM(state = 'fail') AS fail, SUM(state = 'unknown') AS unknown, SUM(state = 'n-a') AS na,
           SUM(julianday('now') - julianday(at) > ttl_minutes / 1440.0) AS stale,
           MAX(at) AS last_tested
    FROM result GROUP BY rule_id
),
accepted AS (
    SELECT rule_id, COUNT(*) AS n FROM finding WHERE status IN ('exception', 'disabled') GROUP BY rule_id
)
SELECT f.framework, f.control,
       COUNT(DISTINCT f.rule_id) AS rules,
       SUM(COALESCE(res.pass, 0)) AS passing,
       SUM(COALESCE(res.fail, 0)) AS failing,
       SUM(COALESCE(a.n, 0)) AS accepted,
       SUM(COALESCE(res.unknown, 0)) AS unknown,
       SUM(res.rule_id IS NULL) AS rules_never_run,
       MAX(res.last_tested) AS last_tested,
       CASE
           WHEN SUM(COALESCE(res.fail, 0)) > SUM(COALESCE(a.n, 0)) THEN 'failing'
           WHEN SUM(COALESCE(res.fail, 0)) > 0 THEN 'failing, risk accepted'
           WHEN SUM(res.rule_id IS NULL) = COUNT(DISTINCT f.rule_id) THEN 'not tested'
           WHEN SUM(COALESCE(res.unknown, 0)) > 0 OR SUM(res.rule_id IS NULL) > 0 OR SUM(COALESCE(res.stale, 0)) > 0 THEN 'partly tested'
           ELSE 'passing'
       END AS status
FROM refs f
LEFT JOIN res ON res.rule_id = f.rule_id
LEFT JOIN accepted a ON a.rule_id = f.rule_id
WHERE (:framework IS NULL OR f.framework = :framework)
GROUP BY f.framework, f.control
ORDER BY f.framework, f.control;
