-- name: rules
-- description: The rule catalogue and how each rule did in its newest results: failing, passing, unknown, never run.
-- param: system optional
SELECT r.rule_id, r.system, r.severity, r.kind, r.title,
       COALESCE(SUM(res.state = 'fail'), 0) AS failing,
       COALESCE(SUM(res.state = 'pass'), 0) AS passing,
       COALESCE(SUM(res.state = 'unknown'), 0) AS unknown,
       MAX(res.at) AS last_result,
       CASE WHEN COUNT(res.rule_id) = 0 THEN 'never run' END AS note,
       r.source_file
FROM rule r
LEFT JOIN result res ON res.rule_id = r.rule_id
WHERE (:system IS NULL OR r.system = :system)
GROUP BY r.rule_id
ORDER BY failing DESC, r.system, r.rule_id;
