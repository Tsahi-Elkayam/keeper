-- name: blind-spots
-- description: What Keeper cannot see: failed or partial coverage in each instance's newest scan, and results that are unknown or stale.
-- param: instance optional
SELECT 'coverage' AS what, r.instance AS instance, r.system AS system, c.scope AS scope, c.item AS item,
       c.state AS state, c.reason AS why, r.started_at AS at
FROM coverage c
JOIN latest_run r ON r.run_id = c.run_id
WHERE c.state IN ('failed', 'partial')
  AND (:instance IS NULL OR r.instance = :instance)
UNION ALL
SELECT 'scan', r.instance, r.system, 'run', r.run_id, r.status, 'the scan itself did not finish cleanly', r.started_at
FROM latest_run r
WHERE r.status <> 'ok'
  AND (:instance IS NULL OR r.instance = :instance)
UNION ALL
SELECT 'result', res.instance, NULL, 'rule', res.rule_id || ' ' || res.entity_key,
       CASE WHEN res.state = 'unknown' THEN 'unknown' ELSE 'stale' END, res.why, res.at
FROM result res
WHERE (res.state = 'unknown' OR julianday(res.at) + res.ttl_minutes / 1440.0 < julianday('now'))
  AND (:instance IS NULL OR res.instance = :instance)
ORDER BY at DESC;
