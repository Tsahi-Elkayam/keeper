-- name: blind-spots
-- description: What Keeper cannot see: gaps in each source's newest run, and results that are unknown, blocked or stale.
-- param: source optional
SELECT 'gap' AS what, r.source AS source, g.scope_type AS scope, g.scope_key AS item, g.target AS target,
       g.state AS state, g.reason AS why, r.started_at AS at
FROM gap g
JOIN run r ON r.run_id = g.run_id
WHERE r.started_at = (SELECT MAX(r2.started_at) FROM run r2 WHERE r2.source = r.source)
  AND (:source IS NULL OR r.source = :source)
UNION ALL
SELECT 'result', rr.source, 'check', res.check_id, res.entity_key,
       CASE WHEN res.state IN ('unknown', 'blocked') THEN res.state ELSE 'stale' END,
       res.why, res.at
FROM result res
LEFT JOIN run rr ON rr.run_id = res.run_id
WHERE (res.state IN ('unknown', 'blocked') OR julianday(res.at) + res.ttl_minutes / 1440.0 < julianday('now'))
  AND (:source IS NULL OR rr.source = :source)
ORDER BY at DESC;
