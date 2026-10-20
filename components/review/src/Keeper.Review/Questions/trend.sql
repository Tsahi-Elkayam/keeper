-- name: trend
-- description: Each day's recorded standing of one system (or '*' for the whole estate): open, serious, fixed, new, checks passing.
-- param: system optional
-- param: days optional
SELECT day, system_id, open, critical + high AS serious, security, overdue, accepted, opened, resolved,
       CASE WHEN checks_judged > 0 THEN ROUND(100.0 * checks_passing / checks_judged, 1) END AS passing_pct
FROM system_trend
WHERE system_id = COALESCE(:system, '*')
  AND julianday(day) >= julianday('now') - COALESCE(CAST(:days AS INTEGER), 90)
ORDER BY day;
