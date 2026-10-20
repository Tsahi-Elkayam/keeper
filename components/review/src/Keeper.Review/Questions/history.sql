-- name: history
-- description: One finding's story: when it appeared, changed, was snoozed or handed off, and resolved.
-- param: key required
SELECT e.at, e.event, e.actor, e.note, e.run_id, f.title, f.severity, f.status, f.lifecycle
FROM finding_event e
JOIN finding f ON f.finding_key = e.finding_key
WHERE e.finding_key = :key
ORDER BY e.at, e.event_id;
