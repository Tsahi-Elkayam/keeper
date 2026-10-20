-- name: changed
-- description: What changed since a date: finding events (new, reopened, resolved, ...), newest first.
-- param: since required
-- param: system optional
SELECT e.at, e.event, f.system_id, f.check_id, f.target, f.severity, f.problem, e.actor, e.note, f.finding_key
FROM finding_event e
JOIN finding f ON f.finding_key = e.finding_key
WHERE julianday(e.at) >= julianday(:since)
  AND (:system IS NULL OR f.system_id = :system)
ORDER BY e.at DESC;
