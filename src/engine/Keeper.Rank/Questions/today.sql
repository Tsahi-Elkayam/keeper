-- name: today
-- description: What to do today: the newest ranking, in order, with why each item is there.
SELECT r.position, f.severity, f.title, f.system_id, f.target, f.deadline, f.days_left, r.minutes, r.reasons, f.fix, f.finding_key
FROM latest_ranking r
JOIN active_finding f ON f.finding_key = r.finding_key
WHERE r.list = 'today'
ORDER BY r.position;
