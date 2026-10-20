-- name: decisions
-- description: Decisions in force: disabled checks, changed thresholds, accepted exceptions, snoozes and hand-offs.
SELECT 'override' AS what, o.override_id AS id, o.check_id AS subject, o.decision, o.entity AS detail,
       o.actor, o.at, o.why
FROM override o
WHERE o.active = 1
UNION ALL
SELECT 'triage', lt.finding_key, f.problem, lt.decision, COALESCE(lt.owner, lt.until), lt.actor, lt.at, lt.why
FROM latest_triage lt
JOIN finding f ON f.finding_key = lt.finding_key
WHERE lt.decision <> 'clear'
ORDER BY at DESC;
