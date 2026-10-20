-- name: decisions
-- description: Decisions in force: disabled rules, changed thresholds, accepted exceptions, snoozes, hand-offs and settings.
SELECT 'override' AS what, o.override_id AS id, o.check_id AS subject, o.decision AS decision,
       COALESCE(NULLIF(o.entity, ''), o.value) AS detail, o.actor AS actor, o.at AS at, o.why AS why
FROM override o
WHERE o.active = 1
UNION ALL
SELECT 'triage', lt.finding_key, f.title, lt.decision, COALESCE(lt.owner, lt.until), lt.actor, lt.at, lt.why
FROM latest_triage lt
JOIN finding f ON f.finding_key = lt.finding_key
WHERE lt.decision <> 'clear'
UNION ALL
SELECT 'setting', s.key, s.key, 'set', s.value, s.actor, s.at, s.why
FROM setting s
ORDER BY at DESC;
