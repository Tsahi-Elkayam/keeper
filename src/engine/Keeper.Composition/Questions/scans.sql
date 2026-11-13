-- name: scans
-- description: The newest scan of every system and integration: when, how it went, and how old it is.
SELECT r.system, r.instance, r.status, r.started_at, r.finished_at,
       CAST(julianday('now') - julianday(r.started_at) AS INTEGER) AS age_days,
       (SELECT COUNT(*) FROM coverage c WHERE c.run_id = r.run_id AND c.state <> 'ok' AND c.scope <> 'rule') AS problems,
       r.run_id
FROM latest_run r
ORDER BY r.started_at;
