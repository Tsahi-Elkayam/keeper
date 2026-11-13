-- name: waiting
-- description: Waiting on others: findings handed to someone, oldest hand-off first.
SELECT f.delegated_to AS owner, f.severity, f.title, f.system_id, f.target, f.deadline,
       lt.at AS handed_off, CAST(julianday('now') - julianday(lt.at) AS INTEGER) AS days_waiting, f.finding_key
FROM active_finding f
JOIN latest_triage lt ON lt.finding_key = f.finding_key AND lt.decision = 'delegate'
ORDER BY lt.at;
