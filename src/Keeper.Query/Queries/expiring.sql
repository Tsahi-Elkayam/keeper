-- name: expiring
-- description: What falls due soon: key dates and finding deadlines within N days (default 30), overdue included.
-- param: days optional
SELECT 'key-date' AS what, key_date_id AS id, kind, title, due_on, system_id, owner
FROM key_date
WHERE julianday(due_on) <= julianday('now') + COALESCE(:days, 30)
UNION ALL
SELECT 'finding', finding_key, kind, problem, deadline, system_id, delegated_to
FROM active_finding
WHERE deadline IS NOT NULL
  AND julianday(deadline) <= julianday('now') + COALESCE(:days, 30)
ORDER BY due_on;
