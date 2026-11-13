-- name: expiring
-- description: What falls due within N days (default 60), overdue included: licences, contracts, key dates, certificates and every finding with a deadline.
-- param: days optional
SELECT 'licence' AS what, licence_id AS id, product AS title, expires_on AS due_on,
       CAST(julianday(expires_on) - julianday(date('now')) AS INTEGER) AS days_left, notice_days, system_id, owner
FROM licence
WHERE expires_on IS NOT NULL AND julianday(expires_on) <= julianday('now') + COALESCE(:days, 60)
UNION ALL
SELECT 'contract', contract_id, title, end_on,
       CAST(julianday(end_on) - julianday(date('now')) AS INTEGER), notice_days, system_id, owner
FROM contract
WHERE end_on IS NOT NULL AND julianday(end_on) <= julianday('now') + COALESCE(:days, 60)
UNION ALL
SELECT 'key-date:' || kind, key_date_id, title, due_on,
       CAST(julianday(due_on) - julianday(date('now')) AS INTEGER), notice_days, system_id, owner
FROM key_date
WHERE julianday(due_on) <= julianday('now') + COALESCE(:days, 60)
UNION ALL
SELECT 'finding:' || category, finding_key, title, deadline, days_left, NULL, system_id, delegated_to
FROM active_finding
WHERE deadline IS NOT NULL AND julianday(deadline) <= julianday('now') + COALESCE(:days, 60)
ORDER BY due_on;
