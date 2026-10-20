-- name: missing
-- description: What should be there and isn't: missing configuration and overdue duties.
-- param: system optional
-- param: security optional
SELECT finding_key, system_id, check_id, target, severity, problem, fix, deadline, lifecycle,
       first_seen, last_seen, snoozed_until, delegated_to
FROM active_finding
WHERE kind = 'missing'
  AND (:system IS NULL OR system_id = :system)
  AND (:security IS NULL OR security = :security)
ORDER BY severity_rank, deadline IS NULL, deadline, first_seen;
