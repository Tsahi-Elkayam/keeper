-- name: broken
-- description: What is broken: active findings of kind 'broken', most severe first.
-- param: system optional
-- param: security optional
SELECT finding_key, system_id, check_id, target, severity, problem, fix, lifecycle,
       deadline, first_seen, last_seen, snoozed_until, delegated_to
FROM active_finding
WHERE kind = 'broken'
  AND (:system IS NULL OR system_id = :system)
  AND (:security IS NULL OR security = :security)
ORDER BY severity_rank, deadline IS NULL, deadline, first_seen;
