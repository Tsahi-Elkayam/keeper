-- name: broken
-- description: What is broken: open findings of kind 'broken', most severe and soonest due first.
-- param: system optional
-- param: security optional
SELECT finding_key, system_id, instance, check_id, target, entity_name, severity, title, deadline, days_left,
       lifecycle, first_seen, last_seen, snoozed_until, delegated_to
FROM active_finding
WHERE kind = 'broken'
  AND (:system IS NULL OR system_id = :system OR system = :system)
  AND (:security IS NULL OR security = :security)
ORDER BY severity_rank, deadline IS NULL, deadline, first_seen;
