-- name: misconfigured
-- description: What exists but is configured wrong: open findings against a standard or best practice.
-- param: system optional
-- param: security optional
SELECT finding_key, system_id, instance, check_id, target, entity_name, severity, title, refs, lifecycle,
       first_seen, last_seen, snoozed_until, delegated_to
FROM active_finding
WHERE kind = 'misconfigured'
  AND (:system IS NULL OR system_id = :system OR system = :system)
  AND (:security IS NULL OR security = :security)
ORDER BY severity_rank, first_seen;
