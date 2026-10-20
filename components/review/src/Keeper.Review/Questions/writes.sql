-- name: writes
-- description: The newest 200 writes keeper-qm applied or refused, with the reason given for each.
-- param: state optional
SELECT request_id, kind, state, submitted_by, submitted_at, reason, error, applied_at
FROM request
WHERE (:state IS NULL OR state = :state)
ORDER BY applied_at DESC
LIMIT 200;
