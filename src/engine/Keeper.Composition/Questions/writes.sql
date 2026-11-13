-- name: writes
-- description: The newest 200 writes the queue manager applied or refused, with the reason given for each.
-- param: state optional
-- param: kind optional
SELECT applied_at, kind, state, submitted_by, reason, error, request_id
FROM request
WHERE (:state IS NULL OR state = :state)
  AND (:kind IS NULL OR kind = :kind)
ORDER BY applied_at DESC
LIMIT 200;
