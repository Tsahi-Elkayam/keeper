-- name: inventory
-- description: What we have: every entity Keeper has seen, with the system it belongs to. --unmanaged 1 = only assets no system claims.
-- param: type optional
-- param: system optional
-- param: unmanaged optional
SELECT entity_type, entity_key, entity_name, system_id, mapped_by, managed, active, first_seen, last_seen
FROM entity
WHERE (:type IS NULL OR entity_type = :type)
  AND (:system IS NULL OR system_id = :system)
  AND (:unmanaged IS NULL OR managed = 1 - :unmanaged)
ORDER BY entity_type, entity_key;
