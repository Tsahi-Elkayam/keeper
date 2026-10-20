-- name: inventory
-- description: What we have: every entity scans have seen, with the system it belongs to. --unmapped 1 = only what no system claims.
-- param: type optional
-- param: system optional
-- param: unmapped optional
-- param: gone optional
SELECT e.instance, e.entity_type, e.entity_key, e.entity_name, e.system_id, e.mapped_by, e.first_seen, e.last_seen, e.gone_since,
       (SELECT COUNT(*) FROM finding f WHERE f.instance = e.instance AND f.target = e.entity_key AND f.status = 'open') AS open_findings
FROM entity e
WHERE (:type IS NULL OR e.entity_type = :type)
  AND (:system IS NULL OR e.system_id = :system)
  AND (:unmapped IS NULL OR (e.system_id = 'UNMAPPED') = (:unmapped = '1'))
  AND (:gone IS NULL OR (e.gone_since IS NOT NULL) = (:gone = '1'))
ORDER BY e.entity_type, e.entity_key;
