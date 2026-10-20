-- Review, version 6.
-- 1. A third synthetic system, ORG: organisation-wide duties and register records that name no system.
--    They were UNMAPPED, which asked for a system rule nobody could write.
-- 2. entity.seen_by: the rule system of the newest scan that returned the entity. Several rule files read
--    through one integration (Keeper's registers and obligations through 'keeper', Entra and Intune through
--    one Graph integration), and a scan of one of them must never mark the other's entities gone.

INSERT OR IGNORE INTO system (system_id, name, notes, updated_by, updated_at) VALUES
    ('ORG', 'Organisation', 'Synthetic: organisation-wide duties and register records that name no system.', 'seed', '1970-01-01T00:00:00Z');

ALTER TABLE entity ADD COLUMN seen_by TEXT;

UPDATE entity SET seen_by = (
    SELECT r.system FROM row_seen rs JOIN run r ON r.run_id = rs.run_id
    WHERE r.instance = entity.instance AND rs.entity_type = entity.entity_type AND rs.entity_key = entity.entity_key
    ORDER BY r.started_at DESC LIMIT 1);

UPDATE entity SET system_id = 'ORG', mapped_by = 'builtin' WHERE instance = 'keeper' AND system_id = 'UNMAPPED';
UPDATE finding SET system_id = 'ORG' WHERE instance = 'keeper' AND system_id = 'UNMAPPED';
