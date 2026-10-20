-- name: big
-- description: Items at least a given size, biggest first.
-- param: min required
-- param: colour optional
SELECT item_id, colour, size
FROM item
WHERE size >= :min
  AND (:colour IS NULL OR colour = :colour)
ORDER BY size DESC;
