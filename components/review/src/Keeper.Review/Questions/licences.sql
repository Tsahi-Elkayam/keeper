-- name: licences
-- description: Every licence and its runway: days left, when the renewal must start, and seat use. Soonest first.
SELECT l.licence_id, l.product, v.name AS vendor, l.system_id, l.expires_on,
       CAST(julianday(l.expires_on) - julianday(date('now')) AS INTEGER) AS days_left,
       date(l.expires_on, '-' || l.notice_days || ' days') AS start_renewal_by,
       l.auto_renews, l.seats, l.seats_used,
       CASE WHEN l.seats > 0 AND l.seats_used IS NOT NULL THEN ROUND(100.0 * l.seats_used / l.seats, 1) END AS used_pct,
       l.cost, l.currency, l.owner
FROM licence l
LEFT JOIN vendor v ON v.vendor_id = l.vendor_id
ORDER BY l.expires_on IS NULL, l.expires_on;
