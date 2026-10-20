-- name: systems
-- description: Systems with their owners and active findings, worst first.
SELECT s.system_id, s.name, s.team, s.owner_person, s.route, s.criticality,
       COUNT(f.finding_key) AS active,
       COALESCE(SUM(f.severity = 'critical'), 0) AS critical,
       COALESCE(SUM(f.severity = 'high'), 0) AS high
FROM system s
LEFT JOIN active_finding f ON f.system_id = s.system_id
WHERE s.active = 1
GROUP BY s.system_id
ORDER BY critical DESC, high DESC, s.system_id;
