-- name: posture
-- description: The three questions per system, counted in checks from each instance's newest scan: configured correctly, should be configured, broken - and not checked, so 'correct' never claims more than was seen.
-- param: system optional
-- should_configure = checks failing that guard something missing or set against best practice; broken = checks
-- failing that guard something that does not work. not_checked = unknown, partial, stale or not configured
-- (blind-spots says why); not_run = the system's rules with no result in its newest scan.
SELECT st.system, st.instance,
       SUM(st.standing = 'correct') AS correct,
       SUM(st.standing = 'should-configure') AS should_configure,
       SUM(st.standing = 'broken') AS broken,
       SUM(st.standing = 'not-checked') AS not_checked,
       SUM(st.standing = 'not-applicable') AS not_applicable,
       (SELECT COUNT(*) FROM rule r WHERE r.system = st.system) - COUNT(*) AS not_run,
       MAX(st.tested_at) AS scanned
FROM rule_standing st
WHERE (:system IS NULL OR st.system = :system OR st.instance = :system)
GROUP BY st.system, st.instance
ORDER BY st.system, st.instance;
