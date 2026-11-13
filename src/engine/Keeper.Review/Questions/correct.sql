-- name: correct
-- description: What is configured correctly: checks that passed on everything they judged, in a clean, fresh read of the newest scan. checked_for names the problem looked for and not found.
-- param: system optional
-- param: security optional
-- A check that failed anywhere, could not read its data, read partly, is older than its refresh interval or had
-- nothing to judge is not here: see posture (counts) and blind-spots (why). threshold_override = passed against a
-- threshold someone changed.
SELECT st.system, st.instance, st.rule_id, st.severity, st.category, st.title AS checked_for,
       st.passed AS judged, st.not_applicable, st.tested_at, st.threshold_override, st.refs
FROM rule_standing st
JOIN severity s ON s.code = st.severity
WHERE st.standing = 'correct'
  AND (:system IS NULL OR st.system = :system OR st.instance = :system)
  AND (:security IS NULL OR st.security = CAST(:security AS INTEGER))
ORDER BY st.system, st.instance, s.rank, st.rule_id;
