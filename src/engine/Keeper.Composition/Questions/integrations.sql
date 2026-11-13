-- name: integrations
-- description: Every integration, the secrets it has (names and expiry only - never values) and its last connection test.
SELECT s.integration_id, s.type, s.enabled, s.auth_kind, s.endpoint, s.secret_name, s.secret_set_at, s.secret_expires_on,
       (SELECT t.state || ' at ' || t.at FROM integration_test t WHERE t.integration_id = s.integration_id ORDER BY t.test_id DESC LIMIT 1) AS last_test
FROM integration_status s
ORDER BY s.integration_id, s.secret_name;
