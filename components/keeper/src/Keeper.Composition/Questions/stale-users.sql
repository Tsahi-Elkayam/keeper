-- name: stale-users
-- description: Why the stale-account count is what it is: every AD account in the newest scans, by what AD and Entra each show.
-- param: days optional
-- The same join as rules/hybrid-identity.yaml (AD objectSid = Entra onPremisesSecurityIdentifier).
-- by_dc_logon_alone is what a domain-logon report would call stale; the bucket is what is true.
WITH win AS (
    SELECT COALESCE(CAST(:days AS INTEGER),
                    (SELECT CAST(value AS INTEGER) FROM setting WHERE key = 'threshold.identity.stale-user-days'),
                    90) AS days
),
ad AS (
    SELECT r.instance, s.entity_key AS account,
           MAX(json_extract(s.attrs, '$.objectSid')) AS sid,
           MAX(CAST(json_extract(s.attrs, '$.userAccountControl') AS INTEGER)) AS uac,
           MAX(json_extract(s.attrs, '$.lastLogonTimestamp')) AS dc_logon_raw,
           MAX(json_extract(s.attrs, '$.whenCreated')) AS created,
           MAX(json_extract(s.attrs, '$.accountExpires')) AS expires,
           MAX(CAST(json_extract(s.attrs, '$.msExchRecipientTypeDetails') AS INTEGER)) AS mailbox_type
    FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
    WHERE r.system = 'active-directory' AND s.entity_type = 'user'
    GROUP BY r.instance, s.entity_key
),
cloud AS (
    SELECT json_extract(s.attrs, '$.onPremisesSecurityIdentifier') AS sid,
           MAX(json_extract(s.attrs, '$.signInActivity.lastSuccessfulSignInDateTime')) AS cloud_signin
    FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
    WHERE r.system = 'entra' AND s.entity_type = 'user'
      AND json_extract(s.attrs, '$.onPremisesSecurityIdentifier') IS NOT NULL
    GROUP BY json_extract(s.attrs, '$.onPremisesSecurityIdentifier')
),
facts AS (
    SELECT ad.instance, ad.uac, ad.mailbox_type, ad.expires, ad.created,
           CASE WHEN ad.dc_logon_raw GLOB '[0-9][0-9][0-9][0-9]-*' THEN julianday('now') - julianday(ad.dc_logon_raw) END AS dc_age,
           julianday('now') - julianday(c.cloud_signin) AS cloud_age,
           julianday('now') - julianday(ad.created) AS created_age,
           (c.sid IS NOT NULL) AS synced,
           w.days
    FROM ad LEFT JOIN cloud c ON c.sid = ad.sid, win w
),
classified AS (
    SELECT instance,
           CASE
               WHEN (COALESCE(uac, 0) & 2) <> 0 THEN '1 disabled'
               WHEN COALESCE(mailbox_type, 0) IN (4, 16, 32, 8589934592, 17179869184, 34359738368) THEN '2 shared, room or equipment mailbox object'
               WHEN expires GLOB '[0-9][0-9][0-9][0-9]-*' AND julianday(expires) < julianday('now') THEN '3 expired'
               WHEN dc_age <= days THEN '4 active: domain logon'
               WHEN cloud_age <= days THEN '5 active: cloud sign-in only'
               WHEN dc_age IS NULL AND cloud_age IS NULL AND created_age <= days THEN '6 new, not used yet'
               WHEN synced = 0 AND NOT EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
                   THEN '7 stale by domain logon; cloud sign-ins unknown (no Entra scan)'
               ELSE '8 stale: no sign-in anywhere'
           END AS bucket,
           CASE WHEN (COALESCE(uac, 0) & 2) = 0 AND (dc_age IS NULL OR dc_age > days) THEN 1 ELSE 0 END AS stale_by_dc
    FROM facts
)
SELECT instance, bucket, COUNT(*) AS accounts, SUM(stale_by_dc) AS by_dc_logon_alone
FROM classified
GROUP BY instance, bucket
ORDER BY instance, bucket;
