-- name: stale-users
-- description: Why the stale-account count is what it is: every enabled AD account in the newest scans, by what AD and Entra each show.
-- param: days optional
-- The same join and patterns as rules/hybrid-identity.yaml (AD objectSid = Entra onPremisesSecurityIdentifier;
-- settings threshold.ad.service-account-pattern, threshold.ad.disabled-ou-pattern, threshold.identity.stale-user-days).
-- by_dc_logon_alone is what a domain-logon report would call stale; the bucket is what is true.
WITH cfg AS (
    SELECT COALESCE(CAST(:days AS INTEGER),
                    (SELECT CAST(value AS INTEGER) FROM setting WHERE key = 'threshold.identity.stale-user-days'),
                    90) AS days,
           COALESCE((SELECT value FROM setting WHERE key = 'threshold.ad.service-account-pattern'),
                    '(?i)^(krbtgt|Guest|DefaultAccount|WDAGUtilityAccount|MSOL_[0-9a-f]+|AAD_[0-9a-f]+|Sync_.*|HealthMailbox.*|SM_[0-9a-f]+|.*\$)$') AS service,
           COALESCE((SELECT value FROM setting WHERE key = 'threshold.ad.disabled-ou-pattern'),
                    '(?i)OU=[^,]*(disable|leaver|terminat|former|departed|deprovision)') AS leavers
),
ad AS (
    SELECT r.instance, s.entity_key AS account,
           MAX(json_extract(s.attrs, '$.distinguishedName')) AS dn,
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
    SELECT ad.instance, ad.account, ad.dn, ad.uac, ad.mailbox_type, ad.expires,
           CASE WHEN ad.dc_logon_raw GLOB '[0-9][0-9][0-9][0-9]-*' THEN julianday('now') - julianday(ad.dc_logon_raw) END AS dc_age,
           julianday('now') - julianday(c.cloud_signin) AS cloud_age,
           julianday('now') - julianday(ad.created) AS created_age,
           c.sid IS NOT NULL AS synced,
           cfg.days, cfg.service, cfg.leavers
    FROM ad LEFT JOIN cloud c ON c.sid = ad.sid, cfg
),
classified AS (
    SELECT instance,
           CASE
               WHEN (COALESCE(uac, 0) & 2) <> 0 THEN '01 disabled'
               WHEN COALESCE(mailbox_type, 0) IN (4, 16, 32, 8589934592, 17179869184, 34359738368) THEN '02 shared, room or equipment mailbox object'
               WHEN expires GLOB '[0-9][0-9][0-9][0-9]-*' AND julianday(expires) < julianday('now') THEN '03 expired'
               WHEN account REGEXP service THEN '04 built-in or service account (by name)'
               WHEN dn REGEXP leavers AND (dc_age <= days OR cloud_age <= days) THEN '05 in a leavers OU but enabled - STILL SIGNING IN'
               WHEN dn REGEXP leavers THEN '06 in a leavers OU but enabled'
               WHEN dc_age <= days THEN '07 active: domain logon'
               WHEN cloud_age <= days THEN '08 active: cloud sign-in only'
               WHEN dc_age IS NULL AND cloud_age IS NULL AND created_age <= days THEN '09 new, not used yet'
               WHEN synced = 0 AND NOT EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
                   THEN '10 stale by domain logon; cloud sign-ins unknown (no Entra scan)'
               WHEN dc_age IS NULL AND cloud_age IS NULL THEN '11 stale: never signed in anywhere'
               WHEN MIN(COALESCE(dc_age, 1e9), COALESCE(cloud_age, 1e9)) > 365 THEN '12 stale: last sign-in over a year ago'
               ELSE '13 stale: last sign-in in the window to a year ago'
           END AS bucket,
           CASE WHEN (COALESCE(uac, 0) & 2) = 0 AND (dc_age IS NULL OR dc_age > days) THEN 1 ELSE 0 END AS stale_by_dc
    FROM facts
)
SELECT instance, bucket, COUNT(*) AS accounts, SUM(stale_by_dc) AS by_dc_logon_alone
FROM classified
GROUP BY instance, bucket
ORDER BY instance, bucket;
