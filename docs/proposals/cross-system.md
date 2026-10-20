# Proposal: cross-system rules (`rules\cross-system.yaml`, prefix `XS-`)

Status: proposal only. Nothing here is loaded or run; Opus writes the rules from these specs.
File to create: `rules\cross-system.yaml`, `system: cross-system`, `integration: keeper`, every query
`protocol: store`. Tenant-free: every name, OU, host and threshold below is a generic default; tenant
specifics are `threshold.<name>` settings.

Every other pack reads one system. Their backlogs end in "needs a join across systems"
(`docs\backlog\infrastructure.md` "Joins across systems", `microsoft-cloud.md` "Joins across queries",
`windows-estate.md` lines 29-30, `certificates-registers-imports.md` line 41). These are those joins.

## How the store sees the other packs (read before any SQL)

- `row_seen(run_id, query, entity_type, entity_key, entity_name, target, attrs JSON, observed_at)`
  holds every row of every kept run; `latest_run` (a view on `run`) is the newest run per
  `(instance, system)` with `status` ok | partial | failed. Join them and read attributes with
  `json_extract(s.attrs, '$.field')`. Several queries of one system return rows for the same entity
  (AD users come from the inventory query and from the adminCount=1 queries), so group by
  `(instance, entity_type, entity_key)` and take `MAX()` per attribute.
- `row_seen.query` is an opaque fingerprint (`q-` + 12 hex of SHA-256 over protocol, fields and key;
  `Keeper.Rules\Model.cs`). It changes whenever the pack edits the query, so a store rule must never
  name it. Consequence: a join cannot tell "this user row came from the adminCount=1 query" from
  "this user row came from the inventory query". Only attributes that a query *requests* are usable.
- Per-host CIM rows (`windows-server`, `workstations`) carry `target` = the host (dNSHostName) and
  `attrs.host`; composite keys look like `host|Name` (`Scanner.cs` KeyOf).
- LDAP rows always carry `distinguishedName`; FILETIME attributes are ISO text, `0` stays `0`, never-expires stays as is
  (so guard with `GLOB '[0-9][0-9][0-9][0-9]-*'` before `julianday`). Booleans from JSON are 1/0.
- Bound parameters: `:now` (ISO UTC) and `:today` (yyyy-MM-dd). `x REGEXP pattern` works
  (`Keeper.Store\Database.cs`). Settings: `SELECT value FROM setting WHERE key = 'threshold.<name>'`.
- Forbidden in the SQL text (`Keeper.Runners\Guards.cs`): the table names `integration_secret`,
  `vault_key`, `request`, `schema_version`, `sqlite_master`, `sqlite_schema` anywhere in the raw text
  (comments and strings included - so the word "request" must not appear at all); and, outside strings
  and comments, the bare words `insert update delete merge drop alter create truncate exec execute grant
  revoke deny backup restore dbcc shutdown kill openrowset openquery opendatasource bulk into attach
  detach pragma vacuum reindex waitfor reconfigure use`. A column alias such as `backup_name` is one
  identifier and passes; an alias `backup` does not. One SELECT/WITH; no second statement.
- A `count:` rule over a store query is judged for the whole system (entity `instance`, target `-`),
  never per host.
- Readable store tables for these rules: `latest_run`, `run`, `row_seen`, `coverage`, `result`,
  `finding`, `active_finding`, `entity`, `system`, `system_rule`, `system_dependency`, `setting`,
  `rule`, `override`, `licence`, `contract`, `key_date`, `vendor`, `attestation`,
  `latest_attestation`, `integration_status`, `integration_test`, `integration` (never its secrets).

### Hostname normalisation used throughout

Different systems name the same machine differently: AD `sAMAccountName` is `NAME$`, `dNSHostName` is
`name.domain.tld`, SCCM `Name` is `NAME`, Intune `deviceName`, Entra device `displayName`, vCenter and
Veeam use the VM name, PRTG `device` is whatever the admin typed, Dynatrace `hostInfo.displayName`
is the OS hostname. Every join below compares the **short name, upper-cased**:

```sql
UPPER(CASE WHEN instr(x, '.') > 0 THEN substr(x, 1, instr(x, '.') - 1) ELSE x END)   -- short name
UPPER(RTRIM(s.entity_key, '$'))                                                        -- AD computer sAMAccountName
```

`UPPER()` in SQLite folds ASCII only, which is enough for hostnames.

### One side never scanned - the convention

No data is not a pass and not a fail. Two devices, used together:

1. Every join rule's SQL demands that **both** sides have a usable newest run:
   `EXISTS (SELECT 1 FROM latest_run WHERE system = '<x>' AND status <> 'failed')` for each side.
   When one side is missing the rule returns no rows, so it reports nothing - never "missing everywhere".
   Where a rule can still say something useful with one side (the hybrid pack's `seen_in` column),
   it keeps a `seen_in` text column naming which side was consulted and which was not.
2. One coverage-style rule, **XS-COVERAGE-JOIN-UNAVAILABLE**, lists every join pair where one side
   has a usable run and the other has none (never scanned, or newest run failed): one `info` row per
   pair, evidence naming both sides. Pairs where neither side was ever scanned are left to
   `KEEPER-SYSTEM-NEVER-SCANNED`.

Evidence strings always name both sides ("AD: ... ; SCCM: ...").

### Reusable CTEs (copied verbatim into each rule's `text:`)

```sql
-- B1 AD users (inventory query AD-USER-* : filter (&{USER}(!{UAC:2048})); plus adminCount from
-- the privileged query once the AD pack requests it - see attribute gaps)
ad_users AS (
  SELECT r.instance, s.entity_key AS account,
         MAX(json_extract(s.attrs, '$.userPrincipalName')) AS upn,
         MAX(json_extract(s.attrs, '$.distinguishedName')) AS dn,
         MAX(json_extract(s.attrs, '$.objectSid')) AS sid,
         MAX(CAST(json_extract(s.attrs, '$.userAccountControl') AS INTEGER)) AS uac,
         MAX(json_extract(s.attrs, '$.lastLogonTimestamp')) AS dc_logon,
         MAX(json_extract(s.attrs, '$.pwdLastSet')) AS pwd_set,
         MAX(json_extract(s.attrs, '$.whenCreated')) AS created,
         MAX(json_extract(s.attrs, '$.accountExpires')) AS expires,
         MAX(json_extract(s.attrs, '$.servicePrincipalName')) AS spn,
         MAX(json_extract(s.attrs, '$.givenName')) AS given_name,
         MAX(json_extract(s.attrs, '$.sn')) AS surname,
         MAX(json_extract(s.attrs, '$.mail')) AS mail,
         MAX(CAST(json_extract(s.attrs, '$.adminCount') AS INTEGER)) AS admin_count
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'active-directory' AND s.entity_type = 'user'
  GROUP BY r.instance, s.entity_key
)

-- B2 AD computers (AD-COMP-* inventory: filter (&{COMPUTER}{ENABLED}) - ENABLED computers only)
ad_computers AS (
  SELECT r.instance, s.entity_key AS account, UPPER(RTRIM(s.entity_key, '$')) AS short_name,
         MAX(json_extract(s.attrs, '$.dNSHostName')) AS dns_name,
         MAX(json_extract(s.attrs, '$.operatingSystem')) AS os,
         MAX(json_extract(s.attrs, '$.distinguishedName')) AS dn,
         MAX(CAST(json_extract(s.attrs, '$.userAccountControl') AS INTEGER)) AS uac,
         MAX(json_extract(s.attrs, '$.lastLogonTimestamp')) AS dc_logon,
         MAX(json_extract(s.attrs, '$.pwdLastSet')) AS pwd_set
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'active-directory' AND s.entity_type = 'computer'
  GROUP BY r.instance, s.entity_key
)

-- B3 which systems have a usable newest run
usable AS (
  SELECT system, MAX(CASE WHEN status <> 'failed' THEN 1 ELSE 0 END) AS ok
  FROM latest_run GROUP BY system
)

-- B4 SCCM devices: SMS_R_System (key ResourceId) and SMS_CombinedDeviceResources (key ResourceID)
-- rows of both the sccm and workstations-sccm systems; same numeric key, so one entity
sccm_devices AS (
  SELECT MIN(r.instance) AS instance, s.entity_key AS resource_id,
         UPPER(MAX(json_extract(s.attrs, '$.Name'))) AS short_name,
         MAX(COALESCE(CAST(json_extract(s.attrs, '$.IsClient') AS INTEGER), CAST(json_extract(s.attrs, '$.Client') AS INTEGER))) AS has_client,
         MAX(COALESCE(CAST(json_extract(s.attrs, '$.IsActive') AS INTEGER), CAST(json_extract(s.attrs, '$.Active') AS INTEGER))) AS active,
         MAX(COALESCE(CAST(json_extract(s.attrs, '$.IsObsolete') AS INTEGER), CAST(json_extract(s.attrs, '$.Obsolete') AS INTEGER))) AS obsolete,
         MAX(CAST(json_extract(s.attrs, '$.ClientCheckPass') AS INTEGER)) AS client_check,
         MAX(json_extract(s.attrs, '$.LastActiveTime')) AS last_active,
         MAX(json_extract(s.attrs, '$.ClientVersion')) AS client_version,
         MAX(COALESCE(json_extract(s.attrs, '$.DeviceOS'), json_extract(s.attrs, '$.OperatingSystemNameandVersion'))) AS os
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system IN ('sccm', 'workstations-sccm') AND s.entity_type = 'computer'
  GROUP BY s.entity_key
)

-- B5 Entra users (the /users inventory query shared by entra.yaml and m365.yaml; both systems load rows)
entra_users AS (
  SELECT s.entity_key AS id,
         MAX(json_extract(s.attrs, '$.userPrincipalName')) AS upn,
         MAX(json_extract(s.attrs, '$.mail')) AS mail,
         MAX(CAST(json_extract(s.attrs, '$.accountEnabled') AS INTEGER)) AS enabled,
         MAX(json_extract(s.attrs, '$.userType')) AS user_type,
         MAX(json_extract(s.attrs, '$.createdDateTime')) AS created,
         MAX(CAST(json_extract(s.attrs, '$.onPremisesSyncEnabled') AS INTEGER)) AS synced,
         MAX(json_extract(s.attrs, '$.onPremisesSecurityIdentifier')) AS sid,
         MAX(json_extract(s.attrs, '$.onPremisesDistinguishedName')) AS onprem_dn,
         MAX(json_extract(s.attrs, '$.signInActivity.lastSuccessfulSignInDateTime')) AS cloud_signin,
         MAX(json_extract(s.attrs, '$.assignedLicenses')) AS licences
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system IN ('entra', 'm365') AND s.entity_type = 'user'
  GROUP BY s.entity_key
)

-- B6 Intune managed devices
intune_devices AS (
  SELECT s.entity_key AS id,
         UPPER(MAX(json_extract(s.attrs, '$.deviceName'))) AS short_name,
         MAX(json_extract(s.attrs, '$.deviceName')) AS device_name,
         MAX(json_extract(s.attrs, '$.operatingSystem')) AS os,
         MAX(json_extract(s.attrs, '$.osVersion')) AS os_version,
         MAX(json_extract(s.attrs, '$.lastSyncDateTime')) AS last_sync,
         MAX(json_extract(s.attrs, '$.complianceState')) AS compliance,
         MAX(json_extract(s.attrs, '$.userPrincipalName')) AS primary_upn,
         MAX(json_extract(s.attrs, '$.serialNumber')) AS serial,
         MAX(json_extract(s.attrs, '$.managedDeviceOwnerType')) AS owner_type
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'intune' AND s.entity_type = 'managed-device'
  GROUP BY s.entity_key
)

-- B7 Entra devices (ENTRA-DEVICE-* : /devices)
entra_devices AS (
  SELECT s.entity_key AS id,
         UPPER(MAX(json_extract(s.attrs, '$.displayName'))) AS short_name,
         MAX(json_extract(s.attrs, '$.displayName')) AS display_name,
         MAX(json_extract(s.attrs, '$.trustType')) AS trust_type,
         MAX(CAST(json_extract(s.attrs, '$.isManaged') AS INTEGER)) AS managed,
         MAX(CAST(json_extract(s.attrs, '$.isCompliant') AS INTEGER)) AS compliant,
         MAX(CAST(json_extract(s.attrs, '$.accountEnabled') AS INTEGER)) AS enabled,
         MAX(json_extract(s.attrs, '$.operatingSystem')) AS os,
         MAX(json_extract(s.attrs, '$.approximateLastSignInDateTime')) AS last_signin
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'entra' AND s.entity_type = 'device'
  GROUP BY s.entity_key
)

-- B8 Entra directory role assignments with the expanded principal
entra_roles AS (
  SELECT s.entity_key AS assignment_id,
         MAX(json_extract(s.attrs, '$.principalId')) AS principal_id,
         MAX(json_extract(s.attrs, '$.roleDefinitionId')) AS role_id,
         MAX(json_extract(s.attrs, '$.directoryScopeId')) AS scope,
         MAX(json_extract(s.attrs, '$.principal.userPrincipalName')) AS upn,
         MAX(json_extract(s.attrs, '$.principal.displayName')) AS display_name,
         MAX(json_extract(s.attrs, '$.principal.appId')) AS app_id,
         MAX(CAST(json_extract(s.attrs, '$.principal.onPremisesSyncEnabled') AS INTEGER)) AS synced,
         MAX(CAST(json_extract(s.attrs, '$.principal.accountEnabled') AS INTEGER)) AS enabled
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'entra' AND s.entity_type = 'role-assignment'
  GROUP BY s.entity_key
)

-- B9 vCenter VMs and ESXi hosts
vc_vms AS (
  SELECT r.instance, s.entity_key AS vm,
         UPPER(MAX(json_extract(s.attrs, '$.name'))) AS short_name,
         MAX(json_extract(s.attrs, '$.name')) AS name,
         MAX(json_extract(s.attrs, '$.power_state')) AS power_state
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'vmware' AND s.entity_type = 'vm'
  GROUP BY r.instance, s.entity_key
)

-- B10 Veeam protected objects (VEEAM-OBJECT-FEW-RESTORE-POINTS: /api/v1/backupObjects)
veeam_objects AS (
  SELECT r.instance, s.entity_key AS object_id,
         UPPER(CASE WHEN instr(MAX(json_extract(s.attrs, '$.name')), '.') > 0
                    THEN substr(MAX(json_extract(s.attrs, '$.name')), 1, instr(MAX(json_extract(s.attrs, '$.name')), '.') - 1)
                    ELSE MAX(json_extract(s.attrs, '$.name')) END) AS short_name,
         MAX(json_extract(s.attrs, '$.name')) AS name,
         MAX(json_extract(s.attrs, '$.type')) AS type,
         MAX(json_extract(s.attrs, '$.platformName')) AS platform,
         MAX(CAST(json_extract(s.attrs, '$.restorePointsCount') AS INTEGER)) AS rp_count
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'veeam' AND s.entity_type = 'backup-object'
  GROUP BY r.instance, s.entity_key
)

-- B11 PRTG devices (distinct device names over the sensor table) and B12 Dynatrace hosts
prtg_devices AS (
  SELECT UPPER(CASE WHEN instr(d, '.') > 0 THEN substr(d, 1, instr(d, '.') - 1) ELSE d END) AS short_name,
         COUNT(*) AS sensors,
         SUM(CASE WHEN CAST(st AS INTEGER) IN (5, 13, 14) THEN 1 ELSE 0 END) AS sensors_down
  FROM (SELECT json_extract(s.attrs, '$.device') AS d, json_extract(s.attrs, '$.status_raw') AS st
        FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
        WHERE r.system = 'prtg' AND s.entity_type = 'sensor')
  GROUP BY 1
)
dt_hosts AS (
  SELECT s.entity_key AS entity_id,
         UPPER(CASE WHEN instr(MAX(json_extract(s.attrs, '$.hostInfo.displayName')), '.') > 0
                    THEN substr(MAX(json_extract(s.attrs, '$.hostInfo.displayName')), 1, instr(MAX(json_extract(s.attrs, '$.hostInfo.displayName')), '.') - 1)
                    ELSE MAX(json_extract(s.attrs, '$.hostInfo.displayName')) END) AS short_name,
         MAX(json_extract(s.attrs, '$.availabilityState')) AS availability,
         MAX(json_extract(s.attrs, '$.monitoringType')) AS monitoring_type
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'dynatrace' AND s.entity_type = 'host'
  GROUP BY s.entity_key
)

-- B13 Wiz assets as seen through the vulnerability-finding rows (KEV, critical-with-fix, exploitable)
wiz_assets AS (
  SELECT UPPER(CASE WHEN instr(an, '.') > 0 THEN substr(an, 1, instr(an, '.') - 1) ELSE an END) AS short_name,
         MAX(an) AS asset_name, MAX(at) AS asset_type,
         MAX(CAST(wide AS INTEGER)) AS internet_exposed,
         COUNT(*) AS findings,
         GROUP_CONCAT(cve, ', ') AS cves
  FROM (SELECT json_extract(s.attrs, '$.vulnerableAsset.name') AS an,
               json_extract(s.attrs, '$.vulnerableAsset.type') AS at,
               json_extract(s.attrs, '$.vulnerableAsset.hasWideInternetExposure') AS wide,
               json_extract(s.attrs, '$.name') AS cve
        FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
        WHERE r.system = 'wiz' AND s.entity_type = 'vulnerability-finding')
  GROUP BY 1
)

-- B14 Keeper's own integration identities, normalised to an AD account name
keeper_identities AS (
  SELECT i.integration_id, i.type, i.endpoint, i.auth_kind, i.enabled, i.identity,
         LOWER(CASE WHEN instr(i.identity, '\') > 0 THEN substr(i.identity, instr(i.identity, '\') + 1)
                    WHEN instr(i.identity, '@') > 0 THEN substr(i.identity, 1, instr(i.identity, '@') - 1)
                    ELSE i.identity END) AS sam,
         LOWER(i.identity) AS identity_lower
  FROM integration i
  WHERE i.enabled = 1 AND i.identity IS NOT NULL AND TRIM(i.identity) <> ''
)
```

Column names in these CTEs deliberately avoid the guard's forbidden words.

## Priority 1 - highest value, attributes already collected (or one small addition)

### XS-COVERAGE-JOIN-UNAVAILABLE

- Joins: every pair below; key: `latest_run.system`.
- Catches: a join whose one side has a usable newest scan while the other was never scanned or its
  newest scan failed. Why: every XS rule goes silent when a side is missing; this is the one row that
  says so, so silence is never read as "nothing wrong".
- Severity: info. kind: missing, lens: both, category: MON, entity: join.
- Attributes: none beyond `latest_run`.
- One side never scanned: this *is* the rule for that case. Both sides never scanned: no row
  (`KEEPER-SYSTEM-NEVER-SCANNED` covers it).
- SQL:

```sql
WITH pairs(join_id, left_system, right_system, rules) AS (
  VALUES ('ad-entra-users',      'active-directory', 'entra',     'XS-USER-*'),
         ('ad-m365-licences',    'active-directory', 'm365',      'XS-USER-LICENSED-LEAVER'),
         ('ad-sccm-computers',   'active-directory', 'sccm',      'XS-COMPUTER-AD-*-SCCM*, XS-COMPUTER-SCCM-AD-GONE'),
         ('ad-intune-devices',   'active-directory', 'intune',    'XS-DEVICE-INTUNE-AD-GONE'),
         ('ad-entra-devices',    'active-directory', 'entra',     'XS-COMPUTER-AD-NOT-HYBRID-JOINED, XS-DEVICE-ENTRA-HYBRID-AD-GONE'),
         ('ad-prtg',             'active-directory', 'prtg',      'XS-SERVER-NOT-MONITORED, XS-MONITOR-TARGET-AD-GONE'),
         ('ad-dynatrace',        'active-directory', 'dynatrace', 'XS-SERVER-NOT-MONITORED, XS-MONITOR-TARGET-AD-GONE'),
         ('ad-veeam',            'active-directory', 'veeam',     'XS-SERVER-AD-NO-BACKUP'),
         ('vmware-veeam',        'vmware',           'veeam',     'XS-VM-NO-BACKUP, XS-BACKUP-OBJECT-VM-GONE'),
         ('vmware-prtg',         'vmware',           'prtg',      'XS-ESXI-HOST-NOT-MONITORED'),
         ('ad-wiz',              'active-directory', 'wiz',       'XS-HOST-KEV-COMPOUND, XS-HOST-EOL-EXPOSED'),
         ('entra-intune',        'entra',            'intune',    'XS-ADMIN-DEVICE-NONCOMPLIANT, XS-INTUNE-PRIMARY-USER-LEAVER'),
         ('ad-sccm-admins',      'active-directory', 'sccm',      'XS-SCCM-ADMIN-AD-DISABLED'),
         ('entra-servicenow',    'entra',            'servicenow','XS-SCIM-*')
),
usable AS (
  SELECT system, MAX(CASE WHEN status <> 'failed' THEN 1 ELSE 0 END) AS ok, MAX(started_at) AS last_at
  FROM latest_run GROUP BY system
)
SELECT p.join_id, p.left_system, p.right_system, p.rules,
       CASE WHEN l.system IS NULL THEN 'never scanned' WHEN l.ok = 0 THEN 'newest scan failed (' || l.last_at || ')' ELSE 'ok' END AS left_state,
       CASE WHEN rt.system IS NULL THEN 'never scanned' WHEN rt.ok = 0 THEN 'newest scan failed (' || rt.last_at || ')' ELSE 'ok' END AS right_state
FROM pairs p
LEFT JOIN usable l  ON l.system  = p.left_system
LEFT JOIN usable rt ON rt.system = p.right_system
WHERE (COALESCE(l.ok, 0) = 1 AND COALESCE(rt.ok, 0) = 0)
   OR (COALESCE(rt.ok, 0) = 1 AND COALESCE(l.ok, 0) = 0)
```
  `key: join_id`, `each: any`,
  evidence `"{join_id}: {left_system} {left_state}; {right_system} {right_state} - {rules} cannot be judged"`.
- Refs: NIST-800-53:CA-7.
- Fix: add or repair the integration for the missing side (`keeper scan <system> --test`), or accept
  the pair if the organisation does not run that system.

### XS-KEEPER-IDENTITY-PRIVILEGED

- Joins: Keeper `integration` (identity) x AD user; key: `identity` parsed to sAMAccountName
  (`DOMAIN\sam`, `sam@upn-suffix` or bare `sam`), or `identity` = `userPrincipalName`.
- Catches: an account Keeper reads with that is a privileged AD account (adminCount=1, or a
  domain-controller-grade flag). Why: Keeper only ever reads; a credential it holds that can also
  write to the whole domain turns a leak of Keeper's vault into a domain compromise.
- Severity: high (critical when `uac` has TRUSTED_FOR_DELEGATION 524288).
  kind: misconfigured, lens: security, category: IAM, entity: integration.
- Attributes - AD side: `sAMAccountName`, `userPrincipalName`, `userAccountControl` (requested by the
  inventory query); **`adminCount` - NOT requested by the inventory query** (`(&{USER}(!{UAC:2048}))`,
  attributes list in AD-POP-USERS-NONE / AD-USER-*). The AD-PRIV-* query selects adminCount=1 in its
  *filter* but does not return the attribute, and its rows cannot be told apart (opaque query id).
  Until `adminCount` (and `memberOf`) are added to the inventory attributes, `admin_count` is NULL
  and the engine returns n/a for the rule - not a pass. Keeper side: `integration.identity`.
- One side never scanned: no AD run -> no rows (XS-COVERAGE-JOIN-UNAVAILABLE needs no pair for this:
  `integration` is always present; add pair `keeper-ad` if wanted).
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
keeper_identities AS ( /* B14 */ )
SELECT k.integration_id, k.type, k.identity, a.instance AS ad_instance, a.account, a.dn,
       a.admin_count, a.uac,
       CASE WHEN a.admin_count IS NULL THEN 'adminCount not collected by the AD pack' ELSE 'adminCount ' || a.admin_count END AS admin_state
FROM keeper_identities k
JOIN ad_users a ON LOWER(a.account) = k.sam OR LOWER(a.upn) = k.identity_lower
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
```
  `key: integration_id`, `each: { any: [ {field: admin_count, op: eq, value: 1}, {field: uac, op: flag, value: 524288} ] }`,
  evidence `"{integration_id} ({type}) signs in as {identity} = AD {account} ({dn}): {admin_state}, userAccountControl {uac}"`.
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-6(5), CIS-Controls-v8:5.4.
- Fix: create a dedicated read-only account (or gMSA) for Keeper with only the read rights the packs
  need; take it out of every protected group; rotate the old credential.

### XS-KEEPER-IDENTITY-PASSWORD-NEVER-EXPIRES

- Joins: as above. Catches: Keeper's AD identity has DONT_EXPIRE_PASSWORD (65536) or
  PASSWD_NOTREQD (32), or its `pwdLastSet` is older than the service-account window. Why: a Keeper
  credential is in a vault and in every scan's log line; one that never rotates stays valid after any leak.
- Severity: medium (high when PASSWD_NOTREQD). kind: misconfigured, lens: security, category: IAM, entity: integration.
- Attributes: AD `userAccountControl`, `pwdLastSet` (requested). Keeper `integration.identity`,
  `integration_status.secret_set_at` (for the comparison "password set in AD after the secret was
  stored = the vault copy is stale").
- One side never scanned: no AD run -> no rows.
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
keeper_identities AS ( /* B14 */ )
SELECT k.integration_id, k.type, k.identity, a.account, a.uac, a.pwd_set,
       (SELECT MAX(secret_set_at) FROM integration_status st WHERE st.integration_id = k.integration_id) AS secret_set_at,
       CASE WHEN a.pwd_set GLOB '[0-9][0-9][0-9][0-9]-*'
            THEN CAST(julianday(:now) - julianday(a.pwd_set) AS INTEGER) END AS pwd_age_days
FROM keeper_identities k
JOIN ad_users a ON LOWER(a.account) = k.sam OR LOWER(a.upn) = k.identity_lower
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
```
  `each: { any: [ {field: uac, op: flag, value: 65536}, {field: uac, op: flag, value: 32}, {field: pwd_age_days, op: gt, value: 365, threshold: cross.keeper-password-max-age-days} ] }`.
  A second, separate rule **XS-KEEPER-SECRET-STALE** uses the same SQL with
  `each: { field: pwd_set, op: ... }` expressed as `secret_set_at < pwd_set` - the engine cannot
  compare two fields (engine gap), so compute `CASE WHEN secret_set_at < pwd_set THEN 1 ELSE 0 END AS secret_older_than_password` in SQL and test `eq 1`.
- Refs: NIST-800-53:IA-5(1), CIS-Controls-v8:5.2.
- Fix: clear the flags, rotate on a schedule, then `keeper integration set-secret`.

### XS-KEEPER-IDENTITY-UNUSABLE

- Joins: as above. Catches: Keeper's AD identity is disabled (UAC 2), expired (`accountExpires` in
  the past), locked in a leavers OU, or has no DC logon for N days although Keeper scans daily (the
  LDAP bind should refresh `lastLogonTimestamp`) - or no AD user matches an identity written as
  `DOMAIN\sam`. Why: a scan that still "works" with a dead account is a scan that is about to stop;
  and an identity that matches no account is a typo nobody noticed because the secret is cached.
- Severity: high. kind: broken, lens: maintenance, category: AUT, entity: integration.
- Attributes: AD `userAccountControl`, `accountExpires`, `lastLogonTimestamp`, `distinguishedName`
  (requested). Setting `threshold.ad.disabled-ou-pattern` (same default as the AD pack).
- One side never scanned: no rows.
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
keeper_identities AS ( /* B14 */ ),
leaver_pattern AS (SELECT COALESCE((SELECT value FROM setting WHERE key = 'threshold.ad.disabled-ou-pattern'),
                                   '(?i)OU=[^,]*(disable|leaver|terminat|former|departed|deprovision)') AS p)
SELECT k.integration_id, k.type, k.identity, a.account, a.dn, a.uac, a.expires, a.dc_logon,
       CASE WHEN a.account IS NULL AND instr(k.identity, '\') > 0 THEN 'no AD user matches'
            WHEN (COALESCE(a.uac, 0) & 2) = 2 THEN 'disabled'
            WHEN a.expires GLOB '[0-9][0-9][0-9][0-9]-*' AND a.expires < :now THEN 'expired ' || a.expires
            WHEN a.dn REGEXP (SELECT p FROM leaver_pattern) THEN 'in a leavers OU'
            WHEN a.dc_logon IS NULL OR a.dc_logon NOT GLOB '[0-9][0-9][0-9][0-9]-*'
                 OR julianday(:now) - julianday(a.dc_logon) > 30 THEN 'no domain logon in 30 days'
            ELSE 'ok' END AS state
FROM keeper_identities k
LEFT JOIN ad_users a ON LOWER(a.account) = k.sam OR LOWER(a.upn) = k.identity_lower
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
  AND (a.account IS NOT NULL OR instr(k.identity, '\') > 0)
```
  `each: { field: state, op: ne, value: ok }`. The 30-day window should read
  `threshold.cross.keeper-identity-idle-days` (COALESCE in SQL, as the hybrid pack does).
- Refs: NIST-800-53:AC-2(3), NIST-800-53:IA-4.
- Fix: fix or replace the account, retest the integration.

### XS-KEEPER-IDENTITY-SHARED-OR-PERSONAL

- Joins: `integration` x `integration` (same identity on several integrations) and x AD user
  (`givenName` + `sn` present = a person's account). Catches: one credential used by several
  integrations (one leak opens them all; one rotation breaks them all), and Keeper signing in as a
  person rather than a service account (leaves with the person; counted in licences and reviews as a user).
- Severity: medium. kind: misconfigured, lens: security, category: IAM, entity: integration.
- Attributes: AD `givenName`, `sn` (requested). Keeper `integration.identity`.
- One side never scanned: the "shared" half needs no AD; the "personal" half emits nothing without AD.
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
keeper_identities AS ( /* B14 */ )
SELECT k.integration_id, k.type, k.identity,
       (SELECT COUNT(*) FROM keeper_identities o WHERE o.identity_lower = k.identity_lower) AS users_of_identity,
       (SELECT GROUP_CONCAT(o.integration_id, ', ') FROM keeper_identities o WHERE o.identity_lower = k.identity_lower AND o.integration_id <> k.integration_id) AS shared_with,
       CASE WHEN a.given_name IS NOT NULL AND a.surname IS NOT NULL THEN 1 ELSE 0 END AS looks_personal,
       a.account, a.given_name, a.surname
FROM keeper_identities k
LEFT JOIN ad_users a ON (LOWER(a.account) = k.sam OR LOWER(a.upn) = k.identity_lower)
                    AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
```
  `each: { any: [ {field: users_of_identity, op: gt, value: 1, threshold: cross.keeper-identity-max-integrations}, {field: looks_personal, op: eq, value: 1} ] }`.
- Refs: NIST-800-53:AC-2, NIST-800-53:IA-4, CIS-Controls-v8:5.5.
- Fix: one service identity per integration type with its own secret; never a named person's account.

### XS-KEEPER-APP-IDENTITY-TIER0-ROLE

- Joins: `integration` (identity = an application/client id, `auth_kind` client-secret or
  certificate) x Entra `role-assignment` (`principal.appId`). Catches: the app registration Keeper
  reads Graph with holds a tier-0 directory role. Why: Keeper needs application *permissions*
  (Directory.Read.All etc.), never a directory role; a role makes its secret a tenant takeover.
- Severity: critical. kind: misconfigured, lens: security, category: IAM, entity: integration.
- Attributes: Entra `roleDefinitionId`, `principal.appId` (requested via `expand: principal` in
  ENTRA-ROLE-* /roleManagement/directory/roleAssignments). Keeper `integration.identity`.
  Tier-0 list: default the eleven ids from entra.yaml; override `threshold.entra.tier0-role-ids`
  (format of list settings in SQL is an engine gap - see end).
- One side never scanned: no Entra run -> no rows.
- SQL:

```sql
WITH entra_roles AS ( /* B8 */ ),
apps AS (SELECT integration_id, type, LOWER(identity) AS app_id FROM integration
         WHERE enabled = 1 AND identity REGEXP '^[0-9a-fA-F-]{36}$')
SELECT a.integration_id, a.type, a.app_id, r.role_id, r.display_name, r.scope
FROM apps a JOIN entra_roles r ON LOWER(r.app_id) = a.app_id
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
  AND r.role_id IN ('62e90394-69f5-4237-9190-012177145e10','e8611ab8-c189-46e8-94e1-60213ab1f814','7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
                    '194ae4cb-b126-40b2-bd5b-6091b380977d','8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2','b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
                    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','158c047a-c907-4556-b7ef-446551a6b5f7','be2f45a1-457d-42af-a067-6ec1fa63bc45',
                    '8329153b-31d0-4727-b945-745eb3bc5f31','3a2c62db-5318-420d-8d74-23affee5d9d5')
```
  `key: "{integration_id}|{role_id}"` (template key), `each: any`.
- Refs: NIST-800-53:AC-6(5), CIS-Controls-v8:5.4.
- Fix: remove the directory role; keep only the application permissions listed in
  `docs\backlog\microsoft-cloud.md` "Graph permissions".

### XS-USER-AD-DISABLED-ENTRA-ENABLED

- Joins: AD user x Entra user on `objectSid` = `onPremisesSecurityIdentifier`.
- Catches: disabled on-premises, still enabled in the cloud. Why: with Connect sync this is sync
  broken or paused (the leaver keeps mail, Teams, SaaS access through Entra); without sync it is a
  half-done leaver. ENTRA-SYNC-STALE sees the sync lag, not which accounts it stranded.
- Severity: high (critical when the Entra side also shows a successful sign-in after the AD
  account was disabled - needs `whenChanged`, see gaps; without it, high).
  kind: broken, lens: security, category: IAM, entity: user.
- Attributes - AD: `objectSid`, `userAccountControl`, `distinguishedName` (requested). Entra:
  `onPremisesSecurityIdentifier`, `accountEnabled`, `onPremisesSyncEnabled`,
  `signInActivity.lastSuccessfulSignInDateTime` (requested in the /users inventory query).
  Entra `onPremisesLastSyncDateTime` per user is **not requested** (would date the drift).
- One side never scanned: no rows.
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
entra_users AS ( /* B5 */ )
SELECT a.instance || '/' || a.account AS id, a.account, a.upn, a.dn, a.uac, e.id AS entra_id, e.upn AS entra_upn,
       e.enabled AS entra_enabled, e.synced, e.cloud_signin
FROM ad_users a JOIN entra_users e ON e.sid = a.sid
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
  AND (COALESCE(a.uac, 0) & 2) = 2 AND e.enabled = 1
```
  `key: id`, `name: upn`, `each: any`,
  evidence `"AD {account} disabled ({dn}); Entra {entra_upn} enabled, synced {synced}, last cloud sign-in {cloud_signin}"`.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:PS-4, CIS-Controls-v8:5.3.
- Fix: run or repair directory sync (check ENTRA-SYNC-STALE); disable the cloud account by hand
  now and revoke its sessions.

### XS-USER-AD-ENABLED-ENTRA-DISABLED

- Joins: same. Catches: blocked in Entra, still enabled in AD. Why: the person (or attacker) can
  still log on to every on-premises service, VPN with LDAP, RDP; cloud "block sign-in" was mistaken
  for offboarding. Also the signature of a cloud-side compromise response that never reached AD.
- Severity: high. kind: broken, lens: security, category: IAM, entity: user.
- Attributes: same as above; AD `lastLogonTimestamp` for the evidence.
- SQL: as above with the condition swapped: `(COALESCE(a.uac,0) & 2) = 0 AND e.enabled = 0 AND e.synced = 1`,
  evidence `"Entra {entra_upn} disabled; AD {account} enabled, last domain logon {dc_logon} ({dn})"`.
  Split the `WHERE` into a `state` column (`ad_disabled_entra_enabled` / `entra_disabled_ad_enabled`)
  if one query should feed both rules (rules with identical `text:` share one fetch).
- Refs: NIST-800-53:AC-2(3), NIST-800-53:PS-4, CIS-Controls-v8:5.3.
- Fix: disable the AD account (the sync then keeps Entra disabled), remove group memberships.

### XS-USER-SYNCED-AD-GONE

- Joins: Entra user (`onPremisesSyncEnabled` = true, SID present) anti-join AD users on SID.
- Catches: a synchronised cloud account whose AD object no longer exists in the newest AD scan
  (deleted in AD but the sync did not delete it - sync filtered OU, deletion threshold, or sync
  stopped) or was moved out of sync scope. Why: an orphaned synced account keeps its licences, its
  mailbox and its group memberships with nobody able to disable it from AD.
- Severity: medium (high when enabled and licensed). kind: broken, lens: both, category: IAM, entity: user.
- Attributes: Entra `onPremisesSyncEnabled`, `onPremisesSecurityIdentifier`, `accountEnabled`,
  `assignedLicenses` (requested). AD `objectSid` (requested). Note the AD inventory filter excludes
  nothing by enabled state for users, so "gone" means gone or out of the reader's scope.
- One side never scanned: no rows; also no rows when the AD run is `partial` (a partial user query
  would make every user look gone) - demand `status = 'ok'` for AD here.
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
entra_users AS ( /* B5 */ )
SELECT e.id, e.upn, e.sid, e.enabled, e.cloud_signin,
       CASE WHEN e.licences IS NOT NULL AND json_array_length(e.licences) > 0 THEN 1 ELSE 0 END AS licensed
FROM entra_users e
WHERE e.synced = 1 AND e.sid IS NOT NULL
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status = 'ok')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
  AND NOT EXISTS (SELECT 1 FROM ad_users a WHERE a.sid = e.sid)
```
  `each: any`; severity `{ field: licensed, map: { "1": high }, default: medium }`.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.1.
- Fix: find the AD object (recycle bin, moved OU); either restore it into sync scope or delete the
  cloud object deliberately (export the mailbox first).

### XS-USER-LICENSED-LEAVER

- Joins: Entra/M365 user (paid licence) x AD user on SID. Catches: a paid licence on an account
  whose AD object is disabled, expired, or in a leavers OU (`threshold.ad.disabled-ou-pattern`).
  Why: M365-LICENSED-USER-DISABLED sees only the cloud flag; most leaver processes disable or move
  the AD account and forget the licence; this is the money and the mailbox that remain.
- Severity: medium (high when the account is still enabled in Entra). kind: misconfigured,
  lens: both, category: CST, entity: user.
- Attributes - Entra: `assignedLicenses[].skuId`, `accountEnabled`, `onPremisesSecurityIdentifier`
  (requested). AD: `userAccountControl`, `accountExpires`, `distinguishedName` (requested).
  Free SKUs: the m365 default list inline; `threshold.m365.free-sku-ids` once list settings are
  readable (engine gap).
- One side never scanned: no rows.
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
entra_users AS ( /* B5 */ ),
leaver_pattern AS (SELECT COALESCE((SELECT value FROM setting WHERE key = 'threshold.ad.disabled-ou-pattern'),
                                   '(?i)OU=[^,]*(disable|leaver|terminat|former|departed|deprovision)') AS p),
paid AS (
  SELECT e.id, GROUP_CONCAT(json_extract(je.value, '$.skuId'), ', ') AS paid_skus
  FROM entra_users e, json_each(e.licences) je
  WHERE json_extract(je.value, '$.skuId') NOT IN (
    'f30db892-07e9-47e9-837c-80727f46fd3d','a403ebcc-fae0-4ca2-8c8c-7a907fd6c235','710779e8-3d4a-4c88-adb9-386c958d1fdf',
    'dcb1a3ae-b33f-4487-846a-a640262fadf4','5b631642-bd26-49fe-bd20-1daaa972ef80','1f2f344a-700d-42c9-9427-5cea1d5d7ba6',
    '6470687e-a428-4b7a-bef2-8a291ad947c9','8c4ce438-32a7-4ac5-91a6-e22ae08d9c8b','bc946dac-7877-4271-b2f7-99d2db13cd2c',
    '440eaaa8-b3e0-484b-a8be-62870b9ba70a','94763226-9b3c-4e75-a931-5c89701abe66','314c4481-f395-4525-be8b-2ec4bb1e9d91')
  GROUP BY e.id
)
SELECT e.id, e.upn, e.enabled AS entra_enabled, p.paid_skus, a.account, a.dn, a.uac, a.expires,
       CASE WHEN (COALESCE(a.uac, 0) & 2) = 2 THEN 'AD disabled'
            WHEN a.expires GLOB '[0-9][0-9][0-9][0-9]-*' AND a.expires < :now THEN 'AD expired ' || a.expires
            WHEN a.dn REGEXP (SELECT p FROM leaver_pattern) THEN 'AD leavers OU'
            ELSE 'ok' END AS ad_state
FROM entra_users e JOIN paid p ON p.id = e.id JOIN ad_users a ON a.sid = e.sid
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system IN ('entra', 'm365') AND status <> 'failed')
```
  `each: { field: ad_state, op: ne, value: ok }`; severity `{ field: entra_enabled, map: { "1": high }, default: medium }`.
- Refs: NIST-800-53:PM-3, NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- Fix: convert the mailbox to shared or inactive, remove the licence, make licensing groups exclude
  disabled and leavers-OU accounts.

### XS-COMPUTER-AD-ACTIVE-NO-SCCM

- Joins: AD computer (enabled, Windows, DC logon within N days) anti-join SCCM device on short name;
  and AD computer x SCCM device without a healthy client (no client, inactive, client check failed).
- Catches: machines in use that Configuration Manager does not know at all (discovery never found
  them - OU outside discovery scope, no AD site, pushed by hand), or knows but does not manage. Why:
  WSF-NO-CLIENT and SCCM-SERVER-NO-CLIENT rely on SCCM's own AD discovery (`ADLastLogonTime`); a
  machine discovery never saw is invisible to them. Nothing patches or inventories it.
- Severity: high for servers (`os` matches `Server`), medium for workstations.
  kind: missing, lens: both, category: LCM, entity: computer.
- Attributes - AD: `sAMAccountName`, `dNSHostName`, `operatingSystem`, `lastLogonTimestamp`
  (requested). SCCM: `Name`, `IsClient`/`Client`, `IsActive`/`Active`, `IsObsolete`/`Obsolete`,
  `ClientCheckPass`, `LastActiveTime` (requested by SMS_CombinedDeviceResources in
  SCCM-CLIENT-PUSH-FAILED, which has no OS filter, and by SMS_R_System in SCCM-SERVER-NO-CLIENT /
  SCCM-CLIENTS-INACTIVE-MANY). Domain controllers are included on purpose.
- One side never scanned: no rows; a `partial` SCCM run also gives no rows (an incomplete device
  list would make every machine "unknown to SCCM").
- SQL:

```sql
WITH ad_computers AS ( /* B2 */ ),
sccm_devices AS ( /* B4 */ )
SELECT a.instance || '/' || a.account AS id, a.account, a.dns_name, a.os, a.dc_logon,
       d.resource_id, d.has_client, d.active, d.client_check, d.last_active, d.client_version,
       CASE WHEN d.resource_id IS NULL THEN 'unknown to SCCM'
            WHEN COALESCE(d.has_client, 0) <> 1 THEN 'SCCM record without client'
            WHEN COALESCE(d.active, 1) = 0 THEN 'client inactive since ' || COALESCE(d.last_active, '?')
            WHEN d.client_check = 2 THEN 'client health check failed'
            ELSE 'ok' END AS sccm_state,
       CASE WHEN a.os LIKE '%Server%' THEN 1 ELSE 0 END AS is_server
FROM ad_computers a
LEFT JOIN sccm_devices d ON d.short_name = a.short_name AND COALESCE(d.obsolete, 0) <> 1
WHERE a.os LIKE 'Windows%'
  AND a.dc_logon GLOB '[0-9][0-9][0-9][0-9]-*'
  AND julianday(:now) - julianday(a.dc_logon) <= COALESCE((SELECT CAST(value AS INTEGER) FROM setting WHERE key = 'threshold.cross.computer-active-days'), 30)
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system IN ('sccm', 'workstations-sccm') AND status = 'ok')
```
  `each: { field: sccm_state, op: ne, value: ok }`; severity `{ field: is_server, map: { "1": high }, default: medium }`;
  evidence `"AD {dns_name} ({os}) logged on {dc_logon}; SCCM: {sccm_state}"`.
- Refs: NIST-800-53:CM-8, NIST-800-53:SI-2, CIS-Controls-v8:1.1, CIS-Controls-v8:7.3.
- Fix: extend AD system discovery to the OU, add the subnet to a boundary group, push or repair the
  client; record devices patched by another tool as exceptions.

### XS-COMPUTER-SCCM-AD-GONE

- Joins: SCCM device (not obsolete, with client) anti-join AD enabled computers on short name.
- Catches: SCCM still manages (and counts, licenses, targets deployments at) a machine whose AD
  computer object is gone or disabled. Why: the AD inventory covers *enabled* computers only, so
  "absent" means deleted or disabled; either way the record is dead weight that keeps compliance
  numbers low and, if the client still talks, a machine outside the domain's control.
- Severity: low; medium when the client is still active (`active` = 1).
  kind: misconfigured, lens: maintenance, category: HYG, entity: computer.
- Attributes: as above. Gap: the AD pack has no query that includes disabled computers, so
  "disabled" and "deleted" cannot be told apart here; `entity.gone_since` (instance of the AD
  integration, entity_type computer) distinguishes "seen before, gone now" from "never seen".
- One side never scanned: no rows; AD run must be `ok`.
- SQL:

```sql
WITH ad_computers AS ( /* B2 */ ),
sccm_devices AS ( /* B4 */ )
SELECT d.instance || '/' || d.resource_id AS id, d.resource_id, d.short_name, d.os, d.active, d.last_active, d.client_version,
       (SELECT MAX(e.gone_since) FROM entity e WHERE e.entity_type = 'computer' AND UPPER(RTRIM(e.entity_key, '$')) = d.short_name) AS ad_gone_since
FROM sccm_devices d
WHERE COALESCE(d.obsolete, 0) <> 1 AND d.has_client = 1 AND d.short_name IS NOT NULL
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status = 'ok')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system IN ('sccm', 'workstations-sccm') AND status <> 'failed')
  AND NOT EXISTS (SELECT 1 FROM ad_computers a WHERE a.short_name = d.short_name)
```
  `each: any`; severity `{ field: active, map: { "1": medium }, default: low }`;
  evidence `"SCCM {short_name} ({os}, client {client_version}, active {active}, last active {last_active}); AD: no enabled computer object (gone since {ad_gone_since})"`.
- Refs: NIST-800-53:CM-8(3), CIS-Controls-v8:1.2.
- Fix: delete the SCCM record (or let the obsolete-record cleanup task do it); if the client is
  active, find the machine - it runs outside the directory.

### XS-VM-NO-BACKUP

- Joins: vCenter VM x Veeam backup object on VM name.
- Catches: a powered-on VM with no Veeam backup object, or one with zero restore points. Why: the
  VM nobody added to a job is found at restore time (`infrastructure.md` BK01). VEEAM-* rules only
  see objects that exist in Veeam.
- Severity: high (critical when the VM's short name matches an AD domain controller - `uac` has
  8192 - or a server mapped to a criticality-1 system in `system` via `entity`).
  kind: missing, lens: both, category: BCK, entity: vm.
- Attributes - vmware: `vm`, `name`, `power_state` (requested, /api/vcenter/vm). veeam: `name`,
  `type`, `platformName`, `restorePointsCount` (requested, /api/v1/backupObjects; the API also
  returns `objectId`/`viType`, not selected). Gap: the VM `instance_uuid` is not in the vCenter
  list (needs per-VM fan-out), so the join is by name; renamed VMs produce false positives, which
  the evidence makes visible.
- One side never scanned: no rows; Veeam run must be `ok` (a partial object list = everything unprotected).
- SQL:

```sql
WITH vc_vms AS ( /* B9 */ ),
veeam_objects AS ( /* B10 */ ),
ad_computers AS ( /* B2 */ )
SELECT v.instance || '/' || v.vm AS id, v.vm, v.name, v.power_state,
       o.object_id, o.rp_count, o.platform,
       CASE WHEN o.object_id IS NULL THEN 'no backup object' ELSE o.rp_count || ' restore points' END AS backup_state,
       CASE WHEN EXISTS (SELECT 1 FROM ad_computers a WHERE a.short_name = v.short_name AND (a.uac & 8192) = 8192) THEN 1 ELSE 0 END AS is_dc
FROM vc_vms v
LEFT JOIN veeam_objects o ON o.short_name = v.short_name
WHERE v.power_state = 'POWERED_ON'
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'vmware' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'veeam' AND status = 'ok')
  AND (o.object_id IS NULL OR COALESCE(o.rp_count, 0) = 0)
```
  `each: any`; severity `{ field: is_dc, map: { "1": critical }, default: high }`;
  evidence `"vCenter VM {name} ({power_state}); Veeam: {backup_state}"`.
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2.
- Fix: add the VM to a backup job (or a job that selects by folder/tag so new VMs are covered);
  VMs that must not be backed up are accepted one by one.

### XS-SERVER-NOT-MONITORED

- Joins: AD server (operatingSystem matches `Server`, DC logon within N days) anti-join PRTG
  devices (sensor table `device`) and Dynatrace hosts (`hostInfo.displayName`), on short name.
- Catches: a live server no monitoring tool watches. Why: outages on it are reported by users;
  `infrastructure.md` "configuration item monitored by none of the monitoring tools".
- Severity: high for domain controllers (uac 8192) and servers of criticality-1 systems, medium otherwise.
  kind: missing, lens: both, category: MON, entity: computer.
- Attributes - AD: as B2 (requested). PRTG: `device`, `status_raw` (requested in every PRTG rule).
  Dynatrace: `hostInfo.displayName`, `availabilityState` (requested). Gap: PRTG `device` is a
  display name; the pack should also request the `host` column (the address) so the match can use
  the FQDN or IP. Dynatrace `hostInfo.ipAddresses` is returned by the API but not relied on.
- One side never scanned: the rule needs AD plus **at least one** monitoring system; the
  `seen_in` column says which monitors were consulted ("PRTG not scanned"), so a server absent from
  the only scanned monitor is still reported, with that caveat in the evidence.
- SQL:

```sql
WITH ad_computers AS ( /* B2 */ ),
prtg_devices AS ( /* B11 */ ),
dt_hosts AS ( /* B12 */ ),
usable AS ( /* B3 */ )
SELECT a.instance || '/' || a.account AS id, a.account, a.dns_name, a.os, a.dc_logon,
       CASE WHEN (a.uac & 8192) = 8192 THEN 1 ELSE 0 END AS is_dc,
       CASE WHEN (SELECT ok FROM usable WHERE system = 'prtg') = 1 THEN 'not in PRTG' ELSE 'PRTG not scanned' END AS prtg_state,
       CASE WHEN (SELECT ok FROM usable WHERE system = 'dynatrace') = 1 THEN 'not in Dynatrace' ELSE 'Dynatrace not scanned' END AS dt_state,
       (SELECT MIN(sy.criticality) FROM entity e JOIN system sy ON sy.system_id = e.system_id
         WHERE e.entity_type = 'computer' AND UPPER(RTRIM(e.entity_key, '$')) = a.short_name) AS criticality
FROM ad_computers a
WHERE a.os LIKE '%Server%'
  AND a.dc_logon GLOB '[0-9][0-9][0-9][0-9]-*'
  AND julianday(:now) - julianday(a.dc_logon) <= COALESCE((SELECT CAST(value AS INTEGER) FROM setting WHERE key = 'threshold.cross.server-active-days'), 30)
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM usable WHERE system IN ('prtg', 'dynatrace') AND ok = 1)
  AND NOT EXISTS (SELECT 1 FROM prtg_devices p WHERE p.short_name = a.short_name)
  AND NOT EXISTS (SELECT 1 FROM dt_hosts d WHERE d.short_name = a.short_name)
```
  `each: any`; severity `{ field: is_dc, map: { "1": high }, default: medium }` (a second map on
  `criticality` is not expressible - engine gap: one severity field only; compute a `sev_class`
  column in SQL instead); evidence `"AD server {dns_name} ({os}, logon {dc_logon}): {prtg_state}; {dt_state}"`.
- Refs: NIST-800-53:SI-4, NIST-800-53:CM-8, CIS-Controls-v8:8.2, CIS-Controls-v8:13.1.
- Fix: add the server to monitoring (auto-discovery group in PRTG, OneAgent via the deployment
  tool); record appliances monitored elsewhere as exceptions.

### XS-HOST-COMPOUND-RISK

- Joins: `active_finding` x `active_finding` on the normalised host (findings-level view), plus
  the SCCM resource-id-to-name map for `workstations-sccm` findings whose target is a ResourceID.
- Catches: one host failing rules of several *classes* at once - patching, end-of-life OS, local
  administrators, perimeter (firewall/RDP/SMB1), protection (AV/EDR/BitLocker), backup, known
  exploited vulnerability. One finding per host, severity by the number of classes. Why: ten
  separate medium findings on one machine are one critical machine; this is the ranking signal the
  single-system packs cannot give.
- Severity: `{ field: classes, ranges: [ {min: 5, value: critical}, {min: 4, value: high}, {min: 3, value: medium} ], default: low }`,
  threshold `cross.compound-min-classes` (default 3). kind: broken, lens: both, category: HYG, entity: computer.
- Attributes: none from `row_seen` except the SCCM `Name` map; everything else is `active_finding`
  (`rule_id`, `target`, `entity_type`, `severity`, `instance`, `system`).
- One side never scanned: inherent - a class that was never checked simply does not count, and the
  evidence lists which classes contributed. No coverage row needed.
- SQL:

```sql
WITH sccm_names AS (
  SELECT s.entity_key AS resource_id, UPPER(MAX(json_extract(s.attrs, '$.Name'))) AS short_name
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system IN ('sccm', 'workstations-sccm') AND s.entity_type = 'computer'
  GROUP BY s.entity_key
),
hits AS (
  SELECT f.rule_id, f.severity, f.system,
         CASE WHEN f.system IN ('sccm', 'workstations-sccm') AND f.entity_type = 'computer'
              THEN (SELECT n.short_name FROM sccm_names n WHERE n.resource_id = f.target)
              ELSE UPPER(RTRIM(CASE WHEN instr(f.target, '|') > 0 THEN substr(f.target, 1, instr(f.target, '|') - 1) ELSE f.target END, '$')) END AS host_raw,
         CASE WHEN f.rule_id GLOB '*-PATCH-NONE-RECENT' OR f.rule_id GLOB '*-CCM-UPDATE-OVERDUE' OR f.rule_id = 'WSF-SUM-NONCOMPLIANT' THEN 'patching'
              WHEN f.rule_id GLOB '*-OS-UNSUPPORTED' OR f.rule_id GLOB '*-OS-BUILD-UNSUPPORTED' OR f.rule_id GLOB '*-OS-WIN10'
                   OR f.rule_id GLOB 'AD-COMP-OS-*' OR f.rule_id GLOB '*-DEVICE-WINDOWS-UNSUPPORTED' THEN 'end-of-life'
              WHEN f.rule_id GLOB '*-LOCALADMIN-*' OR f.rule_id GLOB 'AD-COMP-LAPS-*' THEN 'local-admin'
              WHEN f.rule_id GLOB '*-FW-*' OR f.rule_id GLOB '*-GPO-FIREWALL-OFF' OR f.rule_id GLOB '*-RDP-NO-NLA' OR f.rule_id = 'WINSRV-SMB1-SERVER-ON' THEN 'perimeter'
              WHEN f.rule_id GLOB '*-DEFENDER-*' OR f.rule_id GLOB '*-SVC-AGENT-STOPPED' OR f.rule_id GLOB '*-BITLOCKER-*' OR f.rule_id GLOB '*-AV-*' THEN 'protection'
              WHEN f.rule_id IN ('XS-VM-NO-BACKUP', 'XS-SERVER-AD-NO-BACKUP') THEN 'backup'
              WHEN f.rule_id IN ('XS-HOST-KEV-COMPOUND', 'XS-HOST-EOL-EXPOSED') THEN 'exploited-or-exposed'
              WHEN f.rule_id GLOB 'AD-COMP-*DELEGATION*' OR f.rule_id = 'AD-COMP-PROTOCOL-TRANSITION' THEN 'delegation'
              ELSE NULL END AS class
  FROM active_finding f
  WHERE f.status = 'open'
),
per_host AS (
  SELECT CASE WHEN instr(host_raw, '.') > 0 THEN substr(host_raw, 1, instr(host_raw, '.') - 1) ELSE host_raw END AS host,
         COUNT(DISTINCT class) AS classes,
         GROUP_CONCAT(DISTINCT class) AS class_list,
         COUNT(*) AS findings,
         SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_or_worse
  FROM hits WHERE class IS NOT NULL AND host_raw IS NOT NULL AND host_raw <> '-'
  GROUP BY 1
)
SELECT host, classes, class_list, findings, high_or_worse FROM per_host
```
  `key: host`, `each: { field: classes, op: ge, value: 3, threshold: cross.compound-min-classes }`,
  evidence `"{host}: {classes} risk classes open at once ({class_list}) - {findings} findings, {high_or_worse} high or critical"`.
- Refs: NIST-800-53:RA-3, NIST-800-53:RA-5, CIS-Controls-v8:7.2.
- Fix: treat the host as one work item: patch or retire it first, then the rest; the per-rule
  findings stay open underneath and resolve on their own.
- Engine note: the class map is hard-coded by rule-id pattern. A `tags:` field on rules (and
  `rule.tags` in the store) would make this generic; tenant rules would then join in by tag.

### Provisioning (SCIM) joins - Entra to an app's own user table

From a real case, made generic: new joiners could not reach a SaaS app provisioned from Entra by
SCIM, because (a) the target already held users with the same e-mail under a different username,
Entra matched on UPN and every create failed as a duplicate, and (b) new users were added only to an
old group no longer assigned to the app, so provisioning skipped them. All four need the
**servicenow pack to add a `sys_user` query** (today `rules\servicenow.yaml` reads only `incident`,
`task_sla`, `change_request`, `sc_task`, `ecc_agent`), and the **entra pack to add the app's
assignments and group members**. Attributes to add, named once here:

- servicenow, new query `/api/now/table/sys_user` (entity `app-user`, key `sys_id`,
  `sysparm_display_value=false`, `sysparm_exclude_reference_link=true`):
  `sys_id,user_name,email,active,first_name,last_name,source,sys_created_on,sys_updated_on,last_login_time,locked_out`
  (`source` holds the SCIM/LDAP origin id on most provisioning setups; the `u_`-prefixed custom id
  field, if any, is a tenant setting `cross.app-user-external-id-field` - not needed for the joins below).
- entra, new query per provisioned app (one rule, `path: /servicePrincipals/{id}/appRoleAssignedTo`
  needs fan-out; interim: a tenant copy with the app's object id in the path, entity `app-assignment`,
  key `id`, fields `principalId,principalType,principalDisplayName,resourceId,resourceDisplayName,createdDateTime`).
- entra, group members: `/groups/{id}/transitiveMembers?$select=id,userPrincipalName,accountEnabled`
  for each assigned group (fan-out again; interim: tenant copies per group), entity `group-member`,
  key `"{group}|{id}"`.
- entra, users: `mail` and `employeeHireDate` added to the `/users` inventory select (`mail` is the
  SCIM matching attribute on most apps; `createdDateTime` is already requested).
- entra, provisioning status: `/servicePrincipals/{id}/synchronization/jobs` (`status.code`,
  `status.lastExecution.state`, `status.quarantine`) - a single-system rule for the entra pack
  (quarantined provisioning job), listed here because it explains the joins' findings.

### XS-SCIM-DUPLICATE-TRAP

- Joins: Entra user x app user on e-mail (`mail` = `email`, case-insensitive) where the usernames differ.
- Catches: the same person exists on both sides with the same e-mail but a different username
  (`user_name` != `userPrincipalName`); the provisioning create for that person fails as a duplicate
  (or matches the wrong record). Why: this is the first cause in the case above; it is invisible
  from either side alone.
- Severity: medium (high when the Entra account is enabled and created in the last N days - the joiner
  who cannot work today). kind: broken, lens: maintenance, category: IAM, entity: user.
- Attributes - Entra: `userPrincipalName`, `mail` (**add**), `accountEnabled`, `createdDateTime`.
  App: `user_name`, `email`, `active`, `sys_id` (**add the sys_user query**).
- One side never scanned: no rows.
- SQL:

```sql
WITH entra_users AS ( /* B5 - needs mail */ ),
app_users AS (
  SELECT r.instance, s.entity_key AS sys_id,
         LOWER(MAX(json_extract(s.attrs, '$.user_name'))) AS user_name,
         LOWER(MAX(json_extract(s.attrs, '$.email'))) AS email,
         MAX(json_extract(s.attrs, '$.active')) AS active,
         MAX(json_extract(s.attrs, '$.sys_created_on')) AS created,
         MAX(json_extract(s.attrs, '$.last_login_time')) AS last_login
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'servicenow' AND s.entity_type = 'app-user'
  GROUP BY r.instance, s.entity_key
)
SELECT e.id, e.upn, e.mail, e.enabled, e.created, u.instance AS app_instance, u.sys_id, u.user_name, u.active AS app_active,
       CASE WHEN e.enabled = 1 AND e.created GLOB '[0-9][0-9][0-9][0-9]-*'
                 AND julianday(:now) - julianday(e.created) <= 30 THEN 1 ELSE 0 END AS new_joiner
FROM entra_users e JOIN app_users u ON u.email = LOWER(e.mail)
WHERE LOWER(e.upn) <> u.user_name
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'servicenow' AND status <> 'failed')
```
  `key: "{id}|{sys_id}"`, `each: any`; severity `{ field: new_joiner, map: { "1": high }, default: medium }`;
  evidence `"Entra {upn} (mail {mail}, enabled {enabled}); app user {user_name} (sys_id {sys_id}, active {app_active}) has the same e-mail - provisioning matches on UPN and will fail as a duplicate"`.
- Refs: NIST-800-53:AC-2, NIST-800-53:IA-4, CIS-Controls-v8:5.1, CIS-Controls-v8:6.1.
- Fix: rename the app-side username to the UPN (or set the provisioning matching attribute to
  mail), then restart provisioning for the user.

### XS-SCIM-ASSIGNED-NOT-PROVISIONED

- Joins: Entra user (enabled) x app-assignment (direct) or group-member of an assigned group x app
  user on e-mail or UPN (anti-join).
- Catches: a user who is in scope for the app (assigned, directly or through an assigned group)
  for more than N days and still has no record in the app's user table. Why: provisioning cycles
  skip or fail silently per user; the user finds out when they open the app.
- Severity: high when enabled and in scope for more than N days (default 2). kind: broken,
  lens: maintenance, category: IAM, entity: user.
- Attributes - Entra: app-assignment `principalId`, `principalType`, `createdDateTime`;
  group-member `id`; user `userPrincipalName`, `mail`, `accountEnabled` (**all to add** except UPN
  and accountEnabled). App: `user_name`, `email` (**add**).
- One side never scanned: no rows; the app run must be `ok`.
- SQL:

```sql
WITH entra_users AS ( /* B5 - needs mail */ ),
assigned AS (
  SELECT MAX(json_extract(s.attrs, '$.resourceDisplayName')) AS app_name,
         json_extract(s.attrs, '$.principalId') AS principal_id,
         json_extract(s.attrs, '$.principalType') AS principal_type,
         MAX(json_extract(s.attrs, '$.createdDateTime')) AS assigned_at
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'entra' AND s.entity_type = 'app-assignment'
  GROUP BY 2, 3
),
members AS (
  SELECT json_extract(s.attrs, '$.group') AS group_id, json_extract(s.attrs, '$.id') AS user_id
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'entra' AND s.entity_type = 'group-member'
),
in_scope AS (
  SELECT a.app_name, a.principal_id AS user_id, a.assigned_at, 'direct' AS via FROM assigned a WHERE a.principal_type = 'User'
  UNION
  SELECT a.app_name, m.user_id, a.assigned_at, 'group ' || a.principal_id FROM assigned a JOIN members m ON m.group_id = a.principal_id WHERE a.principal_type = 'Group'
),
app_users AS (
  SELECT LOWER(json_extract(s.attrs, '$.user_name')) AS user_name, LOWER(json_extract(s.attrs, '$.email')) AS email
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'servicenow' AND s.entity_type = 'app-user'
)
SELECT e.id || '|' || i.app_name AS id, e.upn, e.mail, e.created, i.app_name, i.via, i.assigned_at,
       CAST(julianday(:now) - julianday(COALESCE(i.assigned_at, e.created)) AS INTEGER) AS waiting_days
FROM entra_users e JOIN in_scope i ON i.user_id = e.id
WHERE e.enabled = 1
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'servicenow' AND status = 'ok')
  AND NOT EXISTS (SELECT 1 FROM app_users u WHERE u.user_name = LOWER(e.upn) OR (e.mail IS NOT NULL AND u.email = LOWER(e.mail)))
```
  `each: { field: waiting_days, op: gt, value: 2, threshold: cross.scim-provisioning-grace-days }`,
  evidence `"Entra {upn} in scope for {app_name} via {via} since {assigned_at}; app: no user record after {waiting_days} days"`.
- Refs: NIST-800-53:AC-2(1), CIS-Controls-v8:6.1.
- Fix: open the provisioning log for the user (skipped / failed reason), fix the matching or
  attribute mapping, provision on demand.

### XS-SCIM-LEAVER-STILL-IN-APP

- Joins: app user (active) x Entra user on e-mail or UPN: Entra account disabled, or no Entra account at all.
- Catches: leavers (and never-known accounts: local, vendor, test) still active in the app. Why:
  deprovisioning only reaches accounts Entra created and still links; locally created ones outlive
  everyone. `infrastructure.md` "users disabled in the directory who still hold admin in ... a SaaS console".
- Severity: high when the app record signed in after the Entra account was disabled (needs
  `last_login_time`), medium otherwise, low for "no Entra account" (local account - may be a vendor).
  kind: misconfigured, lens: security, category: IAM, entity: user.
- Attributes - App: `user_name`, `email`, `active`, `last_login_time`, `source` (**add**). Entra:
  `userPrincipalName`, `mail`, `accountEnabled` (mail **to add**).
- One side never scanned: no rows; Entra run must be `ok` (otherwise every app user looks unknown).
- SQL:

```sql
WITH entra_users AS ( /* B5 - needs mail */ ),
app_users AS (
  SELECT r.instance, s.entity_key AS sys_id,
         LOWER(MAX(json_extract(s.attrs, '$.user_name'))) AS user_name,
         LOWER(MAX(json_extract(s.attrs, '$.email'))) AS email,
         MAX(json_extract(s.attrs, '$.active')) AS active,
         MAX(json_extract(s.attrs, '$.last_login_time')) AS last_login,
         MAX(json_extract(s.attrs, '$.source')) AS source
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'servicenow' AND s.entity_type = 'app-user'
  GROUP BY r.instance, s.entity_key
)
SELECT u.instance || '/' || u.sys_id AS id, u.user_name, u.email, u.active, u.last_login, u.source,
       e.upn, e.enabled AS entra_enabled,
       CASE WHEN e.id IS NULL THEN 'no Entra account'
            WHEN e.enabled = 0 THEN 'Entra account disabled'
            ELSE 'ok' END AS state
FROM app_users u
LEFT JOIN entra_users e ON LOWER(e.upn) = u.user_name OR (u.email IS NOT NULL AND LOWER(e.mail) = u.email)
WHERE CAST(u.active AS TEXT) IN ('true', '1')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status = 'ok')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'servicenow' AND status <> 'failed')
```
  `each: { field: state, op: ne, value: ok }`; severity `{ field: state, map: { "Entra account disabled": medium, "no Entra account": low }, default: medium }`
  (raise to high in a sibling rule when `last_login` is newer than the Entra disable - needs
  `signInActivity` and a disable date the Graph does not give; use the app's `last_login` within 30
  days as the proxy: `each: all [state ne ok, last_login age-lt 30]`).
- Refs: NIST-800-53:AC-2(3), NIST-800-53:PS-4, CIS-Controls-v8:5.3, CIS-Controls-v8:6.2.
- Fix: deactivate the app record; for local accounts, link them to the directory or record a vendor owner.

### XS-ONBOARDING-NOT-IN-APP-GROUPS

- Joins: AD or Entra user created in the last N days x group-member rows of groups assigned to
  provisioned apps (anti-join); optionally x the app's user table.
- Catches: a new joiner who is in none of the groups that drive app access - typically because
  onboarding adds them to an old group that is no longer assigned. Why: the second cause in the
  case above; the person has an account and nothing works.
- Severity: medium. kind: missing, lens: maintenance, category: IAM, entity: user.
- Attributes - Entra: `createdDateTime`, `accountEnabled`, `userType` (requested); app-assignment
  and group-member rows (**add**, as above). AD alternative: `whenCreated` (requested) joined on
  SID when the groups are AD groups synced to Entra - then `memberOf` on the AD user inventory is
  the missing attribute (**add**), and the assigned AD group DNs come from the Entra group's
  `onPremisesSyncEnabled` + a tenant setting `cross.app-access-group-pattern` (regex on group name).
- One side never scanned: no rows.
- SQL (Entra-side form):

```sql
WITH entra_users AS ( /* B5 */ ),
assigned_groups AS (
  SELECT DISTINCT json_extract(s.attrs, '$.principalId') AS group_id, json_extract(s.attrs, '$.resourceDisplayName') AS app_name
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'entra' AND s.entity_type = 'app-assignment' AND json_extract(s.attrs, '$.principalType') = 'Group'
),
members AS (
  SELECT json_extract(s.attrs, '$.group') AS group_id, json_extract(s.attrs, '$.id') AS user_id
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'entra' AND s.entity_type = 'group-member'
)
SELECT e.id, e.upn, e.created, e.enabled,
       CAST(julianday(:now) - julianday(e.created) AS INTEGER) AS age_days,
       (SELECT COUNT(*) FROM assigned_groups) AS app_groups
FROM entra_users e
WHERE e.enabled = 1 AND e.user_type = 'Member'
  AND e.created GLOB '[0-9][0-9][0-9][0-9]-*'
  AND julianday(:now) - julianday(e.created) <= COALESCE((SELECT CAST(value AS INTEGER) FROM setting WHERE key = 'threshold.cross.onboarding-window-days'), 30)
  AND EXISTS (SELECT 1 FROM assigned_groups)
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status = 'ok')
  AND NOT EXISTS (SELECT 1 FROM members m JOIN assigned_groups g ON g.group_id = m.group_id WHERE m.user_id = e.id)
```
  `each: { field: age_days, op: gt, value: 1, threshold: cross.onboarding-grace-days }`,
  evidence `"{upn} created {created} ({age_days} days ago) is in none of the {app_groups} groups assigned to provisioned apps"`.
- Refs: NIST-800-53:AC-2(1), CIS-Controls-v8:6.1, CIS-Controls-v8:6.8.
- Fix: add the joiner to the current access group; retire the old group (or re-assign it) so
  onboarding scripts stop filling it. A companion single-system check for the entra pack: a group
  that received members in the last N days but is assigned to no app and no licence.

## Priority 2 - high value, needs a name-match convention or one added attribute

### XS-USER-ENTRA-PRIVILEGED-AD-WEAK

- Joins: Entra role-assignment -> Entra user (`principalId` = user `id`) -> AD user (SID).
- Catches: a privileged cloud role on a synchronised account whose AD side is weak: disabled
  (role survives), password never expires, stale DC logon, or in a leavers OU. Why:
  ENTRA-ROLE-SYNCED-HOLDER says "synced holder"; this says *how* the on-premises side can be used
  to take the cloud role (`microsoft-cloud.md` "privileged role holders ... x users").
- Severity: critical when disabled-in-AD or leavers OU (an abandoned admin), high otherwise.
  kind: misconfigured, lens: security, category: IAM, entity: role-assignment.
- Attributes: Entra `principalId`, `roleDefinitionId`, `principal.userPrincipalName`
  (requested); Entra user `onPremisesSecurityIdentifier` (requested); AD `userAccountControl`,
  `lastLogonTimestamp`, `distinguishedName`, `pwdLastSet` (requested). Whether `expand: principal`
  returns `onPremisesSecurityIdentifier` could not be verified offline - the two-hop join through
  the user inventory avoids depending on it.
- One side never scanned: no rows.
- SQL:

```sql
WITH entra_roles AS ( /* B8 */ ), entra_users AS ( /* B5 */ ), ad_users AS ( /* B1 */ ),
leaver_pattern AS (SELECT COALESCE((SELECT value FROM setting WHERE key = 'threshold.ad.disabled-ou-pattern'),
                                   '(?i)OU=[^,]*(disable|leaver|terminat|former|departed|deprovision)') AS p)
SELECT r.assignment_id, r.role_id, r.scope, e.upn, a.account, a.dn, a.uac, a.dc_logon, a.pwd_set,
       CASE WHEN (a.uac & 2) = 2 THEN 'AD disabled'
            WHEN a.dn REGEXP (SELECT p FROM leaver_pattern) THEN 'AD leavers OU'
            WHEN (a.uac & 65536) = 65536 THEN 'AD password never expires'
            WHEN a.dc_logon IS NULL OR a.dc_logon NOT GLOB '[0-9][0-9][0-9][0-9]-*' OR julianday(:now) - julianday(a.dc_logon) > 90 THEN 'AD stale'
            ELSE 'ok' END AS ad_state
FROM entra_roles r JOIN entra_users e ON e.id = r.principal_id JOIN ad_users a ON a.sid = e.sid
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'entra' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status <> 'failed')
```
  `each: { field: ad_state, op: ne, value: ok }`; severity `{ field: ad_state, map: { "AD disabled": critical, "AD leavers OU": critical }, default: high }`.
  Role list filter (privileged ids) as in ENTRA-ROLE-SYNCED-HOLDER, inline.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-2(3), CIS-Controls-v8:5.4.
- Fix: cloud-only admin accounts; remove the role from the synced account.

### XS-ADMIN-DEVICE-NONCOMPLIANT

- Joins: Entra role-assignment (user principal) x Intune managed device on `principal.userPrincipalName` = `userPrincipalName`.
- Catches: a privileged role holder whose primary device is noncompliant, unencrypted, or stale.
  Why: the admin's device is the tier-0 asset; compliance CA only bites if the device is compliant.
- Severity: high (critical for tier-0 roles). kind: misconfigured, lens: security, category: CFG, entity: managed-device.
- Attributes: Entra `principal.userPrincipalName`, `roleDefinitionId` (requested); Intune
  `userPrincipalName`, `complianceState`, `isEncrypted`, `lastSyncDateTime`, `deviceName` (requested).
- One side never scanned: no rows.
- SQL: `entra_roles r JOIN intune_devices d ON LOWER(d.primary_upn) = LOWER(r.upn)` with
  `state = CASE WHEN compliance IN ('noncompliant','error','conflict') THEN ... WHEN last_sync older than 30 d THEN 'stale' ELSE 'ok' END`,
  `each: { field: state, op: ne, value: ok }`, key `"{assignment_id}|{id}"`.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:CM-6, CIS-Controls-v8:5.4.
- Fix: privileged access workstation or at least compliant device for every admin.

### XS-SCCM-ADMIN-AD-DISABLED

- Joins: SCCM `SMS_Admin` (`LogonName` = `DOMAIN\sam`) x AD user on sAMAccountName.
- Catches: an SCCM administrative user whose AD account is disabled, stale, or in a leavers OU
  (SCCM-RBAC-DELETED-ACCOUNT only sees *deleted*). Why: Full Administrator = code execution on
  every client; a disabled account re-enabled by mistake gets it back.
- Severity: medium (high for Full Administrator). kind: misconfigured, lens: security, category: IAM, entity: admin.
- Attributes: SCCM `LogonName`, `IsGroup`, `RoleNames`, `IsDeleted` (requested, SCCM-RBAC-*);
  AD B1 (requested). Groups (`IsGroup` true) need `member` of that group - only builtin groups'
  members are requested today, so group grants are reported as "group, members not checked".
- One side never scanned: no rows.
- SQL:

```sql
WITH ad_users AS ( /* B1 */ ),
admins AS (
  SELECT r.instance, s.entity_key AS admin_id,
         MAX(json_extract(s.attrs, '$.LogonName')) AS logon_name,
         MAX(CAST(json_extract(s.attrs, '$.IsGroup') AS INTEGER)) AS is_group,
         MAX(json_extract(s.attrs, '$.RoleNames')) AS roles
  FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
  WHERE r.system = 'sccm' AND s.entity_type = 'admin'
  GROUP BY r.instance, s.entity_key
)
SELECT m.instance || '/' || m.admin_id AS id, m.logon_name, m.roles, a.account, a.dn, a.uac, a.dc_logon,
       CASE WHEN m.is_group = 1 THEN 'group - members not checked'
            WHEN a.account IS NULL THEN 'no AD user with that name'
            WHEN (a.uac & 2) = 2 THEN 'AD disabled'
            WHEN a.dc_logon IS NULL OR a.dc_logon NOT GLOB '[0-9][0-9][0-9][0-9]-*' OR julianday(:now) - julianday(a.dc_logon) > 90 THEN 'AD stale'
            ELSE 'ok' END AS state,
       CASE WHEN m.roles LIKE '%Full Administrator%' THEN 1 ELSE 0 END AS full_admin
FROM admins m
LEFT JOIN ad_users a ON LOWER(a.account) = LOWER(CASE WHEN instr(m.logon_name, '\') > 0 THEN substr(m.logon_name, instr(m.logon_name, '\') + 1) ELSE m.logon_name END)
WHERE EXISTS (SELECT 1 FROM latest_run WHERE system = 'sccm' AND status <> 'failed')
  AND EXISTS (SELECT 1 FROM latest_run WHERE system = 'active-directory' AND status = 'ok')
```
  `each: { field: state, op: in, value: ['AD disabled', 'AD stale', 'no AD user with that name'] }`;
  severity `{ field: full_admin, map: { "1": high }, default: medium }`.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:AC-6(7), CIS-Controls-v8:5.3.
- Fix: remove the administrative user; grant through one reviewed group.

### XS-INTUNE-PRIMARY-USER-LEAVER

- Joins: Intune managed device (`userPrincipalName`) x Entra user (UPN) and, through SID, AD user.
- Catches: a device whose primary user is disabled or gone (Entra) or disabled/leavers OU (AD).
  Why: the device is still enrolled, still receives policy and apps, still holds data; it was never
  wiped or reassigned. `windows-estate.md` line 29 asks for the SCCM variant; Intune has the
  attribute today.
- Severity: medium (high when the device synced after the account was disabled - `lastSyncDateTime`
  within 30 days). kind: misconfigured, lens: security, category: HYG, entity: managed-device.
- Attributes: Intune `userPrincipalName`, `lastSyncDateTime`, `deviceName`, `managedDeviceOwnerType`
  (requested); Entra `userPrincipalName`, `accountEnabled`, `onPremisesSecurityIdentifier`
  (requested); AD B1 (requested).
- One side never scanned: Intune + Entra required; AD optional (`seen_in` column).
- SQL: `intune_devices d LEFT JOIN entra_users e ON LOWER(e.upn) = LOWER(d.primary_upn) LEFT JOIN ad_users a ON a.sid = e.sid`,
  state `CASE WHEN e.id IS NULL THEN 'no Entra user' WHEN e.enabled = 0 THEN 'Entra disabled' WHEN (a.uac & 2) = 2 THEN 'AD disabled' WHEN a.dn REGEXP leaver THEN 'AD leavers OU' ELSE 'ok' END`,
  `WHERE d.primary_upn IS NOT NULL AND d.primary_upn <> ''` and Entra run `ok`.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:CM-8, CIS-Controls-v8:1.1.
- Fix: retire or wipe the device, or set the new primary user.

### XS-DEVICE-INTUNE-AD-GONE

- Joins: Intune Windows device (corporate, synced within 30 days) anti-join AD enabled computers on `deviceName`.
- Catches: a co-managed or hybrid-joined Windows device that Intune manages but AD no longer has
  (object deleted or disabled while the device keeps syncing). Why: the machine runs on a cached
  domain identity; Kerberos and GPO silently fail; it is also the pattern of a device re-imaged
  outside the process.
- Severity: medium. kind: broken, lens: both, category: HYG, entity: managed-device.
- Attributes: Intune `deviceName`, `operatingSystem`, `lastSyncDateTime`, `managedDeviceOwnerType`
  (requested); gap: Intune `joinType` / `azureADDeviceId` (not requested) would separate Entra-only
  joined devices (expected absent from AD) from hybrid ones; without it, limit to names that match
  the AD naming pattern setting `cross.domain-computer-name-pattern` (default `.*`).
- One side never scanned: no rows; AD run `ok`.
- SQL: `intune_devices d WHERE d.os = 'Windows' AND owner_type = 'company' AND last_sync within 30 d AND NOT EXISTS (ad_computers a WHERE a.short_name = d.short_name)`, with the Entra device row's `trustType` joined by name to annotate (`ServerAd` = hybrid, expected in AD).
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1.
- Fix: rejoin or re-image; delete the stale Intune record.

### XS-DEVICE-ENTRA-HYBRID-AD-GONE

- Joins: Entra device with `trustType` = `ServerAd` (hybrid joined) anti-join AD enabled computers on `displayName`.
- Catches: hybrid device objects whose AD computer is gone - sync leftovers that keep
  Conditional Access "hybrid joined" satisfied for a machine that no longer exists.
  ENTRA-DEVICE-STALE sees only the sign-in date.
- Severity: low (medium when `approximateLastSignInDateTime` within 30 days: something still signs in with it).
  kind: misconfigured, lens: security, category: HYG, entity: device.
- Attributes: Entra device `displayName`, `trustType`, `approximateLastSignInDateTime`, `accountEnabled`
  (requested); AD B2.
- SQL: `entra_devices x WHERE trust_type = 'ServerAd' AND enabled = 1 AND NOT EXISTS (ad_computers a WHERE a.short_name = x.short_name)` with AD run `ok`.
- Refs: NIST-800-53:CM-8(3), CIS-Controls-v8:1.2.
- Fix: delete the device object (Connect sync should have; check its device-writeback/sync scope).

### XS-COMPUTER-AD-NOT-HYBRID-JOINED

- Joins: AD Windows 10/11 workstation or server (active) anti-join Entra device (`ServerAd`) on name.
- Catches: domain computers in use that never registered as hybrid joined, so no device-based
  Conditional Access, no Intune co-management, no Windows Hello for Business. Why: the "require
  compliant or hybrid-joined device" baseline (ENTRA-CA-BASELINE-COMPLIANT-DEVICE) locks these users out
  the day it is enforced - or they are the gap it never covers.
- Severity: medium. kind: missing, lens: both, category: CFG, entity: computer.
- Attributes: AD B2; Entra B7 (requested). Tenant setting `cross.hybrid-join-expected-os-pattern` (default `^Windows (10|11|Server 20(19|22|25))`).
- SQL: `ad_computers a WHERE a.os REGEXP pattern AND dc_logon within 30 d AND NOT EXISTS (entra_devices x WHERE x.short_name = a.short_name AND x.trust_type = 'ServerAd')`; Entra run `ok`.
- Refs: NIST-800-53:AC-19, NIST-800-53:IA-3, CIS-Controls-v8:6.4.
- Fix: enable hybrid join in Connect (OU scope), check the device registration GPO and SCP.

### XS-COMPUTER-SCCM-ACTIVE-AD-STALE

- Joins: SCCM device (client active, `LastActiveTime` within 7 days) x AD computer whose
  `lastLogonTimestamp` is older than N days (or `pwdLastSet` older than 60 days).
- Catches: machines the management client proves alive while the directory says they are stale:
  always-remote devices that never reach a DC, broken secure channels (machine password stuck,
  AD-COMP-MACHINE-PASSWORD-STUCK), or computers re-joined under a new object. Why: AD-COMP-STALE would
  have them deleted; this is the list that stops that mistake, and the list of machines whose domain
  trust is quietly broken.
- Severity: low (medium when `pwd_set` older than 60 days - the trust itself is the problem).
  kind: broken, lens: maintenance, category: HYG, entity: computer.
- Attributes: SCCM `IsActive`, `LastActiveTime`, `Name`; AD `lastLogonTimestamp`, `pwdLastSet` (all requested).
- SQL: `sccm_devices d JOIN ad_computers a ON a.short_name = d.short_name WHERE d.active = 1 AND d.last_active within 7 d AND (a.dc_logon older than 90 d OR a.dc_logon NOT GLOB date)`.
- Refs: NIST-800-53:CM-8, NIST-800-53:IA-3.
- Fix: exclude from stale cleanup; reset the secure channel where the machine password is stuck; move always-remote devices to Entra join.

### XS-COMPUTER-INTUNE-ACTIVE-SCCM-DEAD

- Joins: Intune Windows device (synced within 7 days) x SCCM device of the same name with no client,
  inactive client, or client-check failure.
- Catches: co-managed machines where the Intune half works and the SCCM half died - updates and
  apps whose workload still sits with SCCM never arrive while every cloud dashboard is green.
- Severity: medium. kind: broken, lens: maintenance, category: HLT, entity: computer.
- Attributes: Intune `deviceName`, `lastSyncDateTime`, `operatingSystem`; SCCM B4 (all requested).
- SQL: `intune_devices i JOIN sccm_devices d ON d.short_name = i.short_name WHERE i.os = 'Windows' AND i.last_sync within 7 d AND (d.has_client <> 1 OR d.active = 0 OR d.client_check = 2)`.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.3.
- Fix: repair the client (ccmrepair / reinstall via Intune), or move the workloads to Intune and retire the client.

### XS-BACKUP-OBJECT-VM-GONE

- Joins: Veeam backup object (`platformName` VMware) anti-join vCenter VMs on name.
- Catches: protected objects whose VM no longer exists in vCenter. Why: repository space held by a
  VM nobody can restore to (or a VM that was renamed and is now backed up under neither name - see
  XS-VM-NO-BACKUP), and jobs that warn forever about a missing object.
- Severity: low. kind: misconfigured, lens: maintenance, category: BCK, entity: backup-object.
- Attributes: Veeam `name`, `platformName`, `restorePointsCount`; vmware `name` (requested).
- SQL: `veeam_objects o WHERE o.platform LIKE '%VMware%' AND NOT EXISTS (vc_vms v WHERE v.short_name = o.short_name)`; vmware run `ok`. When several vCenters are integrated the anti-join runs across all of them (no instance match).
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.1.
- Fix: remove the object from the job and let retention expire the chain; keep an archive restore point if the VM was decommissioned on purpose.

### XS-SERVER-AD-NO-BACKUP

- Joins: AD server (active) anti-join Veeam backup objects on short name (any platform: VM, agent, NAS).
- Catches: servers - physical ones included - with no protected object at all. Why: XS-VM-NO-BACKUP
  covers vCenter VMs; physical and cloud servers only show here. `infrastructure.md` BK20.
- Severity: high (critical for domain controllers - and note the directory needs a system-state
  backup, OBL-AD-SYSTEM-STATE-BACKUP, not only an image).
  kind: missing, lens: both, category: BCK, entity: computer.
- Attributes: AD B2; Veeam B10 (requested).
- One side never scanned: no rows; Veeam run `ok`.
- SQL: `ad_computers a WHERE a.os LIKE '%Server%' AND dc_logon within 30 d AND NOT EXISTS (veeam_objects o WHERE o.short_name = a.short_name)`; severity by `is_dc`.
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2.
- Fix: add to a job (agent-based for physical); accept documented stateless servers.

### XS-MONITOR-TARGET-AD-GONE

- Joins: PRTG device / Dynatrace host anti-join AD enabled computers on short name.
- Catches: monitored things whose directory object is gone - usually the sensors that have been down
  for weeks (PRTG-SENSOR-DOWN-LONG) teaching people to ignore red, and the Dynatrace host units
  still licensed for a dead machine. The evidence carries the down-sensor count.
- Severity: low (medium when the PRTG device has down sensors or the Dynatrace host is LOST/CRASHED).
  kind: misconfigured, lens: maintenance, category: HYG, entity: monitor-target.
- Attributes: PRTG `device`, `status_raw`; Dynatrace `hostInfo.displayName`, `availabilityState`; AD B2 (requested).
  Caveat: PRTG devices that are not domain members (switches, printers, appliances) match nothing by
  design - restrict with `cross.domain-computer-name-pattern` or read it as a list to review.
- SQL: `SELECT 'prtg' AS source, short_name, sensors, sensors_down FROM prtg_devices UNION ALL SELECT 'dynatrace', short_name, NULL, CASE WHEN availability IN ('LOST','CRASHED') THEN 1 ELSE 0 END FROM dt_hosts` then anti-join `ad_computers`; AD run `ok`; key `"{source}|{short_name}"`.
- Refs: NIST-800-53:CM-8(3), CIS-Controls-v8:1.2.
- Fix: delete or pause-with-reason the monitoring object; free the licence.

### XS-ESXI-HOST-NOT-MONITORED

- Joins: vCenter ESXi host (`/api/vcenter/host` name) anti-join PRTG devices and Dynatrace hosts on short name.
- Catches: hypervisors nobody monitors for hardware, datastore or NTP alarms outside vCenter.
- Severity: medium. kind: missing, lens: maintenance, category: MON, entity: host.
- Attributes: vmware host `name`, `connection_state` (requested); PRTG/Dynatrace as B11/B12.
- SQL: as XS-SERVER-NOT-MONITORED with `vc_hosts` (`r.system = 'vmware' AND s.entity_type = 'host'`) in place of AD.
- Refs: NIST-800-53:SI-4, CIS-Controls-v8:13.1.
- Fix: add the host (SNMP/REST sensor group or the vSphere extension).

### XS-HOST-THREAT-MULTI-SOURCE

- Joins: findings and rows that name a host with an active threat, across sources: Veeam
  malware-detection events (`machine.displayName`), Defender active threats
  (WINSRV-DEFENDER-ACTIVE-THREAT finding targets), Wiz threat-detection issues
  (`entitySnapshot.name`), Intune partner threat state (`partnerReportedThreatState`).
- Catches: one host named by two or more independent detectors; one finding per host. Why: a
  single source is triaged as noise; two sources agreeing is an incident.
- Severity: critical when >= 2 sources, high for Veeam-infected alone (already VEEAM-MALWARE-INFECTED).
  kind: broken, lens: security, category: MON, entity: computer.
- Attributes: Veeam `machine.displayName`, `detectionTimeUtc`, `state`; Wiz issue
  `entitySnapshot.name`, `type`; Intune `deviceName`, `partnerReportedThreatState` (all requested);
  Defender via `active_finding.target` of `WINSRV-DEFENDER-ACTIVE-THREAT` (`host|ThreatID`).
- One side never scanned: inherent (sources that did not run do not count; evidence lists the sources).
- SQL sketch:

```sql
WITH named AS (
  SELECT 'veeam' AS source, json_extract(s.attrs, '$.machine.displayName') AS h FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
   WHERE r.system = 'veeam' AND s.entity_type = 'malware-event' AND json_extract(s.attrs, '$.state') <> 'FalsePositive'
     AND julianday(:now) - julianday(json_extract(s.attrs, '$.detectionTimeUtc')) <= 30
  UNION ALL
  SELECT 'wiz', json_extract(s.attrs, '$.entitySnapshot.name') FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
   WHERE r.system = 'wiz' AND s.entity_type = 'issue' AND json_extract(s.attrs, '$.type') = 'THREAT_DETECTION'
  UNION ALL
  SELECT 'intune', json_extract(s.attrs, '$.deviceName') FROM latest_run r JOIN row_seen s ON s.run_id = r.run_id
   WHERE r.system = 'intune' AND s.entity_type = 'managed-device' AND json_extract(s.attrs, '$.partnerReportedThreatState') IN ('compromised', 'highSeverity', 'mediumSeverity')
  UNION ALL
  SELECT 'defender', substr(target, 1, instr(target, '|') - 1) FROM active_finding WHERE rule_id = 'WINSRV-DEFENDER-ACTIVE-THREAT'
),
per_host AS (
  SELECT UPPER(CASE WHEN instr(h, '.') > 0 THEN substr(h, 1, instr(h, '.') - 1) ELSE h END) AS host,
         COUNT(DISTINCT source) AS sources, GROUP_CONCAT(DISTINCT source) AS source_list
  FROM named WHERE h IS NOT NULL GROUP BY 1
)
SELECT host, sources, source_list FROM per_host
```
  `each: { field: sources, op: ge, value: 2, threshold: cross.threat-min-sources }`.
- Refs: NIST-800-53:IR-4, NIST-800-53:SI-4, CIS-Controls-v8:17.4.
- Fix: isolate the host, open the incident, restore from a clean point once the entry path is known.

### XS-HOST-KEV-COMPOUND

- Joins: Wiz KEV finding assets (B13) x AD computer (name) x `active_finding` patch-class rules on
  that host x Veeam objects.
- Catches: a host with a known-exploited vulnerability that is also (a) internet-exposed per Wiz,
  (b) confirmed unpatched by an independent source (WINSRV-PATCH-NONE-RECENT / CCM-UPDATE-OVERDUE on
  the same host), or (c) without a backup. One finding per host; the three facts in the evidence.
  Why: the ransomware pre-image - exploited, reachable, unpatched, unrecoverable.
- Severity: critical when exposed or no backup, high otherwise. kind: broken, lens: security, category: LCM, entity: computer.
- Attributes: Wiz `vulnerableAsset.name/type/hasWideInternetExposure`, `name` (requested in
  WIZ-VULN-KEV); AD B2; Veeam B10; `active_finding`. Gap: Wiz asset names for cloud VMs may be the
  cloud resource name, not the OS hostname - `vulnerableAsset.providerUniqueId` and the asset's
  IP addresses are not requested.
- One side never scanned: Wiz required; AD/Veeam/patch findings optional, each annotated.
- SQL: `wiz_assets w LEFT JOIN ad_computers a ON a.short_name = w.short_name LEFT JOIN veeam_objects o ON o.short_name = w.short_name` plus
  `(SELECT COUNT(*) FROM active_finding f WHERE f.rule_id GLOB '*-PATCH-NONE-RECENT' OR f.rule_id GLOB '*-CCM-UPDATE-OVERDUE') AND UPPER(RTRIM(substr(f.target,1,...),'$')) = w.short_name) AS unpatched_by_other_source`,
  `no_backup = CASE WHEN veeam usable AND o.object_id IS NULL THEN 1 ELSE 0 END`,
  `each: { any: [ {field: internet_exposed, op: eq, value: 1}, {field: unpatched_by_other_source, op: gt, value: 0}, {field: no_backup, op: eq, value: 1} ] }`.
- Refs: NIST-800-53:SI-2, NIST-800-53:RA-5, NIST-800-53:CP-9, CIS-Controls-v8:7.7.
- Fix: patch today or remove the exposure; take a backup before anything else.

### XS-OWNER-ACCOUNT-LEFT

- Joins: register owners (`licence.owner`, `contract.owner`, `key_date.owner`, `system.owner_person`,
  free text) x AD user (sAMAccountName or UPN contained in the text) x Entra user (UPN).
- Catches: a register row whose owner's account is disabled or gone - renewal notices and budget
  mail go to a leaver (`certificates-registers-imports.md` line 41).
- Severity: medium (high when the row has a date within its notice period). kind: misconfigured,
  lens: maintenance, category: HYG, entity: register-row.
- Attributes: AD `sAMAccountName`, `userPrincipalName`, `mail` (**mail to add** to the inventory),
  `userAccountControl`; Entra `userPrincipalName`, `accountEnabled`.
- One side never scanned: AD or Entra, whichever is usable; `seen_in` column.
- SQL sketch: `owners AS (SELECT 'licence' AS kind, licence_id AS row_id, owner, expires_on AS due FROM licence UNION ALL ... contract ... key_date ... system)`,
  then `JOIN ad_users a ON instr(LOWER(o.owner), LOWER(a.upn)) > 0 OR LOWER(o.owner) = LOWER(a.account)` with `(a.uac & 2) = 2`,
  and the same against `entra_users e` with `e.enabled = 0`. Owner text that matches no account is
  not reported (a team name is valid).
- Refs: NIST-800-53:CM-8(4), NIST-800-53:PS-4.
- Fix: reassign the owner; point vendor notices at a shared mailbox.

### XS-KEEPER-IDENTITY-KERBEROASTABLE

- Joins: Keeper identity x AD user with `servicePrincipalName`. Catches: the account Keeper reads
  with has an SPN (any domain user can ask for its ticket and crack it offline; if it also has
  adminCount=1 that is AD-PRIV-SPN on Keeper's own account). Severity: high.
  kind: misconfigured, lens: security, category: AUT, entity: integration.
- Attributes: AD `servicePrincipalName`, `pwdLastSet` (requested). SQL: B14 x B1,
  `each: { field: spn, op: notempty }`.
- Refs: NIST-800-53:IA-5(1), CIS-Controls-v8:5.4.
- Fix: a plain user account (no SPN) or a gMSA; long random password.

### XS-KEEPER-RUN-IDENTITY-DRIFT

- Joins: `run.identity` x `integration.identity` for the same instance. Catches: the newest run
  of an integration was made with a different identity than the one configured (someone ran a
  scan with their own account, or the integration was edited after the run). Severity: low.
  kind: misconfigured, lens: security, category: AUT, entity: integration.
- SQL: `SELECT r.instance, r.system, r.identity AS run_identity, i.identity FROM latest_run r JOIN integration i ON i.integration_id = r.instance WHERE r.identity IS NOT NULL AND LOWER(r.identity) <> LOWER(COALESCE(i.identity, ''))`, `each: any`.
- Refs: NIST-800-53:AU-6, NIST-800-53:AC-6(9).
- Fix: rerun with the integration's identity; review why a personal account was used.

<!-- continue -->
