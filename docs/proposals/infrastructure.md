# Proposals - infrastructure APIs (vCenter, Veeam, PRTG, Dynatrace, Azure, ServiceNow, Wiz)

What Keeper should check next in `rules/vmware.yaml` (VMW-), `rules/veeam.yaml` (VEEAM-),
`rules/prtg.yaml` (PRTG-), `rules/dynatrace.yaml` (DT-), `rules/azure.yaml` (AZ-),
`rules/servicenow.yaml` (SNOW-) and `rules/wiz.yaml` (WIZ-). Nothing here is written as a rule yet: each
entry is a spec for whoever writes the YAML. Ids were checked against every id in the seven files (none
collide; the other rule files use other prefixes). No tenant system was contacted; every "verified"
below comes from a public vendor page read on 2026-10-20.

Confidence: **verified** = the path and field names were read on the vendor's reference page (link
given); **likely** = a vendor page, support article or a widely used integration shows the field, but
not the exact revision the rule file pins; **guess** = plausible from the product, must be tried on a
real tenant before shipping (a wrong field is n/a or a GraphQL error, never a silent pass, but it is
also never a finding).

Engine facts the entries rely on (from `docs/RULES.md` and the existing rule files):

- `each:` judges each row; `count: none` / `count: { op, value, where }` judge the row set, so a
  must-exist rule ("a copy job must exist") is `count: { op: lt, value: 1, where: ... }`. A row the
  `where` condition cannot judge is not counted.
- A missing field is n/a; a failed query is unknown; neither is a pass.
- `http` rules: `path` relative to the integration endpoint, `params`, `headers` (never credentials),
  `items`, `paging: offset|none|auto`, `maxPages`. The vSphere `/api` base returns bare values for some
  GETs; the vmware file already uses `/rest/...` where a bare value must become a `{value: ...}` row.
- `graphql` rules: a `query` document only; `$after` is the only variable; literals are inline.
- Dates: ISO 8601, FILETIME, LDAP generalized time. Epoch milliseconds and OLE dates are **not** read
  (see engine gaps). `threshold:` only replaces a condition `value`, never a query parameter.
- Rules with identical `query` text share one read; a new column changes the fingerprint.
- `key:` may be a template `"{a}|{b}"`.

Vendor references used throughout: vSphere Automation API
<https://developer.broadcom.com/xapis/vsphere-automation-api/latest/>; Broadcom lifecycle KB 456708
<https://knowledge.broadcom.com/external/article/456708>; Veeam B&R REST reference
<https://helpcenter.veeam.com/references/vbr/13/rest/1.1-rev1/tag/Jobs> (the 1.2-rev0 page is not
served as a plain page; field paths were read on the 1.1-rev0/rev1 pages of the same model family);
PRTG table API <https://manuals.paessler.com/multiple_object_property_or_status.htm>; Dynatrace
Problems v2 <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2/problems/get-problems-list>,
Settings objects <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/settings/objects/get-objects>,
API tokens v2 <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/tokens-v2/api-tokens/get-all>;
Azure REST <https://learn.microsoft.com/rest/api/azure/>; ServiceNow Table API
<https://www.servicenow.com/docs/bundle/latest-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html>;
Wiz publishes its GraphQL schema only inside the tenant's API explorer (Wiz docs are behind login); the
Steampipe Wiz plugin <https://hub.steampipe.io/plugins/turbot/wiz> and the existing `wiz.yaml` are the
public witnesses. NIST SP 800-53 r5 <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>; CIS Controls v8
<https://www.cisecurity.org/controls/v8>; MITRE ATT&CK <https://attack.mitre.org/>.

---

## Priority 1 - security and backup integrity

### VMware vCenter (`vmware.yaml`, integration `vcenter`)

**VMW-VCSA-LOCAL-ACCOUNT-EXTRA**
- Catches: an enabled appliance local account other than `root`. Local appliance accounts bypass SSO,
  MFA and the directory; one created for a vendor or a migration is a standing back door nobody audits.
- Severity: high.
- Source: `vmware.yaml`, http GET `/api/appliance/local-accounts`. The list operation answers an
  **array of account names (strings)**, not objects, so the names alone cannot be judged; the detail is
  `GET /api/appliance/local-accounts/{name}` (fan-out, see gaps). Until fan-out exists: `count: { op: gt,
  value: 1 }` over the list ("more than one local account exists") with `key: "-"` is expressible today
  if the runner turns a bare string array into rows - today it does not (see gaps). Needs: the names.
- Condition: more than one local account name is returned (root is always one).
- Refs: NIST-800-53:AC-2, NIST-800-53:AC-6, CIS-Controls-v8:5.1, CIS-Controls-v8:5.4.
- Fix: remove the extra account or document it as break-glass with a vaulted password and an expiry.
- Confidence: verified that the list is an array of strings
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/appliance/local-accounts/get/>;
  the engine side is the gap.

**VMW-VCSA-ROOT-PASSWORD-NEVER-EXPIRES**
- Catches: the appliance root password has no expiry. Complements VMW-VCSA-ROOT-PASSWORD-EXPIRY, which
  only fires when an expiry exists.
- Severity: low (security lens).
- Source: `vmware.yaml`, http GET `/api/appliance/local-accounts/root`, `paging: none`, `key: "-"`.
  Same query as VMW-VCSA-ROOT-PASSWORD-EXPIRY (shared read). Fields: `password_expires_at`,
  `last_password_change`, `enabled`.
- Condition: `enabled` eq true and `password_expires_at` absent.
- Refs: NIST-800-53:IA-5, CIS-Controls-v8:5.2.
- Fix: set a root password expiry (the appliance default is 90 days) and put the rotation in the vault's
  calendar; the lockout risk is handled by VMW-VCSA-ROOT-PASSWORD-EXPIRY.
- Confidence: verified (fields already used by the existing rule; the STIG for the appliance asks for a
  90-day maximum).

**VMW-VCSA-PASSWORD-POLICY-MAX-DAYS**
- Catches: the appliance local-account password policy allows passwords older than N days (or never
  expiring).
- Severity: low (security lens).
- Source: `vmware.yaml`, http GET `/api/appliance/local-accounts/global-policy`, `paging: none`,
  `key: "-"`. Fields: `max_days`, `min_days`, `warn_days` (integers).
- Condition: `max_days` gt 90 (threshold `vmware.local-password-max-days`), or `max_days` le 0 if the
  product encodes "never" as 0 or -1 - confirm on the first run which value the appliance returns for
  "never" (the sample on the doc page shows 0 for all three).
- Refs: NIST-800-53:IA-5, CIS-Controls-v8:5.2.
- Fix: set the policy to 90 days or less, warn 7 days before.
- Confidence: field names verified
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/appliance/local-accounts/global-policy/get/>;
  the "never" encoding is a guess.

**VMW-VCSA-SYSLOG-FORWARDING-MISSING**
- Catches: the appliance forwards its logs to no syslog server. When vCenter is compromised or its disk
  fills, the only copy of its audit trail is on the appliance.
- Severity: medium (security lens).
- Source: `vmware.yaml`, http GET `/api/appliance/logging/forwarding`, `paging: none`, `key: hostname`.
  Answer is an **array of objects** `{hostname, port, protocol}`; an empty array means no forwarding.
- Condition: `count: none`.
- Refs: NIST-800-53:AU-4, NIST-800-53:AU-9, CIS-Controls-v8:8.2, CIS-Controls-v8:8.9.
- Fix: add the organisation's log collector as a forwarding target (TLS) and verify receipt.
- Confidence: verified (array of `hostname`, `port`, `protocol`)
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/appliance/logging/forwarding/get/>.

**VMW-VCSA-SYSLOG-UNENCRYPTED**
- Catches: a syslog forwarding target that uses UDP or plain TCP instead of TLS; logs that carry
  usernames and host names cross the network in clear and can be dropped silently (UDP).
- Severity: low (security lens).
- Source: same query as VMW-VCSA-SYSLOG-FORWARDING-MISSING (shared read). Field: `protocol`.
- Condition: `protocol` ne `TLS`.
- Refs: NIST-800-53:AU-9, NIST-800-53:SC-8, CIS-Controls-v8:3.10.
- Fix: switch the forwarding target to TLS (port 6514 is the convention) once the collector supports it.
- Confidence: array and field names verified (link above); the enum value spelling `TLS` / `TCP` / `UDP`
  is likely (the page truncates before the enum) - confirm on the first run.

**VMW-VCSA-BACKUP-PLAINTEXT-PROTOCOL**
- Catches: an appliance file-based backup schedule whose target is `ftp://` or `http://`; the backup
  (which contains the vCenter database and, unless the schedule is password-protected, every host
  password) and the location credentials travel in clear.
- Severity: medium (security lens).
- Source: `vmware.yaml`, http GET `/rest/appliance/recovery/backup/schedules`, `paging: none`,
  `key: key`. Same query as VMW-VCSA-BACKUP-SCHEDULE-DISABLED (shared read). Field: `value.location`.
- Condition: `value.location` match `^(ftp|http)://`.
- Refs: NIST-800-53:SC-8, NIST-800-53:CP-9, CIS-Controls-v8:3.10, CIS-Controls-v8:11.3.
- Fix: move the schedule to FTPS, HTTPS, SFTP or SMB/NFS on a trusted segment, and set a backup password.
- Confidence: `location`, `enable`, `parts`, `location_user`, `recurrence_info`, `retention_info.max_count`
  verified in the Schedules.Info sample
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/appliance/recovery/backup/schedules/get/>;
  the `/rest` wrapping (`value.`) is the convention the existing rules already depend on.

**VMW-VC-TLS-CERT-WEAK-SIGNATURE**
- Catches: the vCenter machine SSL certificate is signed with SHA-1 or MD5.
- Severity: medium (security lens).
- Source: `vmware.yaml`, http GET `/api/vcenter/certificate-management/vcenter/tls`, `paging: none`,
  `key: serial_number`. Same query as VMW-VC-TLS-CERT-EXPIRY (shared read). Field:
  `signature_algorithm` (text, e.g. `SHA256withRSA`).
- Condition: `signature_algorithm` match `sha1|md5`.
- Refs: NIST-800-53:SC-13, NIST-800-53:SC-17, CIS-Controls-v8:3.10.
- Fix: renew the machine certificate (VMCA or CA-signed) with SHA-256.
- Confidence: verified (`version`, `serial_number`, `signature_algorithm`, `issuer_dn`, `subject_dn`,
  `valid_from`, `valid_to`, `thumbprint`, `is_ca`, `path_length_constraint`; no key-size field exists)
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/certificate-management/vcenter/tls/get/>.

### Veeam Backup & Replication (`veeam.yaml`, integration `veeam`, header `x-api-version: 1.2-rev0`)

All job-configuration entries share one new query: http GET `/api/v1/jobs`, `headers: { x-api-version:
1.2-rev0 }`, `paging: offset`, `offsetParam: skip`, `limitParam: limit`, `pageSize: 200`, `items: data`,
`key: id`, `name: name`. The existing rules read `/api/v1/jobs/states` (status and last result only);
the configuration lives in `/api/v1/jobs`. Field paths below were read in the vendor's job JSON sample
(1.1-rev1 page of the same model; 1.2-rev0 adds job types but keeps these paths):
<https://helpcenter.veeam.com/references/vbr/13/rest/1.1-rev1/tag/Jobs>.

**VEEAM-JOB-ENCRYPTION-OFF**
- Catches: a backup job that writes unencrypted backup files. Anyone who can read the repository (a
  stolen disk, a leaked share, a compromised repository host, an exfiltrated object bucket) reads every
  VM in it.
- Severity: high (security lens).
- Source: `/api/v1/jobs` (above). Fields: `isDisabled`, `type`,
  `storage.advancedSettings.storageData.encryption.isEnabled`.
- Condition: `isDisabled` eq false and `storage.advancedSettings.storageData.encryption.isEnabled` eq
  false. Backup-copy jobs inherit the source encryption; restrict to `type` eq `Backup` (and the agent
  and file job types once their models are confirmed) to avoid judging a copy job's missing field.
- Refs: NIST-800-53:SC-28, NIST-800-53:CP-9, CIS-Controls-v8:3.11, CIS-Controls-v8:11.3.
- Fix: enable encryption on the job with a password stored in the privileged-access vault (and in the
  Enterprise Manager key set, or the password loss is a data loss); the next full backup is encrypted.
- Confidence: verified path `storage.advancedSettings.storageData.encryption.isEnabled` (sibling
  `encryptionPasswordId`) on the Jobs sample page (link above).

**VEEAM-JOB-APP-AWARE-OFF**
- Catches: an enabled backup job without application-aware processing. Its restore points of domain
  controllers, SQL, Exchange and anything transactional are crash-consistent; the job is green, the
  restore may not be.
- Severity: medium.
- Source: `/api/v1/jobs`. Fields: `isDisabled`, `type`, `guestProcessing.appAwareProcessing.isEnabled`.
- Condition: `isDisabled` eq false and `type` eq `Backup` and
  `guestProcessing.appAwareProcessing.isEnabled` eq false.
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2.
- Fix: enable application-aware processing with guest credentials from the vault; for machines that
  truly have no application, record the exception on the job.
- Confidence: verified path on the Jobs sample page.

**VEEAM-REPOSITORY-NO-IMMUTABLE**
- Catches: no backup repository of an immutable kind exists at all - every restore point can be deleted
  by whoever controls the backup server, which is exactly what ransomware operators go for first.
- Severity: high (security lens).
- Source: `veeam.yaml`, http GET `/api/v1/backupInfrastructure/repositories`, same headers and offset
  paging as the repository rules, `items: data`, `key: id`, `name: name`. Fields: `type`,
  `repository.makeRecentBackupsImmutableDays`, `repository.useImmutableBackups`.
- Condition: `count: { op: lt, value: 1, where: { any: [ { field: type, op: eq, value: LinuxHardened },
  { field: repository.makeRecentBackupsImmutableDays, op: gt, value: 0 } ] } }`. The second branch covers
  object storage and Windows repositories where the same immutability setting appears; an unreadable
  setting is not counted, so a tenant whose only immutable target has an unknown field shape gets a
  finding that says so, not a pass.
- Refs: NIST-800-53:CP-9, NIST-800-53:SI-7, CIS-Controls-v8:11.4, MITRE-ATTACK:T1490.
- Fix: add a hardened Linux repository or object storage with immutability (object lock) and point at
  least the primary backup chain or a backup copy at it.
- Confidence: `type` enum values verified (`WinLocal, LinuxLocal, Smb, Nfs, AzureBlob, AzureDataBox,
  AzureArchive, AmazonS3, AmazonSnowballEdge, AmazonS3Glacier, S3Compatible, GoogleCloud, IBMCloud,
  WasabiCloud, LinuxHardened`) and `repository.useImmutableBackups` /
  `repository.makeRecentBackupsImmutableDays` seen in the add-repository sample
  <https://helpcenter.veeam.com/references/vbr/13/rest/1.1-rev0/tag/Repositories>; whether those two
  fields are returned on GET for hardened and object-storage repositories is **likely**, the object
  storage `bucket.immutability.*` shape is a **guess** (the backlog already lists this as unverified).

**VEEAM-REPOSITORY-IMMUTABILITY-SHORT**
- Catches: a repository that supports immutability but keeps backups immutable for fewer than N days
  (or zero), so a retention run - or an attacker with the console - can purge recent points.
- Severity: medium (security lens).
- Source: same query as VEEAM-REPOSITORY-NO-IMMUTABLE (shared read). Fields: `type`,
  `repository.makeRecentBackupsImmutableDays`.
- Condition: `type` in [LinuxHardened, AmazonS3, S3Compatible, AzureBlob, WasabiCloud, GoogleCloud,
  IBMCloud] and `repository.makeRecentBackupsImmutableDays` lt 7 (threshold
  `veeam.immutability-min-days`).
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.4, MITRE-ATTACK:T1490.
- Fix: raise the immutability period to cover at least the retention of the shortest job that writes
  there (7 days is the floor; 30 is common).
- Confidence: likely (same caveat as above; a missing field makes the row n/a).

**VEEAM-COPY-JOB-MISSING**
- Catches: no backup copy job exists - one copy of the data in one place is not a backup strategy
  (3-2-1), and a repository failure or a site loss takes every restore point.
- Severity: high.
- Source: `veeam.yaml`, http GET `/api/v1/jobs/states` (same query as VEEAM-JOB-LAST-FAILED, shared
  read). Fields: `type`, `status`.
- Condition: `count: { op: lt, value: 1, where: { all: [ { field: type, op: in, value: [BackupCopy,
  ImmediateBackupCopy, FileBackupCopy] }, { field: status, op: ne, value: Disabled } ] } }`.
- Refs: NIST-800-53:CP-9, NIST-800-53:CP-6, CIS-Controls-v8:11.4.
- Fix: create a backup copy job to a second repository (ideally immutable, ideally off-site) covering
  the primary jobs, and watch its first run.
- Confidence: `type` is in the states row (the existing evidence prints it); the exact enum spellings
  `BackupCopy` / `ImmediateBackupCopy` / `FileBackupCopy` are likely (1.1 pages list `Backup`,
  `vSphereReplica`, `CloudDirectorBackup`; copy types arrived with later revisions) - confirm on the
  first run and widen the list.

**VEEAM-SUREBACKUP-JOB-MISSING**
- Catches: no restore-verification (SureBackup) job exists, so no restore point has ever been proven
  bootable. Closes backlog item BK09.
- Severity: medium.
- Source: `/api/v1/jobs/states` (shared read). Field: `type`.
- Condition: `count: { op: lt, value: 1, where: { field: type, op: eq, value: SureBackup } }`.
- Refs: NIST-800-53:CP-9, NIST-800-53:CP-4, CIS-Controls-v8:11.5.
- Fix: create a SureBackup job with an application group for the critical tier and run it monthly.
- Confidence: guess for the enum spelling `SureBackup` in `/api/v1/jobs/states` (SureBackup management
  came to the REST API in 12.1; its presence in the generic job states list is not confirmed). If the
  states list does not carry it, the fallback is `/api/v1/sessions` with `typeFilter` on the SureBackup
  session type - also unconfirmed.

**VEEAM-LICENSE-EVALUATION**
- Catches: the backup server runs on an evaluation, NFR or rental licence - it will stop, or it was
  never meant for production.
- Severity: medium.
- Source: `veeam.yaml`, http GET `/api/v1/license` (same query as VEEAM-LICENSE-STATUS, shared read).
  Field: `type`.
- Condition: `type` in [Evaluation, NFR, Rental] - treat Rental as a tenant override (service providers
  run on rental legitimately).
- Refs: NIST-800-53:SA-4 (licensing is a procurement control; keep refs minimal).
- Fix: install the purchased licence file.
- Confidence: `type` and `edition` are printed by the existing rule's evidence (verified); the enum
  spellings are likely.

**VEEAM-LICENSE-AUTO-UPDATE-OFF**
- Catches: licence auto-update is off, so a subscription or rental licence is not refreshed before its
  end date and the server stops processing when it lapses.
- Severity: low.
- Source: `/api/v1/license` (shared read). Field: `autoUpdateEnabled`.
- Condition: `type` in [Subscription, Rental] and `autoUpdateEnabled` eq false.
- Refs: none beyond VEEAM-LICENSE-EXPIRY.
- Fix: enable automatic licence update (needs outbound access to the vendor's licensing service).
- Confidence: guess - the License page of the public reference returned 404; the field name comes from
  the PowerShell equivalent (`Enable-VBRLicenseAutoUpdate`) and may differ in REST.

### Dynatrace (`dynatrace.yaml`, integration `dynatrace`)

**DT-TOKEN-NO-EXPIRY**
- Catches: an enabled API token that never expires. Tokens are copied into scripts and CI systems and
  outlive the people who made them.
- Severity: medium (security lens).
- Source: `dynatrace.yaml`, http GET `/api/v2/apiTokens`, params `{ pageSize: "10000", fields:
  "+expirationDate,+lastUsedDate,+scopes,+personalAccessToken" }`, `paging: none`, `items: apiTokens`,
  `key: id`, `name: name`. Needs token scope `apiTokens.read` (add to the file header). Fields: `id`,
  `name`, `enabled`, `owner`, `creationDate`, `expirationDate`, `lastUsedDate`, `scopes`,
  `personalAccessToken`.
- Condition: `enabled` eq true and `expirationDate` absent.
- Refs: NIST-800-53:IA-5, NIST-800-53:AC-2, CIS-Controls-v8:5.3.
- Fix: recreate the token with an expiry (the vendor allows one at creation only) and rotate the consumer.
- Confidence: verified (`fields` must add `expirationDate`, `lastUsedDate`, `scopes`; dates ISO 8601;
  `pageSize` 100-10000) <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/tokens-v2/api-tokens/get-all>.
  One caveat: the reference table says `enabled`, the sample JSON shows `disabled` - confirm on the
  first run and write the condition on whichever is returned.

**DT-TOKEN-UNUSED**
- Catches: an enabled API token not used for 90 days (or never used and older than 90 days) - a
  credential nobody needs that still works.
- Severity: low (security lens).
- Source: same query as DT-TOKEN-NO-EXPIRY (shared read).
- Condition: `enabled` eq true and any of: `lastUsedDate` age-gt 90 (threshold
  `dynatrace.token-unused-days`); `lastUsedDate` absent and `creationDate` age-gt 90.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.3.
- Fix: disable the token; delete it after a quiet period.
- Confidence: verified (link above).

**DT-TOKEN-EXPIRING**
- Catches: an enabled token expiring within 14 days - the integration behind it (ticketing, CMDB sync,
  this review) stops without any Dynatrace problem opening.
- Severity: by days left (critical at 0, high at 7, medium at 14); `deadline: expirationDate`.
- Source: same query (shared read).
- Condition: `enabled` eq true and `expirationDate` until-lt 14 (threshold
  `dynatrace.token-notice-days`).
- Refs: NIST-800-53:IA-5.
- Fix: issue the replacement token and update the consumer before the date.
- Confidence: verified.

**DT-TOKEN-CAN-MINT-TOKENS**
- Catches: an enabled token whose scopes include `apiTokens.write` - it can create further tokens with
  any scope it holds, so it is an admin credential in disguise.
- Severity: medium (security lens).
- Source: same query (shared read). Field: `scopes` (array of strings).
- Condition: `enabled` eq true and `scopes` contains `apiTokens.write`.
- Refs: NIST-800-53:AC-6, CIS-Controls-v8:5.4, MITRE-ATTACK:T1098.
- Fix: split the token: automation tokens without `apiTokens.write`; token management stays with named
  admins through the UI.
- Confidence: verified (`scopes` returned with `fields=+scopes`; the scope name `apiTokens.write` is the
  documented one).

### Azure Resource Manager, tenant scope (`azure.yaml`, integration `azure`)

**AZ-CUSTOM-ROLE-WILDCARD-ACTIONS**
- Catches: a custom role definition that grants `*` (or `*/write`, `*/delete`) in `actions` - an
  Owner-equivalent under a harmless name that no built-in-role review notices.
- Severity: high (security lens).
- Source: `azure.yaml`, http GET `/providers/Microsoft.Authorization/roleDefinitions`, params
  `{ api-version: "2022-04-01", $filter: "type eq 'CustomRole'" }`, `paging: none`, `key: name`,
  `name: properties.roleName`. Reading at the root scope lists custom roles assignable at `/` and
  management groups; subscription-only custom roles are subscription-scoped (gap). Fields:
  `properties.roleName`, `properties.type`, `properties.assignableScopes`,
  `properties.permissions[].actions`, `properties.permissions[].notActions`,
  `properties.permissions[].dataActions`.
- Condition: `properties.permissions[].actions` contains `*` (whole-element match), or match
  `^\*/(write|delete|action)$`.
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-2, CIS-Controls-v8:6.8.
- Fix: replace the wildcard with the explicit actions the role needs; if it truly needs everything, use
  the built-in Owner role so the review sees it.
- Confidence: verified (scope-based list, `$filter`, response shape)
  <https://learn.microsoft.com/rest/api/authorization/role-definitions/list?view=rest-authorization-2022-04-01>;
  that the root scope `/` is accepted for this list with root-scope read is likely (same privilege the
  existing root role-assignment rule needs).

**AZ-CUSTOM-ROLE-ROOT-ASSIGNABLE**
- Catches: a custom role that can be assigned at the tenant root `/` - it reaches every subscription
  that will ever exist.
- Severity: medium (security lens).
- Source: same query as AZ-CUSTOM-ROLE-WILDCARD-ACTIONS (shared read).
- Condition: `properties.assignableScopes` contains `/`.
- Refs: NIST-800-53:AC-6, CIS-Controls-v8:6.8.
- Fix: narrow `assignableScopes` to the management groups or subscriptions the role is for.
- Confidence: verified (link above).

**AZ-SUBSCRIPTION-NONE**
- Catches: the review identity sees no subscriptions - every subscription-level check in this file
  (and in any future per-subscription file) is blind, and the dashboard looks clean.
- Severity: medium (both lenses).
- Source: `azure.yaml`, http GET `/subscriptions`, params `{ api-version: "2022-12-01" }`, `paging:
  none`, `key: subscriptionId` (same query as AZ-SUBSCRIPTION-STATE, shared read).
- Condition: `count: none`.
- Refs: NIST-800-53:CA-7.
- Fix: grant the review identity Reader at the root management group (or each subscription).
- Confidence: verified (existing query).

### ServiceNow (`servicenow.yaml`, integration `servicenow`)

**SNOW-CHANGE-IMPLEMENTED-UNAPPROVED**
- Catches: a non-standard change in Implement or Review state whose approval is not `approved` - it ran
  without approval, or the approval record was skipped.
- Severity: high.
- Source: `servicenow.yaml`, http GET `/api/now/table/change_request`, same params as
  SNOW-CHANGE-WINDOW-OVERRUN but with `sysparm_query: active=true^stateIN-1,0` (a different query; or
  reuse the existing `stateIN-4,-3,-2,-1` read and judge `state` eq -1 only). Fields: `number`, `state`,
  `approval`, `type`, `start_date`, `end_date`, `assigned_to`.
- Condition: `type` ne `standard` and `approval` ne `approved`.
- Refs: NIST-800-53:CM-3, NIST-800-53:CM-5, CIS-Controls-v8:4.1.
- Fix: stop or review the change; record a retrospective approval with the CAB and find out how the
  state transition bypassed the approval gate.
- Confidence: verified base-table fields (state codes and `approval` values are the out-of-the-box
  ones; an instance may customise them - the first run confirms).

**SNOW-ADMIN-ROLE-COUNT**
- Catches: more than N active users hold the `admin` role on the instance.
- Severity: medium (security lens).
- Source: `servicenow.yaml`, http GET `/api/now/table/sys_user_has_role`, params `{ sysparm_query:
  "role.name=admin^user.active=true^inherited=false", sysparm_fields: "sys_id,user,role,inherited",
  sysparm_display_value: all, sysparm_exclude_reference_link: "true" }`, `paging: offset`, `pageSize:
  1000`, `items: result`, `key: sys_id.value`, `name: user.display_value`.
- Condition: `count: { op: gt, value: 10 }` (threshold `servicenow.max-admins`), plus a sibling
  `each: any` rule at info severity to list them (SNOW-ADMIN-ROLE-HOLDER).
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-2, CIS-Controls-v8:5.4.
- Fix: move people to scoped roles (`itil`, `itil_admin`, application admin roles) and keep `admin` for a
  named few with MFA.
- Confidence: likely (dot-walking in `sysparm_query` is standard; the `inherited` column exists on
  `sys_user_has_role`).

### Wiz (`wiz.yaml`, integration `wiz`)

Queries follow the existing file: `issuesV2` and `vulnerabilityFindings` with inline literals and `$after`
only. Field names marked likely are those the existing rules already read on a live tenant.

**WIZ-ISSUE-CRITICAL-AGED**
- Catches: a critical issue open for more than 7 days (the existing WIZ-ISSUE-OPEN-TOO-LONG uses 30 days
  for critical and high together; critical deserves its own, shorter clock).
- Severity: critical.
- Source: `wiz.yaml`, graphql `issuesV2(first: 500, after: $after, filterBy: {status: [OPEN,
  IN_PROGRESS], severity: [CRITICAL]})` with the same node selection as WIZ-ISSUE-OPEN-TOO-LONG;
  `items: data.issues.nodes`, cursor paging, `key: id`. Fields: `createdAt`, `severity`, `sourceRule.name`,
  `entitySnapshot.*`.
- Condition: `createdAt` age-gt 7 (threshold `wiz.critical-max-open-days`).
- Refs: NIST-800-53:RA-5, NIST-800-53:SI-2, CIS-Controls-v8:7.7.
- Fix: fix or contain within the week; anything older needs a named owner and a risk acceptance.
- Confidence: likely (same fields as existing rules).

**WIZ-ISSUE-UNTRIAGED**
- Catches: a critical or high issue still in status OPEN (never moved to IN_PROGRESS, never assigned a
  due date) more than 3 days after creation - nobody has looked.
- Severity: high.
- Source: graphql `issuesV2(first: 500, after: $after, filterBy: {status: [OPEN], severity:
  [CRITICAL, HIGH]})`, same node selection. Fields: `createdAt`, `dueAt`, `status`.
- Condition: `createdAt` age-gt 3 (threshold `wiz.triage-max-days`) and `dueAt` absent.
- Refs: NIST-800-53:IR-4, NIST-800-53:RA-5, CIS-Controls-v8:7.7.
- Fix: triage daily: set IN_PROGRESS with an owner and a due date, or reject with a note.
- Confidence: likely.

**WIZ-VULN-CRITICAL-INTERNET**
- Catches: a critical CVE (exploit known or not) on an asset with wide internet exposure. The existing
  WIZ-VULN-EXPLOIT-INTERNET needs a known exploit; this one does not wait for one.
- Severity: critical.
- Source: graphql `vulnerabilityFindings(first: 500, after: $after, filterBy: {status: [OPEN],
  severity: [CRITICAL]})` with the same node selection as WIZ-VULN-KEV; `maxPages: 200`. Fields:
  `vulnerableAsset.hasWideInternetExposure`, `vulnerableAsset.hasLimitedInternetExposure`, `fixedVersion`.
- Condition: `vulnerableAsset.hasWideInternetExposure` eq true.
- Refs: NIST-800-53:SI-2, NIST-800-53:SC-7, CIS-Controls-v8:7.7, MITRE-ATTACK:T1190.
- Fix: patch to `fixedVersion`; until then remove the exposure (security group, WAF, private endpoint).
- Confidence: likely (fields read by the existing rules on a live tenant).

**WIZ-ISSUE-SECRET-EXPOSED**
- Catches: an open issue whose related entity is a secret (credentials in code, images, user data, or
  environment variables found by the scanner).
- Severity: high.
- Source: graphql `issuesV2(first: 500, after: $after, filterBy: {status: [OPEN, IN_PROGRESS],
  relatedEntity: {type: [SECRET]}})`, same node selection. Fields: `entitySnapshot.type`, `severity`.
- Condition: `each: any`.
- Refs: NIST-800-53:IA-5, NIST-800-53:SC-28, CIS-Controls-v8:3.11, MITRE-ATTACK:T1552.
- Fix: rotate the secret first, then remove it from where it was found; the rotation matters more than
  the clean-up.
- Confidence: guess - `relatedEntity.type` is a filter public integrations use for other entity types;
  the entity type name for secrets (`SECRET`) must be read from the tenant's schema explorer. A wrong
  name is a GraphQL error (unknown), not a pass.

**WIZ-ISSUE-REJECTED-NO-NOTE**
- Catches: a critical or high issue rejected (risk accepted, false positive, won't fix) without a note -
  an exception nobody can audit.
- Severity: low (security lens).
- Source: graphql `issuesV2(first: 500, after: $after, filterBy: {status: [REJECTED], severity:
  [CRITICAL, HIGH]}) { nodes { id severity status resolvedAt resolutionReason note sourceRule {...}
  entitySnapshot {...} } ... }`.
- Condition: `note` empty.
- Refs: NIST-800-53:RA-7, NIST-800-53:CA-5.
- Fix: require a note on rejection (Wiz supports a reason and a note); backfill the open ones.
- Confidence: guess for `note` and `resolutionReason` (the Jira and ServiceNow integrations map a
  note field; names must be read from the schema explorer).

**WIZ-SERVICE-ACCOUNT-SECRET-OLD**
- Catches: a Wiz API service account whose client secret has not been rotated for a year.
- Severity: low (security lens).
- Source: graphql `serviceAccounts(first: 500, after: $after) { nodes { id name type createdAt
  lastRotatedAt scopes } pageInfo { hasNextPage endCursor } }`, `items: data.serviceAccounts.nodes`,
  `key: id`.
- Condition: any of `lastRotatedAt` age-gt 365; `lastRotatedAt` absent and `createdAt` age-gt 365
  (threshold `wiz.service-account-rotation-days`).
- Refs: NIST-800-53:IA-5, CIS-Controls-v8:5.3.
- Fix: rotate the secret (the integration that uses it must be updated in the same change).
- Confidence: likely for `serviceAccounts`, `createdAt`, `lastRotatedAt`, `type` (the Steampipe Wiz
  plugin exposes `last_rotated_at`, `created_at`, `type`, `authentication_source`); the paging shape is
  the same as `controls`.

---

## Priority 2 - availability and monitoring blind spots

### VMware vCenter

**VMW-HOST-NONE**
- Catches: the host list is empty - the session has no read on the inventory, or the vCenter really has
  no hosts. Both look like "nothing wrong" to every other VMW-HOST rule.
- Severity: medium.
- Source: http GET `/api/vcenter/host`, `paging: none`, `key: host` (same query as VMW-HOST-CONNECTION,
  shared read).
- Condition: `count: none`.
- Refs: NIST-800-53:CA-7.
- Fix: give the review account Read-only on the vCenter root with propagation.
- Confidence: verified (existing query).

**VMW-HOST-STANDALONE**
- Catches: an ESXi host that is in no cluster - no HA restarts its VMs, no DRS evacuates it for patching.
- Severity: low.
- Source: http GET `/api/vcenter/host`, params `{ standalone: "true" }`, `paging: none`, `key: host`,
  `name: name`. Fields: `host`, `name`, `connection_state`, `power_state`.
- Condition: `each: any`.
- Refs: NIST-800-53:CP-10.
- Fix: move the host into a cluster, or record why it stands alone (witness, management, licensing).
- Confidence: likely - the host list operation is verified (filters `hosts`, `names`, `folders`, ...;
  the page truncates before `standalone` and `clusters`); `standalone` is a documented FilterSpec
  member in the 7.x/8.x references <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/host/get/>.

**VMW-VC-SERVICE-AUTO-STOPPED**
- Catches: a vCenter service with automatic start-up that is not started - the API still answers, but
  the thing that stopped (content library, vSphere Update Manager, the analytics or the token service)
  silently does not work.
- Severity: high.
- Source: http GET `/rest/vcenter/services` (the `/api` form answers a map keyed by service id, which
  cannot become rows; `/rest` wraps it as `[{key, value}]`), `paging: none`, `key: key`. Fields:
  `value.startup_type`, `value.state`, `value.health`, `value.health_messages[].default_message`,
  `value.name_key`.
- Condition: `value.startup_type` eq `AUTOMATIC` and `value.state` ne `STARTED`.
- Refs: NIST-800-53:SI-4.
- Fix: start the service (appliance management interface, Services) and read its log for why it stopped.
- Confidence: the per-service fields `name_key`, `description_key`, `startup_type`, `state`, `health`,
  `health_messages` are verified in the operation sample
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/services/get/>; the
  enum spellings (`AUTOMATIC`/`MANUAL`/`DISABLED`, `STARTED`/`STOPPED`/`STARTING`/`STOPPING`,
  `HEALTHY`/`HEALTHY_WITH_WARNINGS`/`DEGRADED`) are likely (the page truncates before them); the `/rest`
  wrapping of a map is the convention the backup-schedule rules already rely on.

**VMW-VC-SERVICE-UNHEALTHY**
- Catches: a started vCenter service whose health is degraded or has warnings.
- Severity: by `value.health` (DEGRADED high, HEALTHY_WITH_WARNINGS medium).
- Source: same query as VMW-VC-SERVICE-AUTO-STOPPED (shared read).
- Condition: `value.state` eq `STARTED` and `value.health` ne `HEALTHY`.
- Refs: NIST-800-53:SI-4.
- Fix: read `health_messages` and act on them; restart the service if the message says so.
- Confidence: as above.

**VMW-VC-ELM-REPLICATION-BROKEN**
- Catches: in an Enhanced Linked Mode group, a vCenter whose directory replication with its partner is
  not running or whose partner is unreachable - SSO, roles and tags diverge between the two.
- Severity: high.
- Source: http GET `/api/vcenter/topology/replication-status`, `paging: none`, `key: node`, `name:
  node`. Array items: `node`, `replication_partner`, `partner_available`, `status_available`,
  `replicating`, `change_lag` (integer). A single vCenter returns an empty array (no findings).
- Condition: any of `replicating` eq false; `partner_available` eq false; `status_available` eq false.
- Refs: NIST-800-53:CP-10, NIST-800-53:SI-4.
- Fix: check the partner's vmdir service and network path; run the vendor's replication status tool and
  re-establish the agreement if needed.
- Confidence: verified (fields and types in the response sample; privilege `System.Read`)
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/topology/replication-status/get/>.

**VMW-VC-ELM-REPLICATION-LAG**
- Catches: replication running but behind by more than N changes.
- Severity: medium.
- Source: same query as VMW-VC-ELM-REPLICATION-BROKEN (shared read).
- Condition: `replicating` eq true and `change_lag` gt 100 (threshold `vmware.replication-max-lag`).
- Refs: NIST-800-53:SI-4.
- Fix: same as above; a persistent lag usually means a saturated link or a stuck partner.
- Confidence: verified.

**VMW-VCSA-DNS-SINGLE-SERVER**
- Catches: the appliance has fewer than two DNS servers configured - one resolver outage breaks SSO,
  host connections and backups at once.
- Severity: medium.
- Source: http GET `/api/appliance/networking/dns/servers`, `paging: none`, `key: "-"`. Fields: `mode`
  (`DHCP` / `static`), `servers` (array of strings).
- Condition: `mode` eq `static` and `servers` size-lt 2.
- Refs: NIST-800-53:CP-10, NIST-800-53:SC-5.
- Fix: add a second resolver on a different host or site.
- Confidence: verified <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/appliance/networking/dns/servers/get/>.

**VMW-VCSA-NTP-SINGLE-SERVER**
- Catches: exactly one NTP server configured on the appliance; when it drifts or stops, nothing
  corrects the clock and SSO tokens start failing.
- Severity: low.
- Source: http GET `/rest/appliance/ntp` (the `/api` form answers a bare array of strings; `/rest`
  wraps it as `{value: [...]}`), `paging: none`, `key: "-"`. Field: `value` (array).
- Condition: `value` size-eq 1. (Zero servers is the host-sync or disabled mode, already judged by
  VMW-VCSA-TIMESYNC-DISABLED.)
- Refs: NIST-800-53:AU-8.
- Fix: configure at least two NTP sources, the same ones the domain controllers use.
- Confidence: likely (the `/rest` wrapping of a bare array into `value` follows the same convention as
  `/rest/appliance/access/ssh`; the field list is the documented NTP server list).

**VMW-VCSA-HEALTH-CHECK-STALE**
- Catches: the appliance health check last ran more than a day ago, so every VMW-VCSA-HEALTH-* colour is
  stale while it looks green.
- Severity: low.
- Source: http GET `/rest/appliance/health/system/lastcheck`, `paging: none`, `key: "-"`. The `/api`
  form answers a bare timestamp string (documented as "doesn't return any data structure"); `/rest`
  wraps it as `{value: "<timestamp>"}`.
- Condition: `value` age-gt 1.
- Refs: NIST-800-53:SI-4.
- Fix: check the applmgmt service (VMW-VCSA-HEALTH-APPLMGMT) and restart it.
- Confidence: verified that it is a bare string
  <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/appliance/health/system/lastcheck/get/>;
  the timestamp format is undocumented - if it is not ISO 8601 the engine cannot read it (first-run item).

### Veeam Backup & Replication

**VEEAM-JOB-NONE**
- Catches: the job list is empty - the account cannot read jobs, or nothing is backed up. Every
  VEEAM-JOB rule stays silent either way.
- Severity: medium.
- Source: `/api/v1/jobs/states` (shared read).
- Condition: `count: none`.
- Refs: NIST-800-53:CA-7, NIST-800-53:CP-9.
- Fix: give the review account the Backup Viewer role; if the list is really empty, the estate has no
  backups.
- Confidence: verified (existing query).

**VEEAM-JOB-NOT-SCHEDULED**
- Catches: an enabled job that only runs when started by hand (`runAutomatically` off and not chained
  after another job) - VEEAM-JOB-STALE will catch the symptom after N days; this catches the cause.
- Severity: medium.
- Source: `/api/v1/jobs`. Fields: `isDisabled`, `schedule.runAutomatically`, `schedule.afterThisJob`
  (object with `isEnabled`, if present).
- Condition: `isDisabled` eq false and `schedule.runAutomatically` eq false.
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2.
- Fix: give the job a schedule or chain it; manual-only jobs are for ad-hoc copies, not protection.
- Confidence: verified path `schedule.runAutomatically` (link in the section header); `afterThisJob`
  likely.

**VEEAM-JOB-RETRY-OFF**
- Catches: a job with automatic retry disabled - one transient snapshot or network error loses the
  night's restore point.
- Severity: low.
- Source: `/api/v1/jobs`. Field: `schedule.retry.isEnabled`.
- Condition: `isDisabled` eq false and `schedule.retry.isEnabled` eq false.
- Refs: NIST-800-53:CP-9.
- Fix: enable retry (3 attempts, 10 minutes apart is the usual default).
- Confidence: verified path.

**VEEAM-JOB-SHORT-RETENTION**
- Catches: a job keeping fewer than N restore points or days - a corruption or an encryption event
  noticed after a week has nothing older to go back to.
- Severity: medium.
- Source: `/api/v1/jobs`. Fields: `storage.retentionPolicy.type` (`Days` / `RestorePoints`),
  `storage.retentionPolicy.quantity`, `storage.gfsPolicy.isEnabled`.
- Condition: `isDisabled` eq false and `storage.retentionPolicy.quantity` lt 7 (threshold
  `veeam.min-retention-quantity`) and `storage.gfsPolicy.isEnabled` eq false.
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2.
- Fix: raise retention to at least 14 days or enable GFS weekly points on the copy.
- Confidence: verified paths.

**VEEAM-BACKUP-ORPHANED**
- Catches: a backup on a repository with no parent job (imported, or its job was deleted) - retention
  never applies to it, it fills the repository, and nobody will know whether it is still needed.
- Severity: low.
- Source: http GET `/api/v1/backups`, same headers/paging as the other list rules, `items: data`,
  `key: id`, `name: name`. Fields: `id`, `jobId`, `policyTag`, `platformName`, `platformId`, `name`,
  `creationTime`, `repositoryId`.
- Condition: `jobId` absent or empty.
- Refs: NIST-800-53:CP-9 (hygiene).
- Fix: re-map it to a job, export what matters, or delete it from disk.
- Confidence: field names verified
  <https://helpcenter.veeam.com/references/vbr/13/rest/1.1-rev0/tag/Backups>; that `jobId` is null for
  imported backups is likely (the page does not say).

**VEEAM-EMAIL-NOTIFICATIONS-OFF**
- Catches: global e-mail notifications are disabled - failures reach nobody unless they look at the
  console.
- Severity: medium.
- Source: http GET `/api/v1/generalOptions`, `headers: { x-api-version: 1.2-rev0 }`, `paging: none`,
  `key: "-"`. Fields: `emailSettings.isEnabled`, `emailSettings.notifyOnFailure`,
  `emailSettings.notifyOnWarning`, `emailSettings.notifyOnLastRetry`, `emailSettings.to`.
- Condition: any of `emailSettings.isEnabled` eq false; `emailSettings.notifyOnFailure` eq false.
- Refs: NIST-800-53:SI-4, NIST-800-53:IR-6, CIS-Controls-v8:13.1.
- Fix: enable e-mail notifications to a monitored mailbox or the ticketing intake, at least on failure
  and last retry.
- Confidence: verified field names
  <https://helpcenter.veeam.com/references/vbr/13/rest/1.1-rev0/tag/General-Options>.

**VEEAM-STORAGE-SPACE-WARNING-OFF**
- Catches: the global "warn when repository free space is low" option is off (or set below N %).
- Severity: low.
- Source: same query as VEEAM-EMAIL-NOTIFICATIONS-OFF (shared read). Fields:
  `notifications.storageSpaceThresholdEnabled`, `notifications.storageSpaceThreshold` (percent).
- Condition: any of `notifications.storageSpaceThresholdEnabled` eq false;
  `notifications.storageSpaceThreshold` lt 10 (threshold `veeam.storage-warning-min-percent`).
- Refs: NIST-800-53:SI-4.
- Fix: enable the threshold at 10 % or more; this is the only percentage-based free-space warning
  available until the engine can compute ratios.
- Confidence: verified field names (link above).

### PRTG (`prtg.yaml`, integration `prtg`)

Table API facts (verified): content values include `devices` and `sensors`; columns include `objid`,
`name`, `type`, `probe`, `group`, `device`, `sensor`, `host`, `status`, `message`, `priority`, `tags`,
`active`, `lastup`, `lastdown`, `lastcheck`, `uptimesince`, `downtimesince`, `upsens`, `downsens`,
`warnsens`, `pausedsens`, `unusualsens`, `undefinedsens`, `totalsens`, `downacksens`, `partialdownsens`;
`count` 1-50000, `start` zero-based; every numeric column has a `_raw` twin
<https://manuals.paessler.com/multiple_object_property_or_status.htm>. `content=probes` and the
`condition` column are **not** in the manual but are what Paessler support tells people to use for probe
connection state (`condition_raw` 0 = Disconnected, 2 = Connected)
<https://helpdesk.paessler.com/en/support/solutions/articles/76000077965-how-to-get-probe-status-with-api->.

**PRTG-PROBE-DISCONNECTED**
- Catches: a probe that is not connected to the core - every sensor under it is paused or stale, and
  the dashboard shows the last known colours.
- Severity: high.
- Source: `prtg.yaml`, http GET `/api/table.json`, params `{ content: probes, columns:
  "objid,probe,condition,status,message" }`, `paging: offset`, `offsetParam: start`, `limitParam: count`,
  `pageSize: 5000`, `items: probes`, `key: objid`, `name: probe`. Fields: `condition`, `condition_raw`.
- Condition: `condition_raw` ne 2.
- Refs: NIST-800-53:SI-4, CIS-Controls-v8:8.2.
- Fix: check the probe service and its path to the core (port 23560); approve a probe that re-registered
  with a new GID.
- Confidence: likely (support article; the `items` key for probes - `probes` - is a guess by analogy
  with `sensors`; a wrong key reads as an empty list, which PRTG-PROBE-NONE then flags).

**PRTG-PROBE-NONE**
- Catches: the probe table is empty - the API account sees no probes, so the sensor table is partial too.
- Severity: medium.
- Source: same query as PRTG-PROBE-DISCONNECTED (shared read).
- Condition: `count: none`.
- Refs: NIST-800-53:CA-7.
- Fix: give the API user read rights on the root group.
- Confidence: as above.

**PRTG-DEVICE-ALL-SENSORS-DOWN**
- Catches: a device whose every sensor is down - the host is down, not one service; a bigger thing than
  the per-sensor rules show, and often one alarm among many.
- Severity: high.
- Source: http GET `/api/table.json`, params `{ content: devices, columns:
  "objid,device,host,group,probe,status,totalsens,upsens,downsens,downacksens,partialdownsens,pausedsens,warnsens,unusualsens,undefinedsens" }`,
  offset paging as above, `items: devices`, `key: objid`, `name: device`.
- Condition: `totalsens_raw` gt 0 and `upsens_raw` eq 0 and `warnsens_raw` eq 0 and `downsens_raw` gt 0.
- Refs: NIST-800-53:SI-4, NIST-800-53:IR-4.
- Fix: treat as a host outage; check power, network and the device itself.
- Confidence: verified columns and `_raw` rule; `items: devices` by analogy (likely).

**PRTG-DEVICE-WITHOUT-SENSORS**
- Catches: a device object with no sensors - inventoried but not monitored.
- Severity: low.
- Source: same query as PRTG-DEVICE-ALL-SENSORS-DOWN (shared read).
- Condition: `totalsens_raw` eq 0.
- Refs: NIST-800-53:SI-4, CIS-Controls-v8:1.1.
- Fix: add a ping sensor at least, or delete the device.
- Confidence: verified columns.

**PRTG-DEVICE-PAUSED**
- Catches: a whole device paused by a user - a larger blind spot than one paused sensor, and the one
  people forget after maintenance.
- Severity: medium.
- Source: same query (shared read). Field: `status_raw`.
- Condition: `status_raw` eq 7.
- Refs: NIST-800-53:SI-4.
- Fix: resume the device, or use "pause until" with a date.
- Confidence: likely (object status codes are shared across object types; confirm a paused device
  reports 7 on the first run).

**PRTG-SENSOR-DOWN-HIGH-PRIORITY-DAY**
- Catches: a priority-4 or -5 sensor down and unacknowledged for more than a day (PRTG-SENSOR-DOWN-LONG
  waits seven days for all sensors).
- Severity: high.
- Source: the existing sensor query (shared read). Fields: `status_raw`, `priority_raw`,
  `downtimesince_raw` (seconds).
- Condition: `status_raw` in [5, 14] and `priority_raw` ge 4 and `downtimesince_raw` gt 86400 (threshold
  `prtg.high-priority-down-max-seconds`).
- Refs: NIST-800-53:SI-4, NIST-800-53:IR-4.
- Fix: fix or acknowledge with a note; an unacknowledged high-priority alarm after a day means the
  notification path is broken too.
- Confidence: verified (existing columns).

**PRTG-SENSOR-UNUSUAL**
- Catches: a sensor in the Unusual state (value far from its baseline) - the early warning before a
  limit is crossed.
- Severity: low.
- Source: existing sensor query (shared read).
- Condition: `status_raw` eq 10.
- Refs: NIST-800-53:SI-4.
- Fix: look at the channel graph; raise a ticket if it is real, tune the unusual detection if not.
- Confidence: verified.

**PRTG-MAINTENANCE-EXPIRING / PRTG-UPDATE-AVAILABLE / PRTG-LOW-MEMORY**
- Catch: the PRTG maintenance (licence) ends within 60 days (no more updates); a core update is
  available; the core server is low on memory.
- Severity: medium / low / medium.
- Source: http GET `/api/getstatus.htm`, params `{ id: "0" }` (answers JSON despite the extension),
  `paging: none`, `key: "-"`. Fields (as seen in community output, undocumented): `MaintExpiryDays`,
  `PRTGUpdateAvailable`, `LowMem`, `NewAlarms`, `Alarms`, `AckAlarms`, `Version`, `Clock`.
- Conditions: `MaintExpiryDays` lt 60; `PRTGUpdateAvailable` eq true; `LowMem` eq true.
- Refs: NIST-800-53:SI-2 (update), NIST-800-53:SI-4 (memory), none for maintenance.
- Fix: renew maintenance; install the update in a window; add memory or move the core.
- Confidence: guess - the endpoint is the one Paessler support names
  (<https://helpdesk.paessler.com/en/support/solutions/articles/76000080810-getstatus-api-returning-object-not-found>),
  the field list is from community output, and values may come back as strings ("true", "123") - the
  first run must show whether `lt` on a quoted number works in the engine.

### Dynatrace

**DT-PROBLEM-OPEN-LONG**
- Catches: a problem that has been open for more than 7 days - nobody is working it, or it is a
  permanent condition that should be a maintenance window or a tuned threshold instead of a red problem.
  Works around the epoch-ms gap: the problems API includes a problem when its start or end lies inside
  `from..to`; an open problem has no end, so `to: now-7d` returns exactly the open problems that
  started more than 7 days ago (and within 90).
- Severity: medium.
- Source: http GET `/api/v2/problems`, params `{ problemSelector: 'status("open")', from: now-90d,
  to: now-7d, pageSize: "500" }`, `paging: none`, `items: problems`, `key: problemId`, `name: title`.
- Condition: `each: any`.
- Refs: NIST-800-53:IR-4, NIST-800-53:SI-4.
- Fix: close it with a comment, fix it, or convert it into a maintenance window or a custom threshold.
  The 7-day window is a query parameter, so it is not a tenant threshold (engine gap).
- Confidence: verified semantics ("either the start or end timestamp of the problem is within the
  defined timeframe") <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2/problems/get-problems-list>.

**DT-NOTIFICATION-MISSING**
- Catches: no enabled problem-notification integration exists - problems are visible only to whoever
  opens the UI.
- Severity: high.
- Source: http GET `/api/v2/settings/objects`, params `{ schemaIds: "builtin:problem.notifications",
  scopes: environment, fields: "objectId,value", pageSize: "500" }`, `paging: none`, `items: items`,
  `key: objectId`, `name: value.displayName`. Needs token scope `settings.read` (add to the header).
  Fields: `value.enabled`, `value.type` (`EMAIL`, `SLACK`, `JIRA`, `ANSIBLETOWER`, `OPS_GENIE`,
  `PAGER_DUTY`, `VICTOROPS`, `WEBHOOK`, `XMATTERS`, `TRELLO`, `SERVICE_NOW`), `value.displayName`,
  `value.alertingProfile`.
- Condition: `count: { op: lt, value: 1, where: { field: value.enabled, op: eq, value: true } }`.
- Refs: NIST-800-53:IR-6, NIST-800-53:SI-4, CIS-Controls-v8:13.1.
- Fix: add an e-mail or ticketing notification bound to the default alerting profile.
- Confidence: verified (objects endpoint and the schema's properties)
  <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/settings/schemas/builtin-problem-notifications>.

**DT-HOST-CONNECTION-LOST-DETECTION-OFF**
- Catches: "host or monitoring connection lost" detection switched off at environment scope - a host
  that goes down raises no problem at all; the agent rules in this file would still show it, a day later.
- Severity: high.
- Source: http GET `/api/v2/settings/objects`, params `{ schemaIds:
  "builtin:anomaly-detection.infrastructure-hosts", scopes: environment, fields: "objectId,scope,value",
  pageSize: "500" }`, `paging: none`, `items: items`, `key: objectId`. Field:
  `value.host.connectionLostDetection.enabled`.
- Condition: `value.host.connectionLostDetection.enabled` eq false. A second rule with
  `scopes` omitted (all HOST / HOST_GROUP overrides) lists per-host opt-outs at low severity
  (DT-HOST-CONNECTION-LOST-DETECTION-OVERRIDE).
- Refs: NIST-800-53:SI-4, CIS-Controls-v8:13.1.
- Fix: re-enable; use `onGracefulShutdowns: DONT_ALERT_ON_GRACEFUL_SHUTDOWN` instead of switching it
  off for hosts that reboot on purpose.
- Confidence: verified (property paths and scopes)
  <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/settings/schemas/builtin-anomaly-detection-infrastructure-hosts>.

### Azure

**AZ-BILLING-ACCOUNT-STATUS**
- Catches: a billing account that is not Active (UnderReview, Disabled, Expired, Terminated,
  Transferred, Pending) - the step before AZ-SUBSCRIPTION-STATE turns PastDue.
- Severity: high.
- Source: http GET `/providers/Microsoft.Billing/billingAccounts`, params `{ api-version:
  "2024-04-01" }`, `paging: none`, `key: name`, `name: properties.displayName`. Fields:
  `properties.accountStatus`, `properties.accountStatusReasonCode`, `properties.agreementType`,
  `properties.enrollmentDetails.endDate`, `properties.hasReadAccess`.
- Condition: `properties.accountStatus` ne `Active`.
- Refs: none (financial continuity).
- Fix: contact the billing owner / reseller; a Disabled account stops every subscription under it.
- Confidence: verified (enum `Other, Active, UnderReview, Disabled, Deleted, Extended, Pending, New,
  Expired, Terminated, Transferred`)
  <https://learn.microsoft.com/rest/api/billing/billing-accounts/list?view=rest-billing-2024-04-01>.

**AZ-BILLING-ENROLLMENT-ENDING**
- Catches: an Enterprise Agreement enrollment ending within 90 days.
- Severity: by days left (high at 30, medium at 90); `deadline: properties.enrollmentDetails.endDate`.
- Source: same query as AZ-BILLING-ACCOUNT-STATUS (shared read).
- Condition: `properties.agreementType` eq `EnterpriseAgreement` and
  `properties.enrollmentDetails.endDate` until-lt 90 (threshold `azure.enrollment-notice-days`).
- Refs: none.
- Fix: start the renewal or the move to a Microsoft Customer Agreement with procurement.
- Confidence: verified (`enrollmentDetails.endDate` in the response sample).

**AZ-BILLING-ACCOUNT-NONE**
- Catches: the review identity sees no billing account - the two rules above are blind.
- Severity: low.
- Source: same query (shared read). Condition: `count: none`.
- Refs: NIST-800-53:CA-7.
- Fix: grant Billing Reader on the billing account, or call with `includeAll=true` as a Global Reader.
- Confidence: verified.

**AZ-SAVINGS-PLAN-EXPIRY**
- Catches: a compute savings plan expiring within 60 days without auto-renew - the discount ends
  overnight (the twin of AZ-RESERVATION-EXPIRY).
- Severity: by days left (high at 7, medium at 30, default low); `deadline:
  properties.expiryDateTime`.
- Source: http GET `/providers/Microsoft.BillingBenefits/savingsPlans`, params `{ api-version:
  "2022-11-01", $filter: "(properties/archived eq false)" }`, `paging: none`, `key: name`, `name:
  properties.displayName`. Fields: `properties.expiryDateTime`, `properties.renew`,
  `properties.provisioningState` (`Creating, PendingBilling, ConfirmedBilling, Created, Succeeded,
  Cancelled, Expired, Failed`), `properties.term`, `properties.commitment.amount`,
  `properties.utilization.aggregates[]`.
- Condition: `properties.provisioningState` eq `Succeeded` and `properties.renew` eq false and
  `properties.expiryDateTime` until-lt 60 (threshold `azure.savings-plan-notice-days`).
- Refs: none (cost).
- Fix: turn on renew or decide to let it lapse with finance.
- Confidence: verified
  <https://learn.microsoft.com/rest/api/billingbenefits/savings-plan/list-all?view=rest-billingbenefits-2022-11-01>.

**AZ-SAVINGS-PLAN-FAILED**
- Catches: a savings plan in Failed or Expired provisioning state still listed as unarchived.
- Severity: medium.
- Source: same query (shared read). Condition: `properties.provisioningState` in [Failed, Expired].
- Refs: none.
- Fix: fix the billing problem or archive the plan.
- Confidence: verified.

### ServiceNow

**SNOW-INCIDENT-NEW-UNTOUCHED**
- Catches: an incident of any priority still in state New a day after it was opened - no one has
  accepted it.
- Severity: medium (high when priority is 3 or better).
- Source: http GET `/api/now/table/incident`, params `{ sysparm_query: "active=true^state=1",
  sysparm_fields: "sys_id,number,short_description,priority,state,assigned_to,assignment_group,opened_at,sys_updated_on",
  sysparm_display_value: "false", sysparm_exclude_reference_link: "true" }`, `paging: offset`,
  `pageSize: 1000`, `items: result`, `key: number`, `name: short_description`.
- Condition: `opened_at` age-gt 1 (threshold `servicenow.new-incident-max-days`).
- Refs: NIST-800-53:IR-4, NIST-800-53:IR-6.
- Fix: assign and move to In Progress, or route to the right group.
- Confidence: verified base-table fields (state 1 = New out of the box).

**SNOW-INCIDENT-STALE**
- Catches: an active incident of any priority with no update for 14 days - the forgotten ticket.
- Severity: low (medium for priority 1-3).
- Source: http GET `/api/now/table/incident`, params as above with `sysparm_query: "active=true"`.
- Condition: `sys_updated_on` age-gt 14 (threshold `servicenow.incident-stale-days`).
- Refs: NIST-800-53:IR-4.
- Fix: update, resolve or close it; a stale queue hides the real work.
- Confidence: verified.

**SNOW-INCIDENT-ON-HOLD-LONG**
- Catches: an incident On Hold (state 3) for more than 7 days - waiting on a caller or a vendor with
  nobody chasing.
- Severity: low.
- Source: same `active=true` query as SNOW-INCIDENT-STALE (shared read). Fields: `state`,
  `sys_updated_on`, `hold_reason`.
- Condition: `state` eq 3 and `sys_updated_on` age-gt 7 (threshold `servicenow.on-hold-max-days`).
- Refs: NIST-800-53:IR-4.
- Fix: chase, or resolve as "caller unresponsive" per the policy.
- Confidence: verified (add `hold_reason` to `sysparm_fields` for the evidence).

**SNOW-INCIDENT-REOPENED**
- Catches: an active incident that has been reopened - a fix that did not hold.
- Severity: low.
- Source: same `active=true` query (shared read; add `reopen_count` to `sysparm_fields`).
- Condition: `reopen_count` gt 0.
- Refs: NIST-800-53:IR-4.
- Fix: look for the root cause; link a problem record if it repeats.
- Confidence: likely (`reopen_count` is a base incident column since London).

**SNOW-PROBLEM-UNASSIGNED**
- Catches: an active problem record with no assignee - root-cause work nobody owns.
- Severity: low.
- Source: http GET `/api/now/table/problem`, params `{ sysparm_query: "active=true",
  sysparm_fields: "sys_id,number,short_description,state,priority,assigned_to,assignment_group,opened_at,sys_updated_on",
  sysparm_display_value: "false", sysparm_exclude_reference_link: "true" }`, offset paging, `items:
  result`, `key: number`.
- Condition: `assigned_to` empty.
- Refs: NIST-800-53:IR-4.
- Fix: assign a problem manager.
- Confidence: verified base-table fields.

**SNOW-APPROVAL-PENDING-LONG**
- Catches: an approval request waiting for more than 3 days - a change or a catalog request stalled on
  one person.
- Severity: medium.
- Source: http GET `/api/now/table/sysapproval_approver`, params `{ sysparm_query:
  "state=requested", sysparm_fields: "sys_id,approver,state,sysapproval,document_id,sys_created_on,due_date",
  sysparm_display_value: all, sysparm_exclude_reference_link: "true" }`, offset paging, `items:
  result`, `key: sys_id.value`, `name: approver.display_value`.
- Condition: `sys_created_on.value` age-gt 3 (threshold `servicenow.approval-max-wait-days`).
- Refs: NIST-800-53:CM-3.
- Fix: remind the approver or delegate; set approval delegation for absences.
- Confidence: verified base-table fields (`state` value `requested` is the stored code).

**SNOW-CHANGE-EMERGENCY-OPEN**
- Catches: an active emergency change - each one needs a post-implementation review and is a signal
  that normal change planning failed.
- Severity: info.
- Source: the existing change query (shared read; `type` is already in `sysparm_fields`).
- Condition: `type` eq `emergency`.
- Refs: NIST-800-53:CM-3.
- Fix: review at the next CAB; convert recurring emergencies into standard changes.
- Confidence: verified.

**SNOW-CHANGE-HIGH-RISK-NO-BACKOUT-PLAN**
- Catches: a high or very-high-risk change in the pipeline with an empty backout plan (or test plan).
- Severity: medium.
- Source: http GET `/api/now/table/change_request`, params `{ sysparm_query:
  "active=true^stateIN-4,-3,-2,-1^riskIN1,2", sysparm_fields:
  "sys_id,number,short_description,state,risk,type,start_date,backout_plan,test_plan,assigned_to",
  sysparm_display_value: "false", sysparm_exclude_reference_link: "true" }`, offset paging, `items:
  result`, `key: number`.
- Condition: any of `backout_plan` empty; `test_plan` empty.
- Refs: NIST-800-53:CM-3, NIST-800-53:CP-10.
- Fix: fill the plans before CAB; CAB should not approve without them.
- Confidence: likely (risk codes 1 = Very High / 2 = High out of the box; many instances customise them).

**SNOW-SLA-DEFINITION-MISSING**
- Catches: no active SLA definition exists - SNOW-SLA-BREACHED and SNOW-SLA-AT-RISK can never fire, and
  "no breaches" means nothing.
- Severity: medium.
- Source: http GET `/api/now/table/contract_sla`, params `{ sysparm_query: "active=true",
  sysparm_fields: "sys_id,name,collection,type,duration,active", sysparm_display_value: "false" }`,
  offset paging, `items: result`, `key: sys_id`, `name: name`.
- Condition: `count: none`.
- Refs: NIST-800-53:IR-4.
- Fix: define response and resolution SLAs per priority, at least for incidents.
- Confidence: verified base table (`contract_sla`).

### Wiz

**WIZ-CLOUD-ACCOUNT-NONE**
- Catches: the cloud-account list is empty - nothing is connected, or the service account lacks the read
  scope; every WIZ rule is quiet either way.
- Severity: medium (both lenses).
- Source: the existing `cloudAccounts(first: 500)` query (shared read). Condition: `count: none`.
- Refs: NIST-800-53:CA-7.
- Fix: connect the accounts or add `read:cloud_accounts` to the service account.
- Confidence: verified on a live tenant by the existing rule.

**WIZ-CONNECTOR-NONE-ENABLED**
- Catches: no enabled connector exists.
- Severity: medium (both lenses).
- Source: the existing `connectors(first: 500)` query (shared read).
- Condition: `count: { op: lt, value: 1, where: { field: enabled, op: eq, value: true } }`.
- Refs: NIST-800-53:CA-7.
- Fix: enable or recreate the cloud connector.
- Confidence: verified by the existing rule.

**WIZ-PROJECT-NONE**
- Catches: no (unarchived) project is defined - every finding lands in "all", nothing has an owner or a
  business unit, and nobody can be paged for it.
- Severity: low.
- Source: graphql `projects(first: 500, after: $after) { nodes { id name slug archived } pageInfo {
  hasNextPage endCursor } }`, `items: data.projects.nodes`, cursor paging, `key: id`.
- Condition: `count: { op: lt, value: 1, where: { field: archived, op: eq, value: false } }`.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1.
- Fix: create projects per environment or business unit and assign cloud accounts.
- Confidence: likely (`projects` with `archived` is exposed by the Steampipe plugin and the Wiz UI).

**WIZ-ISSUE-CRITICAL-NO-DUE-DATE**
- Catches: a critical issue in progress without a due date - no commitment, nothing to measure.
- Severity: low.
- Source: the `issuesV2` critical query of WIZ-ISSUE-CRITICAL-AGED (shared read).
- Condition: `status` eq `IN_PROGRESS` and `dueAt` absent.
- Refs: NIST-800-53:RA-7, CIS-Controls-v8:7.7.
- Fix: set a due date when taking an issue.
- Confidence: likely.

---

## Priority 3 - hygiene, lifecycle and cost

### VMware vCenter

**VMW-VCSA-VERSION-SUPPORT-ENDING**
- Catches: vCenter 8.0 - Broadcom ends service for vCenter Server 8.x and vSAN 8.x on 2027-10-11
  (KB 456708); vSphere 7.0 general support ended 2025-10-02 (already caught by
  VMW-VCSA-VERSION-UNSUPPORTED's default pattern). Twelve months of lead time is what an upgrade to 9
  needs.
- Severity: low today; the YAML author should raise it to medium in mid-2027. The engine cannot attach
  a fixed deadline to a constant (gap), so the date lives in the `why`.
- Source: http GET `/api/appliance/system/version` (same query as VMW-VCSA-VERSION-UNSUPPORTED, shared
  read). Fields: `version`, `product`, `build`, `releasedate`.
- Condition: `version` match `^8\.0` (threshold `vmware.support-ending-version-pattern`).
- Refs: NIST-800-53:SA-22, NIST-800-53:SI-2.
- Fix: plan the upgrade to VCF/VVF 9 before the date; check the host hardware compatibility first.
- Confidence: verified date <https://knowledge.broadcom.com/external/article/456708>; the extension of
  7.0 to 2025-10-02 is from Broadcom's lifecycle notice as relayed by resellers.

### Veeam Backup & Replication

(No further low-priority Veeam entries: the remaining asks - repository percentage, per-object RPO,
copy lag - are engine gaps listed below and already in the backlog.)

### PRTG

(PRTG-MAINTENANCE-EXPIRING / UPDATE / LOW-MEMORY sit in priority 2 because they share one query; their
individual value is priority 3.)

### Azure

**AZ-SUBSCRIPTION-UNTAGGED**
- Catches: a subscription with no tags at all - no owner, no cost centre, no environment; cost reports
  and incident routing have nothing to group by.
- Severity: low.
- Source: the existing `/subscriptions` query (shared read). Field: `tags` (object).
- Condition: `tags` absent or empty.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1.
- Fix: apply the tagging policy (owner, cost centre, environment) at the subscription; enforce it with
  Azure Policy once a per-subscription file exists.
- Confidence: likely (`tags` is a member of the Subscription resource in 2022-12-01; whether an untagged
  subscription returns `{}` or omits the key is a first-run item - the condition covers both).

**AZ-MANAGEMENT-GROUP-FLAT**
- Catches: no management group below the tenant root - policy, RBAC and Defender settings can only be
  applied per subscription, and new subscriptions inherit nothing.
- Severity: low.
- Source: http GET `/providers/Microsoft.Management/managementGroups`, params `{ api-version:
  "2021-04-01" }`, `paging: none`, `key: name`, `name: properties.displayName`. Note the page token is
  `@nextLink` here (yet another spelling; see gaps). Fields: `name`, `properties.displayName`,
  `properties.tenantId`.
- Condition: `count: { op: lt, value: 2 }` (the root group counts as one).
- Refs: NIST-800-53:CM-6, CIS-Controls-v8:4.1.
- Fix: create a small hierarchy (platform / landing zones / sandbox) and move subscriptions in.
- Confidence: verified (list shape and `@nextLink`)
  <https://learn.microsoft.com/rest/api/managementgroups/management-groups/list?view=rest-managementgroups-2020-05-01>
  (2020-05-01 page; 2021-04-01 is the same shape).

### ServiceNow - CMDB

All three share one query: http GET `/api/now/table/cmdb_ci_server`, params `{ sysparm_query:
"operational_status=1^install_status=1", sysparm_fields:
"sys_id,name,sys_class_name,owned_by,managed_by,support_group,assigned_to,last_discovered,discovery_source,operational_status,install_status,sys_updated_on",
sysparm_display_value: "false", sysparm_exclude_reference_link: "true" }`, offset paging, `items:
result`, `key: sys_id`, `name: name`. Base-table fields are verified; the choice values 1 = Operational
/ 1 = Installed are out of the box.

**SNOW-CMDB-SERVER-NO-SUPPORT-GROUP**
- Catches: an operational server CI with no support group - no team is paged for it and no change
  approval routes to anyone.
- Severity: medium.
- Condition: `support_group` empty.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1.
- Fix: set the support group; make it mandatory on the class.

**SNOW-CMDB-SERVER-NO-OWNER**
- Catches: an operational server CI with neither an owner nor a manager.
- Severity: low.
- Condition: `owned_by` empty and `managed_by` empty.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1.
- Fix: assign the business owner and the technical manager.

**SNOW-CMDB-SERVER-NOT-DISCOVERED**
- Catches: an operational server CI not seen by discovery for 30 days (or never) - the record is a
  guess, or the server is gone and the CMDB does not know.
- Severity: low.
- Condition: any of `last_discovered` empty; `last_discovered` age-gt 30 (threshold
  `servicenow.ci-discovery-max-days`). Estates without Discovery will see every CI listed - that is the
  finding ("the CMDB is maintained by hand"), to be overridden per tenant if accepted.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1.
- Fix: run Discovery over the server subnets, or retire the CI.

---

## Engine gaps that blocked rules

Ordered by how many of the asked-for checks each one unblocks. Items already in
`docs/backlog/infrastructure.md` are marked (backlog).

1. **Per-object fan-out for vSphere** (backlog): `GET /api/vcenter/vm/{vm}/tools` (tools not running /
   out of date), `/api/vcenter/vm/{vm}/hardware/cdrom` (ISO mounted - `backing.type` `ISO_FILE` and
   `state` `CONNECTED`), `/api/vcenter/host/{host}` (no maintenance-mode or version fields exist in the
   Automation API host list at all), `/api/vcenter/cluster/{cluster}` (admission control, DRS automation
   level), `/api/appliance/local-accounts/{name}` (the list is names only). Snapshots: the Automation
   API has **no** snapshot list in 8.0.3 (the backlog assumption holds); old/large snapshots need the
   Web Services (SOAP) API or the per-VM snapshot operations of the newest releases - a different
   runner either way. ESXi lockdown mode and NTP: not in the Automation API.
2. **Bare scalar / string-array / map answers on the vSphere `/api` base** (backlog): wrap a scalar as
   `{value}`, an array of strings as `[{value}]`, a map as `[{key, value}]`. Needed by
   VMW-VCSA-LOCAL-ACCOUNT-EXTRA (array of strings), and by every `/rest` rule the day `/rest` is
   removed. Until then the proposals use `/rest` where it exists; `/rest/vcenter/services` and
   `/rest/appliance/ntp` are assumed to wrap like the routes the file already uses.
3. **Subscription-scoped Azure routes** (backlog): Defender for Cloud plans
   (`/subscriptions/{id}/providers/Microsoft.Security/pricings`), secure score
   (`.../Microsoft.Security/secureScores`), public IPs (`.../Microsoft.Network/publicIPAddresses`),
   policy assignments and compliance, Owner-role counts per subscription, diagnostic settings (per
   resource), NSG rules, storage account settings - every one of the Azure asks except billing, custom
   roles and management groups. The backlog's design (one `azure` integration per subscription with the
   subscription as the endpoint path, or engine fan-out over `/subscriptions` rows) is the right fix;
   the second rule file it needs could not be created under this task's constraints. Guest access and
   Owner counts across the tenant are Entra (`graph`) questions, not ARM.
4. **Epoch-millisecond dates** (backlog): Dynatrace `startTime`, `lastSeenTimestamp`, `offlineSince`.
   DT-PROBLEM-OPEN-LONG works around it with `to: now-7d`; "ActiveGate offline for N hours" and "host
   not seen for N days" cannot.
5. **Thresholds on query parameters**: `to: now-7d`, `createdAfterFilter`, `from` windows are fixed
   text; a `threshold:` on a param (or a `{DAYS:n}`-style macro like the LDAP `{FT:n}`) would make
   DT-PROBLEM-OPEN-LONG and a Veeam "restore points created after" rule tenant-tunable.
6. **Newest-row-per-entity aggregation** (backlog): Veeam RPO per object (newest restore point per
   `backupObjectId`), last success per job, copy lag; PRTG "sensors paused per parent". The
   `count ... where` form judges the whole set, not per group; a `group: <field>` on `count` would do.
7. **Field-against-field and arithmetic** (backlog): datastore and repository free-space percentages,
   licence used vs licensed (Veeam instances, PRTG sensors, Dynatrace host units), budget consumption.
8. **Paging tokens the runner does not follow** (backlog): ARM `nextLink` and management groups'
   `@nextLink`; Dynatrace `nextPageKey` (the next request must carry only the token - the proposals ask
   for the maximum page size instead); Wiz `cloudAccounts` / `connectors` without a cursor.
9. **A constant deadline**: a lifecycle rule (vSphere 8.0 end of service 2027-10-11) has no date field
   to point `deadline:` at; `deadline: { value: "2027-10-11" }` would let ranking treat it like every
   other expiry.
10. **Joins across integrations** (backlog): VMs in vCenter with no Veeam backup object (the single most
    requested backup check); CMDB servers monitored by neither PRTG nor Dynatrace; Wiz connector owners
    who left. The `store` protocol can read `row_seen` of both scans, so a `hybrid-backup.yaml` store
    rule is possible once both scans run on the same day - a proposal for the store pack, not for
    these files.
11. **Typed JSON from PRTG's status endpoint**: `getstatus.htm` is undocumented and may return numbers
    as strings; the engine's "numbers compare as numbers" needs confirming for quoted numerics before
    PRTG-MAINTENANCE-EXPIRING can be trusted.
12. **Wiz schema access**: `relatedEntity.type` values, `note` / `resolutionReason`, `serviceAccounts`
    fields must be read from the tenant's API explorer; there is no public schema to verify against.

## To confirm on the first real run (additions to the backlog checklist)

- vCenter: `/rest/vcenter/services` and `/rest/appliance/ntp` wrap as assumed; the enum spellings of
  service `startup_type` / `state` / `health`; the `lastcheck` timestamp format; the `protocol` enum of
  syslog forwarding; the "never" encoding of `global-policy.max_days`; `standalone=true` is accepted
  as a query parameter on the host list.
- Veeam: `/api/v1/jobs` returns `storage.advancedSettings.storageData.encryption.isEnabled`,
  `guestProcessing.appAwareProcessing.isEnabled`, `schedule.runAutomatically` for every job type the
  tenant has (file and agent jobs may differ); `type` spellings of copy and SureBackup jobs in
  `/api/v1/jobs/states`; `repository.makeRecentBackupsImmutableDays` is present on GET for hardened and
  object-storage repositories; `jobId` is null (not absent) on imported backups; `license.type` and
  `autoUpdateEnabled` spellings.
- PRTG: `content=probes` answers `{"probes": [...]}` with `condition_raw`; a paused device reports
  `status_raw` 7; `getstatus.htm?id=0` field names and whether numbers are quoted.
- Dynatrace: `apiTokens` rows carry `enabled` (not `disabled`); the token has `apiTokens.read` and
  `settings.read`; the settings objects at environment scope exist (a never-edited environment may
  return zero objects for `builtin:anomaly-detection.infrastructure-hosts` - then the default applies
  and the rule must treat "no object" as the vendor default, which is connection-lost detection ON; a
  `count: none` there would be a false finding, so the per-object `each` form is the right one and an
  empty list is a pass by absence - note this explicitly in the rule's `why`).
- Azure: root-scope `roleDefinitions` with `$filter=type eq 'CustomRole'` is accepted; an untagged
  subscription returns `tags: {}` or no key; `billingAccounts` needs Billing Reader or `includeAll=true`.
- ServiceNow: risk codes 1/2, `sysapproval_approver.state` = `requested`, `reopen_count` present;
  `cmdb_ci_server` is the right class (some estates use `cmdb_ci_computer` or `cmdb_ci_win_server` only).
- Wiz: `relatedEntity: {type: [SECRET]}`, `note`, `resolutionReason`, `serviceAccounts.lastRotatedAt`,
  `projects.archived` exist with those names.
