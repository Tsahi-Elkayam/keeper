# Proposals - checks ported from the old Microsoft cloud catalogue

The old review tool kept a catalogue of checks per Microsoft cloud service (Entra ID, Entra Connect,
Exchange Online, Intune, Microsoft 365 admin, Teams, Purview, SharePoint and OneDrive, Power
Platform and Power BI, Dynamics 365, Defender XDR / for Endpoint / for Office, information
protection) plus a list of known issues. Every row of that catalogue was mapped to Keeper: covered
by a rule that exists, covered by a proposal already written (`microsoft-cloud.md`,
`cross-system.md`, `windows-estate.md`), a duplicate of another row, not automatable (a decision, a
record, a person), blocked on an integration Keeper does not have, or **new** - this file. The
per-row map lives outside the repo because it carries tenant detail; this file carries none: every
check below is described generically, tenant facts are `threshold.<name>` settings, and Microsoft's
own well-known ids are the only constants.

Format per entry, as in `microsoft-cloud.md`: id, what it catches and why, severity, data source
(rules file; Graph version, path, select/filter/expand/`for_each`, fields; or a store join; or a
per-host cim / registry / eventlog / tls query), permission, the condition in Keeper's own words,
canonical refs (`NIST-800-53:XX-n`, `CIS-Controls-v8:n.n`, `CIS-M365:n.n.n`, `MITRE-ATTACK:Tnnnn`),
fix, and confidence in the field names (verified = read on the Microsoft Learn page linked; likely =
from documentation memory; guess = confirm on the first run). A heading that lists several ids with
`/` is one query carrying several rules.

Sections, in the order the old catalogue had them. Each section was mapped by its own pass and
keeps its own conventions; where two passes wrote the same check, one id was kept and the other
section points at it in a short parenthesis. Every section that needs an integration Keeper lacks
ends with a compact "Rules once <integration> exists" list: one line per check (id, what, cmdlet or
endpoint and property, condition, severity), which is the specification the integration work
should implement first. The final section ranks the missing integrations by how many old checks
each one unlocks.

Shared queries referenced by name (Q-USERS, Q-APPS, Q-SPS, Q-CA, Q-ROLES-EXPAND, Q-AUTHM, Q-AUTHZ,
Q-XTAP, Q-DOMAINS, Q-MDEVICES, Q-COMPLIANCE-*, Q-DEVICECONFIG, Q-MAM-*, Q-SPO) are the ones defined
at the top of `microsoft-cloud.md`. Target rules files: `rules\entra.yaml`, `intune.yaml`,
`m365.yaml`, `hybrid-identity.yaml`, `cross-system.yaml`, `workstations.yaml`,
`windows-server.yaml`, `active-directory.yaml`, `certificates.yaml`, `azure.yaml`, and three new
files proposed here: `rules\entra-connect.yaml` (integration cim; targets the sync servers),
`rules\exchange-online.yaml` and `rules\defender.yaml` (both on the graph integration until their
own integrations exist).

Engine gaps that many entries depend on (each entry says which): array leaves with parent context
(name/value settings arrays, nested policy rules); "all elements" conditions on arrays; a two-field
comparison (`field-ne-field`, ratios); ISO 8601 duration comparison; version-number ordering;
run-to-run comparison (counts, growth, configuration hash drift); count per parent for `for_each`
results (done in a store rule meanwhile); map-valued and list-valued thresholds readable from store
SQL; JSON usage reports (`$format=application/json` on beta reports, or a `format: json` option);
read-only POST for the few query endpoints that are POST by design (advanced hunting, Power
Platform tenant settings, Intune export jobs); store-derived target lists for per-host files.

---

## Entra ID


Format follows `docs\proposals\microsoft-cloud.md`. "Shared query" names are the ones defined there
(Q-USERS, Q-APPS, Q-SPS, Q-CA, Q-ROLES-EXPAND, Q-AUTHZ, Q-XTAP, Q-DOMAINS). Several entries extend
Q-USERS with more `select` fields; the author should merge them into one fetch. Store rules read
`row_seen` as described in `docs\proposals\cross-system.md` (CTE B5 for Entra users, B8 for role
assignments). Tenant facts are `threshold.<name>` settings; an empty threshold makes the rule n/a.

---

## Identity signals and emergency access

### ENTRA-RISK-DETECTION-OPEN-RECENT
- Catches: Identity Protection risk detections from the last N days that are still "at risk" -
  leaked credentials, anonymous IP, impossible travel, token anomalies, password spray - grouped by
  detection type. ENTRA-RISKY-USER-OPEN shows the user; this shows the attack technique so the
  response matches it.
- Severity: high (critical when the type is leakedCredentials or passwordSpray).
- Source: entra.yaml; v1.0; `/identityProtection/riskDetections`; filter
  `detectedDateTime ge {DAYS_AGO:7} and riskState eq 'atRisk'`; select id, riskEventType,
  riskLevel, riskState, detectedDateTime, userPrincipalName, userId, ipAddress, location; key
  `{userId}|{riskEventType}`; name userPrincipalName; refresh 1d. New query.
- Permission: IdentityRiskEvent.Read.All. Needs Entra ID P2.
- Condition: `each: any`; severity map on riskEventType.
- Refs: NIST-800-53:SI-4, NIST-800-53:IR-4, MITRE-ATTACK:T1110.003, MITRE-ATTACK:T1078.004.
- Fix: leaked credential or spray: reset password, revoke sessions; anonymous IP or travel: confirm
  with the user; token anomaly: revoke refresh tokens; then confirm or dismiss the risk.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0

### ENTRA-SIGNIN-FOREIGN-SUCCESS-RECENT
- Catches: successful interactive sign-ins in the last N days from countries outside the
  organisation's home list. For an organisation that works from one country, each one is travel
  to confirm or a stolen session.
- Severity: medium.
- Source: entra.yaml; v1.0; `/auditLogs/signIns`; filter
  `createdDateTime ge {DAYS_AGO:7} and status/errorCode eq 0`; select id, userPrincipalName, userId,
  appDisplayName, ipAddress, location, createdDateTime, conditionalAccessStatus; key
  `{userId}|{location.countryOrRegion}`; name userPrincipalName; maxPages capped. New query
  (Graph does not filter on location, so the country test is in the condition).
- Permission: AuditLog.Read.All + Directory.Read.All. Needs P1 for the sign-in log.
- Condition: location.countryOrRegion notin threshold `entra.home-countries` (default empty =
  n/a) and location.countryOrRegion notempty.
- Refs: NIST-800-53:AC-2(12), NIST-800-53:SI-4, MITRE-ATTACK:T1078.004.
- Fix: confirm each user and country; reset and revoke the unexplained ones; add a location-based
  Conditional Access policy.
- Confidence: verified field names - https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0

### ENTRA-BREAKGLASS-UNTESTED
- Catches: an emergency-access account with no successful sign-in for more than N days. An
  account nobody tested this quarter may be blocked by a newer policy, have an expired key or a
  lost password exactly when it is needed.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-USERS (signInActivity selected).
- Permission: User.Read.All + AuditLog.Read.All.
- Condition: id in threshold `entra.breakglass-user-ids` (or userPrincipalName match threshold
  `entra.breakglass-upn-pattern`; both empty = n/a) and
  `signInActivity.lastSuccessfulSignInDateTime` age-gt 90 (threshold
  `entra.breakglass-test-days`) or absent.
- Refs: NIST-800-53:CP-2, NIST-800-53:AC-2, NIST-800-53:IA-5.
- Fix: run the quarterly test sign-in, confirm the alert fires, record it.
- Confidence: verified.

### ENTRA-BREAKGLASS-WEAK-METHODS
- Catches: an emergency-access account that has a phone, e-mail, software OATH or Temporary Access
  Pass method, or no FIDO2 key at all. The most powerful account in the tenant must not be reachable
  through the weakest factor.
- Severity: high.
- Source: entra.yaml; v1.0; `for_each: { threshold list entra.breakglass-user-ids, field: id }` ->
  `/users/{id}/authentication/methods`; rows: one per method with `@odata.type`; key
  `{parent.id}`. New per-object query.
- Permission: UserAuthenticationMethod.Read.All.
- Condition: count lt 1 where `@odata.type` eq `#microsoft.graph.fido2AuthenticationMethod`
  (no key), or any row with `@odata.type` in [phoneAuthenticationMethod,
  emailAuthenticationMethod, softwareOathAuthenticationMethod,
  temporaryAccessPassAuthenticationMethod].
- Refs: NIST-800-53:IA-2(1), NIST-800-53:IA-2(6), MITRE-ATTACK:T1621.
- Fix: register two FIDO2 keys kept offline; remove the phone and e-mail methods; exclude the
  accounts from registration campaigns.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/authentication-list-methods?view=graph-rest-1.0

### ENTRA-PIM-ACTIVATION-WEAK
- Catches: a directory role whose PIM activation settings are weak: activation may last longer
  than N hours, needs no justification, needs no MFA (nor an authentication context), or - for
  roles the tenant marks as tier-0 - needs no approval or allows permanent eligibility.
  ENTRA-PIM-NO-APPROVAL reads approval only; this reads the whole rule set per role.
- Severity: medium (high for tier-0 roles).
- Source: entra.yaml; v1.0; `/policies/roleManagementPolicyAssignments`; filter
  `scopeId eq '/' and scopeType eq 'DirectoryRole'`; expand `policy($expand=rules)`; fields
  roleDefinitionId, policy.rules[] (id, `@odata.type`, maximumDuration, isExpirationRequired,
  enabledRules); key roleDefinitionId. Rows: one per role; rule ids to test:
  `Expiration_EndUser_Assignment` (maximumDuration), `Enablement_EndUser_Assignment`
  (enabledRules contains Justification, MultiFactorAuthentication), `Approval_EndUser_Assignment`
  (setting.isApprovalRequired), `Expiration_Admin_Eligibility` (isExpirationRequired).
- Permission: RoleManagementPolicy.Read.Directory (RoleManagement.Read.Directory). Needs P2.
- Condition: roleDefinitionId in threshold `entra.pim-governed-role-ids` (default: the privileged
  role list) and any of: maximumDuration gt threshold `entra.pim-max-activation` (text compare on
  ISO 8601 duration is an engine gap - compare against a small allow-list such as PT1H..PT8H, or add
  a duration op); enabledRules notcontains Justification; enabledRules notcontains
  MultiFactorAuthentication (and no authenticationContext rule); for tier-0 ids: isApprovalRequired
  eq false or isExpirationRequired eq false. Array leaves with parent context are an engine gap;
  until then one rule per PIM rule id with the policy rows flattened by the author.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-2(7), NIST-800-53:IA-2(1), MITRE-ATTACK:T1098.003.
- Fix: in PIM role settings require MFA and justification, cap activation, require approval and
  an eligibility end date for tier-0 roles.
- Confidence: verified resource; rule id names likely -
  https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyrule?view=graph-rest-1.0

### ENTRA-PIM-ELIGIBILITY-NEVER-ACTIVATED
- Catches: an eligible role assignment that was never activated in the activation history the
  tenant keeps (N days). An eligibility nobody uses is a privilege nobody needs.
- Severity: low (medium for tier-0 roles).
- Source: entra.yaml; v1.0; two queries: `/roleManagement/directory/roleEligibilityScheduleInstances`
  (select id, principalId, roleDefinitionId, startDateTime, memberType) and
  `/roleManagement/directory/roleAssignmentScheduleRequests` filter
  `action eq 'selfActivate' and createdDateTime ge {DAYS_AGO:90}` (select principalId,
  roleDefinitionId, createdDateTime, status). Then a `store` rule (integration keeper) anti-joining
  the two row sets on principalId + roleDefinitionId, excluding eligibilities whose startDateTime is
  inside the window. Key `{principalId}|{roleDefinitionId}`.
- Permission: RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.Read.Directory.
- Condition: `each: any` on the anti-join result.
- Refs: NIST-800-53:AC-6(7), NIST-800-53:AC-2(3), CIS-Controls-v8:6.8.
- Fix: remove the eligibility; re-grant on request.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentschedulerequests?view=graph-rest-1.0

### ENTRA-ROLE-HOLDER-INACTIVE
- Catches: a directory role holder (active or eligible) with no successful cloud sign-in for N
  days. ENTRA-ROLE-DISABLED-HOLDER sees the disabled flag; a dormant enabled admin is the same
  risk with a working password.
- Severity: medium (high for tier-0 roles).
- Source: entra.yaml; `store` rule joining B8 entra_roles (principal_id) with B5 entra_users
  (id, cloud_signin, enabled); plus the eligibility instances query above for eligible holders.
  Key `{assignment_id}`.
- Permission: none beyond the existing queries.
- Condition: enabled eq 1 and (cloud_signin absent or `julianday(:now) - julianday(cloud_signin)`
  gt 90, threshold `entra.admin-inactive-days`). Break-glass ids (threshold) excluded.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:AC-6(7), CIS-Controls-v8:5.3.
- Fix: remove the assignment; re-grant on request.
- Confidence: verified (fields already collected).

### ENTRA-ROLE-HOLDERS-TOO-MANY
- Catches: a directory role whose active-plus-eligible holder count exceeds the cap the tenant
  sets for it. Only the two most powerful roles have their own count rules; every other role (user
  administrators, helpdesk, application, Exchange, SharePoint, security ...) grows unnoticed.
- Severity: medium.
- Source: entra.yaml; `store` rule over B8 entra_roles plus the eligibility instances rows:
  `SELECT role_id, COUNT(DISTINCT principal_id) AS holders ... GROUP BY role_id`; key role_id. Caps
  come from a threshold map `entra.role-max-holders` (role template id -> number); engine gap: map
  thresholds in SQL - until then one rule per role of interest with a scalar threshold.
- Permission: none beyond the existing queries.
- Condition: holders gt the cap for the role.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-2(7), CIS-Controls-v8:5.4.
- Fix: reduce to the people who use the role weekly; use a narrower role for the rest.
- Confidence: verified.

### ENTRA-ROLE-HOLDER-NO-ADMIN-ACTIVITY
- Catches: a role holder who initiated no directory change in the audit window. A review hint,
  not a verdict: reader roles and service-specific admins are expected to show little here.
- Severity: info.
- Source: entra.yaml; v1.0; `/auditLogs/directoryAudits`; filter
  `activityDateTime ge {DAYS_AGO:30} and result eq 'success'`; select id, initiatedBy,
  activityDisplayName, activityDateTime; then a `store` anti-join of B8 entra_roles against the
  distinct `initiatedBy.user.id` values. Key assignment_id. Roles in threshold
  `entra.reader-role-ids` are skipped.
- Permission: AuditLog.Read.All.
- Condition: `each: any` on the anti-join.
- Refs: NIST-800-53:AC-6(7), NIST-800-53:AU-6.
- Fix: confirm the holder still needs the role; otherwise remove it.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0

### ENTRA-ROLE-HOLDER-NAMING
- Catches: a directory role held by an account whose name does not follow the organisation's
  admin-account convention - a daily account that also carries a role.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-ROLES-EXPAND (principal.userPrincipalName).
- Permission: RoleManagement.Read.Directory + User.Read.All.
- Condition: principal is a user and principal.userPrincipalName notmatch threshold
  `entra.admin-account-pattern` (empty = n/a); break-glass ids excluded.
- Refs: NIST-800-53:AC-6(2), NIST-800-53:IA-4.
- Fix: move the role to a dedicated admin account.
- Confidence: verified.

### ENTRA-ROLE-AU-SCOPED-ASSIGNMENT
- Catches: a role assignment scoped to an administrative unit. Scoped admins can reset passwords
  and manage members inside the unit; each scope must be known.
- Severity: info (review list).
- Source: entra.yaml; v1.0; shared query Q-ROLES-EXPAND (directoryScopeId).
- Permission: RoleManagement.Read.Directory.
- Condition: directoryScopeId ne `/`.
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-2(7).
- Fix: confirm each scope; pair with a restricted-management unit for admin accounts.
- Confidence: verified.

### AZ-OWNER-HOLDER-STALE-OR-GUEST  (belongs in azure.yaml; listed here because the row sits in the Entra catalogue)
- Catches: an Azure RBAC Owner or User Access Administrator assignment held by a guest, a
  disabled or inactive user, or a principal that no longer exists.
- Severity: high.
- Source: azure.yaml; http; `/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`
  (for_each subscriptions) filtered to roleDefinitionId ending in the Owner
  (8e3af657-a8ff-443c-a75c-2fe8c4bcb635) and User Access Administrator
  (18d7d88d-d35e-4fb5-a5c3-7773c20a72d9) built-in ids; then a `store` join with B5 entra_users on
  principalId (user_type, enabled, cloud_signin). Key assignment id.
- Permission: Azure Reader on each subscription; existing Entra users query.
- Condition: principalType eq User and (user absent in the Entra rows, or user_type eq Guest, or
  enabled eq 0, or cloud_signin older than 90 days).
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-2(3), CIS-Controls-v8:5.4.
- Fix: remove the assignment; use PIM for Azure resources.
- Confidence: likely - https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription

---

## Conditional Access, tenant settings and authentication

### ENTRA-CA-REQUIRED-LOCATION-UNUSED
- Catches: the tenant has a named location that is supposed to gate access (a secure-egress or
  compliant-network location), and no enabled policy references it. The location was created,
  the decision was never implemented.
- Severity: low.
- Source: entra.yaml; v1.0; `/identity/conditionalAccess/namedLocations` (select id, displayName,
  `@odata.type`) and shared query Q-CA (conditions.locations.includeLocations /
  excludeLocations). A `store` rule joins the two: locations whose displayName match threshold
  `entra.required-named-location-pattern` (empty = n/a) with no enabled policy naming their id.
- Permission: Policy.Read.All.
- Condition: count lt 1 enabled policies referencing a matching location.
- Refs: NIST-800-53:AC-17, NIST-800-53:SC-7.
- Fix: add the location to the policy that should require it, or record the decision not to and
  delete the location.
- Confidence: verified.

### ENTRA-CA-DANGLING-REFERENCE
- Catches: a Conditional Access policy whose include or exclude lists name a user, group or role
  that no longer exists. A deleted group in an include list silently shrinks the policy; in an
  exclude list it hides a past exception.
- Severity: medium.
- Source: entra.yaml; `store` rule: policy rows from Q-CA (conditions.users.includeUsers,
  excludeUsers, includeGroups, excludeGroups, includeRoles, excludeRoles as JSON arrays, expanded
  with json_each) anti-joined against the user rows (B5), the group rows (the /groups inventory
  query) and `/roleManagement/directory/roleDefinitions` ids. Key `{policy id}|{referenced id}`.
  The literal values All, None, GuestsOrExternalUsers are skipped.
- Permission: Policy.Read.All + Directory.Read.All.
- Condition: `each: any` on the anti-join; the group side is judged only when the group run is
  `ok` (a partial group list would make every group look deleted).
- Refs: NIST-800-53:AC-3, NIST-800-53:CM-6.
- Fix: remove the dangling id from the policy.
- Confidence: verified (ids are returned as plain arrays).

### ENTRA-NAMEDLOC-TRUSTED-REVIEW
- Catches: every named location marked trusted, as a review list (each is usually a policy
  exclusion), plus country-type locations used in exclude lists. ENTRA-NAMEDLOC-WIDE-TRUSTED-RANGE
  judges width; this one judges existence.
- Severity: info (medium when a country location is in an exclude list).
- Source: entra.yaml; v1.0; `/identity/conditionalAccess/namedLocations`; fields id, displayName,
  `@odata.type`, isTrusted, ipRanges, countriesAndRegions, includeUnknownCountriesAndRegions;
  key id; name displayName. Shares the query with the rule above.
- Permission: Policy.Read.All.
- Condition: isTrusted eq true; accepted locations become overrides.
- Refs: NIST-800-53:AC-3, NIST-800-53:SC-7.
- Fix: keep trusted locations to documented egress ranges; never trust a whole country.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/namedlocation?view=graph-rest-1.0

### ENTRA-ADMIN-CENTER-NOT-RESTRICTED
- Catches: non-administrators can open the Entra admin center. It leaks directory structure and
  settings to any signed-in user and is the first stop of reconnaissance tooling.
- Severity: low.
- Source: entra.yaml; beta; `/admin/entra/uxSetting`; field restrictNonAdminAccess; key id (single
  object). New query.
- Permission: Policy.Read.All (confirm on first run; the resource is new).
- Condition: restrictNonAdminAccess ne true.
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-3, CIS-M365:5.1.2.4.
- Fix: set "Restrict access to Microsoft Entra admin center" to Yes.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/uxsetting?view=graph-rest-beta

### ENTRA-USER-PER-USER-MFA-ENABLED
- Catches: a member account still under legacy per-user MFA (enabled or enforced). Per-user MFA
  bypasses Conditional Access logic, prompts on every sign-in, and blocks the move to
  authentication strengths; the benchmark asks for it to be off everywhere.
- Severity: low.
- Source: entra.yaml; beta; `for_each: Q-USERS (filter userType eq 'Member' and accountEnabled eq
  true), field: id` -> `/users/{id}/authentication/requirements`; field perUserMfaState; key
  `{parent.id}`. The fan-out is one call per member - bound it with `max` and run weekly.
- Permission: Policy.ReadWrite.AuthenticationMethod is the documented permission; test whether
  UserAuthenticationMethod.Read.All suffices for GET (guess).
- Condition: perUserMfaState in [enabled, enforced].
- Refs: NIST-800-53:IA-2(1), CIS-M365:5.1.2.1.
- Fix: set the per-user state to disabled once Conditional Access MFA is enforced.
- Confidence: verified resource - https://learn.microsoft.com/en-us/graph/api/authentication-get-requirements?view=graph-rest-beta

### ENTRA-PASSWORD-BANNED-LIST-OFF / ENTRA-PASSWORD-LOCKOUT-THRESHOLD-HIGH / ENTRA-PASSWORD-LOCKOUT-DURATION-SHORT  (three rules, one query)
- Catches: the tenant password-protection settings are weak: no custom banned-password list is
  enforced, the smart-lockout threshold is above N failed attempts, or the lockout duration is
  below N seconds. These are the only cloud-side brakes on password spraying.
- Severity: medium (banned list), low (lockout values).
- Source: entra.yaml; v1.0; `/groupSettings`; filter on templateId
  `5cf42378-d67d-4f36-ba46-e8b86229381d` (the Password Rule Settings template); rows: one object
  with `values[]` (name/value pairs: EnableBannedPasswordCheck, BannedPasswordList,
  LockoutThreshold, LockoutDurationInSeconds, BannedPasswordCheckOnPremisesMode). Key id. When the
  object is absent the Microsoft defaults apply (threshold 10, duration 60, no custom list).
- Permission: Directory.Read.All.
- Condition: banned list: object absent, or `values[]` with name EnableBannedPasswordCheck has
  value false, or BannedPasswordList empty (name/value pairs inside one array are an engine gap;
  the author may need a `values[name=X].value` path or a store rule over the JSON). Threshold:
  LockoutThreshold gt 10 (threshold `entra.lockout-max-attempts`). Duration:
  LockoutDurationInSeconds lt 60 (threshold `entra.lockout-min-seconds`).
- Refs: NIST-800-53:IA-5(1), NIST-800-53:AC-7, CIS-M365:5.2.3.2, CIS-M365:5.2.3.8,
  CIS-M365:5.2.3.9, MITRE-ATTACK:T1110.003.
- Fix: enforce a custom banned list of organisation-specific words; keep the lockout threshold at
  or below 10 and the duration at or above 60 seconds.
- Confidence: verified template id and value names -
  https://learn.microsoft.com/en-us/graph/api/resources/groupsetting?view=graph-rest-1.0 (template
  list: https://learn.microsoft.com/en-us/graph/api/groupsettingtemplate-list?view=graph-rest-1.0)

### ENTRA-SSPR-OFF
- Catches: self-service password reset is not enabled for users. Without it every forgotten
  password is a helpdesk call that ends in a password spoken over the phone.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-AUTHZ; field allowedToUseSSPR.
- Permission: Policy.Read.All.
- Condition: allowedToUseSSPR eq false. (The All/Selected scope is portal-only; see the next
  rule for its effect.)
- Refs: NIST-800-53:IA-5, CIS-M365:5.2.4.1.
- Fix: enable SSPR for all users with two registered methods.
- Confidence: verified field - https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0

### ENTRA-SSPR-MEMBER-NOT-REGISTERED
- Catches: an enabled member who is in SSPR scope but has not registered for it. Measures the
  effect of "require registration at sign-in" (a portal-only setting) and of registration
  campaigns.
- Severity: low.
- Source: entra.yaml; v1.0; `/reports/authenticationMethods/userRegistrationDetails` (the query
  ENTRA-MFA-MEMBER-NOT-CAPABLE already runs; add isSsprEnabled, isSsprRegistered, isSsprCapable);
  key id; name userPrincipalName.
- Permission: AuditLog.Read.All (UserAuthenticationMethod.Read.All). Needs P1.
- Condition: userType eq member and isSsprEnabled eq true and isSsprRegistered eq false.
- Refs: NIST-800-53:IA-5, CIS-M365:5.2.4.3.
- Fix: turn on registration enforcement at sign-in; run a registration campaign.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0

### ENTRA-ACCESS-REVIEW-SETTINGS-WEAK
- Catches: an access review definition that exists but cannot do its job: not recurring (or
  less often than monthly for guests), decisions not auto-applied, no-response decision left as
  "no change" for guest reviews, or no review scoped to each privileged role the tenant lists.
  ENTRA-ACCESS-REVIEWS-NONE sees that some review exists; this sees whether it bites.
- Severity: low.
- Source: entra.yaml; v1.0; `/identityGovernance/accessReviews/definitions`; select id,
  displayName, status, scope, settings (recurrence.pattern.type, recurrence.pattern.interval,
  autoApplyDecisionsEnabled, defaultDecision, defaultDecisionEnabled, instanceDurationInDays,
  mailNotificationsEnabled, justificationRequiredOnApproval); key id; name displayName.
- Permission: AccessReview.Read.All. Needs P2 / Governance.
- Condition: status ne Completed and (settings.autoApplyDecisionsEnabled eq false, or
  settings.recurrence.pattern.type empty, or settings.instanceDurationInDays gt 14); for
  guest-scoped reviews additionally settings.defaultDecision ne Deny. Per-role coverage (a review
  whose scope names each role in threshold `entra.reviewed-role-ids`) is a `count` rule with
  `where` on scope.query match the role id.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:AC-6(7), CIS-M365:5.3.2, CIS-M365:5.3.3.
- Fix: set the review to recur, auto-apply, deny on no response for guests, and scope one review
  per privileged role.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/accessreviewscheduledefinition?view=graph-rest-1.0

### ENTRA-IDLE-SESSION-TIMEOUT-NONE
- Catches: no activity-based timeout policy exists, so an unattended browser session in a
  Microsoft portal stays signed in indefinitely.
- Severity: low.
- Source: entra.yaml; v1.0; `/policies/activityBasedTimeoutPolicies`; select id, displayName,
  definition, isOrganizationDefault; key id. New query.
- Permission: Policy.Read.All.
- Condition: count none (no policy), or count lt 1 where isOrganizationDefault eq true.
- Refs: NIST-800-53:AC-11, NIST-800-53:AC-12.
- Fix: create an activity-based timeout policy (or the Microsoft 365 idle session timeout) for
  the admin portals.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/activitybasedtimeoutpolicy?view=graph-rest-1.0

### ENTRA-DOMAIN-FEDERATION-MFA-TRUSTED
- Catches: a federated domain whose configuration accepts MFA claims from the federation server
  (or lets it decide), so a compromised or misconfigured IdP satisfies every MFA policy; also a
  domain whose federation uses a passive sign-in endpoint over plain HTTP. ENTRA-DOMAIN-FEDERATED
  lists the domains; this reads each one's settings.
- Severity: high.
- Source: entra.yaml; v1.0; `for_each: Q-DOMAINS (filter authenticationType eq Federated), field:
  id` -> `/domains/{id}/federationConfiguration`; fields issuerUri, passiveSignInUri,
  federatedIdpMfaBehavior, signingCertificate, nextSigningCertificate, signingCertificateUpdateStatus,
  preferredAuthenticationProtocol; key `{parent.id}`. Certificate expiry is not exposed as a date
  (the certificate is base64; parsing it is an engine gap).
- Permission: Domain.Read.All.
- Condition: federatedIdpMfaBehavior ne rejectMfaByFederatedIdp, or passiveSignInUri match
  `^http://`.
- Refs: NIST-800-53:IA-8, NIST-800-53:IA-2(1), MITRE-ATTACK:T1606.002.
- Fix: set federatedIdpMfaBehavior to rejectMfaByFederatedIdp and enforce MFA in Entra; plan the
  move to managed authentication.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/internaldomainfederation?view=graph-rest-1.0

### ENTRA-TENANT-PRIVACY-PROFILE-UNSET
- Catches: the tenant has no privacy statement URL or privacy contact. Guests and consenting
  users are shown them; an empty profile also fails the data-protection paperwork.
- Severity: low.
- Source: entra.yaml; v1.0; `/organization`; select id, privacyProfile (contactEmail,
  statementUrl) - the organization query already exists for ENTRA-SYNC-STALE; add the field.
- Permission: Organization.Read.All.
- Condition: privacyProfile.statementUrl empty or privacyProfile.contactEmail empty.
- Refs: NIST-800-53:PT-5.
- Fix: set the statement URL and contact in the tenant properties.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/privacyprofile?view=graph-rest-1.0

### ENTRA-XTAP-B2B-COLLABORATION-OPEN
- Catches: the default cross-tenant settings allow B2B collaboration inbound and outbound with
  every organisation for all users and applications. Microsoft's default is open, so this is a
  policy decision the tenant should make on purpose; the rule is low and accepted by override.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-XTAP; fields
  b2bCollaborationInbound.usersAndGroups.accessType, b2bCollaborationInbound.applications.accessType,
  b2bCollaborationOutbound.usersAndGroups.accessType, b2bCollaborationOutbound.applications.accessType.
- Permission: Policy.Read.All.
- Condition: all four accessType values eq allowed with targets containing AllUsers /
  AllApplications.
- Refs: NIST-800-53:AC-20, NIST-800-53:AC-21.
- Fix: decide; restrict in the default and open per partner where needed.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/crosstenantaccesspolicyconfigurationdefault?view=graph-rest-1.0

### ENTRA-XTAP-PARTNER-PRESENT
- Catches: every partner-specific cross-tenant configuration, as a review list - each was added
  for one project and rarely removed.
- Severity: info.
- Source: entra.yaml; v1.0; `/policies/crossTenantAccessPolicy/partners`; select tenantId,
  isServiceProvider, inboundTrust, b2bCollaborationInbound, b2bDirectConnectInbound,
  automaticUserConsentSettings; key tenantId. New query.
- Permission: Policy.Read.All.
- Condition: `each: any`; severity medium when inboundTrust.isMfaAccepted eq true or
  b2bDirectConnectInbound allows all.
- Refs: NIST-800-53:AC-20.
- Fix: remove stale partners; accept the rest by override with the owner recorded.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/crosstenantaccesspolicyconfigurationpartner?view=graph-rest-1.0

### M365-SECURE-SCORE-ACTION-OPEN
- Catches: a Secure Score improvement action with points still open that is neither implemented
  nor marked as accepted risk or third-party-covered. The daily list of Microsoft's own
  recommendations, ranked by points.
- Severity: by maxScore - ge 10: medium, else low.
- Source: m365.yaml; v1.0; `/security/secureScores?$top=1` (controlScores[]: controlName, score,
  scoreInPercentage, implementationStatus) joined by the author with
  `/security/secureScoreControlProfiles` (id, title, maxScore, controlCategory, actionType,
  controlStateUpdates[].state, implementationCost, userImpact); key controlName. Nested arrays
  with parent context are an engine gap: run the profiles query as the row source and use the
  score object for evidence, or use a `store` join of both row sets.
- Permission: SecurityEvents.Read.All.
- Condition: controlStateUpdates newest state notin [ThirdParty, Ignored, Alternative,
  Completed] and scoreInPercentage lt 100.
- Refs: NIST-800-53:CA-7, NIST-800-53:RA-5.
- Fix: work the list from the most points down; mark accepted risks in the portal.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/securescorecontrolprofile?view=graph-rest-1.0

---

## Users: attributes, hygiene, sync

### ENTRA-USER-NAME-PATTERN-SUSPECT
- Catches: an enabled account whose display name or UPN marks it as a test, temporary, demo or
  old account. They are created for a day and live for years with a shared password.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-USERS (add displayName to the select).
- Permission: User.Read.All.
- Condition: accountEnabled true and (displayName or userPrincipalName) match threshold
  `entra.suspect-name-pattern` (default `(^|[^a-z])(test|temp|tmp|demo|old|copy|backup)([^a-z]|$)`).
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.1.
- Fix: delete or disable; convert the ones in use to named accounts.
- Confidence: verified.

### ENTRA-USER-CLOUD-ONLY-MEMBER
- Catches: in a tenant that synchronises from on-premises AD, a member account that is cloud-only.
  It follows no joiner/leaver process in AD; each one must be a known service or admin identity.
- Severity: low (review list; accepted ones become overrides).
- Source: entra.yaml; v1.0; shared query Q-USERS; guard on `/organization` onPremisesSyncEnabled
  (the rule is n/a in a cloud-only tenant - a `store` rule can read both row sets; a plain graph
  rule needs the tenant to enable it).
- Permission: User.Read.All.
- Condition: userType eq Member and accountEnabled true and onPremisesSyncEnabled ne true and
  userPrincipalName notcontains `#EXT#`.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.1.
- Fix: document each as admin or service identity; create the rest in AD.
- Confidence: verified.

### ENTRA-USER-SYNC-LAGGING
- Catches: a synchronised user whose last sync time is far older than the tenant's last sync -
  it was moved out of the sync scope or deleted in AD and left behind, so it no longer follows
  AD, including disablement. ENTRA-SYNC-STALE sees the tenant; this sees the object.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-USERS with onPremisesLastSyncDateTime added.
- Permission: User.Read.All.
- Condition: onPremisesSyncEnabled eq true and onPremisesLastSyncDateTime age-gt 7 (threshold
  `entra.user-sync-lag-days`). (The AD side of the same case is XS-USER-SYNCED-AD-GONE.)
- Refs: NIST-800-53:AC-2, NIST-800-53:CM-8.
- Fix: move the object back into scope or delete the cloud object deliberately.
- Confidence: verified field - https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0

### ENTRA-USER-SYNC-UNEXPECTED-DOMAIN
- Catches: a synchronised object whose on-premises domain is not one of the domains the tenant
  expects - an old sync rule, a second sync server, or a forest nobody documented.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-USERS with onPremisesDomainName added.
- Permission: User.Read.All.
- Condition: onPremisesSyncEnabled eq true and onPremisesDomainName notin threshold
  `entra.expected-onprem-domains` (empty = n/a).
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-2.
- Fix: find the sync source; remove it or document it.
- Confidence: verified field.

### ENTRA-USER-DELETED-RECENT
- Catches: users deleted in the last N days, while they are still restorable. A daily look
  catches a mistaken deletion and an app or group that lost its last owner.
- Severity: info.
- Source: entra.yaml; v1.0; `/directory/deletedItems/microsoft.graph.user`; select id,
  userPrincipalName, displayName, deletedDateTime; key id; name userPrincipalName. New query.
- Permission: User.Read.All (Directory.Read.All).
- Condition: deletedDateTime age-lt 7 (threshold `entra.deleted-review-days`).
- Refs: NIST-800-53:CP-9, NIST-800-53:AC-2.
- Fix: restore by mistake-deleted accounts; confirm the rest.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0

### ENTRA-USER-ATTR-MISSING  (rule family: one rule per attribute)
- Catches: an enabled member missing a directory attribute that downstream systems key on:
  department, job title, manager, employee id, employee type, company name, office location, given
  name, surname, mobile phone; usage location and mail for licensed members; the immutable id for
  synchronised ones. Empty attributes break dynamic groups, licensing, approvals and HR joins.
- Severity: low (medium for usageLocation on licensed users and for the immutable id).
- Source: entra.yaml; v1.0; shared query Q-USERS extended with department, jobTitle, givenName,
  surname, displayName, mail, mobilePhone, businessPhones, officeLocation, usageLocation,
  companyName, employeeId, employeeType, onPremisesImmutableId, onPremisesSamAccountName,
  onPremisesUserPrincipalName, onPremisesDomainName, onPremisesLastSyncDateTime, and expand
  `manager($select=id,accountEnabled)`. One fetch feeds every attribute rule.
- Permission: User.Read.All.
- Condition: userType eq Member and accountEnabled true and <attribute> empty; mail and
  usageLocation only when assignedLicenses notempty; onPremisesImmutableId only when
  onPremisesSyncEnabled eq true; manager: `manager.id` absent. Tenants that do not fill an
  attribute disable that rule by override.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-2, CIS-Controls-v8:5.1.
- Fix: fill at the source (HR feed or AD for synchronised accounts), never by hand in the cloud.
- Confidence: verified fields; nested `$select` on the manager expand likely -
  https://learn.microsoft.com/en-us/graph/api/user-list-manager?view=graph-rest-1.0

### ENTRA-USER-ATTR-DUPLICATE  (rule family, store)
- Catches: two or more enabled members sharing an attribute that should be unique: employee id,
  display name, mobile phone, on-premises account name, mail. Duplicates break HR joins, sign-in
  name resolution and MFA phone ownership.
- Severity: low (medium for employeeId and onPremisesSamAccountName).
- Source: entra.yaml; `store` rule over B5 entra_users extended with the attributes above:
  `SELECT value, COUNT(*) AS holders, GROUP_CONCAT(upn) ... WHERE enabled = 1 AND user_type = 'Member'
  AND value IS NOT NULL GROUP BY LOWER(TRIM(value)) HAVING COUNT(*) > 1`; key = the value.
- Permission: none beyond Q-USERS.
- Condition: `each: any`.
- Refs: NIST-800-53:IA-4, NIST-800-53:CM-8.
- Fix: correct the wrong account at the source.
- Confidence: verified.

### ENTRA-USER-ATTR-VALUE-VARIANTS  (rule family, store)
- Catches: a categorical attribute (department, company name, job title, office location,
  employee type, usage location) that has two spellings differing only by case, accents or
  whitespace. Dynamic group rules and reports match one spelling and miss the other. True synonyms
  still need a person.
- Severity: low.
- Source: entra.yaml; `store` rule over the same rows: `SELECT LOWER(TRIM(value)) AS norm,
  COUNT(DISTINCT value) AS spellings, GROUP_CONCAT(DISTINCT value) ... GROUP BY norm HAVING
  COUNT(DISTINCT value) > 1`; key norm.
- Permission: none beyond Q-USERS.
- Condition: `each: any`.
- Refs: NIST-800-53:CM-8.
- Fix: normalise at the source; then fix the dynamic rules that keyed on the variant.
- Confidence: verified.

### ENTRA-USER-ATTR-FORMAT  (rule family: one rule per attribute and pattern)
- Catches: attribute values in a bad format: leading, trailing or doubled spaces in display
  names, departments, job titles; digits in given names or surnames; a UPN with characters outside
  letters, digits, dot, dash and underscore; a mail address with upper case or spaces; a mobile
  number not in E.164; a business phone with characters other than digits, spaces, dashes and a
  leading plus; a display name mixing two scripts; a member UPN on the tenant's onmicrosoft.com
  suffix (see ENTRA-USER-UPN-ONMICROSOFT).
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-USERS (fields as in ENTRA-USER-ATTR-MISSING).
- Permission: User.Read.All.
- Condition (per rule, `match` on the field): stray spaces `^\s|\s$|\s{2,}`; digits in names
  `\d`; UPN `[^a-z0-9._@-]` on the part before `@`; mail `[A-Z\s]`; mobile not `^\+[1-9]\d{6,14}$`;
  business phone `[^+0-9\s-]`; mixed script: a threshold pattern pairing two Unicode blocks
  (default `(?=.*\p{IsHebrew})(?=.*[A-Za-z])` - .NET regex supports `\p{IsHebrew}`).
- Refs: NIST-800-53:CM-8, NIST-800-53:IA-4.
- Fix: correct at the source.
- Confidence: verified (regex ops exist; `businessPhones[]` is an array leaf).

### ENTRA-USER-UPN-ONMICROSOFT
- Catches: an enabled member whose UPN suffix is the tenant's initial onmicrosoft.com domain. The
  person signs in under a name nobody uses, the mail and UPN differ, and SSO to apps that key on
  UPN breaks.
- Severity: low (medium for synchronised users - the on-premises suffix is not a verified domain).
- Source: entra.yaml; v1.0; shared query Q-USERS.
- Permission: User.Read.All.
- Condition: userType eq Member and accountEnabled true and userPrincipalName match
  `@[^@]+\.onmicrosoft\.com$`.
- Refs: NIST-800-53:IA-4, NIST-800-53:IA-2.
- Fix: verify the proper domain, correct the UPN (in AD for synchronised users).
- Confidence: verified.

### ENTRA-USER-MAIL-UPN-MISMATCH / ENTRA-USER-UPN-ONPREM-MISMATCH  (two store rules)
- Catches: a member whose primary mail differs from the UPN; a synchronised user whose cloud UPN
  differs from the on-premises UPN (the suffix was not verified, or the cloud value was edited).
  Both cause double identities in SaaS apps that match on either field.
- Severity: low (medium for the on-premises mismatch).
- Source: entra.yaml; `store` rules over B5 entra_users extended with mail and
  onPremisesUserPrincipalName: `WHERE LOWER(mail) <> LOWER(upn)` and
  `WHERE synced = 1 AND LOWER(onprem_upn) <> LOWER(upn)`; key id. (Two-field comparison is an
  engine gap for graph rules; the store does it.)
- Permission: none beyond Q-USERS.
- Condition: `each: any`.
- Refs: NIST-800-53:IA-4.
- Fix: align mail and UPN at the source; verify the domain.
- Confidence: verified.

### ENTRA-USER-MANAGER-DISABLED / ENTRA-USER-MANAGER-LOOP
- Catches: an enabled member whose manager is a disabled account (approvals route to nobody);
  and a manager chain that loops back on itself within three hops.
- Severity: low.
- Source: entra.yaml; disabled manager: v1.0 shared query Q-USERS with expand
  `manager($select=id,accountEnabled)`, condition `manager.accountEnabled` eq false. Loop: `store`
  rule self-joining the user rows on manager id up to three levels: `u.manager_id = u.id OR
  m1.manager_id = u.id OR m2.manager_id = u.id`; key id.
- Permission: User.Read.All.
- Condition: as above.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-2.
- Fix: set the right manager at the source.
- Confidence: likely (nested select on the manager expand) - https://learn.microsoft.com/en-us/graph/api/user-list-manager?view=graph-rest-1.0

---

## Applications

### ENTRA-APPPERM-TIER0-UNUSED-APP
- Catches: an application that holds a tenant-takeover or tenant-wide-data Graph permission and
  has not signed in for N days. A powerful grant on a dead app is pure attack surface.
- Severity: high.
- Source: entra.yaml; `store` rule joining the appRoleAssignedTo rows of ENTRA-APPPERM-TIER0 /
  ENTRA-APPPERM-DATA (principalId) with the rows of the beta
  `/reports/servicePrincipalSignInActivities` query that ENTRA-SP-SIGNIN-STALE proposes
  (appId, lastSignInActivity.lastSignInDateTime), through the Q-SPS rows (id -> appId). Key
  principalId.
- Permission: Application.Read.All + AuditLog.Read.All.
- Condition: last sign-in absent or older than 90 days (threshold `entra.app-unused-days`).
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-2(3), MITRE-ATTACK:T1098.001.
- Fix: remove the grant; disable the service principal; delete after the owner confirms.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipalsigninactivity?view=graph-rest-beta

### ENTRA-APP-USES-CLIENT-SECRET
- Catches: an app registration that authenticates with a client secret at all. Secrets are
  copied into config files and pipelines; certificates and federated credentials are not. A
  hygiene list, lower in priority than the long-lived and many-secrets rules.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-APPS (passwordCredentials).
- Permission: Application.Read.All.
- Condition: passwordCredentials notempty.
- Refs: NIST-800-53:IA-5, CIS-Controls-v8:4.1.
- Fix: replace with a certificate, a managed identity or a federated credential.
- Confidence: verified.

### ENTRA-APP-REQUESTED-NOT-GRANTED
- Catches: an app registration whose manifest requests an application permission that was never
  granted to its service principal. The unused request invites a later one-click admin consent.
- Severity: low.
- Source: entra.yaml; `store` rule: Q-APPS rows with requiredResourceAccess (json_each over
  resourceAccess with type eq Role) anti-joined against the appRoleAssignments of the matching
  service principal (`for_each: Q-SPS -> /servicePrincipals/{id}/appRoleAssignments`, select
  appRoleId, resourceId; or the appRoleAssignedTo rows already fetched per resource). Key
  `{appId}|{permission id}`.
- Permission: Application.Read.All.
- Condition: `each: any` on the anti-join.
- Refs: NIST-800-53:CM-7, NIST-800-53:AC-6.
- Fix: trim the manifest to the permissions in use.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0

---

## Groups

### ENTRA-GROUP-NO-OWNER / ENTRA-GROUP-OWNER-DISABLED  (two rules, one query)
- Catches: a cloud group with no owner, or whose owners are all disabled; and a Microsoft 365
  group with fewer than two enabled owners. An ownerless group cannot be reviewed, and ownership of
  a group that grants access is itself access. ENTRA-GROUP-M365-NO-OWNER covers Microsoft 365
  groups only.
- Severity: low (medium when the group is assigned to an application or used in Conditional
  Access - join, later).
- Source: entra.yaml; v1.0; `/groups`; filter `onPremisesSyncEnabled ne true` (advanced query,
  `consistency: eventual`, `$count=true`); select id, displayName, groupTypes, securityEnabled,
  mailEnabled, description, membershipRule, createdDateTime; expand
  `owners($select=id,accountEnabled)`; top 999; key id; name displayName. This is the group
  inventory query reused by the group rules below.
- Permission: Group.Read.All + User.Read.All.
- Condition: owners empty; or `owners[].accountEnabled` all false (array-all is an engine gap:
  express as "owners notempty and no element with accountEnabled true" - needs an `none` or
  `all-elements` form; until then a store rule); Microsoft 365 groups: owners size-lt 2.
- Refs: NIST-800-53:AC-2, NIST-800-53:AC-6, CIS-Controls-v8:5.1.
- Fix: assign two owners; remove the group if nobody claims it.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/group-list-owners?view=graph-rest-1.0

### ENTRA-GROUP-NAME-DUPLICATE / ENTRA-GROUP-NO-DESCRIPTION / ENTRA-GROUP-MAIL-ENABLED-SECURITY
- Catches: two groups with the same display name (the wrong one gets picked in every picker); a
  cloud group with no description (nobody knows what it grants); a mail-enabled security group
  (two purposes in one object - review list).
- Severity: low / low / info.
- Source: entra.yaml; the group inventory query above; duplicate names as a `store` GROUP BY on
  LOWER(TRIM(displayName)) HAVING COUNT(*) > 1.
- Permission: Group.Read.All.
- Condition: description empty; securityEnabled eq true and mailEnabled eq true; duplicate: `each:
  any` on the store result.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-2.
- Fix: rename, describe, or split the group.
- Confidence: verified.

### ENTRA-GROUP-NAMING-POLICY-NONE
- Catches: no naming policy (prefix/suffix or blocked words) applies to user-created Microsoft
  365 groups, so user groups are indistinguishable from official ones and can take names like the
  organisation's departments.
- Severity: low.
- Source: entra.yaml; v1.0; `/groupSettings`; the Group.Unified template
  (62375ab9-6b52-47ed-826b-58e47e0e304b); values PrefixSuffixNamingRequirement,
  CustomBlockedWordsList, EnableGroupCreation, GroupCreationAllowedGroupId; key id. Same query as
  the password-protection rules (filter by templateId in the condition).
- Permission: Directory.Read.All.
- Condition: object absent, or both PrefixSuffixNamingRequirement and CustomBlockedWordsList
  empty (name/value array - same engine note as the password rules).
- Refs: NIST-800-53:CM-6.
- Fix: set a prefix or suffix and a blocked-words list.
- Confidence: verified template - https://learn.microsoft.com/en-us/graph/group-setting-templates?view=graph-rest-1.0

### ENTRA-GROUP-CA-REFERENCED-WEAK
- Catches: a group used in a Conditional Access include or exclude list that has owners who are
  not administrators, or that is dynamic on an attribute users or guests can influence. Whoever
  owns an exclusion group can add themselves and skip MFA.
- Severity: high.
- Source: entra.yaml; `store` rule: group ids from Q-CA (includeGroups/excludeGroups via
  json_each) joined to the group inventory rows (owners, membershipRule, isAssignableToRole); key
  `{policy id}|{group id}`.
- Permission: Policy.Read.All + Group.Read.All.
- Condition: owners notempty and isAssignableToRole ne true (role-assignable groups are owned
  under PIM control), or membershipRule match the external-attribute pattern of
  ENTRA-GROUP-DYNAMIC-GUEST-CONTROLLED-ATTRIBUTE.
- Refs: NIST-800-53:AC-3, NIST-800-53:AC-6(1), MITRE-ATTACK:T1556.
- Fix: make the group role-assignable with no owners, or key the dynamic rule on an admin-set
  attribute.
- Confidence: verified.

### ENTRA-GROUP-EMPTY / ENTRA-GROUP-SINGLE-MEMBER / ENTRA-GROUP-NONUSER-MEMBER / ENTRA-GROUP-DYNAMIC-EMPTY
- Catches: a cloud group with no members (dead configuration, or a dynamic rule that matches
  nobody because the attribute value it tests no longer exists); a group with one member (a
  permission in disguise); a group containing devices, service principals or contacts by mistake.
- Severity: low (medium for the empty dynamic group - joiners are silently not added).
- Source: entra.yaml; v1.0; the group inventory query with expand
  `members($select=id)` (the expand returns at most 20 members per group with `@odata.type`,
  enough for empty / single / type checks); or `for_each` over groups ->
  `/groups/{id}/members/$count` with `consistency: eventual` when the expand is refused on a list.
- Permission: Group.Read.All.
- Condition: members size-eq 0 (dynamic: groupTypes contains DynamicMembership and members
  size-eq 0); members size-eq 1; `members[].@odata.type` in [#microsoft.graph.device,
  #microsoft.graph.servicePrincipal, #microsoft.graph.orgContact] for a security group not meant
  for devices (threshold pattern on displayName for device groups).
- Refs: NIST-800-53:AC-2, NIST-800-53:CM-6.
- Fix: delete empty groups; fix the dynamic rule; move permissions off single-member groups.
- Confidence: likely (list-level expand of members with select) -
  https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0

### ENTRA-GROUP-DISABLED-MEMBER / ENTRA-GROUP-GUEST-MEMBER  (store)
- Catches: a disabled account that is still a member of groups (leaver cleanup never ran); a
  guest inside a security group that was not meant for guests.
- Severity: low (medium when the group grants an application or a role).
- Source: entra.yaml; v1.0; a user membership query: `/users` select id, userPrincipalName,
  accountEnabled, userType; expand `memberOf($select=id,displayName,securityEnabled)`; top 999
  (the expand returns up to 20 groups per user; users in more need `for_each` ->
  `/users/{id}/memberOf`). Then `store` rules keyed `{user id}|{group id}`.
- Permission: User.Read.All + GroupMember.Read.All.
- Condition: accountEnabled eq 0; userType eq Guest and group securityEnabled eq 1 and group not
  in threshold `entra.guest-allowed-group-ids`.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:AC-2(9), CIS-Controls-v8:5.3.
- Fix: remove the membership; add group cleanup to the leaver process.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0

### ENTRA-GROUP-NESTING-DEEP  (store)
- Catches: group-in-group nesting deeper than three levels, or a nesting loop. Effective access
  becomes unreadable and some workloads stop expanding.
- Severity: low.
- Source: entra.yaml; the group inventory query with expand `memberOf($select=id)` (group ->
  parent groups), then a `store` recursive CTE walking parents up to four levels; key group id.
- Permission: Group.Read.All.
- Condition: depth gt 3 or the group reappears in its own chain.
- Refs: NIST-800-53:AC-2, NIST-800-53:AC-6.
- Fix: flatten.
- Confidence: verified (SQLite recursive CTE; expand likely).

---

## Devices

### ENTRA-DEVICE-NAME-DUPLICATE / ENTRA-DEVICE-DISABLED-STALE / ENTRA-DEVICE-REGISTERED-PERSONAL
- Catches: two enabled device objects with the same name (re-joins that were never cleaned up -
  policies and compliance land on the wrong object); a disabled device object older than N days
  that was never deleted; a personally registered (workplace-joined) device, as a review list of
  what gets tokens without management.
- Severity: low / low / info.
- Source: entra.yaml; v1.0; the `/devices` query of ENTRA-DEVICE-STALE (displayName, trustType,
  accountEnabled, approximateLastSignInDateTime, operatingSystem, registrationDateTime,
  isManaged, isCompliant). Duplicates as a `store` GROUP BY on UPPER(displayName) over enabled
  devices.
- Permission: Device.Read.All.
- Condition: duplicate: `each: any`; disabled stale: accountEnabled eq false and
  approximateLastSignInDateTime age-gt 30 (threshold `entra.disabled-device-keep-days`); personal:
  trustType eq Workplace and accountEnabled true.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-19.
- Fix: delete the stale objects; require compliance or app protection for registered devices.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0

---

## Licensing

### M365-SKU-UNUSED-UNITS-MANY / M365-SKU-OVERASSIGNED  (store)
- Catches: a paid SKU with a large share of purchased units unassigned (money on the table at
  renewal); a SKU whose consumed units exceed its enabled units (assignments will start failing).
- Severity: low / medium.
- Source: m365.yaml; `store` rule over the `/subscribedSkus` rows (skuPartNumber, consumedUnits,
  prepaidUnits.enabled, capabilityStatus): `CAST(json_extract(attrs,'$.prepaidUnits.enabled') AS
  INTEGER) - consumedUnits` and the ratio; key skuId.
- Permission: Organization.Read.All.
- Condition: unused share gt 20 % and unused units ge 5 (thresholds `m365.sku-unused-pct`,
  `m365.sku-unused-min`), free SKUs excluded; consumedUnits gt prepaidUnits.enabled.
- Refs: NIST-800-53:PM-3, NIST-800-53:SA-4.
- Fix: reclaim from inactive and disabled accounts first (existing rules), then reduce at renewal;
  for over-assignment buy units or remove assignments.
- Confidence: verified.

### M365-SKU-PLAN-DISABLED-WIDELY  (store)
- Catches: a service plan that is disabled for most holders of a SKU - paid for and switched
  off, either a deliberate block that should be documented or a sign that a cheaper SKU fits.
- Severity: low.
- Source: m365.yaml; `store` rule over B5 entra_users licences: json_each over
  `assignedLicenses[]` and `disabledPlans[]`, grouped by skuId and plan id, divided by holders of
  the SKU; key `{skuId}|{planId}`.
- Permission: User.Read.All.
- Condition: disabled share ge 80 % (threshold `m365.plan-disabled-pct`) and holders ge 10.
- Refs: NIST-800-53:CM-7, NIST-800-53:PM-3.
- Fix: document the block, or move the holders to a SKU without the plan.
- Confidence: verified.

---


---

## Entra Connect (directory synchronisation)


Three target files:

- `rules\entra.yaml` (integration graph) for the `ENTRA-SYNC-*` and `ENTRA-PTA-*` rules - most read
  `/directory/onPremisesSynchronization`, which needs the application permission
  **OnPremDirectorySynchronization.Read.All** (Global Reader is refused on this resource).
- a new `rules\entra-connect.yaml` (integration cim; protocols cim, registry, eventlog, file) for the
  `ECSYNC-*` rules. Targets: the sync servers. Active Directory cannot tell which servers run the sync
  engine, so the file takes `targets: { entity: computer, field: dNSHostName, where: { field:
  dNSHostName, op: in, value: [], threshold: entra-connect.servers } }` - an empty list = the system is
  "not configured", never a pass. Alternative without a threshold: run one cheap cim query
  (`SELECT Name FROM Win32_Service WHERE Name = 'ADSync'`) over all windows-server targets and
  derive the list from `row_seen` (engine feature: target lists from a store query).
- `rules\hybrid-identity.yaml` (store) and `rules\active-directory.yaml` (ldap) for the `HYB-*` rules;
  two of them are eventlog rules over domain-controller targets and belong in a DC eventlog file.

New thresholds (all tenant-free defaults): `entra-connect.servers` (empty), `entra-connect.sync-account-pattern`
(default `^(Sync_|MSOL_|AAD_)`), `entra-connect.admin-workstation-pattern` (empty = n/a),
`entra-connect.approved-admin-pattern` (empty = n/a), `entra-connect.approved-service-pattern`,
`entra-connect.approved-product-pattern`, `entra-connect.supported-version-pattern`,
`entra-connect.localdb-max-bytes` (8 GB), `entra-connect.config-export-max-age-days` (90),
`entra-connect.expected-sync-accounts` (2), `entra-connect.sync-account-max-idle-hours` (1),
`entra-connect.sensitive-extension-pattern`, `entra-connect.tier0-ou-pattern`, `entra.tenant-id`.

---

## Graph-side rules (`rules\entra.yaml`)

### ENTRA-SYNC-RETIRED-FEATURE-ON
- Catches: a directory-synchronisation feature that Microsoft has retired (group writeback in its
  preview form) still switched on. A retired feature stops working without a visible error and can
  block the next engine upgrade.
- Severity: medium.
- Source: entra.yaml; v1.0; `/directory/onPremisesSynchronization`; fields features.groupWriteBackEnabled,
  features.unifiedGroupWritebackEnabled; key id. Shared query with ENTRA-SYNC-PASSWORD-HASH-OFF (no select).
- Permission: OnPremDirectorySynchronization.Read.All.
- Condition: features.groupWriteBackEnabled eq true or features.unifiedGroupWritebackEnabled eq true.
- Refs: NIST-800-53:CM-2, NIST-800-53:SA-22.
- Fix: move group provisioning to the cloud-sync group writeback and turn the legacy flag off in the wizard.
- Confidence: verified field names - https://learn.microsoft.com/en-us/graph/api/resources/onpremisesdirectorysynchronizationfeature?view=graph-rest-1.0

### ENTRA-SYNC-WRITEBACK-ENABLED
- Catches: any cloud-to-on-premises writeback switched on (password, device, user, group). Each one
  lets the cloud change the directory; a writeback nobody uses is an unneeded path from tenant to tier 0.
  A review list: every enabled writeback is a finding until the owner accepts it with its purpose.
- Severity: low (password writeback medium when self-service reset is not in use - cannot be judged here; keep low).
- Source: same query; fields features.passwordWritebackEnabled, features.deviceWritebackEnabled,
  features.userWritebackEnabled, features.groupWriteBackEnabled.
- Permission: OnPremDirectorySynchronization.Read.All.
- Condition: any of the four flags eq true; evidence names the flag.
- Refs: NIST-800-53:AC-6, NIST-800-53:CM-7.
- Fix: disable the writeback in the wizard, or accept the finding with the feature it serves.
- Confidence: verified (same resource page).

### ENTRA-SYNC-SOFT-MATCH-OPEN
- Catches: soft matching (by UPN or proxy address) still allowed outside a migration window; an
  on-premises object with a matching address can claim an existing cloud-only account.
- Severity: medium.
- Source: same query; field features.blockSoftMatchEnabled (ENTRA-SYNC-HARD-MATCH-TAKEOVER-OPEN already
  shows it as evidence; this makes it a condition).
- Permission: OnPremDirectorySynchronization.Read.All.
- Condition: features.blockSoftMatchEnabled eq false.
- Refs: NIST-800-53:AC-2, NIST-800-53:IA-4, MITRE-ATTACK:T1098.
- Fix: enable blockSoftMatch after the last planned match; open it only for a dated migration.
- Confidence: verified.

### ENTRA-SYNC-ACCIDENTAL-DELETE-PREVENTION-WEAK
- Catches: accidental-deletion prevention disabled, or its threshold large enough that one filtering
  mistake deletes a large share of the cloud users (with their mailboxes and files) in one cycle.
- Severity: high (disabled) / medium (threshold above the cap).
- Source: same query; fields configuration.accidentalDeletionPrevention.synchronizationPreventionType,
  configuration.accidentalDeletionPrevention.alertThreshold.
- Permission: OnPremDirectorySynchronization.Read.All.
- Condition: synchronizationPreventionType eq disabled, or (eq enabledForCount and alertThreshold gt 500,
  threshold `entra.sync-delete-threshold-max`), or (eq enabledForPercentage and alertThreshold gt 5).
- Refs: NIST-800-53:CM-3, NIST-800-53:CP-9.
- Fix: enable prevention for a count of 500 or less (or 5 %); lift it for one export only, by a
  recorded decision.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/onpremisesaccidentaldeletionprevention?view=graph-rest-1.0

### ENTRA-SYNC-INTERVAL-LONG
- Catches: a synchronisation interval longer than the default 30 minutes - leaver disables and
  licence changes arrive late, and a customised interval is usually a forgotten troubleshooting step.
- Severity: low.
- Source: same query; fields configuration.synchronizationInterval, configuration.customerRequestedSynchronizationInterval (ISO 8601 durations).
- Permission: OnPremDirectorySynchronization.Read.All.
- Condition: synchronizationInterval ne `PT30M` (threshold `entra.sync-expected-interval`); duration
  comparison is an engine gap (same note as the provisioning-schedule proposal).
- Refs: NIST-800-53:AC-2.
- Fix: clear the customised interval on the sync server.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/onpremisesdirectorysynchronizationconfiguration?view=graph-rest-1.0

### ENTRA-SYNC-CLOUD-PASSWORD-POLICY-OFF
- Catches: with password hash sync, cloud passwords never expire and "must change at next logon" is
  not honoured unless two features are on; an expired or reset-flagged on-premises user keeps
  signing in to cloud services with the old password.
- Severity: low (review; the behaviour may be wanted).
- Source: same query; fields features.cloudPasswordPolicyForPasswordSyncedUsersEnabled,
  features.userForcePasswordChangeOnLogonEnabled.
- Permission: OnPremDirectorySynchronization.Read.All.
- Condition: either flag eq false (two rules or one with evidence per flag).
- Refs: NIST-800-53:IA-5(1).
- Fix: enable the features after reading the caveats on temporary passwords.
- Confidence: verified (feature resource page above).

### ENTRA-SYNC-ACCOUNT-SIGNIN-STALE
- Catches: the cloud identity the sync engine signs in with has no successful sign-in for more than
  N hours. The engine signs in every cycle, so a stale sign-in means no server is exporting (stopped,
  stuck in staging, or broken credentials) - a cloud-side proxy for "exactly one active server".
- Severity: high.
- Source: entra.yaml; v1.0; shared query Q-USERS (userPrincipalName, accountEnabled, signInActivity);
  the sync identities are rows whose userPrincipalName matches `entra-connect.sync-account-pattern`.
  Stronger key: members of the Directory Synchronization Accounts role (template
  d29b2b05-8046-44ba-8758-1e26182fcf32) through Q-ROLES-EXPAND.
- Permission: User.Read.All + AuditLog.Read.All (signInActivity).
- Condition: userPrincipalName match the pattern and accountEnabled true and
  signInActivity.lastSuccessfulSignInDateTime age-gt 0.042 (1 hour; threshold
  `entra-connect.sync-account-max-idle-hours` expressed in days). A tenant with a staging server has
  two identities; only the active one signs in - so judge with `count: { op: lt, value: 1, where:
  <signed in within the hour> }` over the matching rows (must-exist), not per row.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-2.
- Fix: check the service and scheduler on the active server; confirm staging mode is set on the right server.
- Confidence: likely (signInActivity granularity is per day for lastSignInDateTime but
  lastSuccessfulSignInDateTime is a timestamp) - https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0

### ENTRA-SYNC-ACCOUNT-MULTIPLE
- Catches: more sync identities than servers (one is created per install and never deleted), or a
  sync identity that is disabled or idle for weeks. Each stale one is a directory-write credential
  nobody watches.
- Severity: medium.
- Source: same rows as above.
- Permission: as above.
- Condition: two rules - count gt `entra-connect.expected-sync-accounts` (default 2) over rows matching
  the pattern; and per row: accountEnabled false or lastSuccessfulSignInDateTime age-gt 30.
- Refs: NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- Fix: delete the identities of servers that no longer exist (after confirming in the role members list).
- Confidence: verified (fields in use).

### ENTRA-SYNC-ACCOUNT-NO-LOCATION-POLICY
- Catches: the sync identity is excluded from MFA (it must be) but no enforced Conditional Access
  policy limits it to known locations; its password is then a from-anywhere path into directory writes.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-CA; fields state, conditions.users.includeRoles,
  conditions.users.excludeRoles, conditions.locations.excludeLocations, grantControls.builtInControls.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where state enabled and includeRoles contains
  d29b2b05-8046-44ba-8758-1e26182fcf32 and builtInControls contains block and
  conditions.locations.excludeLocations notempty. Companion per-row rule: an enforced MFA policy whose
  excludeRoles contains that template id (extends ENTRA-CA-MFA-EXCLUDES-ROLES with the reason).
- Refs: NIST-800-53:AC-17, NIST-800-53:AC-2(12), MITRE-ATTACK:T1078.004.
- Fix: a policy for the sync role: block all locations except the sync server's egress; or move to
  application-based authentication with a certificate.
- Confidence: verified field names (Q-CA in use); the role template id is a Microsoft constant (likely) -
  https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference

### ENTRA-SYNC-CLOUD-SYNC-OVERLAP
- Catches: cloud-sync (agent-based) provisioning jobs exist while the classic engine is also
  synchronising; two engines over the same objects fight and double-provision.
- Severity: medium (review; a scoped split is legitimate).
- Source: entra.yaml; v1.0; `for_each` over `/servicePrincipals?$filter=startswith(displayName,'<cloud sync app name>')`
  is tenant-naming; use the generic form: `/servicePrincipals` select id, displayName, tags ->
  `/servicePrincipals/{id}/synchronization/jobs` with templateId match `^AD2AAD`; parent flag from
  `/organization` onPremisesSyncEnabled (ENTRA-SYNC-STALE query). Agent inventory: beta
  `/onPremisesPublishingProfiles('provisioning')/agentGroups?$expand=agents`.
- Permission: Synchronization.Read.All; the agent-group read needs OnPremisesPublishingProfiles.ReadWrite.All
  (Graph exposes no read-only permission for that resource - note in the permissions table).
- Condition: count some over cloud-sync jobs when onPremisesSyncEnabled is true (needs a store join or
  a threshold `entra.classic-sync-expected` = true to gate it).
- Refs: NIST-800-53:CM-8, NIST-800-53:CM-6.
- Fix: keep one engine per object scope; document the split or remove the stray agent.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/synchronization-overview?view=graph-rest-1.0,
  https://learn.microsoft.com/en-us/graph/api/resources/onpremisesagentgroup?view=graph-rest-beta

(The synced-user UPN checks - cloud UPN on the service domain, and on-premises suffix differing from
the cloud suffix - are ENTRA-USER-UPN-ONMICROSOFT and ENTRA-USER-UPN-ONPREM-MISMATCH in the Entra
section; add onPremisesUserPrincipalName to the shared users query so the second one can be a plain
Graph rule once a two-field compare exists.)

### ENTRA-SYNC-DIRECTORY-EXTENSION-SENSITIVE
- Catches: directory-extension attributes synced to the cloud whose names suggest personal data
  (national identifier, salary, health) - every application with directory read then sees them.
- Severity: medium (info when the pattern threshold is empty - review list of all extensions).
- Source: entra.yaml; v1.0; `/applications` select id, displayName, filter
  `startswith(displayName,'Tenant Schema Extension')` -> for_each `/applications/{id}/extensionProperties`
  fields name, dataType, targetObjects; key `{parent.id}|{name}`. Gate: features.directoryExtensionsEnabled from the sync-configuration query.
- Permission: Application.Read.All.
- Condition: name match `entra-connect.sensitive-extension-pattern` (default `(?i)(ssn|national|identity|passport|salary|health|birth)`).
- Refs: NIST-800-53:PT-2, NIST-800-53:SC-28.
- Fix: remove the attribute from the extension list; involve the data-protection owner.
- Confidence: verified (extensionProperty resource) - https://learn.microsoft.com/en-us/graph/api/resources/extensionproperty?view=graph-rest-1.0;
  the schema-extension app's display name is a Microsoft default (likely).

### ENTRA-SYNC-AUDIT-SETTINGS-CHANGED-RECENT
- Catches: tenant-level sync settings changed in the last N days (features set, directory
  synchronisation flag toggled, company information changed) - the audit log is the only place these
  land, and it keeps 30 days.
- Severity: medium (review list; evidence shows who).
- Source: entra.yaml; v1.0; `/auditLogs/directoryAudits`; filter
  `activityDateTime ge {DAYS_AGO:7} and category eq 'DirectoryManagement' and result eq 'success'`;
  select id, activityDisplayName, activityDateTime, initiatedBy, targetResources; key id.
- Permission: AuditLog.Read.All.
- Condition: activityDisplayName match `^(Set DirSync feature|Set Company Information|Set directory feature on tenant|Set DirSyncEnabled flag)`
  (threshold `entra.audit-sync-activity-pattern`).
- Refs: NIST-800-53:AU-6, NIST-800-53:CM-3, MITRE-ATTACK:T1484.
- Fix: match each event to a change record; revert unexplained changes and review the actor.
- Confidence: likely (activity names from the audit activity reference) - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities

### ENTRA-PTA-AGENTS-FEW
- Catches: pass-through authentication in use with fewer than three active agents - every cloud
  sign-in depends on them reaching a domain controller.
- Severity: medium.
- Source: entra.yaml; beta; `/onPremisesPublishingProfiles('authentication')/agentGroups?$expand=agents`;
  fields agents[].machineName, agents[].status, agents[].externalIp (do not put the IP in evidence); key id.
- Permission: OnPremisesPublishingProfiles.ReadWrite.All (no read-only permission exists).
- Condition: per group, agents notempty and count of agents with status active lt 3 (same-element
  count is an engine gap; approximate with `agents size-lt 3`). A tenant without PTA returns no
  agents = no finding.
- Refs: NIST-800-53:CP-2, NIST-800-53:IA-2.
- Fix: install agents on two more hardened servers.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/onpremisesagent?view=graph-rest-beta

### ENTRA-PTA-AGENT-INACTIVE
- Catches: a registered agent that is not active - a dead server still listed, or an agent someone
  else installed.
- Severity: medium.
- Source: same query; key `{id}|{agents[].machineName}` is not expressible (nested array) - one
  finding per group with the inactive names in evidence.
- Condition: `agents[].status` ne active.
- Refs: NIST-800-53:CM-8, NIST-800-53:SI-4.
- Fix: remove unknown or dead agents from the group.
- Confidence: likely (same page).

### ENTRA-SYNC-NO-PREMIUM-ENTITLEMENT
- Catches: directory sync is on but no enabled subscription carries an Entra ID P1 service plan -
  Connect Health agents and several hybrid features silently need it, and a licence clean-up can
  remove the last SKU that carried it.
- Severity: low.
- Source: entra.yaml (or m365.yaml); v1.0; `/subscribedSkus`; fields skuPartNumber, capabilityStatus,
  servicePlans[].servicePlanName, servicePlans[].provisioningStatus; key id.
- Permission: Organization.Read.All.
- Condition: must-exist - count lt 1 where capabilityStatus eq Enabled and servicePlans[].servicePlanName
  match `^AAD_PREMIUM`. Gate on sync being enabled is a store join (or accept the rule as always-on).
- Refs: NIST-800-53:SA-4, NIST-800-53:PM-3.
- Fix: keep one SKU with the P1 plan in the licence plan before removing overlapping suites.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/subscribedsku?view=graph-rest-1.0

---

## Server-side rules (`rules\entra-connect.yaml`, integration cim; targets = the sync servers)

### ECSYNC-SERVICE-DOWN
- Catches: the sync engine service, or either Connect Health agent service, not running or not
  automatic on a sync server. The engine down = every change stops reaching the cloud; the agents down
  = nobody is told.
- Severity: critical (engine) / medium (agents).
- Source: entra-connect.yaml; cim root/cimv2; `SELECT Name, State, StartMode, StartName, ProcessId FROM Win32_Service WHERE Name = 'ADSync' OR Name LIKE 'AzureADConnectHealth%' OR Name = 'AADConnectProvisioningAgent' OR Name = 'AzureADConnectAuthenticationAgent' OR Name = 'Ec2VssSoftwareProvider'`;
  key `{host}|{Name}`. Second query for engine restarts: `SELECT Name, CreationDate FROM Win32_Process WHERE Name = 'miiserver.exe'`,
  condition CreationDate age-lt 1 (info: engine restarted in the last day).
- Permission: WinRM/CIM read on the server.
- Condition: Name eq ADSync and (State ne Running or StartMode ne Auto) -> critical; Name match
  `^AzureADConnectHealth` and State ne Running -> medium. A missing ADSync row on a listed target is
  `count: { op: lt, value: 1, where: { Name eq ADSync } }` (the host is not a sync server - fix the list).
- Refs: NIST-800-53:CP-2, NIST-800-53:SI-4.
- Fix: read the Application and System events first (ECSYNC-APPLOG-ERRORS, ECSYNC-SERVICE-CRASH-EVENTS), then start the service.
- Confidence: verified (Win32_Service fields; service names from the installation docs) -
  https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions

### ECSYNC-LOCALDB-SIZE-HIGH
- Catches: the sync database on the bundled LocalDB approaching its 10 GB hard limit; at the limit the
  engine stops with no cloud-side warning.
- Severity: high (critical at 9.5 GB).
- Source: entra-connect.yaml; registry `SYSTEM\CurrentControlSet\Services\ADSync\Parameters` values
  Server, SQLInstance, DBName (LocalDB when the instance name is the LocalDB default); cim
  `SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Name = '<program files>\\Microsoft Azure AD Sync\\Data\\ADSync.mdf'`
  (path as threshold `entra-connect.localdb-mdf-path`); key host.
- Permission: WinRM/CIM read.
- Condition: FileSize gt 8589934592 (threshold `entra-connect.localdb-max-bytes`); severity map at 10200547328.
  Growth per month needs run-to-run comparison (engine gap; record the size as evidence).
- Refs: NIST-800-53:CP-2, NIST-800-53:SC-5.
- Fix: follow the LocalDB 10-GB recovery guidance (run-history clean-up, shrink); move to full SQL Server if growth continues.
- Confidence: verified - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-recover-from-localdb-10gb-limit

### ECSYNC-VERSION-BELOW-MINIMUM
- Catches: an installed sync engine build outside the supported line (retired major version, or a build
  past its retirement date). Retired builds stop syncing after service-side changes.
- Severity: high (critical when the major version is retired).
- Source: entra-connect.yaml; registry `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` with
  `subkeys: true`, values DisplayName, DisplayVersion, InstallDate; key `{host}|{DisplayName}`.
- Permission: WinRM/registry read.
- Condition: DisplayName match `^Microsoft (Entra|Azure AD) Connect` and DisplayVersion notmatch
  `entra-connect.supported-version-pattern` (the release table becomes a regex the tenant updates,
  e.g. `^2\.(4|5)\.`). Version comparison is an engine gap.
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22.
- Fix: upgrade in place or swing through a staging server in a change window.
- Confidence: verified (uninstall registry layout); the product display name varies by release (likely) -
  https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history

### ECSYNC-BUNDLED-COMPONENT-OLD
- Catches: the bundled LocalDB and Visual C++ runtime, and the Connect Health agent, below their
  current builds - their security fixes come from Microsoft Update, not from the engine's auto-upgrade.
- Severity: low (agent medium).
- Source: same registry query; thresholds `entra-connect.localdb-version-pattern`,
  `entra-connect.vcredist-version-pattern`, `entra-connect.health-agent-version-pattern`.
- Condition: DisplayName match the product and DisplayVersion notmatch its pattern (three rules, one query).
- Refs: NIST-800-53:SI-2.
- Fix: apply through the update channel.
- Confidence: likely.

### ECSYNC-DOTNET-BELOW-MINIMUM
- Catches: .NET Framework below 4.8 (or Windows PowerShell below 5.1) on the sync server - blocks the
  next engine upgrade and the TLS 1.2 defaults.
- Severity: medium.
- Source: entra-connect.yaml; registry `SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full` value Release;
  registry `SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine` value PowerShellVersion; key host.
- Condition: Release lt 528040 (threshold `entra-connect.dotnet-min-release`); PowerShellVersion notmatch `^5\.1`.
- Refs: NIST-800-53:SI-2.
- Fix: install .NET Framework 4.8 or later in a window.
- Confidence: verified - https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed

### ECSYNC-APPLOG-ERRORS
- Catches: errors and warnings from the sync engine, password hash sync and the Health agent in the
  Application log over the last 7 days, grouped per provider and event id.
- Severity: high (errors) / medium (warnings).
- Source: entra-connect.yaml; eventlog `log: Application`, `providers: [ADSync, "Directory Synchronization", AzureADConnectHealthSyncMonitor, AzureADConnectHealthSyncInsights]`,
  `days: 7`, `max: 500`; key `{host}|{provider}|{id}`.
- Condition: level in [1, 2] -> high; level eq 3 -> medium; ids in threshold
  `entra-connect.acknowledged-event-ids` excluded. (Known upgrade and deletion-threshold event ids can
  be added to this list's documentation once confirmed on a server.)
- Refs: NIST-800-53:AU-6, NIST-800-53:SI-4.
- Fix: per event id; unknown ids get a cause and a fix recorded.
- Confidence: verified provider names (troubleshooting docs) - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-sync-errors

### ECSYNC-PHS-FAILURE-611
- Catches: password hash sync failing for a domain (event 611: replication access denied, DC
  unreachable) - cloud passwords go stale and a leaver's old password keeps working.
- Severity: high.
- Source: entra-connect.yaml; eventlog `log: Application`, `providers: ["Directory Synchronization"]`,
  `ids: [611]`, `days: 7`; key `{host}|{recordId}`.
- Condition: `each: any`.
- Refs: NIST-800-53:IA-5, NIST-800-53:SI-4.
- Fix: the cause is in the message: connector account replication rights, DC reachability, RPC.
- Confidence: verified - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization

### ECSYNC-PHS-HEARTBEAT-EVENTS-MISSING
- Catches: no password-sync batch events (656 change requests / 657 results) in the last day on the
  active server - the PHS loop is not running even though the service is up.
- Severity: medium.
- Source: same provider; `ids: [656, 657]`, `days: 1`; key `{host}|{recordId}`.
- Condition: `count: none` (per host). A staging server legitimately has none - apply the rule to the
  active server only (threshold `entra-connect.active-server`, or accept the staging finding).
- Refs: NIST-800-53:IA-5.
- Fix: as above; also ENTRA-SYNC-PASSWORD-HASH-STALE from the cloud side.
- Confidence: verified (same page).

### ECSYNC-PASSWORD-WRITEBACK-ERRORS
- Catches: password writeback failures - a self-service reset succeeds in the portal and never
  reaches the directory; the user is locked out at the next domain logon.
- Severity: medium.
- Source: entra-connect.yaml; eventlog `log: Application`, `providers: [PasswordResetService]`, `days: 7`;
  key `{host}|{id}`. Only meaningful when ENTRA-SYNC-WRITEBACK-ENABLED shows passwordWritebackEnabled.
- Condition: level in [1, 2, 3].
- Refs: NIST-800-53:IA-5.
- Fix: follow the writeback troubleshooting page (connector account reset rights, outbound 443).
- Confidence: likely (provider name from the writeback troubleshooting doc) - https://learn.microsoft.com/en-us/entra/identity/authentication/troubleshoot-sspr-writeback

### ECSYNC-SERVICE-CRASH-EVENTS
- Catches: the engine or a Health agent service terminated unexpectedly or failed to start (Service
  Control Manager 7000/7023/7031/7034 naming them), and LocalDB/SQL errors in the Application log.
- Severity: high.
- Source: entra-connect.yaml; eventlog `log: System`, `providers: ["Service Control Manager"]`,
  `ids: [7000, 7023, 7031, 7034]`, `days: 7`; key `{host}|{recordId}`; second query `log: Application`,
  providers matching the LocalDB/MSSQL instance providers, level 1-2.
- Condition: param1 match `^(Microsoft Entra Connect Sync|Microsoft Azure AD Sync|Azure AD Connect Health)` (threshold `entra-connect.service-display-pattern`).
- Refs: NIST-800-53:SI-4.
- Fix: read the database errors before restarting the service.
- Confidence: verified (SCM event data param1 = service display name; the exact display names vary by release - likely).

### ECSYNC-WIZARD-RUN-RECENT
- Catches: the configuration wizard ran on the server in the last 7 days (trace files or the persisted
  state file modified) - every such run is a tier-0 change (filtering, features, credentials, upgrade).
- Severity: info (medium when no change record is expected - a person decides).
- Source: entra-connect.yaml; cim `SELECT Name, LastModified, FileSize FROM CIM_DataFile WHERE Drive = 'C:' AND Path = '\\ProgramData\\AADConnect\\' AND Extension = 'log'`
  and the same for `PersistedState.xml`; key `{host}|{Name}`. Metadata only - never content.
- Condition: LastModified age-lt 7.
- Refs: NIST-800-53:CM-3, NIST-800-53:AU-6.
- Fix: match to a change record; otherwise review who logged on (ECSYNC-LOGON-BY-UNAPPROVED-ACCOUNT).
- Confidence: verified (CIM_DataFile; the trace folder is documented) - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-connectivity

### ECSYNC-ADSYNC-GROUP-MEMBER-UNEXPECTED
- Catches: a member of the engine's local administration groups (Admins, Operators, Browse,
  PasswordSet) outside the approved pattern. Admins can rewrite sync rules and filtering (tier 0);
  Browse reads every connector-space attribute; PasswordSet sets passwords through the engine.
- Severity: high (Admins) / medium (others).
- Source: entra-connect.yaml; cim `SELECT GroupComponent, PartComponent FROM Win32_GroupUser WHERE GroupComponent = "Win32_Group.Domain='{HOST}',Name='ADSyncAdmins'"`
  (one query per group, or one query without the WHERE and filter GroupComponent by match); key `{host}|{PartComponent}`.
- Condition: PartComponent notmatch `entra-connect.approved-admin-pattern` (empty = the rule is not
  configured, never a pass). Disabled or departed members: a store join of PartComponent's account
  name to AD users (HYB-* family) - second rule when the join lands.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-2, CIS-Controls-v8:5.4.
- Fix: replace leavers with the approved tier-0 group; keep Operators/Browse/PasswordSet empty.
- Confidence: verified (pattern already used by WINSRV-LOCALADMIN-*); group names from the accounts and permissions reference.

### ECSYNC-LOGON-RIGHT-BROAD
- Catches: interactive, remote-interactive or network logon rights on the sync server granted to a
  broad or tier-1 group - a non-tier-0 admin sitting on the box leaves tier-0 secrets in memory.
- Severity: high.
- Source: entra-connect.yaml; cim namespace `root/rsop/computer`,
  `SELECT UserRight, AccountList, precedence FROM RSOP_UserPrivilegeRight WHERE precedence = 1`;
  key `{host}|{UserRight}`.
- Condition: UserRight in [SeInteractiveLogonRight, SeRemoteInteractiveLogonRight, SeNetworkLogonRight]
  and AccountList contains a value matching `(?i)(Domain Users|Authenticated Users|Everyone|Users$|Helpdesk|Tier ?[12])`
  (threshold `entra-connect.broad-logon-pattern`); and the matching Deny rights absent for tier-1/tier-2 groups (second rule).
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-17.
- Fix: a tier-0 server GPO that scopes the logon rights and denies the lower tiers.
- Confidence: verified (RSOP_UserPrivilegeRight is already read by the workstation pack).

### ECSYNC-LOGON-FROM-UNAPPROVED-HOST
- Catches: an interactive or RDP logon to the sync server from a workstation not on the approved
  admin-workstation list - administration must come from a privileged access workstation.
- Severity: medium (high for an account outside the approved admins).
- Source: entra-connect.yaml; eventlog `log: Security`, `ids: [4624, 4648]`, `days: 7`, `max: 500`;
  fields LogonType, TargetUserName, WorkstationName, IpAddress; key `{host}|{TargetUserName}|{WorkstationName}`.
  Needs Security-log read rights on the server.
- Condition: LogonType in [2, 10] and WorkstationName notmatch `entra-connect.admin-workstation-pattern` (empty = not configured).
  Second condition (registry `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers` with subkeys) records whether an MFA credential provider is present - evidence only.
- Refs: NIST-800-53:AC-17, NIST-800-53:IA-2(1), NIST-800-53:AU-6.
- Fix: restrict RDP sources; add an MFA provider for RDP.
- Confidence: verified (4624 event data fields).

### ECSYNC-LOGON-BY-UNAPPROVED-ACCOUNT
- Catches: a logon (interactive, RDP, or privileged network) to the sync server by an account
  outside the approved tier-0 admin list and the known service identities.
- Severity: high.
- Source: same query plus `ids: [4672]` (special privileges assigned).
- Condition: TargetUserName (SubjectUserName for 4672) notmatch `entra-connect.approved-admin-pattern`
  and notmatch `^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-|ADSync$|.*\$$)` (threshold `entra-connect.service-identity-pattern`).
- Refs: NIST-800-53:AU-6, NIST-800-53:AC-2(12).
- Fix: investigate; remove the access path (local admins, logon rights).
- Confidence: verified.

### ECSYNC-COHOSTED-SOFTWARE
- Catches: services and products on the sync server beyond the engine and its approved agents - each
  one brings its administrators, listeners and vulnerabilities into tier 0.
- Severity: high.
- Source: entra-connect.yaml; cim `SELECT Name, DisplayName, PathName, State, StartName FROM Win32_Service`,
  key `{host}|{Name}`; registry Uninstall `subkeys: true` (DisplayName, Publisher), key `{host}|{DisplayName}`;
  optional cim namespace `root/StandardCimv2` `SELECT LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2`.
- Condition: PathName notmatch `(?i)^"?[a-z]:\\windows\\` and Name notmatch `entra-connect.approved-service-pattern`
  (default `^(ADSync|AzureADConnectHealth.*|CcmExec|Sense|WinDefend|MsSense|AmazonSSMAgent|Ec2.*|VeeamVssSupport|.*Backup.*)$`);
  products: DisplayName notmatch `entra-connect.approved-product-pattern`.
- Refs: NIST-800-53:CM-7, NIST-800-53:CM-8.
- Fix: move the other products to tier-1 servers; until then record each with a move date.
- Confidence: verified (fields in use elsewhere); MSFT_NetTCPConnection namespace likely.

### ECSYNC-BROWSER-INSTALLED
- Catches: a third-party browser installed on the sync server - the clearest sign the tier-0 box is
  used for browsing.
- Severity: medium.
- Source: same registry Uninstall query.
- Condition: DisplayName match `(?i)^(Google Chrome|Mozilla Firefox|Opera|Brave)` (threshold `entra-connect.browser-pattern`).
- Refs: NIST-800-53:CM-7, NIST-800-53:SC-7(5).
- Fix: remove; block browsing by policy; restrict egress at the network layer.
- Confidence: verified.

### ECSYNC-CREDENTIAL-GUARD-OFF
- Catches: Credential Guard not running on the sync server (LSA protection and WDigest are the
  WS-REG-LSA-PPL / WS-REG-WDIGEST registry proposals; this is the virtualisation-based half).
- Severity: medium (the instance type may not support it - then accept with the reason).
- Source: entra-connect.yaml; cim namespace `root/Microsoft/Windows/DeviceGuard`,
  `SELECT SecurityServicesRunning, SecurityServicesConfigured, VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard`; key host.
- Condition: SecurityServicesRunning notcontains 1.
- Refs: NIST-800-53:SC-39, MITRE-ATTACK:T1003.001.
- Fix: enable by the tier-0 server GPO after a test with the engine.
- Confidence: verified - https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure#verify-that-credential-guard-is-running

### ECSYNC-ROOT-AUTOUPDATE-DISABLED
- Catches: automatic root-certificate update turned off on the sync server - the engine fails at
  the next Microsoft TLS root rotation.
- Severity: medium.
- Source: entra-connect.yaml; registry `SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot` value DisableRootAutoUpdate; key host.
- Condition: DisableRootAutoUpdate eq 1. The chain presented by the cloud endpoints is a `tls` rule
  from the scanner (certificates.yaml: chainValid, issuer notmatch an inspection-CA pattern); from the
  server itself it needs remoting.
- Refs: NIST-800-53:SC-17, NIST-800-53:SC-8.
- Fix: restore auto-update, or install the documented Microsoft roots by policy.
- Confidence: verified - https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-trust

### ECSYNC-EVENT-FORWARDING-OFF
- Catches: no Windows Event Forwarding subscription manager configured on the sync server (and no
  log agent service) - its Security and Application logs live only on the box and wrap in days.
  Generic enough for every server; written here first.
- Severity: medium.
- Source: entra-connect.yaml (twin for windows-server.yaml); registry
  `SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager` (values: all); key host.
  Log-agent presence from the ECSYNC-SERVICE-DOWN query (threshold `entra-connect.log-agent-service-pattern`).
- Condition: exists eq false (and no log-agent service row).
- Refs: NIST-800-53:AU-4, NIST-800-53:AU-9(2), NIST-800-53:AU-6.
- Fix: include the server in central log collection; raise local retention meanwhile (WS-REG-SECURITY-LOG-SIZE).
- Confidence: verified - https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription

### ECSYNC-CONFIG-EXPORT-STALE
- Catches: no exported sync configuration (the wizard's settings JSON) newer than N days in the
  imports folder - a rebuild would reconstruct filtering, rules and features from memory.
- Severity: medium.
- Source: entra-connect.yaml; file `path: "entra-connect/*.json"`, format json, items `$` (one row per
  file with `_file`, `_modified`); key `_file`. Someone copies the export there after each change;
  Keeper never produces it.
- Condition: `count: none` (no export at all) and per row `_modified age-gt 90` (threshold `entra-connect.config-export-max-age-days`).
- Refs: NIST-800-53:CP-9, NIST-800-53:CM-2(3).
- Fix: export after each change; copy off-server.
- Confidence: verified (file protocol semantics in RULES.md) - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-import-export-config

---

## Directory and store rules (`rules\active-directory.yaml`, `rules\hybrid-identity.yaml`, DC eventlog)

### HYB-SYNC-CONNECTOR-ACCOUNT-MULTIPLE
- Catches: more than one directory-connector account (the accounts each installation creates, or a
  legacy dirsync account) - every extra one is a stored credential with directory-replication rights
  that nobody rotates. Also a disabled or stale one (an install that left).
- Severity: high.
- Source: active-directory.yaml; ldap filter `(&{USER}(sAMAccountName=MSOL_*))` (threshold
  `entra-connect.connector-account-pattern` for the legacy name); attributes sAMAccountName, description,
  userAccountControl, pwdLastSet, lastLogonTimestamp, whenCreated, memberOf, adminCount; key sAMAccountName.
- Condition: `count: { op: gt, value: 1, threshold: entra-connect.expected-connector-accounts }`;
  second rule per row: userAccountControl flag 2 or lastLogonTimestamp age-gt 7 (the live one logs on every cycle).
  Replication-right ACEs themselves are security descriptors - not readable by the ldap runner.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:AC-6, MITRE-ATTACK:T1003.006.
- Fix: remove replication rights from, then disable, the accounts of servers that no longer exist.
- Confidence: verified (naming convention documented) - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions

### HYB-SYNC-CONNECTOR-ACCOUNT-PRIVILEGED
- Catches: the connector account carrying more than its delegated rights - adminCount set, a
  protected-group membership, "password not required", or sitting outside a tier-0 OU. Whoever can
  reset its password inherits replication (DCSync).
- Severity: high.
- Source: same ldap rows.
- Condition: adminCount eq 1 or memberOf match `(?i)CN=(Domain Admins|Enterprise Admins|Administrators|Account Operators)`
  or userAccountControl flag 32 or distinguishedName notmatch `entra-connect.tier0-ou-pattern`.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-3.
- Fix: apply the restricted-permissions script from the engine's configuration module; move the
  account to the tier-0 OU; remove group memberships.
- Confidence: verified (attributes in use by the AD pack).

### HYB-SYNC-DOMAIN-GROUPS-UNPROTECTED
- Catches: domain groups used for the engine's administration (created when installing with domain
  groups) that sit outside a tier-0 OU or have no manager - tier-0 power in an ordinary OU's ACL.
  Orphan groups from earlier installs land here too.
- Severity: medium.
- Source: active-directory.yaml; ldap filter `(&(objectClass=group)(cn=ADSync*))`; attributes
  distinguishedName, managedBy, member, whenCreated; key distinguishedName.
- Condition: distinguishedName notmatch `entra-connect.tier0-ou-pattern` or managedBy absent.
- Refs: NIST-800-53:AC-6, NIST-800-53:CM-8.
- Fix: move the groups to the tier-0 OU; delete the ones of servers that are gone.
- Confidence: verified.

### HYB-HYBRID-JOIN-SCP-MISSING
- Catches: the hybrid-join service connection point missing from the configuration partition, or
  pointing at another tenant - domain PCs then never hybrid-join (co-management and device-based
  Conditional Access depend on it).
- Severity: medium.
- Source: active-directory.yaml; ldap `base: config`, filter
  `(&(objectClass=serviceConnectionPoint)(cn=62a0ff2e-97b9-4513-943f-0d221bd30080))`; attributes keywords; key distinguishedName.
- Condition: `count: none`; second rule: keywords notcontains `azureADId:<threshold entra.tenant-id>`
  (empty threshold = not configured). Never put the tenant id in evidence.
- Refs: NIST-800-53:CM-6, NIST-800-53:IA-3.
- Fix: run the device-options step of the wizard again.
- Confidence: verified (SCP GUID is a Microsoft constant) - https://learn.microsoft.com/en-us/entra/identity/devices/how-to-hybrid-join

### HYB-USER-SYNCED-NO-CONSISTENCY-GUID
- Catches: a synchronised user whose directory object has no consistency GUID although that
  attribute is the source anchor - the object relies on writeback that may have failed, and a forest
  move would re-create it.
- Severity: low.
- Source: hybrid-identity.yaml; store join of Entra users (`onPremisesSyncEnabled` = 1, SID) with AD users
  on `objectSid` where `json_extract(attrs,'$.mS-DS-ConsistencyGuid')` is null. **Attribute gap:** the
  AD inventory query must add `mS-DS-ConsistencyGuid` to its attributes. The anchor setting itself is
  only on the server (remoting).
- Condition: `each: any` over the join rows.
- Refs: NIST-800-53:IA-4.
- Fix: let the engine write the anchor (check the writeback rule); never hand-edit.
- Confidence: verified attribute name - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts

### HYB-USER-AD-PRIVILEGED-SYNCED
- Catches: a tier-0 directory account (adminCount set or in a protected group) that is synchronised
  to the cloud - exposed to cloud password spray and blurring the tier boundary.
- Severity: high.
- Source: hybrid-identity.yaml; store join AD users (`admin_count` = 1, or memberOf matching the
  protected-group pattern) x Entra users on SID (B1 x B5 in cross-system.md). **Attribute gap:** adminCount
  and memberOf are not requested by the AD inventory query (already noted in cross-system.md).
- Condition: `each: any`; evidence names the account and whether the cloud side is enabled or licensed.
- Refs: NIST-800-53:AC-6(5), CIS-Controls-v8:5.4.
- Fix: move the account to an OU outside the sync scope (check mailbox and licence first) or add an attribute filter.
- Confidence: verified (join pattern exists).

### HYB-SYNC-ACCOUNT-LOGON-FOREIGN-HOST
- Catches: the connector account authenticating from a host other than the sync servers - its
  password lives only in the engine, so any other source is credential theft or a forgotten install.
- Severity: critical.
- Source: a DC eventlog file (targets: domain controllers); eventlog `log: Security`,
  `ids: [4624, 4768, 4776]`, `days: 7`; fields TargetUserName, WorkstationName, IpAddress, LogonType;
  key `{host}|{TargetUserName}|{WorkstationName}`. Needs Security-log read on the DCs.
- Condition: TargetUserName match `entra-connect.connector-account-pattern` and WorkstationName
  notin `entra-connect.servers` (and IpAddress notin `entra-connect.server-addresses`). Do not print addresses in evidence.
- Refs: NIST-800-53:AU-6, NIST-800-53:AC-2(12), MITRE-ATTACK:T1003.006.
- Fix: incident: reset the connector account through the wizard; find the source host.
- Confidence: verified (event data fields).

### HYB-SYNC-CONNECTOR-UNSIGNED-LDAP-BIND
- Catches: the connector account binding to a domain controller without signing (Directory Service
  event 2889 naming it) - the day LDAP signing is enforced on the DCs, sync stops.
- Severity: medium.
- Source: same DC eventlog file; eventlog `log: Directory Service`, `providers: [ActiveDirectory_DomainService]`,
  `ids: [2889]`, `days: 7`; the client identity and address are event data fields; key `{host}|{recordId}`.
  A generic "any unsigned bind" rule for the AD pack is the natural twin.
- Condition: the identity field match `entra-connect.connector-account-pattern`.
- Refs: NIST-800-53:SC-8, MITRE-ATTACK:T1557.
- Fix: set the connector to sign and seal (default) or LDAPS before enforcing signing on the DCs.
- Confidence: verified (2889 requires LDAP interface diagnostics level 2) - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server

---

## Engine gaps surfaced by this group

- Target lists for per-host files that AD cannot derive (which servers run the engine): a threshold
  list now; a store-derived target list later.
- Run-to-run comparison (object counts, database growth, configuration hash drift, device-count trend).
- Two-field comparison (UPN suffix on-premises vs cloud; free space vs database size).
- Version-number ordering (engine, bundled components); regex thresholds stand in.
- Per-host threshold overrides (a tier-0 server wants a stricter local-admin pattern than the estate).
- Security descriptors are refused by the ldap runner, so every ACL check (connector account,
  seamless-SSO object, consistency-GUID write rights, OU delegation) needs remoting.


---

## Exchange Online


Conventions as in `docs\proposals\microsoft-cloud.md`: shared queries Q-USERS, Q-CA, Q-ROLES-EXPAND, Q-DOMAINS;
tenant facts are `threshold.<name>` settings. "Usage report" below means the Microsoft 365 usage
report `getMailboxUsageDetail`: in v1.0 it answers with a 302 to a CSV, in beta `?$format=application/json`
returns JSON items (likely; https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-beta).
If the graph runner cannot follow the redirect, the CSV goes through the `file` protocol
(imports\m365\MailboxUsageDetail*.csv). When the tenant's report privacy setting is on, the report
conceals user names and UPNs (the rule then keys on the concealed value and the evidence says so).
Shared query for the report rules, **Q-MBXUSAGE**: beta `/reports/getMailboxUsageDetail(period='D30')`
with `$format=application/json`; fields userPrincipalName, displayName, isDeleted, deletedDate,
createdDate, lastActivityDate, itemCount, storageUsedInBytes, issueWarningQuotaInBytes,
prohibitSendQuotaInBytes, prohibitSendReceiveQuotaInBytes, recipientType, hasArchive; key
userPrincipalName. Permission Reports.Read.All (application).

## Priority 1

### M365-MAILBOX-NEAR-QUOTA
- Catches: a mailbox whose storage is at or above N % of its prohibit-send quota. Past the quota it
  cannot send; past the send/receive quota inbound mail bounces, which on a public-facing shared
  mailbox is a silent service failure.
- Severity: medium (high at or above the send/receive quota).
- Source: m365.yaml; shared query Q-MBXUSAGE. The percentage is not a field: the engine cannot divide
  two fields (gap) - either compute in a `store` rule over row_seen
  (`storageUsedInBytes * 100 / prohibitSendQuotaInBytes`) or the YAML author adds a derived-field
  op. Store form: `SELECT ... FROM latest_run r JOIN row_seen s ... WHERE entity_type = 'mailbox-usage'`.
- Permission: Reports.Read.All.
- Condition: pct ge 90 (threshold `m365.mailbox-quota-warn-pct`); severity high when
  storageUsedInBytes ge prohibitSendReceiveQuotaInBytes. Evidence: recipientType, hasArchive.
- Refs: NIST-800-53:CP-2, NIST-800-53:SC-5.
- Fix: enable the archive (auto-expanding where licensed), clean up, or move the mailbox to a plan
  with a larger quota.
- Confidence: likely (field names from the beta JSON report) -
  https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-beta

### M365-SHARED-MAILBOX-OVER-FREE-CAP
- Catches: a shared mailbox above the storage cap that Microsoft allows without a licence, while
  the account carries no Exchange licence. It stops receiving when full and is a licence-terms
  finding at true-up.
- Severity: high.
- Source: m365.yaml; `store` join of Q-MBXUSAGE rows (recipientType eq Shared, storageUsedInBytes)
  with Q-USERS rows (assignedLicenses) on userPrincipalName.
- Permission: Reports.Read.All + User.Read.All.
- Condition: recipientType eq Shared and storageUsedInBytes gt 48 GB (threshold
  `m365.shared-mailbox-free-cap-bytes`, default 50 GB minus a margin) and assignedLicenses contains no
  SKU in threshold `m365.exchange-plan2-sku-ids`. Empty threshold = n/a.
- Refs: NIST-800-53:CP-2, NIST-800-53:SA-4.
- Fix: licence the mailbox (Exchange Online Plan 2 or a suite containing it) or enable the archive
  with a move policy and reduce the primary mailbox.
- Confidence: likely (recipientType value text to confirm on first run).

### M365-USER-SERVICE-PROVISIONING-ERROR
- Catches: a user or group with an unresolved service-provisioning error (duplicate proxy
  address and similar) reported by a workload such as Exchange. The mailbox is not created or not
  updated until someone fixes the source attribute; ENTRA-SYNC-PROVISIONING-ERROR sees only the
  directory-sync errors, not the workload ones.
- Severity: medium.
- Source: entra.yaml; v1.0; `/users`; filter `serviceProvisioningErrors/any(e:e/isResolved eq false)`;
  select id, userPrincipalName, serviceProvisioningErrors; key id; name userPrincipalName. Second
  query on `/groups` with the same filter. New queries (small result sets).
- Permission: User.Read.All, Group.Read.All.
- Condition: `each: any`; evidence lists `serviceProvisioningErrors[].serviceInstance`,
  `.createdDateTime`, `.errorDetail`.
- Refs: NIST-800-53:CM-8, NIST-800-53:SI-10.
- Fix: correct the attribute at its source (on-premises AD for synchronised objects, Entra for
  cloud ones), then wait one sync cycle.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/serviceprovisioningerror?view=graph-rest-1.0

### M365-INBOX-RULE-FORWARD-OR-HIDE
- Catches: an inbox rule that forwards or redirects mail (outside the tenant, or at all when the
  organisation forbids forwarding), or that deletes or moves messages matching keywords - the
  classic post-compromise persistence and hiding technique. Rules created in Outlook are not visible
  in the Exchange admin cmdlets' audit until the next sweep; this reads them directly.
- Severity: high (forward/redirect), medium (delete or move on keyword).
- Source: m365.yaml; v1.0; `for_each` Q-USERS (accountEnabled true, members) → `/users/{id}/mailFolders/inbox/messageRules`;
  fields id, displayName, isEnabled, hasError, actions (forwardTo[].emailAddress.address,
  forwardAsAttachmentTo[].emailAddress.address, redirectTo[].emailAddress.address, delete,
  moveToFolder, markAsRead), conditions (subjectContains, bodyOrSubjectContains, senderContains);
  key `{parent.id}|{id}`; name = parent userPrincipalName. One call per mailbox: bound the fan-out
  with `max` and `refresh: 7d`; mailboxes without one return an empty list (not a failure). Hidden
  rules are not returned (the exo-powershell rule covers those).
- Permission: MailboxSettings.Read (application).
- Condition: isEnabled true and (forwardTo notempty or redirectTo notempty or forwardAsAttachmentTo
  notempty) → high, unless every target address matches threshold `m365.forwarding-allow-pattern`
  (empty by default = none allowed); or (delete eq true or moveToFolder notempty) and
  (subjectContains or bodyOrSubjectContains match threshold `m365.inbox-rule-hide-keyword-pattern`,
  default `(password|invoice|payment|security|alert|phish|suspicious|sign-in)`) → medium.
- Refs: CIS-M365:6.2.1, MITRE-ATTACK:T1114.003, MITRE-ATTACK:T1564.008, NIST-800-53:AC-4, NIST-800-53:SI-4.
- Fix: disable the rule, treat as possible compromise (review sign-ins, revoke sessions, reset the
  password), then block automatic forwarding tenant-wide.
- Confidence: verified resource and action fields -
  https://learn.microsoft.com/en-us/graph/api/resources/messagerule?view=graph-rest-1.0 (application
  permission on the list call: likely - https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messagerules?view=graph-rest-1.0).

### ENTRA-ADMIN-ACCOUNT-MAIL-ENABLED
- Catches: an administrative account (holder of a privileged directory role, or matching the
  admin-naming threshold) that has a mailbox or sits in mail-enabled groups. Business mail in the
  most powerful identity means phishing lands exactly where it hurts; admin accounts should be
  mail-less, hidden from the address list, with notices routed to role mailboxes.
- Severity: medium.
- Source: entra.yaml; v1.0; `/users`; filter `accountEnabled eq true` plus either
  `userPrincipalName` match threshold `entra.admin-account-pattern` (e.g. a prefix convention) or
  id in the principal ids of Q-ROLES-EXPAND (store join); select id, userPrincipalName, mail,
  proxyAddresses, assignedLicenses, showInAddressList; expand `memberOf($select=id,displayName,mailEnabled)`;
  key id.
- Permission: User.Read.All + GroupMember.Read.All (+ RoleManagement.Read.Directory via the shared role query).
- Condition: any of: mail exists and assignedLicenses contains a SKU in threshold
  `m365.exchange-bearing-sku-ids`; `memberOf[].mailEnabled` eq true; showInAddressList eq true (the
  field is often null - treat null as unknown, not a pass; confirm on first run).
- Refs: CIS-M365:1.1.4, NIST-800-53:AC-6(2), NIST-800-53:AC-6(5), MITRE-ATTACK:T1566.
- Fix: remove the admin account from mail groups and licences; hide it from the address list; send
  admin notices to a monitored role mailbox.
- Confidence: likely (showInAddressList semantics: guess) - https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0

### M365-ALERT-MAILBOX-UNTRIAGED
- Catches: a monitored alert or account-notice mailbox with more than N unread items, or whose
  newest item is older than N days - a monitoring gap with a mailbox attached (vendor, cloud-account
  and security notices nobody reads).
- Severity: medium.
- Source: m365.yaml; v1.0; `for_each` over the threshold list `m365.alert-mailbox-ids` (user object
  ids) → `/users/{id}/mailFolders/inbox`; select id, unreadItemCount, totalItemCount; key = parent id.
  Empty threshold = n/a.
- Permission: Mail.ReadBasic.All (application) - counts only, no message content.
- Condition: unreadItemCount gt 50 (threshold `m365.alert-mailbox-max-unread`).
- Refs: NIST-800-53:IR-6, NIST-800-53:SI-4, CIS-Controls-v8:17.1.
- Fix: name a triage owner; sort with inbox rules into folders (never forward); re-point notices
  that belong elsewhere.
- Confidence: verified fields; Mail.ReadBasic.All on mailFolders: likely -
  https://learn.microsoft.com/en-us/graph/api/mailfolder-get?view=graph-rest-1.0

## Priority 2

### M365-OUTLOOK-VERSION-UNSUPPORTED
- Catches: users connecting with an Outlook desktop release that Microsoft no longer supports for
  Microsoft 365 connections (no security fixes, legacy auth behaviour). Two rules on one report: the
  counts (never concealed) and the per-user detail.
- Severity: medium (high when the count on the oldest releases is above the threshold).
- Source: m365.yaml; beta `/reports/getEmailAppUsageVersionsUserCounts(period='D30')?$format=application/json`;
  fields reportPeriod, outlook2007, outlook2010, outlook2013, outlook2016, outlook2019, outlookM365,
  undetermined; key reportRefreshDate. Detail rule: `/reports/getEmailAppUsageUserDetail(period='D30')`
  fields userPrincipalName, outlookVersions (list); key userPrincipalName (concealed by the privacy
  setting).
- Permission: Reports.Read.All.
- Condition: counts rule - any of outlook2007, outlook2010, outlook2013, outlook2016, outlook2019 gt 0
  (threshold `m365.outlook-unsupported-max-users`, default 0; the set of unsupported releases is
  threshold `m365.outlook-unsupported-versions`, default those five). Detail rule - `outlookVersions`
  contains a value in that list.
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22, CIS-Controls-v8:2.2.
- Fix: upgrade to Microsoft 365 Apps through the endpoint-management tool; block old clients with an
  authentication policy once the upgrade is done.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/reportroot-getemailappusageversionsusercounts?view=graph-rest-beta

### M365-SHARED-MAILBOX-SIGNIN-ENABLED
- Catches: a shared mailbox whose directory account can sign in. The account has a password nobody
  owns and usually no MFA; blocking sign-in is the control.
- Severity: medium.
- Source: m365.yaml; `store` join of Q-MBXUSAGE rows (recipientType eq Shared) with Q-USERS rows on
  userPrincipalName (accountEnabled). Both scans must be usable (cross-system convention).
- Permission: Reports.Read.All + User.Read.All.
- Condition: recipientType eq Shared and accountEnabled eq 1.
- Refs: CIS-M365:1.2.2, NIST-800-53:AC-2, NIST-800-53:IA-2.
- Fix: block sign-in on the account; grant delegates Full Access / Send As instead.
- Confidence: likely.

### M365-RESOURCE-MAILBOX-SIGNIN-RECENT
- Catches: a shared, room or equipment mailbox account with a successful sign-in in the last N
  days - someone holds its password. Meeting-room devices that sign in as the room are the documented
  exception (threshold list).
- Severity: medium.
- Source: m365.yaml; same store join as above with Q-USERS `signInActivity.lastSuccessfulSignInDateTime`.
- Permission: Reports.Read.All + User.Read.All + AuditLog.Read.All.
- Condition: recipientType in [Shared, Room, Equipment] and lastSuccessfulSignInDateTime age-lt 90
  (threshold `m365.resource-mailbox-signin-window-days`) and id notin threshold
  `m365.resource-mailbox-signin-allow-ids`.
- Refs: NIST-800-53:AC-2, NIST-800-53:IA-2, MITRE-ATTACK:T1078.004.
- Fix: reset the password, block sign-in, find who used it (sign-in log, device).
- Confidence: likely.

### M365-MAILBOX-USER-DISABLED-NOT-CONVERTED
- Catches: a disabled account that still owns a user mailbox (not converted to shared, not an
  inactive mailbox) for longer than N days - an undecided leaver: mail arriving, nobody reading it,
  often a licence still attached (that half is M365-LICENSED-USER-DISABLED).
- Severity: low.
- Source: m365.yaml; `store` join of Q-MBXUSAGE rows (recipientType eq User, isDeleted false) with
  Q-USERS rows (accountEnabled, and employeeLeaveDateTime if selected).
- Permission: Reports.Read.All + User.Read.All.
- Condition: accountEnabled eq 0 and recipientType eq User. The "disabled for more than N days"
  part needs a disabled-since date: use the entity's first-seen-disabled from Keeper's store (gap)
  or employeeLeaveDateTime age-gt 30 when set.
- Refs: NIST-800-53:PS-4, NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- Fix: run the leaver process - convert to shared or place on hold, then remove the licence.
- Confidence: likely.

### M365-MAILBOX-INACTIVE
- Catches: an enabled user mailbox with no owner activity for N days (leavers HR missed, long
  leave, service accounts dressed as users). Complements M365-LICENSED-USER-INACTIVE, which looks at
  sign-ins rather than mailbox use.
- Severity: low.
- Source: m365.yaml; Q-MBXUSAGE with period D180; store join with Q-USERS accountEnabled.
- Permission: Reports.Read.All + User.Read.All.
- Condition: recipientType eq User and accountEnabled eq 1 and (lastActivityDate absent or age-gt 90,
  threshold `m365.mailbox-inactive-days`).
- Refs: NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- Fix: reconcile with HR; convert, hold or close.
- Confidence: likely.

### M365-CALENDAR-DEFAULT-PERMISSION-WIDE
- Catches: a user's calendar whose default ("My Organization") or anonymous entry grants more than
  free/busy - every meeting subject and location readable by the whole organisation or by anyone
  with the link.
- Severity: medium.
- Source: m365.yaml; v1.0; `for_each` Q-USERS (enabled members) → `/users/{id}/calendar/calendarPermissions`;
  fields id, emailAddress.name, emailAddress.address, isInsideOrganization, isRemovable, role,
  allowedRoles; key `{parent.id}|{id}`. One call per user: `max` and `refresh: 7d`.
- Permission: Calendars.Read (application).
- Condition: isRemovable eq false (the default and anonymous entries) and role notin
  [none, freeBusyRead] (threshold `m365.calendar-default-max-role`, default freeBusyRead; limitedRead
  may be accepted by the tenant).
- Refs: NIST-800-53:AC-3, NIST-800-53:AC-22, CIS-Controls-v8:3.3.
- Fix: reset the default calendar permission to free/busy; keep named delegates explicit.
- Confidence: verified resource fields (default entry has isRemovable false; which entry is
  anonymous: likely by emailAddress.name) -
  https://learn.microsoft.com/en-us/graph/api/resources/calendarpermission?view=graph-rest-1.0

### M365-MAILBOX-AUTOREPLY-STALE
- Catches: a public-facing mailbox (threshold list) whose automatic reply is scheduled and its end
  date has passed, or is always-on and older than the tenant's approval window - an outdated holiday
  text read by the public as the organisation's official answer.
- Severity: medium (low when the reply is internal-only).
- Source: m365.yaml; v1.0; `for_each` over threshold `m365.public-mailbox-ids` →
  `/users/{id}/mailboxSettings/automaticRepliesSetting`; fields status (disabled, alwaysEnabled,
  scheduled), externalAudience, scheduledStartDateTime.dateTime, scheduledEndDateTime.dateTime,
  externalReplyMessage (length only in evidence); key = parent id. Empty threshold = n/a.
- Permission: MailboxSettings.Read (application).
- Condition: status eq scheduled and scheduledEndDateTime.dateTime until-lt 0 (already past, the
  service keeps the stale schedule); or status eq alwaysEnabled and externalAudience ne none (review
  list: pair with an attestation that the owner approved the text within N days - the approved-text
  hash comparison is an engine gap).
- Refs: NIST-800-53:CM-6, NIST-800-53:SI-12.
- Fix: update or clear the reply with the mailbox owner; give the owner Full Access so they maintain
  it themselves.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/automaticrepliessetting?view=graph-rest-1.0

### ENTRA-USER-DELETED-PURGE-SOON
- Catches: a deleted user whose 30-day restore window closes within N days. After it the account,
  its mailbox (unless on hold) and its OneDrive are purged for good; this is the last day to restore a
  leaver whose deletion was a mistake or whose mailbox was never preserved.
- Severity: medium (deadline-ranked). kind: broken, category: BCK, entity: user, `deadline` = purge date.
- Source: entra.yaml; v1.0; `/directory/deletedItems/microsoft.graph.user`; select id,
  userPrincipalName, displayName, deletedDateTime, assignedLicenses; key id; name userPrincipalName.
  New query. Purge date = deletedDateTime + 30 d: the engine has no date arithmetic on a field
  (gap) - use `deletedDateTime age-gt 23` (threshold `entra.deleted-user-warn-after-days`) as "fewer
  than 7 days left".
- Permission: User.Read.All (Directory.Read.All for the deletedItems container).
- Condition: deletedDateTime age-gt 23. Evidence: days left, licences at deletion.
- Refs: NIST-800-53:CP-9, NIST-800-53:AU-11, CIS-Controls-v8:11.2.
- Fix: restore the user if the mailbox must be kept, convert it to shared or apply a hold, then
  delete again; otherwise record the decision.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0

### ENTRA-CA-BASELINE-APP-ENFORCED-RESTRICTIONS
- Catches: no enabled Conditional Access policy applies app-enforced restrictions (read-only web
  access, attachment download blocked) to Exchange Online and SharePoint on unmanaged devices. The
  OWA mailbox policy only takes effect when such a policy exists; without it a home browser can
  download every attachment.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-CA; fields state, conditions.applications.includeApplications,
  conditions.devices.deviceFilter, sessionControls.applicationEnforcedRestrictions.isEnabled.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where state eq enabled and
  sessionControls.applicationEnforcedRestrictions.isEnabled eq true and
  conditions.applications.includeApplications contains one of `Office365`,
  `00000002-0000-0ff1-ce00-000000000000` (Exchange Online), `00000003-0000-0ff1-ce00-000000000000`
  (SharePoint Online).
- Refs: CIS-M365:5.2.2.x (unmanaged-device controls), NIST-800-53:AC-19, NIST-800-53:AC-20.
- Fix: create the policy targeting unmanaged devices (device filter or exclude compliant/hybrid)
  with the app-enforced-restrictions session control, and set the OWA mailbox policy to read-only
  or attachments-blocked (exo-powershell rule).
- Confidence: verified field - https://learn.microsoft.com/en-us/graph/api/resources/applicationenforcedrestrictionssessioncontrol?view=graph-rest-1.0

### ENTRA-CA-BASELINE-MOBILE-APPROVED-CLIENT
- Catches: no enabled Conditional Access policy requires an approved client app or an app
  protection policy for Exchange Online on iOS and Android. Without it native mail apps over
  ActiveSync hold a copy of the mailbox outside app protection.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-CA; fields state, conditions.platforms.includePlatforms,
  conditions.applications.includeApplications, grantControls.builtInControls.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where state eq enabled and conditions.platforms.includePlatforms
  contains iOS and contains android (or all) and includeApplications contains Office365 or the
  Exchange Online app id and grantControls.builtInControls contains approvedApplication or
  compliantApplication (or compliantDevice, accepted by threshold `entra.mobile-mail-accept-compliant-device`).
- Refs: NIST-800-53:AC-19, NIST-800-53:AC-17, CIS-Controls-v8:4.1.
- Fix: create the policy (users All, platforms iOS/Android, Exchange Online, grant "require app
  protection policy"); then set the ActiveSync default access to quarantine (exo-powershell rule).
- Confidence: verified (grant control enum) - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0

### ENTRA-USER-PRIMARY-ADDRESS-ONMICROSOFT
- Catches: a user or group whose primary SMTP address is in the tenant's onmicrosoft.com domain,
  or who carries a proxy address in a domain the tenant has not verified. Mail from the onmicrosoft
  address fails the organisation's DMARC alignment and looks like phishing; unverified-domain
  proxies cause sync errors and bounces.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-USERS with proxyAddresses and mail added to the select
  (and `/groups` select id, displayName, mail, proxyAddresses, mailEnabled); key id. The
  unverified-domain half is a `store` join of the proxy domain against Q-DOMAINS (isVerified).
- Permission: User.Read.All, Group.Read.All, Domain.Read.All.
- Condition: `proxyAddresses[]` match `^SMTP:.*@[^@]*\.onmicrosoft\.com$` (upper-case SMTP = primary)
  and userType eq Member and accountEnabled true, excluding ids in threshold
  `entra.onmicrosoft-primary-allow-ids` (service accounts); store half: a proxy domain not in the
  verified-domain set.
- Refs: NIST-800-53:CM-6, NIST-800-53:SI-8, CIS-Controls-v8:9.5.
- Fix: set the primary address in the organisation's domain (in AD for synchronised objects);
  remove or verify the stray domain.
- Confidence: verified (proxyAddresses format) - https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0

### ENTRA-GROUP-DISTRIBUTION-NO-OWNER-OR-EMPTY
- Catches: a distribution list with no owner (nobody can review or manage it) or with no members
  (a dead address that still accepts mail). ENTRA-GROUP-M365-NO-OWNER covers Microsoft 365 groups only.
- Severity: low.
- Source: entra.yaml; v1.0; `/groups`; filter `mailEnabled eq true and securityEnabled eq false`
  (exclude groupTypes contains Unified); select id, displayName, mail, onPremisesSyncEnabled,
  groupTypes; expand `owners($select=id)` and `members($select=id)` (if two expands are refused,
  `for_each` → `/groups/{id}/members/$count` with consistency eventual); key id.
- Permission: Group.Read.All, GroupMember.Read.All.
- Condition: owners empty or members empty. Caveat: for synchronised lists the on-premises
  ManagedBy is not surfaced as a Graph owner - exclude onPremisesSyncEnabled eq true from the
  no-owner half (those are judged by the exo-powershell rule) and keep the empty-members half.
- Refs: NIST-800-53:AC-2, NIST-800-53:CM-8, CIS-Controls-v8:5.1.
- Fix: assign an owner; delete empty lists or document them.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0

### AD-EXCHANGE-SERVER-UNSUPPORTED
- Catches: an Exchange Server object in the forest's configuration partition whose version is
  below the supported line (the 2016/2019 line left support in 2025) or that has not been updated
  for a long time (a server that was removed without cleanup). A live one is an unpatched mail
  server inside the identity plane; a stale object keeps hybrid and autodiscover logic alive.
- Severity: high (version unsupported), low (stale object).
- Source: active-directory.yaml; ldap; base config; filter `(objectClass=msExchExchangeServer)`;
  attributes cn, serialNumber, msExchCurrentServerRoles, versionNumber, whenChanged, networkAddress;
  key cn. Store join to the computer object (B2 in cross-system.md) for enabled state and last logon
  is a second, XS-style rule.
- Permission: domain user (configuration partition is world-readable).
- Condition: serialNumber match `Version 15\.(0|1|2)\b` (threshold
  `ad.exchange-unsupported-version-pattern`; 15.2 = 2019, 15.1 = 2016, 15.0 = 2013) → high; or
  whenChanged age-gt 180 → low (stale).
- Refs: NIST-800-53:SA-22, NIST-800-53:SI-2, CIS-Controls-v8:2.2.
- Fix: upgrade to the subscription edition, or finish the decommission (remove the server, keep
  the management tools for recipient attributes) and clean the object.
- Confidence: likely (attribute names from the Exchange schema; serialNumber format "Version 15.x (Build y)").

### AD-EXCHANGE-AUTODISCOVER-SCP-STALE
- Catches: an Autodiscover service connection point in the configuration partition pointing at a
  server that no longer exists or no longer serves autodiscover. Domain-joined Outlook tries the SCP
  before DNS; a stale one causes profile failures and credential prompts.
- Severity: medium.
- Source: active-directory.yaml; ldap; base config; filter
  `(&(objectClass=serviceConnectionPoint)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596))`;
  attributes cn, serviceBindingInformation, keywords, whenChanged; key distinguishedName.
- Permission: domain user.
- Condition: `each: any` when the tenant has no on-premises Exchange (threshold
  `ad.exchange-onprem-expected` false, default false); otherwise serviceBindingInformation notmatch
  threshold `ad.exchange-autodiscover-host-pattern`. The public CNAME half (autodiscover → the
  cloud service) needs a DNS resolver integration.
- Refs: NIST-800-53:CP-2, NIST-800-53:CM-8.
- Fix: remove the SCP after the server decommission; publish the public CNAME.
- Confidence: verified GUID (Autodiscover SCP keyword) - https://learn.microsoft.com/en-us/exchange/architecture/client-access/autodiscover

(TLS interception of the Exchange Online web and mail endpoints is M365-ENDPOINT-TLS-INTERCEPTED in
the Microsoft 365 admin section; its default endpoint list must include the Exchange Online web and
mail hosts on 443. The probe runs from the collector only; a per-workstation sample is outside Keeper.)

## Rules once exo-powershell exists

One line per distinct check (id, what, cmdlet and properties, condition, severity). Where two old
rows are the same check they share a line. File: `rules\exchange-online.yaml`, integration
`exo-powershell` (new type), one query per cmdlet, rows = objects.

Mail flow and queues
- EXO-TRACE-FAILED-SPIKE: failed deliveries in 24 h above threshold - Get-MessageTraceV2 -Status Failed; count gt N; medium.
- EXO-TRACE-PENDING-OLD: messages pending > 60 min per recipient domain / connector - Get-MessageTraceV2 -Status Pending, Get-MessageTraceDetailV2 Defer; count some; high.
- EXO-TRACE-NDR-CODE-RECURRING: same enhanced status code > N times in 7 d, any tenant-blocked code (5.7.705/708/750) - MessageTraceDetailV2 Detail; match + per-key count; high.
- EXO-TRACE-DEVICE-SENDER-SILENT: known device/application sender with no message in a business day (threshold list) - Get-MessageTraceV2 -SenderAddress; count none; medium.
- EXO-TRACE-OUTBOUND-SENDER-SPIKE: sender with > N external recipients per day - Get-MessageTraceV2; per-key count; medium.
- EXO-TRACE-NOTICE-TO-DISABLED-MAILBOX: system/vendor notices delivered to disabled accounts' mailboxes (store join to users) - Get-MessageTraceV2 -RecipientAddress; each any; medium.
- EXO-MAILFLOW-OUTBOUND-DETECTIONS: outbound spam/malware detections > 0, or any event type outside its band - Get-MailflowStatusReport; gt 0; low.
- EXO-ROLE-MAILBOX-UNREACHABLE: role mailbox (threshold list) missing, restricted or with no delivered mail in 7 d - Get-EXORecipient, Get-MessageTraceV2; each; high.
- EXO-POSTMASTER-ABUSE-MISSING: no postmaster@/abuse@ for an authoritative domain - Get-TransportConfig, Get-EXORecipient; count none per domain; low.

Capacity and structure
- EXO-ARCHIVE-NEAR-QUOTA: archive >= 90 % without auto-expanding - Get-EXOMailbox -Archive -PropertySets Archive,Quota; Get-EXOMailboxStatistics -Archive; low.
- EXO-RECOVERABLE-ITEMS-NEAR-QUOTA: held mailbox Recoverable Items >= 90 % of quota - Get-EXOMailboxFolderStatistics -FolderScope RecoverableItems; medium.
- EXO-FOLDER-TOO-MANY-ITEMS: folder > 100k items or mailbox > 5k folders - Get-EXOMailboxFolderStatistics; low.
- EXO-RECIPIENT-COUNT-DRIFT: recipient counts per type changed > 5 % since last run - Get-EXORecipient; store trend; info.
- EXO-MESSAGE-LIMITS-INCONSISTENT: mailbox limits above plan, RecipientLimits > 500 - Get-TransportConfig, Get-MailboxPlan, Get-EXOMailbox; low.
- EXO-PUBLIC-FOLDER-OPEN: Default/Anonymous above Reviewer, mail-enabled folder accepting external - Get-PublicFolderClientPermission, Get-MailPublicFolder; low.

Lifecycle and retirements
- EXO-HYBRID-REMNANTS: OnPremisesOrganization, OnPremises connectors, org relationships, migration endpoints with no supported server - Get-OnPremisesOrganization, Get-*Connector ConnectorType OnPremises, Get-MigrationEndpoint; count some; high.
- EXO-EAS-DEVICE-OLD-OS: native ActiveSync partnership from an OS below the floor - Get-MobileDevice DeviceOS, ClientType; match; low.
- EXO-IMPERSONATION-OR-ACCESS-POLICY-LEFT: ApplicationImpersonation assignments or Application Access Policies still present - Get-ManagementRoleAssignment, Get-ApplicationAccessPolicy; count some; low.
- EXO-MIGRATION-BATCH-FAILED-OR-STALE: batches Failed/SyncedWithErrors or completed > 30 d; endpoints to retired hosts - Get-MigrationBatch, Get-MigrationUser, Get-MigrationEndpoint; low.
- EXO-OFFICE-CONNECTORS-ENABLED: legacy connectors enabled for Outlook/groups - Get-OrganizationConfig ConnectorsEnabled*; eq true; low.
- EXO-EWS-UNRESTRICTED: EwsEnabled not false and EwsApplicationAccessPolicy ne EnforceAllowList - Get-OrganizationConfig; medium.
- EXO-LEGACY-TOKENS-ALLOWED: legacy Exchange tokens not blocked - Get-AuthenticationPolicy; low.
- EXO-CLIENT-ACCESS-RULE-LEFT: any client access rule - Get-ClientAccessRule; count some; low.

Auditing
- EXO-MAILBOX-AUDIT-SET-CUSTOM: AuditEnabled false or DefaultAuditSet missing Admin/Delegate/Owner - Get-EXOMailbox -PropertySets Audit; medium.
- EXO-AUDIT-BYPASS-ENABLED: AuditBypassEnabled true - Get-MailboxAuditBypassAssociation; count some; high.
- EXO-AUDIT-INGESTION-SILENT: no MailItemsAccessed / ExchangeAdmin / Send record in 24 h - Search-UnifiedAuditLog ResultSize 1 x3; count none; medium.
- EXO-AUDIT-AGE-LIMIT-SHORT: AuditLogAgeLimit < 180 d - Get-EXOMailbox -PropertySets Audit; low.
- EXO-AUDIT-PREMIUM-MISSING: SearchQueryInitiated absent from AuditOwner on premium-licensed mailboxes - Get-EXOMailbox; low.
- EXO-INBOX-RULE-IN-ERROR: enabled rule InError on shared/alert mailboxes - Get-InboxRule -IncludeHidden; low.
- EXO-TRANSPORT-RULE-HITS-DRIFT: rule hits outside band, rules with 0 hits in 90 d - Get-MailDetailTransportRuleReport; store trend; low.

Connectors, domains, transport rules
- EXO-OUTBOUND-CONNECTOR-UNVALIDATED: IsValidated false or LastValidationTimestamp > 365 d - Get-OutboundConnector; low.
- EXO-OUTBOUND-CONNECTOR-WEAK-TLS: TlsSettings EncryptionOnly/none, '*' routing to an undocumented host - Get-OutboundConnector; medium.
- EXO-OUTBOUND-SINGLE-SMART-HOST: all mail forced to one smart host (count of hosts eq 1 on '*') - Get-OutboundConnector; medium (fallback runbook = attestation).
- EXO-INBOUND-CONNECTOR-UNRESTRICTED: RequireTls false or no certificate/IP restriction; SenderDomains '*'; TreatMessagesAsInternal outside hybrid - Get-InboundConnector; high.
- EXO-INBOUND-CONNECTOR-NO-ENHANCED-FILTERING: gateway connector without EFSkipLastIP/EFSkipIPs for all users or in test mode - Get-InboundConnector; medium.
- EXO-CONNECTOR-CHANGED-RECENTLY: connector added/changed in 7 d - Get-*Connector WhenChanged age-lt 7; high (review list).
- EXO-CONNECTOR-CERT-NAME-UNTRACKED: TlsSenderCertificateName/TlsDomain not in the certificate register - store join; medium.
- EXO-PARTNER-TLS-NOT-FORCED: partner domain (threshold list) without a DomainValidation/CertificateValidation connector - Get-OutboundConnector; low.
- EXO-ACCEPTED-DOMAIN-RELAY-OR-SUBDOMAINS: DomainType ne Authoritative or MatchSubDomains true - Get-AcceptedDomain; medium.
- EXO-REMOTE-DOMAIN-OOF-EXTERNAL: AllowedOOFType External on the default remote domain - Get-RemoteDomain; low (AutoForwardEnabled is ScubaGear MS.EXO.1.1).
- EXO-OUTBOUND-SPAM-AUTOFORWARD-ON: AutoForwardingMode ne Off, or an On policy whose rule scope is wider than the allowed exception - Get-HostedOutboundSpamFilterPolicy/-Rule; high.
- EXO-OUTBOUND-SPAM-LIMITS-UNSET: RecipientLimit* zero or ActionWhenThresholdReached ne BlockUser - Get-HostedOutboundSpamFilterPolicy; low.
- EXO-TRANSPORT-RULE-EXTERNAL-COPY: enabled rule with RedirectMessageTo/BlindCopyTo/CopyTo/AddToRecipients outside accepted domains - Get-TransportRule; high.
- EXO-TRANSPORT-RULE-FILTER-BYPASS: SetSCL -1 or skip-Safe-Links/Attachments headers keyed on sender domain - Get-TransportRule; high.
- EXO-TRANSPORT-RULE-CHANGED-RECENTLY: rule added/changed in 7 d - Get-TransportRule WhenChanged; medium.
- EXO-TRANSPORT-RULE-SHADOWED: security rule below a StopRuleProcessing rule with overlapping scope - Get-TransportRule; low (needs cross-row logic).
- EXO-TRANSPORT-RULE-DEAD: Disabled or Mode ne Enforce for > 90 d - Get-TransportRule; low.
- EXO-ENCRYPTION-RULE-MISSING: no enforced rule applying encryption to the threshold recipient pattern; AzureRMSLicensingEnabled false - Get-TransportRule, Get-IRMConfiguration; count none; medium.
- EXO-JOURNAL-RULE-UNKNOWN-TARGET: journal address outside the allowed archive domain, JournalingReportNdrTo unset - Get-JournalRule, Get-TransportConfig; high.
- EXO-OME-NOT-CONFIGURED: AzureRMSLicensingEnabled false or encrypt templates absent - Get-IRMConfiguration, Get-RMSTemplate; low.

Client policies and user-facing settings
- EXO-OWA-PERSONAL-ACCOUNTS: PersonalAccountsEnabled or PersonalAccountCalendarsEnabled true - Get-OwaMailboxPolicy; medium (CIS 6.3.2).
- EXO-OWA-STORAGE-PROVIDERS: AdditionalStorageProvidersAvailable true - Get-OwaMailboxPolicy; low (CIS 6.5.3).
- EXO-OWA-NO-CA-RESTRICTION: ConditionalAccessPolicy Off on the default policy - Get-OwaMailboxPolicy; medium.
- EXO-MAILTIPS-OFF: MailTips* false or LargeAudienceThreshold > 25 - Get-OrganizationConfig; low (CIS 6.5.2).
- EXO-ADDIN-SELF-INSTALL: role assignment policy carrying My Custom Apps / My Marketplace Apps / My ReadWriteMailbox Apps - Get-RoleAssignmentPolicy; medium (CIS 6.3.1).
- EXO-CALENDAR-PUBLISHED: PublishEnabled with DetailLevel above availability - Get-MailboxCalendarFolder per mailbox; low.
- EXO-DL-ACCEPTS-EXTERNAL: RequireSenderAuthenticationEnabled false on a distribution or dynamic group not on the allow list - Get-DistributionGroup, Get-DynamicDistributionGroup; medium.
- EXO-LARGE-GROUP-UNRESTRICTED: group > 500 members without sender restriction or moderation - Get-*Group, member counts; medium.
- EXO-DYNAMIC-GROUP-EMPTY: dynamic group returning 0 members - Get-DynamicDistributionGroupMember; low.
- EXO-ROOM-PROCESSING-OPEN: AllowConflicts, ProcessExternalMeetingMessages true, AutomateProcessing ne AutoAccept - Get-CalendarProcessing; low.
- EXO-SHARED-SENT-COPY-OFF: MessageCopyForSentAsEnabled / SendOnBehalf false on shared mailboxes - Get-EXOMailbox; low.
- EXO-M365-GROUP-ACCEPTS-EXTERNAL: RequireSenderAuthenticationEnabled false on a Microsoft 365 group - Get-UnifiedGroup; low.
- EXO-EAS-DEFAULT-ALLOW: DefaultAccessLevel Allow with no device access rules - Get-ActiveSyncOrganizationSettings; medium.
- EXO-ORG-RELATIONSHIP-STALE: relationship not on the partner list, FreeBusyAccessLevel above availability, MailboxMoveEnabled - Get-OrganizationRelationship; low.
- EXO-RECIPIENT-LIMIT-RAISED: RecipientLimits > 500 on a mailbox - Get-EXOMailbox; low.
- EXO-SAFE-SENDER-OWN-OR-CONSUMER-DOMAIN: TrustedSendersAndDomains containing an accepted or consumer domain - Get-MailboxJunkEmailConfiguration per mailbox; medium.
- EXO-AUTOREPLY-STALE (hidden-rule and text-hash variant of the Graph rule) - Get-MailboxAutoReplyConfiguration; medium.

Identity and permissions
- EXO-ROLEGROUP-MEMBER-UNEXPECTED: Organization Management (and the other admin role groups) members beyond role-linked and break-glass; new member since last run - Get-RoleGroupMember; high.
- EXO-DISCOVERY-RIGHTS-STANDING: Discovery Management, Mailbox Import Export, Mailbox Search holders not on the compliance list, or disabled - Get-RoleGroupMember, Get-ManagementRoleAssignment; high (eDiscovery groups via purview-powershell).
- EXO-ROLE-DIRECT-USER-ASSIGNMENT: administrative role assigned directly to a user - Get-ManagementRoleAssignment -RoleAssigneeType User; medium.
- EXO-APP-RBAC-UNSCOPED: service-principal role assignment without a management scope - Get-ManagementRoleAssignment -RoleAssigneeType ServicePrincipal, Get-ManagementScope; medium.
- EXO-APP-MAIL-PERMISSION-UNSCOPED: app with tenant-wide mail application permission (from Graph) and no application access policy or RBAC scope - store join Get-ApplicationAccessPolicy; high.
- EXO-FULLACCESS-UNDOCUMENTED: non-owner FullAccess on a user mailbox not on the delegate list, or granted to a broad group - Get-EXOMailboxPermission; medium.
- EXO-SENDAS-ON-PERSONAL-MAILBOX: SendAs trustee on a user mailbox - Get-EXORecipientPermission; medium.
- EXO-SENDONBEHALF-STALE: GrantSendOnBehalfTo entries not on the delegate list - Get-EXOMailbox; low.
- EXO-PERMISSION-HELD-BY-DISABLED: FullAccess/SendAs/SendOnBehalf trustee disabled in the directory - store join to users; medium.
- EXO-FOLDER-DEFAULT-PERMISSION-WIDE: Default/Anonymous on Inbox above None (calendar half is the Graph rule) - Get-EXOMailboxFolderPermission; medium.
- EXO-MAILBOX-FORWARDING-SET: ForwardingSmtpAddress/ForwardingAddress set outside the allow pattern - Get-EXOMailbox; high.
- EXO-INBOX-RULE-HIDDEN-FORWARD: hidden or error-state rules that forward/redirect/delete (Graph misses hidden) - Get-InboxRule -IncludeHidden; high.
- EXO-ADMIN-MAILBOX-FORWARDING: admin-pattern accounts with forwarding or DL membership - Get-EXOMailbox, Get-DistributionGroupMember; medium.
- EXO-POWERSHELL-OPEN-TO-USERS: RemotePowerShellEnabled true on non-admin users - Get-User; low.
- EXO-SENSITIVE-MAILBOX-NO-EXCLUSIVE-SCOPE: VIP mailboxes not covered by an exclusive management scope - Get-ManagementScope -Exclusive, Get-User -IsVIP; low.
- EXO-ROLE-MAILBOX-DELEGATE-RIGHTS-MISSING: role mailbox delegate without FullAccess and SendAs - per threshold list; low.
- EXO-SHARED-MAILBOX-NO-ENABLED-DELEGATE: shared mailbox whose FullAccess holders are all disabled or absent - Get-EXOMailboxPermission + users join; low.
- EXO-SMTP-AUTH-MAILBOX-EXCEPTION-PERSON: SmtpClientAuthenticationDisabled false on a person's mailbox - Get-CASMailbox; medium.
- EXO-POP-IMAP-ENABLED: PopEnabled/ImapEnabled true outside the allow list - Get-CASMailbox; medium.
- EXO-CAS-PLAN-POP-IMAP-ON: CAS mailbox plan with POP/IMAP enabled - Get-CASMailboxPlan; low.
- EXO-MODERN-AUTH-OFF: OAuth2ClientProfileEnabled false - Get-OrganizationConfig; medium (CIS 6.5.1).
- EXO-DIRECT-SEND-ALLOWED: RejectDirectSend false - Get-OrganizationConfig; medium (CIS 6.5.5).
- EXO-AUTH-POLICY-ALLOWS-BASIC: any AllowBasicAuth* true in the default policy, or no default policy - Get-AuthenticationPolicy, Get-OrganizationConfig; low.
- EXO-DKIM-KEY-WEAK-OR-OLD: key size < 2048 or not rotated in 365 d - Get-DkimSigningConfig; low.
- EXO-HYBRID-CERT-EXPIRY: hybrid/federation certificate < 60 d (n/a without hybrid) - Get-IntraOrganizationConnector, Get-FederatedOrganizationIdentifier (+ winrm on the server); low.

Retention, holds and backup
- EXO-RETENTION-COVERAGE-GAP: user/shared mailbox with no org-wide retention policy hold and no litigation hold - Get-EXOMailbox -PropertySets Hold (policy side via purview-powershell Get-RetentionCompliancePolicy); high.
- EXO-LITIGATION-HOLD-NO-OWNER: LitigationHoldEnabled with empty owner/comment or unlimited and unreviewed - Get-EXOMailbox; medium.
- EXO-SOFTDELETED-MAILBOX-NO-HOLD: soft-deleted mailbox without hold inside the purge window - Get-EXOMailbox -SoftDeletedMailbox; high.
- EXO-DELETED-ITEM-RETENTION-SHORT: RetainDeletedItemsFor < 30 d or SingleItemRecoveryEnabled false - Get-EXOMailbox, Get-MailboxPlan; low.
- EXO-BACKUP-COVERAGE-GAP: mailbox/archive counts vs the SaaS-backup tool's covered count - store join with the backup integration; high.
- EXO-ELC-PROCESSING-OFF: ElcProcessingDisabled true or no RetentionPolicy - Get-OrganizationConfig, Get-EXOMailbox; low.
- EXO-STATUTORY-MAILBOX-NO-HOLD: threshold-listed mailboxes without a long-term hold - Get-EXOMailbox -PropertySets Hold; medium.
- EXO-LICENCE-FEATURE-MISMATCH: shared mailbox licensed without need / needing a licence (archive, hold, size) without one; auto-expanding archive or hold on a plan that lacks it - Get-EXOMailbox -PropertySets Archive,Hold + licence join; low/medium.

Monitoring
- EXO-RESTRICTED-SENDER: any restricted user - Get-BlockedSenderAddress; count some; high.
- EXO-AUDIT-CHANGE-RECENT: forwarding, inbox-rule, permission, transport-rule, connector, journal and policy operations in 7 d - Search-UnifiedAuditLog ExchangeAdmin/ExchangeItem; each any (review list); high.
- EXO-AUDIT-MAILITEMS-UNKNOWN-APP: MailItemsAccessed by a ClientAppId not on the known list, or admin logon to user mailboxes - Search-UnifiedAuditLog; medium.
- EXO-PROTECTION-ALERT-MISROUTED: Exchange alert policies disabled or NotifyUser not a monitored address - purview-powershell Get-ProtectionAlert; high (ScubaGear MS.EXO.16.x covers the baseline set).
- EXO-ADDRESS-ONMICROSOFT-OR-FOREIGN-DOMAIN: full-recipient variant of the Graph rule (contacts, mail users, public folders) - Get-EXORecipient; low.
- EXO-CONTACT-STALE: visible mail contact in no list, unchanged > 3 years, or used as a forwarding target - Get-MailContact, Get-MailUser; low.
- EXO-ADMIN-MAILBOX-VISIBLE-IN-GAL: admin/service pattern recipients with HiddenFromAddressListsEnabled false - Get-EXORecipient; low.
- EXO-MIGRATION-LEFTOVERS: endpoints for retired servers, duplicate MailUser for a cloud mailbox - Get-MigrationEndpoint, Get-EXORecipient; low.
- EXO-CONFIG-EXPORT: no rule - the scan's row_seen of the connector, rule, domain and policy queries is the dated configuration export.


---

## Intune


Format as `docs\proposals\microsoft-cloud.md`. Shared queries referenced by name: **Q-MDEVICES**
(`/deviceManagement/managedDevices`, the 18-field select in `intune.yaml`), **Q-DEVICECONFIG**
(`/deviceManagement/deviceConfigurations` expand assignments), **Q-COMPLIANCE-ASSIGN**,
**Q-COMPLIANCE-BETA**, **Q-ENROLL** (`/deviceManagement/deviceEnrollmentConfigurations`, used by
INTUNE-ENROLL-*), **Q-CONFIGPOLICIES** (the beta `/deviceManagement/configurationPolicies` query the
INTUNE-ESEC-* rules share), **Q-MAM-IOS / Q-MAM-ANDROID**, **Q-CA** (`/identity/conditionalAccess/policies`),
**Q-USERS** (`/users`). Tenant facts are `threshold.<name>` settings, empty by default where no safe
default exists. Rule ids in `workstations.yaml` keep that file's `WS-` prefix; store joins keep `XS-`.

Engine gaps hit more than once below: no aggregate over rows (percentages, trends, group-by outside
the store protocol); `@odata.type` not addressable; no version-string comparison (regex thresholds
instead); no certificate decoding from bytes; `for_each` is one level deep.

---

## Priority 1 - things breaking today

### INTUNE-APP-REQUIRED-INSTALL-FAILING
- Catches: an assigned application whose install summary shows failed devices above a threshold.
  A failing Required app is a broken package, detection rule or requirement; devices retry forever
  and nobody sees it unless they open each app.
- Severity: medium (high when failed devices exceed 10x the threshold).
- Source: intune.yaml; beta; `for_each: { path: /deviceAppManagement/mobileApps, filter: "isAssigned eq true", select: [id, displayName, publisher], field: id, max: 500 }`
  -> `/deviceAppManagement/mobileApps/{id}/installSummary`; fields installedDeviceCount,
  failedDeviceCount, notInstalledDeviceCount, pendingInstallDeviceCount, notApplicableDeviceCount;
  key `{parent.id}`, name parent displayName. New per-object query (shared with the next rule's
  parent list).
- Permission: DeviceManagementApps.Read.All.
- Condition: failedDeviceCount gt 5 (threshold `intune.app-failed-devices-max`). Ratio to targeted
  devices is an engine gap; evidence shows installed and failed counts.
- Refs: NIST-800-53:CM-8, NIST-800-53:SI-2, CIS-Controls-v8:2.5.
- Fix: open the app's device install status, read the error code, fix the package, detection rule or
  requirement, then let devices retry.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-mobileappinstallsummary?view=graph-rest-beta

### INTUNE-APP-DEVICE-INSTALL-ERROR
- Catches: per app, the devices whose install failed, with the error code - the same error code on
  many devices is one cause (detection, content download, pending reboot).
- Severity: low (per row); the grouping by `{parent.id}|{errorCode}` makes one finding per app and
  code once template keys group rows (engine gap: row count per key).
- Source: intune.yaml; beta; `for_each` the same assigned-app list ->
  `/deviceAppManagement/mobileApps/{id}/deviceStatuses?$filter=installState eq 'failed'`; fields
  deviceName, userPrincipalName, installState, errorCode, lastSyncDateTime; key
  `{parent.id}|{errorCode}`. Replaces the POST install-status report, which Keeper refuses.
- Permission: DeviceManagementApps.Read.All.
- Condition: `each: any`; evidence names app, code, device.
- Refs: NIST-800-53:SI-2, NIST-800-53:CM-8.
- Fix: map the code (detection failed, installer exit code, reboot pending) and fix the common
  cause; do not retry blindly.
- Confidence: likely (deviceStatuses relationship on mobileApp; filter on installState to confirm)
  - https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-mobileappinstallstatus?view=graph-rest-beta

### INTUNE-ENROLL-FAILURES-RECENT
- Catches: enrolment failures in the last N days (licence, restriction, token, MDM authority). A
  burst blocks every new or replaced device.
- Severity: medium.
- Source: intune.yaml; beta; `/deviceManagement/troubleshootingEvents`; filter
  `eventDateTime ge {DAYS_AGO:7}`; fields id, eventDateTime, correlationId, failureCategory,
  failureReason, operatingSystem, osVersion, deviceId, userId, enrollmentType; key
  `{failureCategory}|{id}` (per category once grouping lands); maxPages capped. New query.
- Permission: DeviceManagementManagedDevices.Read.All.
- Condition: `each: any`; severity medium when failureCategory in [licence, restriction, token]
  style values (threshold pattern `intune.enroll-failure-category-high-pattern`).
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-19.
- Fix: fix the restriction, licence or token behind the top category; re-run the enrolment.
- Confidence: likely (enrollmentTroubleshootingEvent is a beta subtype; filter on eventDateTime
  documented) - https://learn.microsoft.com/en-us/graph/api/resources/intune-troubleshooting-enrollmenttroubleshootingevent?view=graph-rest-beta

### INTUNE-DEVICE-ACTION-PENDING-STALE
- Catches: a device whose retire, wipe or delete was issued more than N days ago and never
  completed - it keeps company data and a licence and usually never checks in again.
- Severity: low.
- Source: intune.yaml; v1.0; Q-MDEVICES with `managementState` added to the select.
- Permission: DeviceManagementManagedDevices.Read.All.
- Condition: managementState in [retirePending, retireIssued, wipePending, wipeIssued,
  deletePending] and lastSyncDateTime age-gt 14 (threshold `intune.pending-action-max-days`).
- Refs: NIST-800-53:MP-6, NIST-800-53:CM-8.
- Fix: confirm the device is gone, then delete the record.
- Confidence: verified (managementState enum on managedDevice) - https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice?view=graph-rest-1.0

### INTUNE-DEVICE-STORAGE-LOW
- Catches: an active managed device with less than N bytes free - feature updates and app installs
  fail on it.
- Severity: low.
- Source: intune.yaml; v1.0; Q-MDEVICES with freeStorageSpaceInBytes and totalStorageSpaceInBytes
  added to the select.
- Permission: DeviceManagementManagedDevices.Read.All.
- Condition: lastSyncDateTime age-lt 30 and freeStorageSpaceInBytes lt 10737418240 (threshold
  `intune.free-storage-min-bytes`). A percentage needs a ratio op (gap).
- Refs: NIST-800-53:CP-2, NIST-800-53:SI-2.
- Fix: Storage Sense policy or a remediation script; replace small disks before the next feature update.
- Confidence: verified (fields on managedDevice).

### XS-COMPUTER-AD-ACTIVE-NOT-IN-INTUNE
- Catches: an enabled Windows workstation with a recent domain logon that has no Intune managed
  device of the same name - never enrolled, so it gets no compliance, no MDM policy and no
  Intune-delivered security settings. The reverse direction (Intune device, AD object gone) is
  XS-DEVICE-INTUNE-AD-GONE.
- Severity: medium (high when the AD object is a server, if servers are in scope by threshold).
- Source: cross-system.yaml; `protocol: store`; CTEs B2 (ad_computers) and B6 (intune_devices) from
  `docs\proposals\cross-system.md`; `LEFT JOIN intune_devices i ON i.short_name = a.short_name
  WHERE i.id IS NULL AND a.os LIKE 'Windows 1%' AND julianday(:now) - julianday(a.dc_logon) <=
  COALESCE(threshold cross.computer-active-days, 30)`, both sides demanded usable (`latest_run`
  intune status = ok, AD not failed). Key `{instance}/{account}`.
- Permission: none beyond the two packs.
- Condition: `each: any`; evidence "AD <name> (<os>) logged on <date>; Intune: not enrolled".
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1, CIS-Controls-v8:4.1.
- Fix: fix auto-enrolment for the OU (group policy, licence, MDM scope) or add the machine to the
  co-management target; exclude kiosks and lab machines by OU pattern threshold.
- Confidence: verified (store schema in cross-system.md); the hostname normalisation is the pack's own.

### INTUNE-COMPLIANCE-NO-BLOCK-ACTION
- Catches: an assigned compliance policy whose actions for noncompliance never block (only report),
  or block after a grace period longer than N hours - noncompliance stays a report line.
- Severity: medium.
- Source: intune.yaml; v1.0; `for_each: { path: /deviceManagement/deviceCompliancePolicies, select: [id, displayName], field: id }`
  -> `/deviceManagement/deviceCompliancePolicies/{id}/scheduledActionsForRule?$expand=scheduledActionConfigurations`;
  fields scheduledActionConfigurations[].actionType, [].gracePeriodHours,
  [].notificationTemplateId; key `{parent.id}`. New per-object query.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: `scheduledActionConfigurations[].actionType` notcontains block, or (actionType block
  and `scheduledActionConfigurations[].gracePeriodHours` gt 72, threshold
  `intune.noncompliance-grace-max-hours`). "Any element" semantics of array leaves: the second
  clause needs "the block element's grace" - note for the engine; interim: the max grace across elements.
- Refs: NIST-800-53:CM-6, NIST-800-53:AC-19, CIS-M365:4.1.
- Fix: add "mark device noncompliant" with a 1-3 day grace and an end-user notification.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicecompliancescheduledactionforrule?view=graph-rest-1.0

### INTUNE-AUDIT-CHANGES-RECENT / INTUNE-AUDIT-DESTRUCTIVE-ACTION-RECENT  (two rules, one query)
- Catches: (a) every create, delete, patch or assign in Intune in the last N days with its actor -
  the morning review list; (b) wipe, retire, delete, fresh start, bulk actions, passcode reset and
  remote lock in the window - the actions an attacker with Intune rights takes first.
- Severity: (a) info; (b) high.
- Source: intune.yaml; v1.0; `/deviceManagement/auditEvents`; filter
  `activityDateTime ge {DAYS_AGO:7}`; select id, displayName, componentName, activity,
  activityType, activityOperationType, activityResult, activityDateTime, actor, resources,
  category; key id; maxPages capped. New query.
- Permission: DeviceManagementApps.Read.All or DeviceManagementConfiguration.Read.All (either
  grants auditEvents).
- Condition: (a) activityOperationType in [create, delete, patch, action, assign] and
  actor.userPrincipalName notmatch threshold `intune.audit-expected-actor-pattern` (empty = every
  change listed); (b) activityType match
  `(?i)(wipe|retire|delete|freshStart|cleanWindowsDevice|bulk|resetPasscode|remoteLock)` (threshold
  `intune.audit-destructive-activity-pattern`).
- Refs: NIST-800-53:AU-6, NIST-800-53:CM-3, NIST-800-53:IR-4, CIS-Controls-v8:8.11.
- Fix: match each to a ticket; for an unexplained destructive action, treat as an incident and
  enable multi-admin approval.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-auditing-auditevent?view=graph-rest-1.0
  (activityType text values are free-form; the pattern is a guess to confirm on first run).

### INTUNE-DEVICE-OWNERSHIP-MISMATCH
- Catches: a device enrolled through a corporate-only path (Android fully managed, dedicated,
  Apple automated enrolment) yet marked personally owned, or the reverse where a personal enrolment
  type is marked company - ownership decides which remote actions are allowed and what inventory
  is collected.
- Severity: low.
- Source: intune.yaml; v1.0; Q-MDEVICES with `deviceEnrollmentType` added to the select.
- Permission: DeviceManagementManagedDevices.Read.All.
- Condition: deviceEnrollmentType in [androidEnterpriseFullyManaged, androidEnterpriseDedicatedDevice,
  appleBulkWithUser, appleBulkWithoutUser, windowsAutoEnrollment, windowsBulkAzureDomainJoin] and
  managedDeviceOwnerType eq personal.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-19.
- Fix: correct the ownership in the device record.
- Confidence: verified enum names (deviceEnrollmentType) - https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-deviceenrollmenttype?view=graph-rest-1.0

## Priority 2 - hardening and coverage

### INTUNE-DEVICE-ENCRYPTION-NOT-READY
- Catches: a Windows device whose encryption readiness is "not ready" or whose policy setting state
  is in error - the policy reports success while the disk stays clear (no TPM, recovery
  environment disabled, firmware).
- Severity: medium.
- Source: intune.yaml; beta; `/deviceManagement/managedDeviceEncryptionStates`; select id,
  deviceName, osVersion, encryptionState, encryptionReadinessState, encryptionPolicySettingState,
  tpmSpecificationVersion, advancedBitLockerStates, userPrincipalName; key id, name deviceName. New query.
- Permission: DeviceManagementConfiguration.Read.All (also accepted:
  DeviceManagementManagedDevices.Read.All).
- Condition: encryptionReadinessState eq notReady or encryptionPolicySettingState in [error,
  conflict, notApplicable] or (encryptionState eq notEncrypted and encryptionReadinessState eq ready).
- Refs: NIST-800-53:SC-28, NIST-800-53:MP-5, CIS-Controls-v8:3.6.
- Fix: fix the readiness blocker (enable TPM, WinRE, firmware mode), then let the policy apply.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddeviceencryptionstate?view=graph-rest-beta

### INTUNE-COMPLIANCE-ANDROID-NO-PLAY-INTEGRITY
- Catches: an assigned Android compliance policy that does not require the Play Integrity (device
  attestation) verdicts, so a tampered device with a reset flag passes.
- Severity: medium.
- Source: intune.yaml; beta; Q-COMPLIANCE-BETA (Android rows told by
  `securityRequireSafetyNetAttestationBasicIntegrity` existing).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: securityRequireSafetyNetAttestationBasicIntegrity eq false or
  securityRequireSafetyNetAttestationCertifiedDevice eq false (any Android policy type).
- Refs: NIST-800-53:SI-7, NIST-800-53:AC-19, CIS-Controls-v8:4.1.
- Fix: require both basic integrity and certified device; add a security patch level floor.
- Confidence: verified field names (androidDeviceOwnerCompliancePolicy) - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androiddeviceownercompliancepolicy?view=graph-rest-beta

### INTUNE-ENROLL-DEVICE-LIMIT-HIGH
- Catches: an enrolment limit configuration allowing more than N devices per user; a high limit
  hides sprawl and lets stolen credentials enrol more devices. The Entra registration quota is
  ENTRA-DEVREG-QUOTA-HIGH.
- Severity: low.
- Source: intune.yaml; v1.0; Q-ENROLL (rows of type deviceEnrollmentLimitConfiguration told by
  `limit` existing).
- Permission: DeviceManagementServiceConfig.Read.All.
- Condition: limit exists and limit gt 5 (threshold `intune.enroll-device-limit-max`); evidence
  includes priority (the default configuration has the lowest priority).
- Refs: NIST-800-53:AC-19, NIST-800-53:CM-8.
- Fix: lower the default; give enrolment managers a separate, named configuration.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentlimitconfiguration?view=graph-rest-1.0

### INTUNE-ENROLL-ESP-NONE
- Catches: no assigned enrolment status page configuration that blocks device use until apps and
  policies install - a new PC reaches the desktop unprotected.
- Severity: low.
- Source: intune.yaml; v1.0; Q-ENROLL with expand assignments (rows told by
  `showInstallationProgress` existing).
- Permission: DeviceManagementServiceConfig.Read.All.
- Condition: must-exist - count lt 1 where showInstallationProgress eq true and
  blockDeviceSetupRetryByUser exists and assignments notempty. Pairs with the rule
  INTUNE-ENROLL-ESP-USE-ON-FAILURE. A tenant imaging through another tool accepts once.
- Refs: NIST-800-53:CM-2, NIST-800-53:CM-6.
- Fix: create the ESP, select the security apps as blocking apps, timeout 60 min.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-windows10enrollmentcompletionpageconfiguration?view=graph-rest-1.0

### INTUNE-ESEC-APP-CONTROL-NONE
- Catches: no assigned endpoint-security App Control for Business policy (settings-catalog family
  endpointSecurityApplicationControl) - standard users can install and run anything the store
  block does not catch. Device-side twins: WS-WDAC-AUDIT-ONLY, WS-REG-APPLOCKER-ENFORCED (windows-estate).
- Severity: medium.
- Source: intune.yaml; beta; Q-CONFIGPOLICIES.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: must-exist - count lt 1 where isAssigned eq true and templateReference.templateFamily
  eq endpointSecurityApplicationControl.
- Refs: NIST-800-53:CM-7(5), NIST-800-53:CM-11, CIS-Controls-v8:2.5, MITRE-ATTACK:T1204.002.
- Fix: deploy the policy in audit mode to a pilot ring, then enforce.
- Confidence: likely (templateFamily enum includes endpointSecurityApplicationControl) - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationpolicytemplatereference?view=graph-rest-beta

### INTUNE-DELIVERY-OPTIMIZATION-NONE
- Catches: no assigned Delivery Optimization profile, so every PC pulls update and app content
  across the WAN on its own.
- Severity: low.
- Source: intune.yaml; v1.0; Q-DEVICECONFIG (rows told by `deliveryOptimizationMode` existing).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: must-exist - count lt 1 where deliveryOptimizationMode exists and assignments notempty.
  Settings-catalog equivalents are not seen (settings bodies are not queried) - a tenant using them
  accepts once.
- Refs: NIST-800-53:SC-5, NIST-800-53:CP-2.
- Fix: create a DO profile with LAN peering by site or subnet and a business-hours bandwidth cap.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowsdeliveryoptimizationconfiguration?view=graph-rest-1.0

### INTUNE-WIFI-PROFILE-PSK
- Catches: an assigned corporate Wi-Fi profile secured by a pre-shared key or WEP instead of
  certificate/EAP - the key sits on every device and cannot be revoked per device.
- Severity: low (medium when connectAutomatically is true).
- Source: intune.yaml; v1.0; Q-DEVICECONFIG (Wi-Fi rows told by `wifiSecurityType` existing; the
  key value is never selected).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: wifiSecurityType in [wep, wpaPersonal, wpa2Personal] and assignments notempty.
- Refs: NIST-800-53:IA-3, NIST-800-53:AC-18(1).
- Fix: move to WPA-Enterprise with EAP-TLS and device certificates; keep PSK for guest or
  dedicated-device networks only.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowswificonfiguration?view=graph-rest-1.0

### INTUNE-ANDROID-OWNER-RESTRICTIONS-WEAK
- Catches: an assigned fully-managed Android device restriction profile that leaves developer
  options, unknown-source installs or factory reset open.
- Severity: medium.
- Source: intune.yaml; v1.0; Q-DEVICECONFIG (rows told by `factoryResetBlocked` existing).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: assignments notempty and (securityDeveloperSettingsEnabled eq true or
  securityAllowDebuggingFeatures eq true or appsAllowInstallFromUnknownSources eq true or
  factoryResetBlocked eq false).
- Refs: NIST-800-53:CM-7, NIST-800-53:AC-19, CIS-Controls-v8:4.1.
- Fix: block developer settings and unknown sources, block factory reset (or set factory reset
  protection accounts).
- Confidence: likely (field names of androidDeviceOwnerGeneralDeviceConfiguration) - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androiddeviceownergeneraldeviceconfiguration?view=graph-rest-1.0

### INTUNE-ANDROID-SYSTEM-UPDATE-POSTPONED
- Catches: a fully-managed Android restriction profile whose system update setting is postpone or
  device default - OS updates are deferred indefinitely.
- Severity: low.
- Source: same rows as above.
- Condition: assignments notempty and systemUpdateInstallType in [postpone, deviceDefault].
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.4.
- Fix: set automatic or windowed install.
- Confidence: likely (same page).

### INTUNE-ANDROID-ENROLLMENT-PROFILE-UNUSED
- Catches: a corporate Android enrolment profile with no enrolled devices long after creation -
  leftover tokens and QR codes that still enrol devices into a profile nobody maintains.
- Severity: low.
- Source: intune.yaml; v1.0; shared query of INTUNE-ANDROID-PROFILE-TOKEN-EXPIRED
  (`/deviceManagement/androidDeviceOwnerEnrollmentProfiles`) with enrolledDeviceCount and
  createdDateTime added.
- Condition: enrolledDeviceCount eq 0 and createdDateTime age-gt 90 (threshold
  `intune.enrollment-profile-unused-days`).
- Refs: NIST-800-53:CM-8(3), NIST-800-53:AC-19.
- Fix: delete the profile and revoke its token.
- Confidence: verified (fields on androidDeviceOwnerEnrollmentProfile).

### INTUNE-MAM-OFFLINE-WIPE-LONG
- Catches: an app protection policy that lets corporate data stay on a device that has been offline
  for more than N days before wiping, or sets no minimum OS/app version, so stale and old clients
  keep data.
- Severity: low.
- Source: intune.yaml; v1.0; Q-MAM-IOS / Q-MAM-ANDROID.
- Condition: periodOfflineBeforeWipeIsEnforced absent, or its day count gt 90 (ISO 8601 duration -
  duration comparison is an engine gap; interim: notmatch `^P(([1-8]?[0-9])|90)D$`), or
  minimumRequiredOsVersion empty.
- Refs: NIST-800-53:AC-19, NIST-800-53:MP-6, NIST-800-53:SI-2.
- Fix: offline wipe at 90 days or less; set OS and app minimums.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-managedappprotection?view=graph-rest-1.0

### ENTRA-CA-BASELINE-APP-PROTECTION
- Catches: no enforced Conditional Access policy requires an app protection policy (or an approved
  client app) for iOS and Android access to Office 365 - users outside the MAM scope read mail on
  phones with no protection at all.
- Severity: medium.
- Source: entra.yaml; v1.0; Q-CA.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where state enabled and conditions.platforms.includePlatforms
  contains iOS (and android, or all) and grantControls.builtInControls contains compliantApplication
  (approvedApplication also accepted) and conditions.applications.includeApplications contains
  Office365 or All.
- Refs: NIST-800-53:AC-19, NIST-800-53:AC-20(3), CIS-M365:5.2.2.4.
- Fix: create the policy (require app protection policy) for iOS/Android against Office 365,
  report-only first.
- Confidence: verified (conditionalAccessGrantControls builtInControls enum) - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0

### INTUNE-APPCONFIG-OUTLOOK-ACCOUNTS-OPEN
- Catches: no assigned managed-app configuration that restricts the mail client to organisation
  accounts only, so users add personal accounts beside the corporate one in the same managed app.
- Severity: low.
- Source: intune.yaml; v1.0; `/deviceAppManagement/targetedManagedAppConfigurations`; expand
  assignments; fields id, displayName, customSettings (name/value pairs), isAssigned; key id. New query.
- Permission: DeviceManagementApps.Read.All.
- Condition: must-exist - count lt 1 where isAssigned eq true and `customSettings[].name` contains
  IntuneMAMAllowedAccountsOnly and `customSettings[].value` contains Enabled (array leaves: both
  must hold on the same element - engine gap noted; interim accept either).
- Refs: NIST-800-53:AC-20, NIST-800-53:AC-4.
- Fix: create the app configuration policy for managed apps with allowed-accounts-only and the
  organisation's UPN suffixes.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-targetedmanagedappconfiguration?view=graph-rest-1.0

### INTUNE-WIN32-APP-DETECTION-NOT-VERSIONED
- Catches: an assigned Win32 app whose detection rules do not compare a version (file version or
  MSI product version with an operator), so a newer installed build is "not detected" and the app
  retries forever.
- Severity: low.
- Source: intune.yaml; beta; `/deviceAppManagement/mobileApps`; filter
  `isof('microsoft.graph.win32LobApp') and isAssigned eq true`; select id, displayName,
  displayVersion, detectionRules, rules; key id. New query.
- Permission: DeviceManagementApps.Read.All.
- Condition: `detectionRules[].detectionType` notin [version] and `detectionRules[].operator` in
  [notConfigured, equal] and no script detection (`detectionRules[].scriptContent` absent).
- Refs: NIST-800-53:CM-8, NIST-800-53:SI-2.
- Fix: use "file version greater than or equal" or MSI product-version detection, or a script.
- Confidence: guess (detection-rule subtype fields: win32LobAppFileSystemDetection.detectionType,
  win32LobAppProductCodeDetection.productVersionOperator) - https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-win32lobapp?view=graph-rest-beta

### INTUNE-RBAC-ASSIGNMENT-UNSCOPED
- Catches: an Intune role assignment whose scope is all devices or all users on a role other than
  the full administrator - a helpdesk role that can act on the whole estate.
- Severity: medium.
- Source: intune.yaml; beta; `/deviceManagement/roleAssignments?$expand=roleDefinition`; fields id,
  displayName, scopeType, resourceScopes, members, roleDefinition.displayName,
  roleDefinition.isBuiltIn; key id. New query.
- Permission: DeviceManagementRBAC.Read.All.
- Condition: scopeType in [allDevices, allLicensedUsers, allDevicesAndLicensedUsers] and
  roleDefinition.displayName notmatch threshold `intune.rbac-full-scope-role-pattern` (default
  `^(Intune Administrator|Endpoint Security Manager)$`).
- Refs: NIST-800-53:AC-6(1), NIST-800-53:AC-2(7), CIS-Controls-v8:6.8.
- Fix: scope the assignment to the groups the team serves; use scope tags.
- Confidence: likely (scopeType enum on deviceAndAppManagementRoleAssignment, beta) - https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-deviceandappmanagementroleassignment?view=graph-rest-beta

### INTUNE-ROLE-CUSTOM-SCRIPT-RIGHTS
- Catches: a custom Intune role that grants script or app creation and assignment, or remote wipe -
  code execution as SYSTEM on every targeted PC, handed out under a custom name nobody reviews.
  (Counting the human holders needs group expansion - a later join.)
- Severity: medium.
- Source: intune.yaml; v1.0; `/deviceManagement/roleDefinitions`; filter `isBuiltIn eq false`;
  fields id, displayName, isBuiltIn, rolePermissions (resourceActions.allowedResourceActions); key id. New query.
- Permission: DeviceManagementRBAC.Read.All.
- Condition: `rolePermissions[].resourceActions[].allowedResourceActions` match
  `(DeviceConfigurations_(Create|Assign)|MobileApps_(Create|Assign)|ManagedDevices_RemoteTasks|RemoteTasks_Wipe|DeviceHealthScripts|ManagementScripts)`
  (threshold `intune.role-powerful-action-pattern`).
- Refs: NIST-800-53:AC-6(1), NIST-800-53:CM-5, CIS-Controls-v8:6.8.
- Fix: split the role; keep script and app assignment with named administrators.
- Confidence: likely (resourceAction strings are documented per built-in role) - https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-roledefinition?view=graph-rest-1.0

### INTUNE-MAA-POLICY-NONE
- Catches: no multi-admin-approval access policy for destructive device actions, scripts or RBAC
  changes - a single compromised administrator can wipe every device.
- Severity: medium.
- Source: intune.yaml; beta; `/deviceManagement/operationApprovalPolicies`; fields id, displayName,
  policyType, policyPlatform, approverGroupIds, lastModifiedDateTime; key id. New query.
- Permission: DeviceManagementRBAC.Read.All.
- Condition: must-exist - count lt 1 where policyType in [deviceWipe, deviceRetire, deviceDelete]
  (one rule); optional second rule for policyType in [script, app, role].
- Refs: NIST-800-53:AC-5, NIST-800-53:CM-5(1), CIS-Controls-v8:5.4.
- Fix: create access policies with an approver group of at least two named staff.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-operationapprovalpolicy?view=graph-rest-beta

### INTUNE-MDM-USER-SCOPE-ALL
- Catches: the Intune MDM (or MAM) mobility policy applies to all users, so any user can enrol a
  personal Windows PC by adding a work account, unless personal enrolment is blocked
  (INTUNE-ENROLL-PERSONAL-ALLOWED).
- Severity: low.
- Source: intune.yaml; beta; `/policies/mobileDeviceManagementPolicies` and
  `/policies/mobileAppManagementPolicies`; fields id, displayName, appliesTo, isValid,
  includedGroups; key id. New queries (two rules).
- Permission: Policy.Read.All.
- Condition: displayName match `Intune` and appliesTo eq all.
- Refs: NIST-800-53:AC-19, NIST-800-53:CM-8.
- Fix: set the scope to a named group, or keep All and block personal Windows enrolment.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/mobilitymanagementpolicy?view=graph-rest-beta

### INTUNE-SHAREDPC-GUEST-ALLOWED
- Catches: an assigned shared PC profile that allows guest accounts, or a kiosk profile with
  auto-logon outside a kiosk - unauthenticated access to a device with cached data.
- Severity: low.
- Source: intune.yaml; v1.0; Q-DEVICECONFIG (shared PC rows told by `allowedAccounts` existing).
- Condition: assignments notempty and allowedAccounts contains guest.
- Refs: NIST-800-53:AC-14, NIST-800-53:AC-2.
- Fix: allow domain accounts only; keep kiosk auto-logon on dedicated kiosk groups.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-sharedpcconfiguration?view=graph-rest-1.0

### INTUNE-CORPORATE-IDENTIFIERS-NONE
- Catches: personal Windows enrolment is blocked but no corporate device identifiers are uploaded,
  so the block relies on the enrolment path alone. Low; a tenant that enrols through hybrid join or
  Autopilot accepts once.
- Severity: low.
- Source: intune.yaml; beta; `/deviceManagement/importedDeviceIdentities`; select id,
  importedDeviceIdentityType, lastContactedDateTime; key id. New query.
- Permission: DeviceManagementServiceConfig.Read.All.
- Condition: count none.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-19.
- Fix: upload serial numbers or hashes for corporate devices, or record the hybrid-join decision.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-importeddeviceidentity?view=graph-rest-beta

### INTUNE-CERT-PROFILE-RENEWAL-LOW
- Catches: an assigned SCEP or PKCS certificate profile with a renewal threshold under N percent of
  validity, or a validity period over N years - devices renew too late or carry long-lived keys. The
  pushed root's own expiry needs certificate decoding (engine gap).
- Severity: low.
- Source: intune.yaml; v1.0; Q-DEVICECONFIG (rows told by `renewalThresholdPercentage` existing).
- Condition: assignments notempty and (renewalThresholdPercentage lt 20 or
  (certificateValidityPeriodScale eq years and certificateValidityPeriodValue gt 2)).
- Refs: NIST-800-53:SC-17, NIST-800-53:IA-5(2).
- Fix: renewal threshold 20-50 percent; validity 1-2 years.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows81scepcertificateprofile?view=graph-rest-1.0

### INTUNE-TRUSTED-ROOT-PROFILE-REVIEW
- Catches: every assigned trusted-root certificate profile, as a review list - each root pushed to
  devices widens what they trust (an inspection CA on the wrong groups, an old internal root left
  behind). Accept each once documented.
- Severity: info.
- Source: intune.yaml; v1.0; Q-DEVICECONFIG (rows told by `certFileName` existing; the certificate
  bytes are never selected); fields certFileName, destinationStore, assignments.
- Condition: `each: any` where assignments notempty.
- Refs: NIST-800-53:SC-17, NIST-800-53:SC-8.
- Fix: remove obsolete roots; scope the inspection root to the groups behind inspection.
- Confidence: verified (windows81TrustedRootCertificate fields).

### INTUNE-LAPS-BACKUP-STALE / XS-DEVICE-WINDOWS-NO-LAPS-BACKUP
- Catches: (a) a device whose Windows LAPS password backup in Entra is older than the rotation
  window plus a grace - the stored password may be stale and the local admin password has been
  usable too long; (b) an active managed Windows device with no LAPS backup at all (store anti-join).
- Severity: (a) medium; (b) medium.
- Source: (a) entra.yaml; v1.0; `/directory/deviceLocalCredentials`; select id, deviceName,
  lastBackupDateTime, refreshDateTime; key id; the password is never requested (the credentials
  relationship stays unselected). (b) cross-system.yaml store join of those rows (entity_type
  device-local-credential) with B6 intune_devices on deviceName, where os eq Windows and last_sync
  within 30 days and no credential row; both sides usable.
- Permission: DeviceLocalCredential.ReadBasic.All.
- Condition: (a) lastBackupDateTime age-gt 37 (threshold `intune.laps-backup-max-age-days`); (b)
  `each: any`.
- Refs: NIST-800-53:IA-5(1), NIST-800-53:CP-9, MITRE-ATTACK:T1078.003.
- Fix: fix the LAPS policy scope (INTUNE-ESEC-LAPS-NONE) and the Entra LAPS switch
  (ENTRA-DEVREG-LAPS-OFF); force a rotation on stale devices.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/devicelocalcredentialinfo?view=graph-rest-1.0

### ENTRA-BITLOCKER-KEY-OLD / XS-DEVICE-ENCRYPTED-NO-RECOVERY-KEY
- Catches: (a) a BitLocker recovery key in Entra older than N years (never rotated after use or
  policy change) - the inventory query that makes (b) possible; (b) an active managed Windows
  device reported encrypted with no recovery key escrowed for its Entra device id - data is lost at
  the next TPM or firmware event.
- Severity: (a) low; (b) high.
- Source: (a) entra.yaml; v1.0; `/informationProtection/bitlocker/recoveryKeys`; select id,
  createdDateTime, deviceId, volumeType; key id; the key material is never selected (it needs a
  separate GET per key with a different permission). (b) cross-system.yaml store anti-join: B6
  intune_devices (add `azureADDeviceId` and keep `isEncrypted` in Q-MDEVICES) where os Windows,
  encrypted = 1 and last_sync within 30 days, NOT EXISTS recovery-key row with deviceId =
  azureADDeviceId and volumeType operatingSystemVolume; both sides usable (entra run ok).
- Permission: BitLockerKey.ReadBasic.All.
- Condition: (a) createdDateTime age-gt 1095 (threshold `entra.bitlocker-key-max-age-days`); (b)
  `each: any`, evidence names device and last sync.
- Refs: NIST-800-53:CP-9, NIST-800-53:SC-28, CIS-Controls-v8:11.1.
- Fix: run a remediation that backs the OS-volume protector up to Entra; require escrow before
  encryption in the disk-encryption policy.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/bitlockerrecoverykey?view=graph-rest-1.0

### INTUNE-APPLE-TOKEN-PERSONAL-ACCOUNT
- Catches: the Apple ID behind the MDM push certificate, the automated-enrolment token or the
  volume-purchase token is a personal or consumer address rather than a role mailbox - the renewal
  warning goes to someone who may leave, and renewal needs that same Apple ID. The Google side is
  INTUNE-MGP-CONSUMER-ACCOUNT.
- Severity: medium.
- Source: intune.yaml; v1.0; the existing APNs, DEP and VPP queries with `appleIdentifier`
  (applePushNotificationCertificate, depOnboardingSettings) and `appleId` (vppTokens) added to the
  selects; three rules.
- Permission: DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All.
- Condition: the identifier field match threshold `intune.consumer-mail-pattern` (default
  `@(gmail|googlemail|outlook|hotmail|live|yahoo|icloud)\.`), or notmatch threshold
  `intune.role-mailbox-pattern` when set.
- Refs: NIST-800-53:IR-6, NIST-800-53:CP-2, NIST-800-53:AC-2.
- Fix: renew the certificate and tokens under a role Apple ID held by a shared mailbox with
  documented recovery.
- Confidence: verified (appleIdentifier on applePushNotificationCertificate and depOnboardingSetting; appleId on vppToken).

### ENTRA-SIGNIN-BLOCKED-DEVICE-COMPLIANCE-RECENT
- Catches: sign-ins in the last N days blocked because the device was not compliant or not managed
  (Conditional Access device errors) - after a compliance rollout, these are the users cut off and
  the devices whose compliance data is wrong.
- Severity: low (medium when one user or device repeats above a threshold - grouping gap).
- Source: entra.yaml; v1.0; `/auditLogs/signIns`; filter
  `createdDateTime ge {DAYS_AGO:7} and (status/errorCode eq 53000 or status/errorCode eq 53001 or status/errorCode eq 530003)`;
  select id, userPrincipalName, userId, appDisplayName, createdDateTime, deviceDetail,
  appliedConditionalAccessPolicies; key `{userId}|{deviceDetail.deviceId}`; maxPages capped. New query.
- Permission: AuditLog.Read.All + Directory.Read.All.
- Condition: `each: any`.
- Refs: NIST-800-53:AC-19, NIST-800-53:AU-6, CIS-M365:5.2.2.9.
- Fix: fix the device's compliance or enrolment; adjust the rollout ring if a whole group is blocked.
- Confidence: likely (filter on status/errorCode documented for sign-ins) - https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0

## Priority 3 - lifecycle, hygiene, cost

### INTUNE-ANALYTICS-STARTUP-SCORE-LOW
- Catches: a device whose Endpoint analytics startup performance score is below N, or whose core
  boot time exceeds N seconds - the slow-PC complaint measured without touching the PC. An empty
  result means Endpoint analytics is not enabled: n/a, never a pass.
- Severity: low.
- Source: intune.yaml; beta; `/deviceManagement/userExperienceAnalyticsDevicePerformance`; select
  id, deviceName, model, manufacturer, coreBootTimeInMs, coreLoginTimeInMs, startupPerformanceScore,
  diskType, restartCount, blueScreenCount; key id, name deviceName. New query.
- Permission: DeviceManagementManagedDevices.Read.All.
- Condition: startupPerformanceScore lt 50 (threshold `intune.startup-score-min`) or coreBootTimeInMs
  gt 60000 (threshold `intune.core-boot-max-ms`) or blueScreenCount gt 0.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-2.
- Fix: look at the model and disk type; replace HDDs, trim startup apps, fix the crashing driver.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-userexperienceanalyticsdeviceperformance?view=graph-rest-beta

### INTUNE-MAM-REGISTRATION-OLD-PLATFORM
- Catches: a managed-app registration (a device/app pair under app protection) active recently on
  an OS major version below the floor - data under MAM on an unpatched phone.
- Severity: low.
- Source: intune.yaml; v1.0; `/deviceAppManagement/managedAppRegistrations`; select id,
  appIdentifier, platformVersion, applicationVersion, deviceType, lastSyncDateTime, userId; key id. New query.
- Permission: DeviceManagementApps.Read.All.
- Condition: lastSyncDateTime age-lt 30 and platformVersion match threshold
  `intune.mam-old-platform-pattern` (default `^(1[0-5]|[0-9])\.` for iOS and `^(1[01]|[0-9])\.` for
  Android - two rules, one query, told apart by `appIdentifier` type fields).
- Refs: NIST-800-53:SI-2, NIST-800-53:AC-19.
- Fix: set minimum OS and app versions in conditional launch; the registration then blocks itself.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-managedappregistration?view=graph-rest-1.0

### INTUNE-DRIVER-UPDATE-PROFILE-NONE
- Catches: no Windows driver update profile exists - drivers and firmware are nobody's job in
  Intune. A tenant that drives firmware through another tool accepts once.
- Severity: low.
- Source: intune.yaml; beta; `/deviceManagement/windowsDriverUpdateProfiles`; select id,
  displayName, approvalType, deviceReporting, newUpdates; expand assignments; key id. New query.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: must-exist - count lt 1 where assignments notempty.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.4.
- Fix: create a driver update profile (automatic approval for a pilot ring, manual for broad).
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-softwareupdate-windowsdriverupdateprofile?view=graph-rest-beta

### INTUNE-RETIRED-FEATURE-IN-USE  (two rules, two queries)
- Catches: (a) a Windows Information Protection policy still exists (feature retired; policies stop
  applying and cannot be edited); (b) an on-premises Exchange connector is still configured
  (retired with on-premises Exchange device access).
- Severity: low.
- Source: intune.yaml; beta; (a) `/deviceAppManagement/mdmWindowsInformationProtectionPolicies` and
  `/deviceAppManagement/windowsInformationProtectionPolicies` (select id, displayName,
  lastModifiedDateTime); (b) `/deviceManagement/exchangeConnectors` (select id, serverName,
  status, lastSyncDateTime). Keys id.
- Permission: DeviceManagementApps.Read.All; DeviceManagementServiceConfig.Read.All.
- Condition: count some (each).
- Refs: NIST-800-53:SA-22, NIST-800-53:CM-7.
- Fix: remove the WIP policies after moving the data-protection intent to app protection or
  Purview; delete the Exchange connector.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-mdmwindowsinformationprotectionpolicy?view=graph-rest-beta,
  https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-devicemanagementexchangeconnector?view=graph-rest-1.0

### INTUNE-BASELINE-TEMPLATE-SUPERSEDED
- Catches: an assigned settings-catalog policy built from a template whose lifecycle state is
  superseded, deprecated or retired - most often an old security baseline version that is now
  read-only and misses settings for current Windows.
- Severity: low.
- Source: intune.yaml; beta; `/deviceManagement/configurationPolicyTemplates`; select id,
  displayName, templateFamily, lifecycleState, version; key id; plus a cross-system store rule that
  joins those rows to Q-CONFIGPOLICIES rows on `templateReference.templateId` where isAssigned = 1.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: template rule: lifecycleState in [superseded, deprecated, retired] (review list); join
  rule: `each: any` on assigned policies using such a template.
- Refs: NIST-800-53:CM-2, NIST-800-53:CM-6, CIS-Controls-v8:4.1.
- Fix: create the baseline on the current version, copy the overrides, re-assign, delete the old.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationpolicytemplate?view=graph-rest-beta

### INTUNE-AGENT-APP-VERSION-OLD
- Catches: devices running a management agent app (company portal, management extension, Intune
  app) below a version floor - old agents fail new enrolment flows and app features.
- Severity: low.
- Source: intune.yaml; v1.0; `/deviceManagement/detectedApps`; filter
  `startswith(displayName,'Company Portal') or startswith(displayName,'Microsoft Intune')`; select
  id, displayName, version, deviceCount, platform; key id. New query.
- Permission: DeviceManagementManagedDevices.Read.All.
- Condition: version match threshold `intune.agent-old-version-pattern` (empty = n/a; the tenant
  sets it from the current release) and deviceCount gt 0.
- Refs: NIST-800-53:SI-2.
- Fix: let the store update the app; find devices blocked from updating.
- Confidence: likely (detectedApps filter support on displayName) - https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-detectedapp?view=graph-rest-1.0

### INTUNE-ASSIGNMENT-ALL-NO-FILTER
- Catches: a policy or app assigned to all devices or all users without an assignment filter - it
  lands on servers enrolled by mistake, shared PCs and tablets alike. Blocked today: the target type
  is only in `@odata.type`, which the engine cannot address; written for when it can.
- Severity: low.
- Source: intune.yaml; v1.0; Q-DEVICECONFIG, Q-COMPLIANCE-ASSIGN, Q-CONFIGPOLICIES (expand
  assignments); fields assignments[].target.@odata.type,
  assignments[].target.deviceAndAppManagementAssignmentFilterId.
- Condition: `assignments[].target.@odata.type` match `all(Devices|LicensedUsers)AssignmentTarget`
  and the same element's deviceAndAppManagementAssignmentFilterId empty.
- Refs: NIST-800-53:CM-6.
- Fix: add a platform filter or target a group.
- Confidence: verified field shape - https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-alldevicesassignmenttarget?view=graph-rest-1.0

### INTUNE-POLICY-CMD-BLOCK-BROAD
- Catches: a settings-catalog policy that disables the command prompt or registry editor for its
  targets and is assigned to all users - it also hits administrators and installers, so software
  installs fail in ways nobody connects to the policy.
- Severity: low.
- Source: intune.yaml; beta; `for_each` Q-CONFIGPOLICIES (isAssigned eq true) ->
  `/deviceManagement/configurationPolicies/{id}/settings`; fields settingInstance.settingDefinitionId,
  settingInstance.choiceSettingValue.value; key `{parent.id}|{settingInstance.settingDefinitionId}`;
  the parent's assignments from the same list query (expand assignments).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: settingDefinitionId match `(?i)(disablecmd|disableregistrytools)` and
  choiceSettingValue.value notmatch `_0$|disabled` and parent assigned to all users (needs the
  `@odata.type` gap, or threshold group id list `intune.broad-group-ids`).
- Refs: NIST-800-53:CM-7, NIST-800-53:AC-6.
- Fix: scope the policy to standard-user devices or exclude administrator accounts.
- Confidence: guess (settingDefinitionId text for the ADMX-backed settings) - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationsetting?view=graph-rest-beta

### INTUNE-POLICY-NAME-NONCONFORMING
- Catches: a policy or profile whose display name does not follow the tenant's naming convention
  (platform, purpose, ring) - n/a until the tenant sets the pattern.
- Severity: info.
- Source: intune.yaml; Q-DEVICECONFIG, Q-COMPLIANCE-ASSIGN, Q-CONFIGPOLICIES; field displayName / name.
- Condition: displayName notmatch threshold `intune.policy-name-pattern` (empty = n/a).
- Refs: NIST-800-53:CM-8.
- Fix: rename.
- Confidence: verified.

### INTUNE-APP-UNASSIGNED
- Catches: an application in the tenant that is assigned to nobody and not a built-in or store
  placeholder - uploaded content that never shipped.
- Severity: info.
- Source: intune.yaml; v1.0; `/deviceAppManagement/mobileApps`; filter `isAssigned eq false`; select
  id, displayName, publisher, createdDateTime, lastModifiedDateTime; key id. New query.
- Permission: DeviceManagementApps.Read.All.
- Condition: createdDateTime age-gt 90 and publisher notmatch `^Microsoft` (threshold
  `intune.app-unassigned-ignore-publisher-pattern`).
- Refs: NIST-800-53:CM-8(3).
- Fix: assign or delete.
- Confidence: verified (isAssigned filter on mobileApps).

### XS-INTUNE-DEVICE-DUPLICATE-SERIAL
- Catches: more than one Intune device record with the same serial number - re-imaged devices that
  kept the old record; compliance and inventory count them twice. Group-by needs the store protocol.
- Severity: low.
- Source: cross-system.yaml; store; over B6 intune_devices (serial column):
  `SELECT serial, COUNT(*) AS records, MIN(last_sync) AS oldest_sync, GROUP_CONCAT(device_name, ', ') AS names
  FROM intune_devices WHERE serial IS NOT NULL AND serial <> '' GROUP BY serial HAVING COUNT(*) > 1`,
  intune run demanded ok. Key serial.
- Condition: `each: any`; severity low; evidence lists the records.
- Refs: NIST-800-53:CM-8.
- Fix: delete the older records.
- Confidence: verified (serialNumber is in Q-MDEVICES).

### XS-INTUNE-DEVICE-USER-UNLICENSED
- Catches: a managed device whose primary user has no enabled Intune service plan - a licence
  compliance finding and a device that may stop receiving policy.
- Severity: low.
- Source: cross-system.yaml; store join of B6 intune_devices (primary_upn) with B5 entra_users
  (add `assignedPlans` to Q-USERS, or test `assignedLicenses` against a threshold list of SKUs that
  carry Intune): `WHERE NOT EXISTS (json_each(assignedPlans) with servicePlanId = the Intune plan id
  and capabilityStatus = 'Enabled')`; devices with no primary user excluded (device licences).
- Condition: `each: any`.
- Refs: NIST-800-53:SA-4, NIST-800-53:CM-8.
- Fix: license through a group.
- Confidence: likely (assignedPlans servicePlanId for the Intune plan is a Microsoft constant; verify on first run).

### AZURE-INTUNE-DIAGNOSTIC-SETTINGS-NONE
- Catches: Intune audit and operational logs are not streamed to a Log Analytics workspace or
  storage account - the portal keeps the audit log for a limited time and operational logs not at all.
- Severity: low.
- Source: azure.yaml (existing azure ARM http integration); `path:
  /providers/microsoft.intune/diagnosticSettings`, params api-version=2017-04-01-preview; items
  value; fields name, properties.workspaceId, properties.storageAccountId, properties.logs[] (category,
  enabled, retentionPolicy); key name.
- Permission: Azure Reader on the tenant scope plus the Intune administrator read the provider demands.
- Condition: must-exist - count lt 1 where `properties.logs[].category` contains AuditLogs and
  `properties.logs[].enabled` eq true and (workspaceId notempty or storageAccountId notempty).
- Refs: NIST-800-53:AU-4, NIST-800-53:AU-11, CIS-Controls-v8:8.9.
- Fix: create the diagnostic setting with AuditLogs and OperationalLogs to a workspace with a year's retention.
- Confidence: likely - https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/review-logs-using-azure-monitor

(TLS interception of the device-management endpoints - management, device registration, MDM
check-in hosts - is M365-ENDPOINT-TLS-INTERCEPTED in the Microsoft 365 admin section; add those hosts
to its endpoint list. Per-PC probes are not possible; the companion registry rule
WS-REG-INSPECTION-ROOT-TRUSTED below shows which PCs trust an inspection root.)

## Device-side rules (`rules\workstations.yaml`, cim / registry / eventlog)

### WS-EVT-MDM-AUTOENROLL-FAIL
- Catches: a domain-joined PC whose automatic MDM enrolment failed in the window (the provider's
  "auto MDM enroll failed" event) - the machine looks healthy in group policy and is outside Intune.
- Severity: medium.
- Source: workstations.yaml; eventlog; log
  `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin`; ids [76]; days 7; key
  `{host}|{id}`.
- Condition: count some per host (or `each: any`); evidence shows the event text with the error code.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-19.
- Fix: read the error code (licence, MDM scope, credential type), fix the cause, re-run enrolment.
- Confidence: verified (event 76 documented in the auto-enrolment troubleshooting page) - https://learn.microsoft.com/en-us/windows/client-management/mdm/enroll-a-windows-10-device-automatically-using-group-policy

### WS-EVT-MDM-POLICY-ERRORS
- Catches: repeated MDM policy (CSP) errors on a PC in the window - a setting that never applies on
  that build, retried every sync.
- Severity: low.
- Source: same channel; `providers` the same provider; level error; days 1; max 200; key
  `{host}|{id}`.
- Condition: count gt 5 per host (threshold `workstations.mdm-errors-max-per-day`).
- Refs: NIST-800-53:CM-6, NIST-800-53:SI-4.
- Fix: find the CSP in the message, remove or correct the setting for that build.
- Confidence: likely (the eventlog runner's level filter: use `ids` of the known error events if level is not filterable).

### WS-REG-MDM-AUTOENROLL
- Catches: the effective MDM auto-enrolment policy on a PC: not set, or set with a credential type
  that cannot enrol shared PCs. The policy's OU links are an ldap gPLink rule for the AD pack.
- Severity: low.
- Source: workstations.yaml; registry; path
  `SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM`; values [AutoEnrollMDM,
  UseAADCredentialType]; key host.
- Condition: exists eq false, or AutoEnrollMDM ne 1, or UseAADCredentialType ne threshold
  `workstations.mdm-credential-type` (1 user, 2 device; empty = n/a).
- Refs: NIST-800-53:CM-6, NIST-800-53:CM-8.
- Fix: link the auto-enrolment policy to the target OUs with the intended credential type.
- Confidence: verified value names (same page as above).

### WS-REG-MDM-WINS-OVER-GP
- Catches: the effective MDM-over-group-policy precedence on a PC differs from the tenant's decision
  (or is unset where MDM and GPO both manage the device).
- Severity: low.
- Source: registry; path `SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict`;
  values [MDMWinsOverGP]; key host.
- Condition: MDMWinsOverGP ne threshold `workstations.mdm-wins-over-gp` (empty = n/a).
- Refs: NIST-800-53:CM-6.
- Fix: set the policy CSP value through the co-management policy.
- Confidence: verified - https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-controlpolicyconflict

### WS-REG-LEGACY-LAPS-ENABLED
- Catches: the legacy local-admin-password solution client-side extension is still enabled on a PC
  while Windows LAPS is the chosen mechanism - two mechanisms, two accounts, two passwords.
- Severity: low (medium when WS-REG-MDM-AUTOENROLL shows the device is also under Intune LAPS -
  cross-rule correlation is the ranker's job).
- Source: registry; path `SOFTWARE\Policies\Microsoft Services\AdmPwd`; values [AdmPwdEnabled,
  AdminAccountName, PasswordAgeDays]; key host.
- Condition: exists eq true and AdmPwdEnabled eq 1.
- Refs: NIST-800-53:IA-5(1), NIST-800-53:CM-6.
- Fix: retire the legacy policy and package after Windows LAPS covers the device.
- Confidence: verified (legacy LAPS policy key documented in the Windows LAPS migration guidance) - https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-legacy

### WS-REG-ESU-NOT-LICENSED
- Catches: a Windows 10 PC past end of support without an activated Extended Security Updates
  licence - no security fixes at all. Complements INTUNE-DEVICE-WINDOWS-UNSUPPORTED (which cannot
  see ESU).
- Severity: high.
- Source: workstations.yaml; cim; wql `SELECT Name, LicenseStatus FROM SoftwareLicensingProduct
  WHERE Name LIKE '%Extended Security%' AND PartialProductKey IS NOT NULL`; key `{host}|{Name}`;
  targets: workstations whose OS caption matches Windows 10 (targets where).
- Condition: count lt 1 where LicenseStatus eq 1 (judged per host; a host with no rows fails).
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22, CIS-Controls-v8:7.3.
- Fix: buy and activate ESU for the devices that cannot upgrade in time; upgrade the rest.
- Confidence: likely (SoftwareLicensingProduct names for ESU vary by year; confirm the name pattern on first run) - https://learn.microsoft.com/en-us/windows/whats-new/extended-security-updates

### WS-REG-INSPECTION-ROOT-TRUSTED
- Catches: a PC whose machine root store holds a root certificate matching the tenant's inspection
  CA pattern (or any root not on the allow list) - the device will accept intercepted TLS.
- Severity: info (review); medium when the device group should not be behind inspection
  (threshold OU pattern).
- Source: registry; path `SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates`; subkeys true;
  key `{host}|{subkey}` (the subkey is the thumbprint; the blob value is never read).
- Condition: subkey in threshold list `workstations.inspection-root-thumbprints` (empty = n/a).
- Refs: NIST-800-53:SC-8, NIST-800-53:SC-17.
- Fix: scope the root distribution to the groups behind inspection.
- Confidence: verified (the registry layout of the machine ROOT store).


---

## Microsoft 365 admin, Teams, Purview


New checks for `rules/m365.yaml` unless another file is named. Conventions as in
`docs/proposals/microsoft-cloud.md`: Microsoft constants (first-party app ids, SKU and service-plan
ids) are fine; anything tenant-specific is a `threshold.<name>` setting.

Two shared queries introduced here:

- **Q-ROOM-DEVICES** (beta `/teamwork/devices`, select id, deviceType, healthStatus, activityState,
  currentUser, lastModifiedDateTime; filter `deviceType eq 'teamsRoom' or deviceType eq 'touchConsole'`
  if the runner can pass it, else client-side on deviceType) and its per-object child
  `/teamwork/devices/{id}/health` (`for_each` over Q-ROOM-DEVICES, field id). Permission
  TeamworkDevice.Read.All. Used by two rules.
- **Q-EDISCOVERY-CASES** (v1.0 `/security/cases/ediscoveryCases`, select id, displayName, status,
  createdDateTime, lastModifiedDateTime, closedDateTime). Permission eDiscovery.Read.All. Used by
  three rules (one plain, two `for_each`).

---

### M365-SKU-NO-HEADROOM
- Catches: a paid licence SKU whose free seats (enabled minus consumed) are below a floor, so the
  next joiner cannot be licensed until someone reclaims or buys. The existing zero-assigned rule
  looks at the opposite end of the scale.
- Severity: medium (high when free seats are 0).
- Source: `store` rule (integration `keeper`, file `rules/cross-system.yaml` or a new
  `rules/m365-store.yaml`) over the newest m365 run's `/subscribedSkus` rows in `row_seen`:
  `json_extract(attrs,'$.prepaidUnits.enabled')`, `'$.consumedUnits'`, `'$.skuPartNumber'`,
  `'$.capabilityStatus'`; compute `free = enabled - consumed` and `free_pct` in SQL; exclude the
  free-SKU list the m365 pack already uses. The condition engine cannot subtract two fields, which is
  why this is a store rule and not a Graph rule.
- Permission: none beyond the m365 scan (Organization.Read.All already granted).
- Condition: capabilityStatus eq Enabled and enabled gt 0 and (free lt 10 or free_pct lt 2)
  (thresholds `m365.sku-min-free-seats`, `m365.sku-min-free-pct`); severity high when free eq 0.
  Demand a usable newest m365 run (`EXISTS latest_run ... status <> 'failed'`).
- Refs: NIST-800-53:SA-4, NIST-800-53:CP-2, CIS-Controls-v8:2.1.
- Fix: reclaim seats from inactive and disabled accounts (M365-LICENSED-USER-INACTIVE/-DISABLED), or
  raise the order before the next joiner wave.
- Confidence: verified field names (subscribedSku) - https://learn.microsoft.com/en-us/graph/api/resources/subscribedsku?view=graph-rest-1.0

### M365-SKU-IDLE-SEATS
- Catches: a paid SKU with a large share of purchased seats never assigned - money idle, or the
  trace of a bulk removal nobody planned.
- Severity: low.
- Source: same store query as M365-SKU-NO-HEADROOM (identical `text:` so one fetch).
- Permission: as above.
- Condition: capabilityStatus eq Enabled and enabled ge 10 and free_pct gt 3 (threshold
  `m365.sku-max-idle-pct`), paid SKUs only. The register rule REG-LIC-UNUSED-SEATS covers the same
  idea for licences recorded by hand; this one reads the live tenant.
- Refs: NIST-800-53:SA-4, CIS-Controls-v8:2.1.
- Fix: assign the seats or reduce the count at renewal.
- Confidence: verified (same fields).

### M365-APPS-SHARED-ACTIVATION-OFF
- Catches: a session host or shared computer running Microsoft 365 Apps without shared computer
  activation, so every signed-in user burns one of their activations and Office eventually stops
  activating on the host.
- Severity: low.
- Source: `rules/windows-server.yaml` (integration `cim`, protocol `registry`); hive HKLM, path
  `SOFTWARE\Microsoft\Office\ClickToRun\Configuration`, values SharedComputerLicensing, Platform,
  VersionToReport, UpdateChannel; targets: server computers whose name matches threshold
  `winsrv.session-host-name-pattern` (empty = rule n/a, never pass), or the hosts listed in a
  `winsrv.session-hosts` threshold. Key host.
- Permission: remote registry read (StdRegProv) as the cim integration's identity.
- Condition: exists eq true (Office is installed) and SharedComputerLicensing ne 1 (absent counts
  as off).
- Refs: NIST-800-53:CM-6, CIS-Controls-v8:4.1.
- Fix: set shared computer activation in the deployment configuration or by policy and reinstall or
  update the Office installation on the host.
- Confidence: verified registry value - https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/overview-shared-computer-activation
  (the per-user activation-count report is a CSV download, outside the graph runner).

### M365-TEAMS-ROOM-SOFTWARE-OUTDATED
- Catches: a Teams Rooms device or touch console whose Teams app, firmware or operating system
  reports an available update that has sat for a long time; stale rooms lose sign-in and features
  first.
- Severity: low (medium when the Teams client itself is outdated).
- Source: m365.yaml; beta; `for_each` Q-ROOM-DEVICES → `/teamwork/devices/{id}/health`; fields
  softwareUpdateHealth.teamsClientSoftwareUpdateStatus, .firmwareSoftwareUpdateStatus,
  .operatingSystemSoftwareUpdateStatus (each with softwareFreshness, currentVersion,
  availableVersion); key `{parent.id}`, name parent displayName or currentUser.
- Permission: TeamworkDevice.Read.All (application).
- Condition: any of the three `softwareFreshness` values eq updateAvailable (or
  updateAvailableNonUrgent? - confirm the enum on the first run); the "for more than N days" half
  has no timestamp in the resource, so evidence shows current vs available and the device's
  lastModifiedDateTime.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.4.
- Fix: push the update from the Teams admin centre or the vendor's device portal.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/teamworkdevicehealth?view=graph-rest-beta
  and https://learn.microsoft.com/en-us/graph/api/resources/teamworksoftwareupdatehealth?view=graph-rest-beta

### M365-TEAMS-ROOM-UNHEALTHY
- Catches: a Teams Rooms device that is offline, critical or signed out of Teams or Exchange - a
  meeting room nobody can use, usually noticed by the people standing in it.
- Severity: by healthStatus - offline/critical: high, nonUrgent: low.
- Source: m365.yaml; beta; Q-ROOM-DEVICES for healthStatus; and the same `for_each` child as
  above for loginStatus.teamsConnection.connectionStatus, loginStatus.exchangeConnection,
  connection.connectionStatus. Two rules may share the child fetch; refresh 6h.
- Permission: TeamworkDevice.Read.All.
- Condition: healthStatus in [offline, critical, nonUrgent], or (child) any connectionStatus ne
  connected (enum: unknown, connected, disconnected).
- Refs: NIST-800-53:CP-2, NIST-800-53:SI-4.
- Fix: sign the resource account in on the device; check its password policy and conditional
  access (next rule); restart the console.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/teamworkdevice?view=graph-rest-beta
  (healthStatus enum: unknown, offline, critical, nonUrgent, healthy).

### M365-TEAMS-ROOM-ACCOUNT-PASSWORD-EXPIRES
- Catches: a room resource account (identified by its Teams Rooms licence) whose password can
  expire. Rooms sign in unattended; an expired password takes the room offline with no prompt
  anyone sees.
- Severity: medium.
- Source: m365.yaml; v1.0; `/users`; filter
  `assignedLicenses/any(l:l/skuId eq <room sku>)` for each id in threshold `m365.room-sku-ids`
  (defaults: Teams Rooms Pro 4cde982a-ede4-4409-9ae6-b003453c8ea6, Teams Rooms Basic
  6af4b3d6-14bb-4a2a-960c-6c902aad34f3 - Microsoft constants, confirm on first run); select id,
  userPrincipalName, accountEnabled, passwordPolicies, assignedLicenses, signInActivity; key id,
  name userPrincipalName.
- Permission: User.Read.All (+ AuditLog.Read.All for signInActivity).
- Condition: accountEnabled true and passwordPolicies notcontains DisablePasswordExpiration. A
  sibling rule M365-TEAMS-ROOM-ACCOUNT-NO-SIGNIN: signInActivity.lastSuccessfulSignInDateTime
  age-gt 2 (threshold `m365.room-signin-max-days`) - the room is not signing in.
- Refs: NIST-800-53:IA-5, NIST-800-53:AC-2, CIS-Controls-v8:5.2.
- Fix: set the account's password to never expire; keep the room account out of user MFA policies
  (compliant-device or trusted-location policy instead).
- Confidence: verified passwordPolicies and the assignedLicenses filter -
  https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0 ; SKU ids likely -
  https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference

### M365-LICENSE-ADVANCED-AUDIT-PLAN-DISABLED
- Catches: a user whose licence includes the advanced auditing service plan but has that plan
  disabled, so the richer audit events (mail items accessed, search queries) are never written for
  exactly the accounts that paid for them.
- Severity: low.
- Source: m365.yaml; v1.0; `/users`; filter `accountEnabled eq true`; select id,
  userPrincipalName, assignedPlans; top 999; key id. (The shared user query could carry
  assignedPlans, but it is large; keep separate.)
- Permission: User.Read.All.
- Condition: an `assignedPlans[]` element with servicePlanId eq
  2f442157-a11c-46b9-ae5b-6e39ff4e5849 (advanced auditing, Microsoft constant) and capabilityStatus
  ne Enabled - a same-element array condition (engine gap 1). Until it exists: evidence lists the
  element and the rule is marked approximate.
- Refs: NIST-800-53:AU-2, NIST-800-53:AU-12, CIS-Controls-v8:8.2.
- Fix: re-enable the service plan in the licensing group's plan selection.
- Confidence: verified assignedPlans shape - https://learn.microsoft.com/en-us/graph/api/resources/assignedplan?view=graph-rest-1.0 ;
  plan id likely (service-plan reference page above).

### M365-ENDPOINT-TLS-INTERCEPTED
- Catches: a Microsoft 365 endpoint (identity, mail, Graph, Teams) that presents a certificate
  issued by something other than Microsoft's public CAs when reached from the Keeper host - a proxy
  or TLS-inspection layer is decrypting traffic Microsoft says must bypass inspection, which slows
  clients and breaks certificate pinning.
- Severity: high.
- Source: `rules/certificates.yaml` (integration `tls`); targets: the host list in threshold
  `m365.endpoint-hosts` (default: login.microsoftonline.com, outlook.office365.com,
  graph.microsoft.com, teams.microsoft.com - public Microsoft names, not tenant data); fields
  issuer, chainValid, chainErrors, nameMatches, subject; key endpoint.
- Permission: outbound 443 from the Keeper host.
- Condition: issuer notmatch `(Microsoft|DigiCert)` (threshold `m365.endpoint-issuer-pattern`)
  or chainValid eq false.
- Refs: NIST-800-53:SC-8, NIST-800-53:SC-7, CIS-Controls-v8:12.2.
- Fix: add the Microsoft 365 Optimize and Allow categories to the inspection bypass list of every
  proxy and endpoint agent on the path; re-run from a workstation sample (workstation pack) to
  prove the user path.
- Confidence: verified (tls protocol fields are Keeper's own); the Microsoft CA set changes, so
  the issuer pattern is a threshold - https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-network-connectivity-principles

### M365-THIRD-PARTY-STORAGE-ENABLED
- Catches: Office on the web can open and save files to consumer storage providers, which takes
  files out of retention, DLP and backup. The control is the first-party service principal for
  third-party storage being present and disabled; a tenant that never touched the setting has no
  service principal at all, which means enabled.
- Severity: low.
- Source: m365.yaml; v1.0; `/servicePrincipals`; filter
  `appId eq 'c1f33bc0-bdb4-4248-ba9b-096807ddb43e'` (Microsoft constant); select id, appId,
  displayName, accountEnabled; key id.
- Permission: Application.Read.All.
- Condition: must-exist - count lt 1 where accountEnabled eq false.
- Refs: CIS-M365:1.3.7, NIST-800-53:AC-20, NIST-800-53:AC-4.
- Fix: turn off third-party storage in the organisation settings for Microsoft 365 on the web.
- Confidence: likely (the app id is the one the benchmark names; the toggle creates the service
  principal) - https://learn.microsoft.com/en-us/microsoft-365/admin/setup/set-up-file-storage-and-sharing

### M365-REPORTS-NAMES-CONCEALED
- Catches: usage reports are set to conceal user, group and site names. Not wrong in itself, but
  every report-based rule then returns hashes, so leaver, quota and usage checks cannot name the
  object; the rule makes that state visible instead of silent.
- Severity: info.
- Source: m365.yaml; v1.0; `/admin/reportSettings`; field displayConcealedNames; key id (single
  object).
- Permission: ReportSettings.Read.All.
- Condition: displayConcealedNames eq true.
- Refs: NIST-800-53:AU-3, NIST-800-53:PT-2.
- Fix: record the privacy decision; if names are needed for operations, turn concealment off, or
  keep it and accept that report rules work on hashes.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/adminreportsettings?view=graph-rest-1.0

### M365-APPS-MACROS-INTERNET-NOT-BLOCKED
- Catches: no user policy enforces "block macros in Office files from the internet" for Word, Excel
  and PowerPoint, or a policy sets VBA macro notifications weaker than "disable all except
  digitally signed". Macro attachments remain a top initial-access vector; Microsoft's default
  block can be undone by one policy.
- Severity: high.
- Source: `rules/active-directory.yaml` or a new `rules/group-policy.yaml` (integration `files`,
  protocol `file`); path `gpo/*.xml` - GPO XML reports exported by the administrator into
  `imports\gpo\` (one file per GPO, or one `-All` file); format xml; items XPath on the
  administrative-template policy elements under the User configuration
  (`//*[local-name()='Policy']`), fields Name, State, Category, and the drop-down value element;
  plus `_file`. Key `{_file}|{Name}|{Category}`.
- Permission: none at scan time (file import); the export needs GPO read on a domain member.
- Condition: must-exist per application - count lt 1 where Name eq the "block macros from the
  internet" policy name and State eq Enabled and Category contains the application name; a second
  rule for the VBA notification policy where the selected value is not the signed-only option.
  Policy display names are localisation-dependent: thresholds
  `gpo.macro-block-policy-name`, `gpo.vba-notification-policy-name`.
- Refs: NIST-800-53:CM-7, NIST-800-53:SI-3, CIS-Controls-v8:2.7, MITRE-ATTACK:T1566.001.
- Fix: set the two policies in a GPO linked to all users (or the Office cloud policy service) and
  record exceptions per group.
- Confidence: guess on the XML element names (GPO report schema is documented only by example);
  confirm on the first import - https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gporeport
  Policy background: https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked

### M365-APPS-SECURITY-BASELINE-UNSET
- Catches: a Microsoft 365 Apps security-baseline setting (VBA project object-model access,
  packager prompts, Protected View for internet and attachments, legacy file-block, ActiveX
  blocking) that no policy sets, or that a policy sets to the insecure value.
- Severity: medium.
- Source: same GPO XML import as above; the required settings are a threshold list of (policy
  name, required state or value) pairs - `gpo.office-baseline` - which needs a list-of-pairs
  threshold (engine gap; until then one rule per setting, each with two scalar thresholds).
- Permission: as above.
- Condition: per pair, must-exist - count lt 1 where Name eq pair.name and State eq pair.state.
- Refs: NIST-800-53:CM-6, NIST-800-53:CM-7, CIS-Controls-v8:4.1.
- Fix: import the vendor baseline into a GPO or the cloud policy service, roll out in rings,
  record deviations.
- Confidence: guess (same schema caveat); baseline source -
  https://learn.microsoft.com/en-us/deployoffice/security/security-baseline

### M365-PARTNER-CONTRACT-PRESENT
- Catches: a partner contract (reseller, advisor, syndication) exists in the tenant. Each one is an
  outside organisation that may hold delegated administration; every row is a finding until the
  owner accepts it with the partner's scope and end date recorded.
- Severity: medium (review list).
- Source: m365.yaml; v1.0; `/contracts`; select id, contractType, displayName, defaultDomainName,
  customerId; key id, name displayName.
- Permission: Directory.Read.All.
- Condition: `each: any`.
- Companion **M365-PARTNER-SIGNIN-RECENT**: v1.0 `/auditLogs/signIns`; filter
  `createdDateTime ge {DAYS_AGO:30} and crossTenantAccessType eq 'serviceProvider'`; select id,
  userPrincipalName, appDisplayName, createdDateTime, homeTenantId, ipAddress,
  conditionalAccessStatus; key `{homeTenantId}|{userPrincipalName}`; `each: any` - names which
  partner identities actually signed in, so unused relationships can be removed and used ones
  checked for MFA. Permission AuditLog.Read.All + Directory.Read.All. Granular delegated admin
  roles and expiry are not readable from the customer tenant through Graph; that half stays an
  admin-centre review.
- Refs: NIST-800-53:AC-6, NIST-800-53:SA-9, NIST-800-53:PS-7, CIS-Controls-v8:15.1.
- Fix: remove legacy delegated admin privileges; keep only least-privilege, time-bound granular
  relationships per partner; remove partners that never sign in.
- Confidence: verified contract resource - https://learn.microsoft.com/en-us/graph/api/resources/contract?view=graph-rest-1.0 ;
  sign-in filter on crossTenantAccessType likely - https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0

### M365-EDISCOVERY-CASE-STALE
- Catches: an eDiscovery case left active with no change for a long time - its holds keep data
  and storage indefinitely and its members keep search and export rights over the held content.
- Severity: low.
- Source: m365.yaml; v1.0; Q-EDISCOVERY-CASES.
- Permission: eDiscovery.Read.All (application).
- Condition: status eq active and lastModifiedDateTime age-gt 180 (threshold
  `m365.ediscovery-case-idle-days`).
- Refs: NIST-800-53:AU-11, NIST-800-53:AC-6(9), NIST-800-53:SI-12.
- Fix: close the case with legal, which releases its holds; or record why it stays open.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/security-ediscoverycase?view=graph-rest-1.0

### M365-EDISCOVERY-HOLD-ON-CLOSED-CASE
- Catches: a legal hold that is still enabled under a case that is closed - data kept and
  storage consumed after the matter ended; or a hold in error that holds nothing while appearing to.
- Severity: low (medium when status is error).
- Source: m365.yaml; v1.0; `for_each` Q-EDISCOVERY-CASES → `/security/cases/ediscoveryCases/{id}/legalHolds`;
  fields id, displayName, isEnabled, status, createdDateTime, lastModifiedDateTime, errors; key
  `{parent.id}|{id}`; the parent's status is carried into the row.
- Permission: eDiscovery.Read.All.
- Condition: (parent.status ne active and isEnabled eq true) or status eq error.
- Refs: NIST-800-53:AU-11, NIST-800-53:SI-12.
- Fix: release the hold (legal decision) or repair its locations.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/security-ediscoveryholdpolicy?view=graph-rest-1.0

### M365-EDISCOVERY-EXPORT-RECENT
- Catches: an export (or purge) operation run on an eDiscovery case in the last N days - a bulk
  copy of mailboxes or sites leaving the tenant, listed every morning so each one maps to a legal
  request.
- Severity: medium (high for purge).
- Source: m365.yaml; v1.0; `for_each` Q-EDISCOVERY-CASES → `/security/cases/ediscoveryCases/{id}/operations`;
  fields id, action, status, createdDateTime, completedDateTime, createdBy; key `{parent.id}|{id}`;
  refresh 1d. Content searches made outside a case are not visible here (unified audit log only).
- Permission: eDiscovery.Read.All.
- Condition: action in [contentExport, exportResult, exportReport, purgeData] and createdDateTime
  age-lt 7 (threshold `m365.ediscovery-export-window-days`). Filtering on createdDateTime
  server-side with `{DAYS_AGO:7}` if the relationship accepts `$filter`.
- Refs: NIST-800-53:AU-6, NIST-800-53:AC-6(9), CIS-Controls-v8:8.11.
- Fix: confirm each export against the case's request; investigate exports by people outside
  the eDiscovery role groups.
- Confidence: likely (caseOperation action enum from the resource page) -
  https://learn.microsoft.com/en-us/graph/api/resources/security-caseoperation?view=graph-rest-1.0

### M365-IDLE-SESSION-TIMEOUT-OFF
- Catches: no idle session timeout policy exists for Microsoft 365 web apps, so a browser left
  signed in on a shared or home computer stays signed in.
- Severity: low.
- Source: m365.yaml; v1.0; `/policies/activityBasedTimeoutPolicies`; fields id, displayName,
  definition, isOrganizationDefault; key id.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where definition contains `WebSessionIdleTimeout` and
  isOrganizationDefault eq true. The timeout length inside the definition JSON string is a
  second rule once the engine can read JSON-in-a-string (gap): `definition` match
  `"WebSessionIdleTimeout":"0?[0-3]:` as an approximation for "3 hours or less".
- Refs: CIS-M365:1.3.2, NIST-800-53:AC-11, NIST-800-53:AC-12.
- Fix: turn on idle session timeout in the organisation security settings (which writes this
  policy).
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/activitybasedtimeoutpolicy?view=graph-rest-1.0

### M365-TENANT-CONTACT-ACCOUNT-DISABLED
- Catches: a tenant notification address (technical, security and compliance, privacy contact)
  that belongs to a disabled or missing account, so Microsoft's service, security and privacy
  notices go to nobody. The existing rules only check that an address is set.
- Severity: medium.
- Source: `store` rule (integration `keeper`): the newest entra or m365 run's `/organization`
  row (`json_each` over `technicalNotificationMails`, `securityComplianceNotificationMails`,
  `privacyProfile.contactEmail`) left-joined to the Entra user rows (B5 in cross-system.md) on
  lower(mail) or lower(userPrincipalName); the organisation query must select those fields
  (check the shared query; add them if absent).
- Permission: none beyond the existing scans.
- Condition: no matching user (external or group addresses excluded by a threshold pattern
  `m365.contact-external-allow-pattern`) or matched user with accountEnabled eq 0; both sides need
  a usable newest run.
- Refs: NIST-800-53:IR-6, NIST-800-53:AC-2(3).
- Fix: point every notification address at a monitored role mailbox or distribution list.
- Confidence: verified organization fields - https://learn.microsoft.com/en-us/graph/api/resources/organization?view=graph-rest-1.0

### M365-AUDIT-TENANT-CHANGE-RECENT
- Catches: tenant-level directory changes in the last N days - partner added or removed, domain
  added or verified, domain authentication or federation settings changed, company information or
  settings updated. Rare, tenant-wide, and the first step of several takeover techniques.
- Severity: medium (high for federation and domain-authentication changes).
- Source: entra.yaml; v1.0; `/auditLogs/directoryAudits`; filter
  `activityDateTime ge {DAYS_AGO:7} and category eq 'DirectoryManagement' and result eq 'success'`;
  select id, activityDisplayName, activityDateTime, initiatedBy, targetResources, result; key id;
  name activityDisplayName.
- Permission: AuditLog.Read.All.
- Condition: activityDisplayName match
  `^(Add partner|Remove partner|Add (unverified )?domain|Verify domain|Set domain authentication|Set federation settings|Set company information|Update company settings|Set DirSync)`
  (threshold `entra.audit-tenant-activity-pattern`); severity high when it matches
  `(federation|domain authentication)`.
- Refs: MITRE-ATTACK:T1484.002, NIST-800-53:AU-6, NIST-800-53:CM-3, CIS-Controls-v8:8.11.
- Fix: match each event to a change record; revert the ones nobody asked for and treat a
  federation change without a ticket as an incident.
- Confidence: likely (activity names are from the audit activity reference; wording varies) -
  https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities

### M365-COPILOT-SEAT-IDLE
- Catches: a user holding a Copilot licence with no Copilot activity for N days - the most
  expensive per-seat add-on sitting unused.
- Severity: low.
- Source: m365.yaml; beta; `/reports/getMicrosoft365CopilotUsageUserDetail(period='D90')`
  (JSON); fields userPrincipalName, displayName, lastActivityDate, and the per-app last-activity
  dates; key userPrincipalName. Rows are the licensed users as the report sees them; with name
  concealment on (M365-REPORTS-NAMES-CONCEALED) the key is a hash and the rule still counts.
- Permission: Reports.Read.All.
- Condition: lastActivityDate absent or age-gt 60 (threshold `m365.copilot-idle-days`). Rule
  n/a when the tenant has no Copilot SKU (count none on the report is not a pass).
- Refs: NIST-800-53:SA-4, CIS-Controls-v8:2.1.
- Fix: reassign the seat.
- Confidence: likely (report exists in beta and returns JSON; field names from the page) -
  https://learn.microsoft.com/en-us/graph/api/reportroot-getmicrosoft365copilotusageuserdetail?view=graph-rest-beta

---

## Rules once teams-powershell / purview-powershell / exo-powershell exist

One generic line each; cmdlet and property named so the rule writes itself when the integration
lands. Ids are suggestions with no collisions against the loaded rule files.

**purview-powershell** (Security & Compliance PowerShell, `Connect-IPPSSession`)
- PURVIEW-AUDIT-RETENTION-SHORT - no audit retention policy keeps the core workloads' records for
  a year; `Get-UnifiedAuditLogRetentionPolicy` Enabled, RecordTypes, RetentionDuration; must-exist
  with RetentionDuration in [TwelveMonths, ..., TenYears] for each core record type; medium.
- PURVIEW-LABEL-POLICY-NONE - no published label policy with a default label and downgrade
  justification; `Get-LabelPolicy` Mode, Settings (defaultlabelid, requiredowngradejustification);
  must-exist; medium.
- PURVIEW-DLP-POLICY-NOT-ENFORCED - no DLP policy in Mode Enable covering mail, sites, OneDrive
  and Teams with the national identity / bank / card sensitive-information types the tenant names
  in a threshold; `Get-DlpCompliancePolicy` Mode and locations, `Get-DlpComplianceRule`
  ContentContainsSensitiveInformation, BlockAccess; must-exist; medium.
- PURVIEW-DLP-COPILOT-NONE - Copilot SKU present and no enabled DLP policy with the Copilot
  location; `Get-DlpCompliancePolicy` locations; must-exist; low.
- PURVIEW-RETENTION-LABEL-NONE - no retention label published or auto-applied;
  `Get-ComplianceTag`, `Get-RetentionCompliancePolicy` (label policies); must-exist; low.
- PURVIEW-ROLEGROUP-MEMBER-REVIEW - members of the compliance, records, information-protection and
  eDiscovery role groups; `Get-RoleGroupMember`; `each: any` review list joined to Entra
  accountEnabled for a "disabled member" variant; medium.
- PURVIEW-RETENTION-WORKLOAD-UNCOVERED - a workload (mail, sites, OneDrive, groups, Teams
  channels and chats) with no enabled retention policy; `Get-RetentionCompliancePolicy
  -DistributionDetail` Enabled and the location properties; must-exist per workload; high.
- PURVIEW-POLICY-DISTRIBUTION-ERROR - retention, label or DLP policy whose DistributionStatus is
  Error, or Pending for longer than a week; `Get-RetentionCompliancePolicy`,
  `Get-DlpCompliancePolicy`, `Get-LabelPolicy` DistributionStatus, WhenChanged; each; medium.
- PURVIEW-ALERT-POLICY-ROUTING - default alert policies disabled or notifying an address outside
  the monitored list; `Get-ProtectionAlert` Disabled, NotifyUser, Severity; each; high (the
  enabled half is already ScubaGear MS.DEFENDER.5.1).
- PURVIEW-AUDIT-ROLE-HOLDERS - members of the audit reader / audit manager role groups;
  `Get-RoleGroup`, `Get-RoleGroupMember`; review list; low.

**exo-powershell** (Exchange Online PowerShell V3, `Connect-ExchangeOnline`)
- EXO-ADMIN-AUDIT-OFF - `Get-AdminAuditLogConfig` AdminAuditLogEnabled ne true; low (the service
  keeps it on; mostly a sanity row). UnifiedAuditLogIngestionEnabled on the same object is the
  native form of ScubaGear MS.EXO.17.1.
- EXO-AUDIT-SAMPLE-MISSING - `Search-UnifiedAuditLog -ResultSize 1` for each core RecordType over
  the last 24-72 h returns nothing; count none per record type; medium.
- EXO-BOOKINGS-OPEN - `Get-OrganizationConfig` BookingsEnabled with
  `Get-OwaMailboxPolicy` BookingsMailboxCreationEnabled true on the default policy; low.
- EXO-ORG-APP-REVIEW - centrally deployed add-ins; `Get-App -OrganizationApp` DisplayName,
  ProviderName, Enabled, DefaultStateForUser; `each: any` review list; low.
- EXO-AUDIT-ROLE-HOLDERS - `Get-ManagementRoleAssignment -Role 'View-Only Audit Logs','Audit Logs'`
  RoleAssignee outside the expected role groups; low.
- EXO-CUSTOMER-LOCKBOX-OFF - `Get-OrganizationConfig` CustomerLockBoxEnabled ne true; low
  (native form of the Maester CIS 1.3.6 test).
- EXO-SHARED-MAILBOX-SIGNIN-ENABLED - `Get-EXOMailbox -RecipientTypeDetails SharedMailbox` joined
  in the store to Entra users with accountEnabled 1; medium (native form of CIS 1.2.2).

**teams-powershell** (`Connect-MicrosoftTeams`)
- TEAMS-SECURITY-REPORTING-OFF - `Get-CsTeamsMessagingPolicy` AllowSecurityEndUserReporting ne true
  on the global policy, with EXO `Get-ReportSubmissionPolicy` ReportChatMessageEnabled; low.
  (Meeting, federation, email-integration and app policies are already ScubaGear MS.TEAMS.1-5
  through the file import; native rules would read `Get-CsTeamsMeetingPolicy`,
  `Get-CsTenantFederationConfiguration`, `Get-CsTeamsClientConfiguration`,
  `Get-CsTeamsAppPermissionPolicy`.)

**defender-xdr-api** (advanced hunting, POST)
- M365-APPS-PERPETUAL-OFFICE-PRESENT - software inventory rows whose product is a perpetual Office
  release past end of support; count some; high. Needs a runner that can POST a hunting query, or
  the SCCM inventory path in the windows-estate pack.

**mscommerce-api** (outside the vocabulary - see below)
- M365-SELF-SERVICE-PURCHASE-ALLOWED - a product whose self-service purchase policy is not
  Disabled (trials without payment method by decision); each; medium.


---

## SharePoint, OneDrive, groups and Teams governance


Specs for whoever writes the YAML. Tenant-free: every list, name pattern and limit is a
`threshold.<name>` setting; Microsoft's own well-known ids are fine. Format follows
`docs\proposals\microsoft-cloud.md`. Ids use `M365-SPO-`, `M365-ONEDRIVE-` for SharePoint and
OneDrive; `M365-GROUP-` and `M365-TEAMS-` where the object is a Microsoft 365 group or a team
(the directive's prefix list did not foresee those rows); one rule belongs in
`rules\workstations.yaml` and keeps the `M365-ONEDRIVE-` id only so the port map can find it.

Shared notes for this part:

- **Usage reports as JSON.** Several rules read `/reports/get...Detail(period='D7')`. In v1.0 the
  call answers with a redirect to a CSV; the beta endpoint accepts `?$format=application/json` and
  returns a `value` array with camelCase fields (`siteUrl`, `lastActivityDate`,
  `storageUsedInBytes`, `storageAllocatedInBytes`, `rootWebTemplate`, `fileCount`, `isDeleted`,
  `siteId`). The graph runner has no `params` option; either the path may carry the query string
  or the runner needs `format: json` (engine gap, confirm on first run). Permission:
  Reports.Read.All (application). When the admin-centre privacy setting conceals names, user,
  group and site names are hashed in these reports: key rows on ids (`siteId`), never on names.
  Confidence for the field names: likely -
  https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-beta
- **Site ids carry commas** (`hostname,siteCollectionId,webId`). The runner only puts plain ids
  into a path, so `for_each` over `/sites/getAllSites` needs either the runner to accept commas or
  `field: sharepointIds.siteId` (the site resource exposes `sharepointIds`; a GUID alone is a
  valid `/sites/{id}` segment). Confidence: likely -
  https://learn.microsoft.com/en-us/graph/api/resources/site?view=graph-rest-1.0
- **Nested `$select` on `$expand=owners`** (accountEnabled, userPrincipalName) is the same
  unconfirmed behaviour the Entra backlog already lists; fallback is `for_each` ->
  `/groups/{id}/owners/microsoft.graph.user?$select=...`.
- **Ratios and arithmetic** (used/allocated, days left = deleted + retention - today) are engine
  gaps; the rules below use absolute thresholds and say so.

---

## Capacity and lifecycle (SharePoint and OneDrive)

### M365-SPO-SITE-STORAGE-HIGH
- Catches: a site collection whose used storage is above an absolute limit, as an early warning
  before it hits its allocation and rejects uploads (Teams files included).
- Severity: medium (high above twice the threshold).
- Source: rules\m365.yaml; beta; `/reports/getSharePointSiteUsageDetail(period='D7')` as JSON (see
  shared note); fields siteId, siteUrl, ownerPrincipalName, isDeleted, lastActivityDate,
  storageUsedInBytes, storageAllocatedInBytes, rootWebTemplate; key siteId, name siteUrl.
  New query, shared by M365-SPO-SITE-INACTIVE and M365-SPO-CLASSIC-SITE-ACTIVE.
- Permission: Reports.Read.All.
- Condition: isDeleted eq false and storageUsedInBytes gt threshold
  `m365.site-storage-warn-bytes` (default 500 GB in bytes). Evidence shows allocated bytes so the
  reader sees the headroom; the percentage itself is an engine gap.
- Refs: NIST-800-53:CP-2, NIST-800-53:SC-5.
- Fix: review versions and the preservation hold library with the owner, raise the site quota, or
  buy pooled storage.
- Confidence: likely (field names from the beta JSON report; v1.0 returns CSV).

### M365-ONEDRIVE-ACCOUNT-STORAGE-HIGH
- Catches: a OneDrive that is close to its allocation - the user's desktop and documents stop
  syncing and that is usually their only copy.
- Severity: low.
- Source: rules\m365.yaml; beta; `/reports/getOneDriveUsageAccountDetail(period='D7')` as JSON;
  fields siteUrl, ownerPrincipalName, isDeleted, lastActivityDate, storageUsedInBytes,
  storageAllocatedInBytes, fileCount; key siteUrl. New query.
- Permission: Reports.Read.All.
- Condition: isDeleted eq false and storageUsedInBytes gt threshold
  `m365.onedrive-storage-warn-bytes` (default 900 GB in bytes for a 1 TB default quota; the tenant
  lowers it when its default quota is smaller). Ratio is an engine gap.
- Refs: NIST-800-53:CP-2.
- Fix: raise the user's quota or clean up with the user; check that Known Folder Move is not
  syncing a bulk folder.
- Confidence: likely (beta JSON field names) -
  https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-beta

### M365-SPO-PRESERVATION-HOLD-LARGE
- Catches: a site whose Preservation Hold Library (kept by retention) has grown past an absolute
  size - held versions of edited and deleted files silently eat the pooled storage.
- Severity: low.
- Source: rules\m365.yaml; v1.0; `for_each: { path: /sites/getAllSites, select: [id, webUrl,
  sharepointIds], field: sharepointIds.siteId, max: 2000 }` -> `/sites/{id}/drives`; select id,
  name, quota, webUrl; key `{parent.id}|{id}`, name `{parent.webUrl}`. New per-object query (shared
  with nothing yet; a later libraries rule can reuse it).
- Permission: Sites.Read.All (application).
- Condition: name eq `Preservation Hold Library` and quota.used gt threshold
  `m365.preservation-hold-warn-bytes` (default 100 GB). Comparison with the site's own total is an
  engine gap.
- Refs: NIST-800-53:AU-11, NIST-800-53:CP-2.
- Fix: review the retention policy scope and the version limits for the site with the records
  owner; never delete held content by hand.
- Confidence: guess - whether `/sites/{id}/drives` lists the hidden preservation library needs
  confirming on the first run; https://learn.microsoft.com/en-us/graph/api/drive-list?view=graph-rest-1.0

### M365-SPO-SITE-INACTIVE
- Catches: a site with no activity for N days - it still holds data, sharing links and guests and
  is the cheapest exposure to retire or archive.
- Severity: low.
- Source: same beta usage report query as M365-SPO-SITE-STORAGE-HIGH (period D180 gives a longer
  activity window; if one period must be shared, use D180 for all three rules).
- Permission: Reports.Read.All.
- Condition: isDeleted eq false and (lastActivityDate absent or lastActivityDate age-gt 180,
  threshold `m365.site-inactive-days`).
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:3.1.
- Fix: ask the owner; archive (Microsoft 365 Archive), lock read-only or delete by decision.
- Confidence: likely.

### M365-SPO-CLASSIC-SITE-ACTIVE
- Catches: a site on a classic template that is still active - classic sites miss modern sharing
  controls, Teams connection and label enforcement.
- Severity: low.
- Source: same report query; field rootWebTemplate.
- Permission: Reports.Read.All.
- Condition: isDeleted eq false and lastActivityDate age-lt 180 and rootWebTemplate match
  threshold `m365.classic-template-pattern` (default `classic|publishing|blank`).
- Refs: NIST-800-53:SA-22, NIST-800-53:CM-8.
- Fix: modernise or archive with the owner.
- Confidence: guess on the template names the report uses; fix the default pattern on first run.

### M365-SPO-CRITICAL-SITE-UNREACHABLE
- Catches: a site the organisation listed as critical (holds registers, plans, runbooks) that no
  longer answers or has not changed for a long time.
- Severity: medium.
- Source: rules\m365.yaml; v1.0; `for_each` over the threshold list `m365.critical-site-ids`
  (site ids; empty list = rule n/a, never a pass) -> `/sites/{id}?$select=id,webUrl,
  lastModifiedDateTime,displayName`; key id, name displayName. New query.
- Permission: Sites.Read.All.
- Condition: lastModifiedDateTime age-gt 180 (threshold `m365.critical-site-stale-days`). A site
  that returns 404 makes the result partial; the engine must surface a partial for_each as a
  finding on that object (gap) - until then the run status is the signal. Lock state and owner
  health need spo-admin-rest.
- Refs: NIST-800-53:CP-2, NIST-800-53:CM-8.
- Fix: restore from the site recycle bin, unlock, or reassign the owner.
- Confidence: verified for `/sites/{id}` fields -
  https://learn.microsoft.com/en-us/graph/api/site-get?view=graph-rest-1.0

### M365-ONEDRIVE-DEFAULT-QUOTA-DRIFT
- Catches: the tenant's default OneDrive quota differs from the documented value (a changed
  default alters what new users and leavers' drives can hold).
- Severity: low.
- Source: rules\m365.yaml; v1.0; shared query Q-SPO (`/admin/sharepoint/settings`); field
  personalSiteDefaultStorageLimitInMB.
- Permission: SharePointTenantSettings.Read.All.
- Condition: personalSiteDefaultStorageLimitInMB ne threshold `m365.onedrive-default-quota-mb`
  (empty = n/a, never a pass).
- Refs: NIST-800-53:CM-6.
- Fix: set the default back, or update the documented value.
- Confidence: verified field - https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0

### M365-ONEDRIVE-DELETED-USER-NEAR-PURGE
- Catches: a deleted user whose directory object is about to leave the recycle bin (30 days) -
  the last easy moment to restore the account, hand the OneDrive to a manager or confirm the
  backup copy.
- Severity: medium.
- Source: rules\m365.yaml; v1.0; `/directory/deletedItems/microsoft.graph.user`; select id,
  userPrincipalName, displayName, deletedDateTime; key id, name userPrincipalName. New query.
- Permission: User.Read.All (Directory.Read.All also works).
- Condition: deletedDateTime age-gt 16 (threshold `m365.deleted-user-notice-age-days`, i.e. 30
  minus a 14-day notice). Days-left arithmetic against the OneDrive retention setting is an engine
  gap; the OneDrive side (who was given access) needs spo-admin-rest.
- Refs: NIST-800-53:CP-9, NIST-800-53:PS-4.
- Fix: restore the user if the deletion was premature; otherwise grant the manager access to the
  OneDrive or confirm the content was moved.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0

### M365-ONEDRIVE-KFM-NOT-ENFORCED  (rules\workstations.yaml, registry protocol)
- Catches: a workstation without the Known Folder Move policy - desktop and documents live only on
  the local disk and in no retention, no backup.
- Severity: medium.
- Source: rules\workstations.yaml; protocol registry; hive HKLM; path
  `SOFTWARE\Policies\Microsoft\OneDrive`; values KFMSilentOptIn, KFMBlockOptOut,
  KFMOptInWithWizard, FilesOnDemandEnabled; per target workstation; key host.
- Permission: the workstations pack's existing read identity.
- Condition: exists eq true and KFMSilentOptIn absent and KFMOptInWithWizard absent (either sets
  the move; silent is the one that protects without user action). Evidence lists which values are
  set. A missing key is `exists false` - fails too (policy never applied).
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2.
- Fix: deploy the OneDrive Known Folder Move policy (GPO or Intune settings catalog) in rings.
- Confidence: verified value names -
  https://learn.microsoft.com/en-us/sharepoint/redirect-known-folders

---

## Groups and Teams governance

### M365-GROUP-EXPIRING-SOON
- Catches: a Microsoft 365 group (and its team and site) that the expiration policy will delete
  within N days, especially one with no enabled owner to receive the renewal mail.
- Severity: medium (high when owners empty or every owner disabled - the latter needs
  element counting, engine gap; use `owners[].accountEnabled eq false` as the high trigger).
- Source: rules\entra.yaml or m365.yaml; v1.0; `/groups`; filter
  `groupTypes/any(c:c eq 'Unified')`; select id, displayName, expirationDateTime,
  renewedDateTime; expand `owners($select=id,accountEnabled)`; key id, name displayName. New
  query (ENTRA-GROUP-M365-NO-OWNER selects fewer fields; merge the selects so one fetch serves
  this rule, M365-GROUP-SINGLE-OWNER and M365-GROUP-OWNER-DISABLED).
- Permission: Group.Read.All + User.Read.All (owner properties).
- Condition: expirationDateTime until-lt 30 (threshold `m365.group-expiry-notice-days`);
  deadline expirationDateTime.
- Refs: NIST-800-53:CP-2, NIST-800-53:AC-2.
- Fix: renew the group or assign an owner before the date; set the policy's alternate
  notification mailbox to a monitored address.
- Confidence: verified (expirationDateTime is returned with $select) -
  https://learn.microsoft.com/en-us/graph/api/resources/group?view=graph-rest-1.0

### M365-GROUP-SINGLE-OWNER
- Catches: a group or team with exactly one owner - one leaver away from ownerless.
- Severity: low.
- Source: same merged /groups query.
- Permission: Group.Read.All.
- Condition: owners size-eq 1.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.1.
- Fix: ask the owner to add a co-owner; enable the ownerless-group policy.
- Confidence: verified.

### M365-GROUP-OWNER-DISABLED
- Catches: a group whose owner list contains a disabled account - ownership looks healthy while
  nobody can act, and a re-enabled leaver regains control.
- Severity: low (medium when owners size-eq 1).
- Source: same merged /groups query (nested select on the expand, see shared note).
- Permission: Group.Read.All + User.Read.All.
- Condition: `owners[].accountEnabled` eq false. "All owners disabled" needs element counting
  (gap 1); until then this rule flags any disabled owner.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:PS-4.
- Fix: remove the disabled owner, add a live one.
- Confidence: guess on the nested select (backlog item); fallback per-object owners call.

### M365-GROUP-HAS-GUESTS
- Catches: a group or team that contains guest members - a review list for owners, because a
  guest in a team sees every standard channel and file, and project guests are rarely removed.
- Severity: low (info).
- Source: rules\entra.yaml; v1.0; `for_each: { path: /groups, filter: "groupTypes/any(c:c eq
  'Unified')", select: [id, displayName], field: id, max: 2000 }` -> `/groups/{id}/members`;
  select id, userType, userPrincipalName, accountEnabled; key `{parent.id}|{id}`; name
  `{parent.displayName}`. Plain members listing, no advanced query needed. New per-object query.
- Permission: GroupMember.Read.All.
- Condition: userType eq Guest. One finding per guest membership; the YAML author may prefer a
  grouped key `{parent.id}` with the guest count in evidence (gap 4).
- Refs: NIST-800-53:AC-2(13), NIST-800-53:AC-21, CIS-Controls-v8:6.2.
- Fix: owners confirm or remove each guest; run access reviews on groups with guests.
- Confidence: verified (members listing returns userType for user members) -
  https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0

### M365-GROUP-NO-SENSITIVITY-LABEL
- Catches: a Microsoft 365 group (and its site and team) without a sensitivity label, so no
  classification governs its sharing and guest settings.
- Severity: low (n/a-by-decision when the tenant has not enabled labels for groups; the
  companion rule M365-GROUP-CREATION-UNRESTRICTED reads the same settings template).
- Source: same /groups query with assignedLabels added to the select (returned only on $select).
- Permission: Group.Read.All.
- Condition: assignedLabels empty.
- Refs: NIST-800-53:AC-16, CIS-Controls-v8:3.7.
- Fix: publish a default container label and label existing groups in bulk with the owners.
- Confidence: verified property - https://learn.microsoft.com/en-us/graph/api/resources/group?view=graph-rest-1.0

### M365-GROUP-NAME-OR-DESCRIPTION-POOR
- Catches: a group with no description or a throwaway name - ownership and classification then
  become guesses.
- Severity: low.
- Source: same /groups query with description added.
- Permission: Group.Read.All.
- Condition: description empty or displayName match threshold `m365.group-name-junk-pattern`
  (default `^(test|tmp|temp|new team|demo)\b`). Duplicate display names need a cross-row
  comparison (gap).
- Refs: NIST-800-53:CM-8.
- Fix: rename and describe with the owner; adopt a naming policy.
- Confidence: verified.

### M365-GROUP-CREATION-UNRESTRICTED
- Catches: any user can create Microsoft 365 groups (and therefore teams and sites) - either the
  Group.Unified settings template was never instantiated (Microsoft's default is open) or it is
  instantiated with creation left open. Companion of the existing rule M365-SPO-USER-SITE-CREATION
  (site creation); together they cover "who may create sites, groups and teams".
- Severity: low.
- Source: rules\entra.yaml; v1.0; `/groupSettings`; fields id, displayName, templateId, values
  (name/value pairs); key id, name displayName. New query, shared with
  M365-GROUP-NAMING-POLICY-NONE.
- Permission: Directory.Read.All.
- Condition: two rules in one spirit - (a) must-exist: count lt 1 where displayName eq
  Group.Unified (no template = defaults = open); (b) per row: displayName eq Group.Unified and the
  element named EnableGroupCreation has value true - this pairing is engine gap 1 (same-element
  condition); until it exists, (b) is approximated by `values[].value` containing true being
  insufficient, so ship only (a) and note (b).
- Refs: CIS-Controls-v8:6.8, NIST-800-53:AC-6, NIST-800-53:CM-11.
- Fix: instantiate the template, set EnableGroupCreation false and name an allowed group; publish
  a request path.
- Confidence: verified resource - https://learn.microsoft.com/en-us/graph/api/resources/groupsetting?view=graph-rest-1.0

(The missing naming policy - no prefix/suffix requirement and no blocked-words list in the
Group.Unified settings - is ENTRA-GROUP-NAMING-POLICY-NONE in the Entra section; it reads the same
/groupSettings query and needs the same same-element pairing.)

### M365-GROUP-DELETED-RECENT
- Catches: groups (and so teams and their sites) deleted in the last N days - a daily review list,
  because a deleted team is often a mistake noticed weeks later, inside the 30-day restore window.
- Severity: info.
- Source: rules\entra.yaml; v1.0; `/directory/deletedItems/microsoft.graph.group`; select id,
  displayName, deletedDateTime, groupTypes; key id, name displayName; refresh 1d. New query.
- Permission: Group.Read.All.
- Condition: deletedDateTime age-lt 7 (threshold `m365.deleted-group-review-days`); `each` on that
  condition. Deadline = deletedDateTime plus 30 days (arithmetic gap; evidence states the date).
- Refs: NIST-800-53:CP-9, NIST-800-53:AU-6.
- Fix: confirm with the deleting admin; restore the group if it was a mistake.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0

### M365-GROUP-GUEST-ADDED-RECENT  (needs relative dates)
- Catches: an external account added to a group in the last N days - the weekly list owners
  should confirm, since each guest in a team gets the whole team's files.
- Severity: low.
- Source: rules\entra.yaml; v1.0; `/auditLogs/directoryAudits`; filter
  `activityDateTime ge {DAYS_AGO:7} and activityDisplayName eq 'Add member to group' and result eq 'success'`;
  select id, activityDateTime, initiatedBy, targetResources; key id. New query (same endpoint as
  ENTRA-AUDIT-ROLE-ASSIGNMENT-RECENT, different filter).
- Permission: AuditLog.Read.All.
- Condition: `targetResources[].userPrincipalName` contains `#EXT#` (the added member is one of
  the target resources; the group is another).
- Refs: NIST-800-53:AC-2(13), NIST-800-53:AU-6, CIS-Controls-v8:6.2.
- Fix: the group owner confirms or removes the guest.
- Confidence: likely (filter on activityDisplayName and activityDateTime is documented; the target
  resource layout for group-member adds needs confirming on first run) -
  https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0

### M365-TEAMS-INACTIVE
- Catches: a team with no activity for N days; one that still has guests is both clutter and
  exposure.
- Severity: low (medium when guests gt 0).
- Source: rules\m365.yaml; beta; `/reports/getTeamsTeamActivityDetail(period='D180')` as JSON;
  fields teamId, teamName, teamType, isDeleted, lastActivityDate, details (activeUsers, guests,
  activeChannels); key teamId, name teamName. New query.
- Permission: Reports.Read.All.
- Condition: isDeleted eq false and (lastActivityDate absent or age-gt 180, threshold
  `m365.team-inactive-days`); severity raised when `details[].guests` gt 0.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-2(13).
- Fix: archive or delete the team with the owner; remove guests first.
- Confidence: likely (nested `details` array in the JSON form) -
  https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsteamactivitydetail?view=graph-rest-beta

### M365-TEAMS-WEBHOOK-CONNECTOR-INSTALLED
- Catches: a team that still has the Incoming Webhook or an Office 365 Connector app installed -
  these are being retired, and the alert posts that use them stop arriving without any error.
- Severity: low.
- Source: rules\m365.yaml; v1.0; `for_each: { path: /groups, filter:
  "resourceProvisioningOptions/any(x:x eq 'Team')", select: [id, displayName], field: id,
  max: 2000 }` -> `/teams/{id}/installedApps?$expand=teamsAppDefinition`; fields id,
  teamsAppDefinition.teamsAppId, teamsAppDefinition.displayName; key `{parent.id}|{id}`, name
  `{parent.displayName}`. New per-object query.
- Permission: TeamsAppInstallation.ReadForTeam.All (application) + Group.Read.All.
- Condition: teamsAppDefinition.teamsAppId in threshold `m365.retired-teams-app-ids` (default:
  203a1e2c-26cc-47ca-83ae-be98f960b6b2, the Incoming Webhook app - a Microsoft constant; the
  tenant adds connector app ids it finds).
- Refs: NIST-800-53:SA-22.
- Fix: recreate the posts with Workflows (Power Automate) and remove the app from the team.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/team-list-installedapps?view=graph-rest-1.0

### M365-TEAMS-ADDON-LICENSE-UNUSED  (store join; confidence guess)
- Catches: an add-on Teams licence (Premium, Phone, Rooms) on a user who showed no Teams activity
  in the report period.
- Severity: low.
- Source: rules\cross-system.yaml (protocol store) joining the Entra `/users` inventory rows
  (assignedLicenses) with rows of a companion graph query that must exist first: beta
  `/reports/getTeamsUserActivityUserDetail(period='D90')` as JSON (fields userPrincipalName,
  lastActivityDate, isDeleted). The SKU ids to test are a threshold list `m365.teams-addon-sku-ids`
  (empty = n/a).
- Permission: Reports.Read.All; User.Read.All.
- Condition: user holds a listed SKU and the report row shows lastActivityDate absent or older
  than 90 days. The SQL follows the cross-system CTE B5 and reads the report rows from row_seen.
- Refs: NIST-800-53:PM-3, CIS-Controls-v8:2.1.
- Fix: reclaim through the licensing group.
- Confidence: guess - depends on the JSON report being collected as a graph rule first and on
  the usage-report privacy setting (hashed names break the join; ids are not in that report).

---

## Access and authentication

### M365-SPO-UNMANAGED-DEVICE-CA-MISSING
- Catches: no enforced Conditional Access policy applies app-enforced restrictions to SharePoint
  Online (the half of "limited web-only access from unmanaged devices" that Graph can see; the
  SharePoint tenant switch itself needs spo-admin-rest).
- Severity: medium.
- Source: rules\entra.yaml; v1.0; shared query Q-CA; fields state,
  conditions.applications.includeApplications, sessionControls.applicationEnforcedRestrictions.isEnabled.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where state eq enabled and
  sessionControls.applicationEnforcedRestrictions.isEnabled eq true and
  (conditions.applications.includeApplications contains Office365 or contains
  00000003-0000-0ff1-ce00-000000000000 (SharePoint Online, Microsoft constant) or contains All).
- Refs: NIST-800-53:AC-19, NIST-800-53:AC-20, CIS-Controls-v8:4.1.
- Fix: create the policy (all users, Office 365, session control "use app enforced
  restrictions") and set SharePoint's unmanaged-device access to limited or blocked.
- Confidence: verified (applicationEnforcedRestrictions session control) -
  https://learn.microsoft.com/en-us/graph/api/resources/applicationenforcedrestrictionssessioncontrol?view=graph-rest-1.0

### M365-USER-NO-MANAGER
- Catches: an enabled member account without a manager attribute - OneDrive access delegation,
  leaver hand-over and approval flows all key on it.
- Severity: low.
- Source: rules\entra.yaml; v1.0; `/users`; filter
  `accountEnabled eq true and userType eq 'Member'`; select id, userPrincipalName, employeeType,
  department; expand `manager($select=id)`; top 999; key id, name userPrincipalName. New query
  (Q-USERS cannot carry the expand without changing many rules).
- Permission: User.Read.All.
- Condition: manager absent and userPrincipalName notmatch threshold
  `entra.service-account-upn-pattern` (default `^(svc|srv|sa|mbx|room|shared)[-_.]`).
- Refs: NIST-800-53:PS-4, NIST-800-53:AC-2(1).
- Fix: populate the manager attribute in the source directory (HR feed); exclude service accounts
  by pattern.
- Confidence: likely (`$expand=manager` on the list is documented) -
  https://learn.microsoft.com/en-us/graph/api/user-list-manager?view=graph-rest-1.0

---

## Rules once spo-admin-rest exists

One line each, generic. Source for all: SharePoint admin tenant properties
(`Get-SPOTenant` / `_api/SPO.Tenant`), per-site properties (`Get-SPOSite`), site users
(`Get-SPOUser`), per-site REST (`_api/web`, `_api/web/lists`). Severity as in the old rows.

- SPO-ADMIN-POOL-STORAGE-HIGH - pooled storage used over quota percentage; StorageQuota vs sum of
  site StorageUsageCurrent; gt 85 % medium, 90 % high, 98 % critical.
- SPO-ADMIN-POOL-GROWTH-FAST - projected months to full under 12, from run-over-run used storage.
- SPO-ADMIN-SITE-NEAR-QUOTA - site StorageUsageCurrent / StorageQuota ge 95 %; medium.
- SPO-ADMIN-VERSION-LIMIT-NONE - no tenant version policy (EnableAutoExpirationVersionTrim false and
  MajorVersionLimit unset); low.
- SPO-ADMIN-SITE-LOCKED - site LockState in [ReadOnly, NoAccess] and not in an archive allow list; medium.
- SPO-ADMIN-LEGACY-APP-AUTH - DisableCustomAppAuthentication false; medium.
- SPO-ADMIN-INFOPATH-LIBRARY - per active site, list BaseTemplate eq 115; medium.
- SPO-ADMIN-SITE-SHARING-WIDER-THAN-TENANT - site SharingCapability wider than the tenant decision;
  medium (Anyone on a site = high).
- SPO-ADMIN-ONEDRIVE-SHARING-OPEN - OneDriveSharingCapability eq ExternalUserAndGuestSharing; medium.
- SPO-ADMIN-DEFAULT-LINK-TYPE-WIDE - DefaultSharingLinkType eq AnonymousAccess (or Internal when
  the decision is Direct); medium.
- SPO-ADMIN-DEFAULT-LINK-EDIT - DefaultLinkPermission eq Edit; low.
- SPO-ADMIN-ANYONE-LINK-NO-EXPIRY - RequireAnonymousLinksExpireInDays unset or gt 30 while Anyone
  sharing is allowed; medium.
- SPO-ADMIN-ANYONE-LINK-EDIT - File/FolderAnonymousLinkType eq Edit; medium.
- SPO-ADMIN-GUEST-CODE-REAUTH-LONG - EmailAttestationRequired false or EmailAttestationReAuthDays gt 15; medium.
- SPO-ADMIN-GUEST-NO-EXPIRY - ExternalUserExpirationRequired false or ExternalUserExpireInDays gt 90; medium.
- SPO-ADMIN-SHARE-GROUP-RESTRICTION-NONE - no WhoCanShare group restriction set; low.
- SPO-ADMIN-B2B-INTEGRATION-OFF - EnableAzureADB2BIntegration false; medium.
- SPO-ADMIN-INFECTED-DOWNLOAD-ALLOWED - DisallowInfectedFileDownload false; medium.
- SPO-ADMIN-CUSTOM-SCRIPT-ALLOWED - site DenyAddAndCustomizePages ne Enabled on OneDrives and
  self-service sites, or DelayDenyAddAndCustomizePagesEnforcement true; medium.
- SPO-ADMIN-OWNER-NOTIFICATIONS-OFF - any of NotifyOwnersWhenInvitationsAccepted,
  NotifyOwnersWhenItemsReshared, OwnerAnonymousNotification false; low.
- SPO-ADMIN-PEOPLE-PICKER-OPEN - ShowPeoplePickerSuggestionsForGuestUsers true or ShowEveryoneClaim /
  ShowAllUsersClaim true; medium.
- SPO-ADMIN-LABEL-INTEGRATION-OFF - EnableAIPIntegration false; medium.
- SPO-ADMIN-SITE-UNLABELLED - site SensitivityLabel empty on active non-group sites; low.
- SPO-ADMIN-NEW-FILES-NOT-SENSITIVE - MarkNewFilesSensitiveByDefault ne BlockExternalSharing while
  a DLP policy covers SharePoint; low.
- SPO-ADMIN-RESTRICTED-SEARCH-UNDECIDED - restricted search / restricted access control state
  against the tenant's recorded decision when a Copilot SKU is present; medium.
- SPO-ADMIN-SENSITIVE-SITE-NO-RAC - listed sensitive sites without RestrictedAccessControl; low.
- SPO-ADMIN-ONEDRIVE-QUOTA-EXCEPTION - personal site StorageQuota ne the tenant default; low.
- SPO-ADMIN-NONGROUP-SITE-NO-ADMIN - non-group site with no enabled site collection admin; medium.
- SPO-ADMIN-EVERYONE-CLAIM-GRANTED - site user claims matching Everyone / Everyone-except-external;
  high on labelled-confidential sites.
- SPO-ADMIN-SITE-ADMIN-DISABLED - site collection admin whose account is disabled; low.
- SPO-ADMIN-ONEDRIVE-EXTRA-ADMIN - personal site with a non-owner site admin older than 90 days; medium.
- SPO-ADMIN-SPFX-PERMISSION-REQUEST-PENDING - pending SPFx permission requests; low.
- SPO-ADMIN-ACCESS-REQUEST-EMAIL-DEAD - site RequestAccessEmail set to a disabled or missing account; low.
- SPO-ADMIN-IP-ENFORCEMENT-UNDECIDED - IPAddressEnforcement state against the recorded decision; info.
- SPO-ADMIN-SENSITIVE-SITE-DEVICE-POLICY - listed sensitive sites without ConditionalAccessPolicy
  limited/blocked or an authentication context; low.
- SPO-ADMIN-LIBRARY-VERSIONING-OFF - per site, document library EnableVersioning false or
  MajorVersionLimit lt 100; medium.
- SPO-ADMIN-UNIQUE-PERMISSIONS-HEAVY - library with more than N uniquely permissioned items; low.
- SPO-ADMIN-LIBRARY-TOO-LARGE - list ItemCount over the sync or view threshold; low.
- SPO-ADMIN-DELETED-SITE-NEAR-PURGE - deleted site with DaysRemaining lt 14; low.
- SPO-ADMIN-EXTRA-STORAGE-MISMATCH - extra-storage SKU units against pool usage; low.
- SPO-ADMIN-SAM-FEATURE-UNLICENSED - RestrictedAccessControl / restricted search in use without a
  SharePoint Advanced Management or Copilot SKU; low.

## Rules once teams-powershell exists

Source: Teams PowerShell (`Get-Cs*` policies and configurations, `Get-CsOnlineUser`,
`Get-CsOnlinePSTNGateway`). Where ScubaGear already reports the control, the direct rule adds
per-policy evidence and daily freshness.

- TEAMS-UPGRADE-NOT-TEAMS-ONLY - global upgrade policy mode ne TeamsOnly or any user not TeamsOnly; low.
- TEAMS-FEDERATION-OPEN - AllowFederatedUsers true with no allowed-domain list; medium.
- TEAMS-CONSUMER-ACCESS-ON - AllowTeamsConsumer or AllowTeamsConsumerInbound true; medium.
- TEAMS-TRIAL-TENANT-ACCESS-OPEN - ExternalAccessWithTrialTenants ne Blocked or AllowPublicUsers true; medium.
- TEAMS-GUEST-CAPABILITIES-WIDE - guest private calling, Meet Now or message deletion allowed; medium.
- TEAMS-EMAIL-INTO-CHANNEL-ON - AllowEmailIntoChannel true without a restricted sender list; low.
- TEAMS-THIRD-PARTY-STORAGE-ON - any of the cloud-storage switches true; low.
- TEAMS-ANONYMOUS-JOIN-UNDECIDED - DisableAnonymousJoin against the recorded decision; low.
- TEAMS-MEETING-POLICY-ANON-START - AllowAnonymousUsersToStartMeeting true in any policy; medium.
- TEAMS-MEETING-POLICY-LOBBY-OPEN - AutoAdmittedUsers eq Everyone in any policy; medium.
- TEAMS-MEETING-POLICY-PSTN-BYPASS - AllowPSTNUsersToBypassLobby true; low.
- TEAMS-MEETING-POLICY-ANON-CHAT - MeetingChatEnabledType eq Enabled; low.
- TEAMS-MEETING-POLICY-EVERYONE-PRESENTS - DesignatedPresenterRoleMode eq EveryoneUserOverride; low.
- TEAMS-MEETING-POLICY-EXTERNAL-CONTROL - AllowExternalParticipantGiveRequestControl true; medium.
- TEAMS-MEETING-POLICY-UNTRUSTED-CHAT - AllowExternalNonTrustedMeetingChat true; low.
- TEAMS-MEETING-POLICY-RECORDING-DEFAULT - global AllowCloudRecording true, no expiry days, or
  storage outside region; low.
- TEAMS-CUSTOM-POLICY-WEAKER-THAN-GLOBAL - any custom meeting/messaging policy weaker than Global on
  the security properties; medium (needs field-to-field comparison - engine gap, or compare each
  property to a fixed value instead).
- TEAMS-USER-REPORTING-OFF - AllowSecurityEndUserReporting false; low.
- TEAMS-SIDELOADING-ALLOWED - AllowSideLoading true in a policy not assigned to a developer group; low.
- TEAMS-CHANNEL-EXTERNAL-SHARING-ON - AllowChannelSharingToExternalUser or
  AllowUserToParticipateInExternalSharedChannel true without a partner decision; low.
- TEAMS-EVENTS-PUBLIC-BY-DEFAULT - global events policy EventAccessType eq Everyone; low.
- TEAMS-VOICE-INVENTORY - PSTN gateways, voice routes and enterprise-voice users as an info row; info.
- TEAMS-ANON-APP-INTERACTION-ON - DisableAppInteractionForAnonymousUsers false; low.
- TEAMS-LARGE-TEAM-UNGOVERNED - team over N members with fewer than two owners or no moderation on
  the general channel; low.

## Rules once exo-powershell exists (unified audit log)

Source: `Search-UnifiedAuditLog` (needs View-Only Audit Logs). All are "last N days" lists.

- UAL-SPO-INGESTION-GAP - zero records for a SharePoint, OneDrive or Teams record type in 24 h; medium.
- UAL-SPO-LABEL-DOWNGRADE - label removed or downgraded on a file; low.
- UAL-SPO-ANYONE-LINK-LIVE - anonymous links created and not removed in 90 days; high when the
  tenant forbids them.
- UAL-SPO-EXTERNAL-SHARE-SPIKE - external shares per user over threshold or over the baseline; medium.
- UAL-SPO-MASS-FILE-ACTIVITY - downloads, deletions or renames per user per day over threshold; high.
- UAL-SPO-BROAD-PERMISSION-GRANT - Everyone claims or site-admin grants added in 7 days; medium.

## Rules once purview-powershell exists

- PURVIEW-RETENTION-SPO-NOT-ALL - no enabled retention policy with SharePoint and OneDrive
  locations set to All and distribution status success; high.
- PURVIEW-RETENTION-TEAMS-NONE - no enabled retention policy covering Teams channel, chat and
  private-channel messages; medium.
- PURVIEW-ALERT-POLICY-OFF-OR-UNROUTED - built-in SharePoint/OneDrive alert policies disabled or
  notifying a disabled or personal mailbox; medium.

## Rules once admin-center-export exists (imported reports, file protocol)

- ONEDRIVE-SYNC-HEALTH-ERRORS - devices with sync errors over N percent, or any error type over
  N devices; low.
- ONEDRIVE-SYNC-CLIENT-OLD - devices on a sync build older than six months; low.
- TEAMS-CALL-QUALITY-POOR - poor-stream rate over target overall or per building; low.
- ONEDRIVE-ACCESS-DELEGATION-OFF - manager access or secondary owner not configured; medium.


---

## Power Platform, Power BI and Dynamics 365


Status: proposal only; nothing here is loaded or run. Tenant-free: thresholds hold the tenant's
own values, empty by default where no safe default exists. Format follows
`docs\proposals\microsoft-cloud.md`.

Keeper has no Power Platform, Power BI/Fabric or Dataverse integration today. Of this group's old
checks, eight are automatable now (Graph, Windows registry/event log, or an attestation) and are
written below as full proposals. The rest wait for two integrations, specified at the end; their
rules are listed compactly so the integration work implements the right reads.

---

## Proposals that need nothing new

### PP-ADMIN-ROLE-PERMANENT
- Catches: a permanent (non-PIM) active assignment of a workload administrator role - Power
  Platform Administrator, Dynamics 365 Administrator, Fabric Administrator. These roles control
  every environment, every data policy and the whole BI service, but they are outside the tier-0
  list, so ENTRA-ROLE-PERMANENT-TIER0 never sees them and nobody counts their holders.
- Severity: medium.
- Source: entra.yaml; v1.0; same fetch and mechanism as ENTRA-ROLE-PERMANENT-TIER0 (shared query
  Q-ROLES-EXPAND plus the schedule-instance comparison that rule already uses); role template ids
  as threshold `entra.workload-admin-role-ids`, default: Power Platform Administrator
  `11648597-926c-4cf3-9c36-bcebb0ba8dcc`, Dynamics 365 Administrator
  `44367163-eba1-44c3-98af-f5787879f96a`, Fabric Administrator
  `a9ea8996-122f-4c74-9520-8edcd192826c`.
- Permission: RoleManagement.Read.Directory.
- Condition: roleDefinitionId in the threshold list and the assignment is permanent (not an
  activation of an eligibility). Guest and disabled holders already fire ENTRA-ROLE-GUEST-HOLDER
  and ENTRA-ROLE-DISABLED-HOLDER for every role, so this rule adds only the PIM question.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-2(7), CIS-Controls-v8:5.4, CIS-M365:5.3.1.
- Fix: convert the holders to eligible assignments with approval; keep at most one documented
  permanent break-glass holder.
- Confidence: verified role template ids -
  https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference;
  mechanism already in use (verified).

### D365-PARTNER-GDAP-PRIVILEGED
- Catches: an active delegated admin relationship (GDAP) through which a partner holds a tier-0
  directory role, or that lasts far longer than the engagement. A partner relationship is standing
  tenant-wide access that appears in no environment's user list and in no role report of the
  tenant's own accounts. Generic; belongs in entra.yaml despite the prefix.
- Severity: high when a tier-0 role is granted; medium when only the duration is long.
- Source: entra.yaml; v1.0; `/tenantRelationships/delegatedAdminRelationships`; select id,
  displayName, status, createdDateTime, activatedDateTime, endDateTime, duration,
  accessDetails, customer; key id, name displayName. New query. Field
  `accessDetails.unifiedRoles[].roleDefinitionId`.
- Permission: DelegatedAdminRelationship.Read.All.
- Condition: status eq active and (`accessDetails.unifiedRoles[].roleDefinitionId` in the tier-0
  role id list, or not (endDateTime until-lt 730, threshold `entra.gdap-max-remaining-days`)).
  Two rules if the YAML author prefers one condition each.
- Refs: NIST-800-53:AC-2(2), NIST-800-53:AC-6, NIST-800-53:AC-20, CIS-Controls-v8:6.8,
  MITRE-ATTACK:T1199.
- Fix: ask the partner to request a relationship with least-privilege roles (never Global
  Administrator) and a short duration; terminate the old one.
- Confidence: resource verified, nested field names likely -
  https://learn.microsoft.com/en-us/graph/api/resources/delegatedadminrelationship?view=graph-rest-1.0

### D365-SKU-NO-HEADROOM
- Catches: a paid licence SKU whose consumed units reach its enabled units. New joiners then
  cannot be licensed and the licensing group silently fails for them. Generic (fits m365.yaml as
  the fourth M365-SKU-* rule); the Dynamics seat pool is one instance.
- Severity: medium (low when the free units are below N but not zero).
- Source: m365.yaml; v1.0; `/subscribedSkus` (shared with M365-SKU-*); fields skuId,
  skuPartNumber, capabilityStatus, prepaidUnits.enabled, consumedUnits. The engine cannot compare
  two fields of one row (gap), so until that exists write it as a `store` rule over `row_seen` of
  the same query: `json_extract(attrs,'$.prepaidUnits.enabled') - json_extract(attrs,'$.consumedUnits') AS headroom`.
- Permission: Organization.Read.All.
- Condition: capabilityStatus eq Enabled and prepaidUnits.enabled gt 0 and headroom le 0
  (threshold `m365.sku-min-headroom`, default 0); skus on the free list excluded.
- Refs: NIST-800-53:SA-4, NIST-800-53:AC-2(1), CIS-Controls-v8:2.1.
- Fix: reclaim seats from disabled and inactive holders (M365-LICENSED-USER-DISABLED,
  M365-LICENSED-USER-INACTIVE) before buying more.
- Confidence: verified field names (query already runs) -
  https://learn.microsoft.com/en-us/graph/api/resources/subscribedsku?view=graph-rest-1.0

### D365-RELEASE-WAVE-REGRESSION-TEST
- Catches: no attestation that the organisation's Dataverse customisations were regression-tested
  in a sandbox on the current release wave before it reached production. Twice a year the platform
  changes underneath the customisations; a vendor script using a removed API breaks the morning the
  wave lands.
- Severity: medium.
- Source: obligations.yaml; `store` protocol in the OBL-* pattern (latest_attestation for the
  obligation id, interval 182 days, threshold `obligation.release-wave-test-interval-days`).
- Permission: none (Keeper store).
- Condition: no attestation of done within the interval, or attested as not done
  (OBL-ATTESTED-NO handles the latter generically). Evidence names the sandbox and the result.
- Refs: NIST-800-53:CM-3(2), NIST-800-53:CM-4, NIST-800-53:SI-2, CIS-Controls-v8:16.2.
- Fix: enable early access in a sandbox each wave; require the customisation vendor's test record
  and attest with it.
- Confidence: verified (release waves and early-access opt-in) -
  https://learn.microsoft.com/en-us/power-platform/admin/opt-in-early-access-updates

### PP-GATEWAY-RECOVERY-KEY-ATTESTED
- Catches: no attestation that the on-premises data gateway recovery key is held in the approved
  secrets store with two named custodians and was proven usable (a member added with it, or a
  restore) within the year. Without the key a gateway cannot be restored or extended; it is usually
  known only to whoever installed it.
- Severity: high.
- Source: obligations.yaml; `store` protocol in the OBL-* pattern, interval 365 days (threshold
  `obligation.gateway-recovery-key-interval-days`).
- Permission: none.
- Condition: no attestation of done within the interval. Later, a Power BI gateway integration can
  replace the proof half with "memberGateways count ge 2".
- Refs: NIST-800-53:CP-9, NIST-800-53:CP-10, NIST-800-53:IA-5, CIS-Controls-v8:11.1.
- Fix: if the key is lost, reinstall the gateway with a new key and rebind the data sources; then
  record the key with two custodians.
- Confidence: verified (recovery key semantics) -
  https://learn.microsoft.com/en-us/data-integration/gateway/service-gateway-install

### PP-GATEWAY-SERVICE-ERRORS
- Catches: a server whose Application log carries repeated errors from the on-premises data gateway
  service in the last 7 days - query timeouts, credential failures, relay connection errors - the
  precursors of refresh failures. Hosts without the gateway return no rows and are never judged.
- Severity: medium.
- Source: windows-server.yaml; `eventlog` protocol; log Application; providers
  `["On-premises data gateway service"]` (provider name to confirm on first run - threshold
  `winsrv.gateway-event-provider`); level 1 and 2; days 7; max 500; key `{host}|{id}`.
- Permission: Event Log Readers on the host (the existing cim/eventlog identity).
- Condition: count ge 5 per host (threshold `winsrv.gateway-errors-min`), judged per host as the
  eventlog protocol does. The gateway's own text log files are not readable by any Keeper protocol.
- Refs: NIST-800-53:AU-6, NIST-800-53:SI-4, CIS-Controls-v8:8.11.
- Fix: open the named data source or credential; raise the timeout with the report owner.
- Confidence: guess on the provider name (the service name is PBIEgwService) -
  https://learn.microsoft.com/en-us/data-integration/gateway/service-gateway-tshoot

### PP-GATEWAY-HOST-TLS-LEGACY
- Catches: a server where TLS 1.0 or 1.1 is still enabled in SCHANNEL, or where .NET Framework is
  told not to use the system TLS defaults. Generic for every server; the gateway hosts matter most
  because the gateway talks to the service bus and to every data source over TLS.
- Severity: low (medium on hosts that run the gateway service).
- Source: windows-server.yaml; `registry` protocol; two rules, one query each: (1) path
  `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server` values
  Enabled, DisabledByDefault (repeat for `TLS 1.1\Server`, `TLS 1.0\Client`, `TLS 1.1\Client`);
  (2) path `SOFTWARE\Microsoft\.NETFramework\v4.0.30319` values SchUseStrongCrypto,
  SystemDefaultTlsVersions (and the Wow6432Node twin); key host.
- Permission: remote registry read (StdRegProv).
- Condition: (1) Enabled eq 1 - an absent key means the OS default, which on current servers is
  "enabled" for TLS 1.0/1.1 only before Windows Server 2022, so pair with WINSRV-OS-* rather than
  treating absent as fail; (2) SchUseStrongCrypto eq 0 or SystemDefaultTlsVersions eq 0 (absent is
  acceptable on .NET 4.7 and later).
- Refs: NIST-800-53:SC-8, NIST-800-53:SC-13, CIS-Controls-v8:3.10.
- Fix: set the SCHANNEL values to disable TLS 1.0/1.1 and the .NET values to 1; restart.
- Confidence: verified -
  https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings and
  https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls

### PP-GATEWAY-HOST-DOTNET-OLD
- Catches: a server whose .NET Framework 4.x release is below 4.8. The gateway requires 4.8; older
  runtimes also miss the TLS defaults above. Generic server rule.
- Severity: medium.
- Source: windows-server.yaml; `registry` protocol; path
  `SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`; values Release; key host.
- Permission: remote registry read.
- Condition: exists eq true and Release lt 528040 (threshold `winsrv.dotnet-min-release`).
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22, CIS-Controls-v8:7.3.
- Fix: install .NET Framework 4.8 or 4.8.1 in a maintenance window.
- Confidence: verified -
  https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed

---

## Rules once power-platform-admin-api exists

Format: id - what - read (endpoint or cmdlet, property) - condition - severity. Environment-scoped
reads use `for_each` over the environment list. "production" means environments with the
Production SKU; "the default environment" means isDefault true. Tenant-specific values are
thresholds.

Capacity and health
- PP-CAPACITY-DATABASE-NEAR-CAP - Database or File pool near entitlement - `licensing/tenantCapacity` capacity[].consumption.actual vs rated - ratio ge 0.85 (high at 0.95, critical at 1.0) - medium..critical.
- PP-CAPACITY-LOG-OVER - Log pool over entitlement - same call, capacityType Log - ratio ge 0.85 - high.
- PP-CAPACITY-GROWTH-FAST - pool growth per week against the previous run - store comparison of two runs of the same query - weekly growth gt threshold or months-to-cap lt 6 - high.
- PP-ENV-CAPACITY-SHARE-HIGH - one non-production environment holds a large share of the pool - BAP environments `$expand=properties.capacity` - share gt 25 % (threshold) - medium.
- PP-CAPACITY-ENFORCEMENT-ACTIVE - a capacity restriction is in force - tenantCapacity status/notifications, environment states.management - restriction flag present - high.
- PP-CAPACITY-ADDON-UNALLOCATED - purchased add-on capacity not allocated while a pool is over - tenantCapacity entitlement breakdown - add-on gt allocated and overage gt 0 - medium.
- PP-AI-CAPACITY-UNUSED - prepaid AI/Copilot capacity mostly unused - tenantCapacity add-on rows - consumption lt 50 % of entitlement - low.
- PP-CAPACITY-WARNING-THRESHOLD-HIGH - storage warning threshold set too high or environment-admin reports off - tenant settings licensing.* - threshold gt 85 or report flags false - low.
- PP-ENV-NOT-READY - a production environment not Ready/Enabled - BAP environments states.management.id, states.runtime.id - ne Ready / ne Enabled - high.
- PP-ENV-BACKGROUND-OPS-OFF - background operations disabled on production - linkedEnvironmentMetadata.backgroundOperationsState - ne Enabled - high.
- PP-ENV-VERSION-LAG - production environment version behind the sandbox or current release - linkedEnvironmentMetadata.version - store comparison across environments - low.
- PP-FLOW-RUNS-FAILING - started flow with many failed runs in 7 days - flows admin API, per-flow runs `status eq 'Failed'` and startTime ge {DAYS_AGO:7} - count gt 3 per flow - medium.
- PP-FLOW-SUSPENDED - suspended flow in production or default - flows admin API state Suspended, suspensionReason - any - high.
- PP-FLOW-FAILURE-ALERT-OFF - started production flow without failure notifications - flows properties.flowFailureAlertSubscribed - eq false - low.
- PP-API-THROTTLING - integration identity hitting service-protection limits - admin-center API-call analytics (no public GET documented; admin-center-export fallback) - sustained 429s in 30 d - medium.

Tenant settings (read-only POST `listTenantSettings`, see integration note)
- PP-TENANT-ENV-CREATION-OPEN - non-admins may create production/sandbox environments - disableEnvironmentCreationByNonAdminUsers - eq false - medium (native form of the ScubaGear control).
- PP-TENANT-TRIAL-CREATION-OPEN - non-admins may create trial/developer environments - disableTrialEnvironmentCreationByNonAdminUsers, disableDeveloperEnvironmentCreationByNonAdminUsers - eq false - medium.
- PP-TENANT-CAPACITY-ALLOCATION-OPEN - environment admins may allocate add-on capacity - disableCapacityAllocationByEnvironmentAdmins - eq false - low.
- PP-TENANT-SHARE-EVERYONE-ALLOWED - apps can be shared with Everyone - powerApps.disableShareWithEveryone - eq false - medium.
- PP-TENANT-GUESTS-CAN-MAKE - guests may build apps and flows - powerApps.enableGuestsToMake - eq true - medium.
- PP-TENANT-CONNECTION-SHARE-EVERYONE - connections can be shared with Everyone - powerApps.disableConnectionSharingWithEveryone - eq false - medium.
- PP-TENANT-SETTINGS-DRIFT - routing, support-ticket visibility, maker match, create-from-image settings differ from the recorded decision - governance.* and powerApps.* flags - ne threshold values - low.
- PP-TENANT-DISABLED-USER-CLEANUP-OFF - disabled users not removed from environments automatically - userManagementSettings.enableDeleteDisabledUserinAllEnvironments - eq false - low.
- PP-TENANT-AI-SETTINGS-DRIFT - model data sharing on, or Copilot settings differ from the decision - intelligence.*, modelExperimentation.enableModelDataSharing - enableModelDataSharing eq true; others ne threshold - medium.
- PP-ADMIN-DIGEST-OFF - weekly admin digest disabled - governance.disableAdminDigest - eq true - low.
- PP-DLP-DESKTOP-FLOW-POLICY-OFF - desktop flow module policies not managed - governance.policy.enableDesktopFlowDataPolicyManagement - eq false - low.

Data policies and isolation (`PowerPlatform.Governance/v2/policies`, `v1/tenants/{id}/tenantIsolationPolicy`)
- PP-DLP-NO-TENANT-POLICY - no policy covers all environments - policies[].environmentType - count lt 1 where AllEnvironments - high.
- PP-DLP-DEFAULT-ENV-WEAK - default environment not covered, or new connectors default to business - policy scope and defaultConnectorsClassification - no covering policy, or default ne Blocked/NonBusiness - high.
- PP-DLP-EXFIL-CONNECTORS-NOT-BLOCKED - HTTP, custom-connector patterns and consumer storage connectors not in the blocked group - connectorGroups[].classification per connector id - threshold must-block list notin Blocked - medium.
- PP-DLP-CHANGED-RECENT - policy modified in the last 7 days - lastModifiedTime - age-lt 7 - medium (review list).
- PP-TENANT-ISOLATION-OFF - cross-tenant isolation disabled - tenantIsolationPolicy properties.isDisabled - eq true - high (native form of the ScubaGear control).
- PP-TENANT-ISOLATION-ALLOWLIST-UNDOCUMENTED - allowed tenants outside the recorded partner list - allowedTenants[].tenantId - notin threshold list - medium.

Environments
- PP-ENV-NOT-MANAGED - production environment is not a Managed Environment, or has no sharing limit - governanceConfiguration.protectionLevel, settings.extendedSettings.limitSharingMode - protectionLevel ne Standard or limitSharingMode empty - medium.
- PP-ENV-DEFAULT-NOT-MANAGED - the default environment is not managed - same fields, isDefault - medium.
- PP-ENV-NO-SECURITY-GROUP - non-default environment without a security group - linkedEnvironmentMetadata.securityGroupId - empty - medium.
- PP-ENV-OUT-OF-REGION - environment outside the agreed geography - location / azureRegion - notin threshold list - low.
- PP-ENV-BACKUP-RETENTION-SHORT - production backup retention not 28 days - properties.retentionPeriod - ne P28D - medium.
- PP-ENV-NO-BACKUP-BEFORE-RELEASE - a managed solution landed in production with no manual backup in the 48 h before it - environments/{id}/backups (for_each) joined in the store to Dataverse solutions installedon - no backup in window - medium.
- PP-ENV-COPY-UNAPPROVED - a copy into a sandbox in the last year without an override, or into a sandbox with no security group - environments/{id}/lifecycleOperations type copy - any (accept per copy) - medium.
- PP-ENV-TRIAL-EXPIRED - trial environment older than 30 days - environmentSku Trial, createdTime - age-gt 30 - low.
- PP-ENV-DEVELOPER-ORPHANED - developer environment whose owner is disabled - environmentSku Developer, createdBy joined to Entra users - owner accountEnabled eq false - low.
- PP-ENV-SANDBOX-OVERSIZED - sandbox capacity larger than half of production - capacity per environment, store comparison - ratio gt 0.5 - medium.
- PP-ENV-NAMING - environment name outside the convention, or more than one Production SKU - displayName notmatch threshold pattern; count gt 1 where Production - low.
- PP-DEFAULT-ENV-SPRAWL - business apps shared to many users living in the default environment - apps admin API sharedUsersCount - gt 50 in the default environment - medium.
- PP-PAGES-SITE-PUBLIC - public Power Pages site without an override - `powerpages/environments/{id}/websites` siteVisibility - eq public - medium.

Apps, flows and connections (Power Apps / Power Automate admin APIs)
- PP-APP-SHARED-WITH-EVERYONE - app permission granted to the whole tenant - apps/{id}/permissions principal.type - eq Tenant - medium.
- PP-APP-SHARED-LARGE-GROUP - app shared to a group above the size threshold outside a managed environment - permissions principal group joined to Entra group size - gt threshold - low.
- PP-APP-CRITICAL-CONNECTION-BROKEN - a threshold-listed critical app has a connection not Connected or a dependent flow not Started - app connectionReferences + connections statuses + flows - any - high.
- PP-APP-OWNER-DISABLED - shared app whose owner is disabled - apps owner joined to Entra users - accountEnabled eq false - medium.
- PP-APP-UNUSED - app not launched in a year - admin-center usage export (admin-center-export) - last launch age-gt 365 - low.
- PP-FLOW-SINGLE-OWNER - started production flow with one owner - flows/{id}/owners count - eq 1 - high.
- PP-FLOW-OWNER-DISABLED - started flow whose only owner is disabled - owners joined to Entra users - any - high.
- PP-FLOW-STOPPED-STALE - stopped flow untouched for 90 days - state Stopped, lastModifiedTime - age-gt 90 - low.
- PP-CONNECTION-OWNER-DISABLED - connection owned by a disabled user and referenced by a started flow or shared app - connections createdBy joined to Entra users + references - any - medium.
- PP-CONNECTION-SHARED-EVERYONE - connection shared with the whole tenant - connections/{id}/permissions principal.type - eq Tenant - medium.
- PP-CONNECTION-ERROR-REFERENCED - connection in Error state referenced by a started flow - statuses.status eq Error + references - any - low.
- PP-CONNECTOR-DEPRECATED-IN-USE - connection or flow on a connector in the deprecated list - connections properties.apiId - in threshold list - medium.
- PP-CUSTOM-CONNECTOR-WEAK-AUTH - custom connector with no security or an API key / basic definition - `apis?$filter=isCustomApi eq true` connectionParameters securityDefinition type - in [none, apiKey, basic] - low.
- PP-MANAGED-ENV-UNLICENSED-USER - user of a managed environment without a premium licence - environment users joined to Entra assignedLicenses - no qualifying SKU - medium.

Power BI / Fabric sub-integration (`api.powerbi.com`, `api.fabric.microsoft.com`)
- PBI-DATASET-REFRESH-FAILING - scheduled dataset whose last refreshes failed - admin/groups expand datasets, per-dataset refreshes - last status Failed (3 in a row = medium) - medium.
- PBI-DATASET-GATEWAY-DEAD - gateway-dependent dataset bound to no live cluster - admin/datasets isOnPremGatewayRequired + datasources gatewayId joined to clusters - no match - medium.
- PBI-GATEWAY-MEMBER-OFFLINE - gateway cluster member not Live - gatewayclusters expand memberGateways status - ne Live - high.
- PBI-GATEWAY-SINGLE-MEMBER - resource cluster with one member - memberGateways size-lt 2 - high.
- PBI-GATEWAY-VERSION-OLD - member version not current - memberGateways versionStatus - ne UpToDate (Deprecated = high) - medium.
- PBI-GATEWAY-PERSONAL-IN-USE - personal gateway backing a workspace dataset - clusters type Personal joined to dataset datasources - any - low.
- PBI-GATEWAY-DATASOURCE-UNREACHABLE - data source status not OK - gatewayclusters/{id}/datasources/{ds}/status (for_each) - ne 200 - medium.
- PBI-GATEWAY-DATASOURCE-UNUSED - data source referenced by no dataset or flow - datasources joined to dataset datasources - no reference - low.
- PBI-GATEWAY-CREDENTIAL-WEAK - anonymous or key credential, unencrypted connection, public privacy level - datasources credentialType, credentialDetails.encryptedConnection, privacyLevel - in [Anonymous, Key] / ne Encrypted / eq Public - medium.
- PBI-GATEWAY-ADMIN-DISABLED - gateway admin whose account is disabled - gatewayclusters/{id}/permissions role Admin joined to Entra users - any - medium.
- PBI-GATEWAY-ADMIN-SINGLE - fewer than two enabled admins - permissions count - lt 2 - medium.
- PBI-WORKSPACE-ORPHANED - workspace with no admin - admin/groups expand users, state - eq Orphaned or no Admin user - medium.
- PBI-WORKSPACE-SINGLE-ADMIN - active workspace with content and one admin - users groupUserAccessRight Admin count - eq 1 - low.
- PBI-WORKSPACE-CLASSIC - classic (group) workspace - admin/groups type - eq Group - low.
- PBI-WORKSPACE-EMPTY - active workspace with no content for 90 days - expand reports, datasets, dashboards - all empty - low.
- PBI-ACTIVITY-PUBLISH-TO-WEB - a report published to the web in the last 7 days - admin/activityevents (one day per call, continuation token - paging gap) Activity - eq PublishToWebReport - high.
- PBI-ACTIVITY-EXTERNAL-SHARE - share to an external recipient - activityevents ShareReport/ShareDashboard with external recipient - any - medium.
- PBI-ACTIVITY-GATEWAY-CHANGE - gateway or data source created/changed - activityevents CreateGateway, DeleteGateway, AddDatasourceToGateway, UpdateDatasource - any (review list) - medium.
- PBI-LICENCE-PRO-UNUSED - Pro/PPU holder with no view activity in 90 days - activityevents distinct users joined to Entra assignedLicenses - no activity - low.
- PBI-TENANT-PUBLISH-TO-WEB-OPEN - admin/tenantsettings PublishToWeb enabled without a security group - enabled eq true and enabledSecurityGroups empty - high.
- PBI-TENANT-GUEST-ACCESS-OPEN - AllowGuestUserToAccessSharedContent / ElevatedGuestsTenant enabled unscoped - medium.
- PBI-TENANT-GUEST-INVITE-OPEN - ExternalSharingV2 enabled unscoped - medium.
- PBI-TENANT-LABELS-OFF - EimInformationProtectionEdit disabled - low.
- PBI-TENANT-ORG-LINKS-OPEN - ShareLinkToEntireOrg enabled unscoped - medium.
- PBI-TENANT-EXTERNAL-DATASET-SHARING-OPEN - EnableDatasetInPlaceSharing enabled unscoped - medium.
- PBI-TENANT-SP-API-UNSCOPED - ServicePrincipalAccessPermissionAPIs, AllowServicePrincipalsCreateAndUseProfiles, ServicePrincipalAccessGlobalAPIs enabled unscoped - medium.
- PBI-TENANT-SCRIPT-VISUALS-ON - RScriptVisual / PythonVisual enabled unscoped - low.
- PBI-TENANT-EXPORT-UNSCOPED - export/copy settings family enabled unscoped - low.
- PBI-TENANT-UNCERTIFIED-VISUALS - CertifiedCustomVisualsOnly disabled or external template apps allowed - low.
- PBI-TENANT-EXTERNAL-SUBSCRIPTIONS-ON - external email subscriptions enabled (settingName to confirm) - low.
- PBI-TENANT-AUDIT-OFF - AuditLog or UsageMetrics disabled - medium.
- PBI-TENANT-COPILOT-CROSS-GEO - Copilot cross-geo processing enabled (settingName to confirm) - medium.
- PBI-TENANT-RESOURCE-KEY-AUTH-ALLOWED - BlockResourceKeyAuthentication disabled - medium.
- PBI-TENANT-FABRIC-OPEN - Fabric item creation or trials enabled unscoped - medium.

## Rules once dataverse-web-api exists

All reads are `GET /api/data/v9.2/...` per environment (one integration instance per environment,
or `for_each` over the environment list when the admin API exists). `$apply` aggregates and
`RetrieveTotalRecordCount` are reads; nothing here writes.

Audit and logging
- D365-AUDIT-OFF - auditing disabled on a production environment - organizations isauditenabled - eq false - high.
- D365-AUDIT-ACCESS-OFF - user-access (and, by decision, read) auditing off - organizations isuseraccessauditenabled, isreadauditenabled - eq false (read half thresholded) - medium.
- D365-AUDIT-RETENTION-FOREVER - audit retention unbounded or outside the agreed range - organizations auditretentionperiodv2 - eq -1 or notin [365..2555] - high.
- D365-AUDIT-ON-LOG-TABLE - auditing enabled on a high-churn technical table - EntityDefinitions IsAuditEnabled where LogicalName match threshold pattern - eq true - medium.
- D365-AUDIT-PII-TABLE-OFF - personal-data table or column not audited - EntityDefinitions / Attributes IsAuditEnabled for threshold-listed tables - eq false - high.
- D365-AUDIT-TOP-PRODUCERS - weekly audit rows per table and operation (review list; technical tables on top = finding) - audits `$apply=filter(createdon ge {DAYS_AGO:7})/groupby((objecttypecode,operation),aggregate($count as n))` - n gt threshold for a technical table - medium.
- D365-PLUGIN-TRACE-ALL - plug-in trace set to All in production, or trace table large - organizations plugintracelogsetting eq 2; RetrieveTotalRecordCount plugintracelog gt 100000 - low.
- D365-MASS-UPDATE-UNEXPLAINED - a day with mass record modification and no override - asyncoperations by operationtype over 30 d, audit row count per day, solutions installedon - modified records gt threshold without an override - medium.

Health
- D365-ASYNC-JOBS-FAILING - system job name with 3 or more failures in 7 days - asyncoperations statuscode eq 31 and completedon ge {DAYS_AGO:7}, grouped by name - count ge 3 - medium.
- D365-ASYNC-BACKLOG-STUCK - jobs waiting or suspended beyond the window - asyncoperations statecode 1, statuscode in (0, 10), createdon older than the window (sub-day granularity is an engine gap) - any - medium.
- D365-PLUGIN-EXCEPTIONS - plug-in type with 5 or more exceptions in 7 days - plugintracelogs exceptiondetails notempty grouped by typename - count ge 5 - medium.
- D365-PLUGIN-SLOW - plug-in execution near the sandbox limit - plugintracelogs performanceexecutionduration - gt 30000 ms - medium.
- D365-MAILBOX-SYNC-FAILING - server-side sync mailbox in failure or stale - mailboxes incomingemailstatus / outgoingemailstatus ne Success, lastsuccessfulsynccompletedon age-gt - high.
- D365-MAIL-APPROVAL-OFF - mailbox approval not required or profile not server-to-server - organizations requireapprovalforuseremail / requireapprovalforqueueemail eq false; emailserverprofiles authenticationprotocol - medium.
- D365-SLA-KPI-NONCOMPLIANT - share of SLA KPI instances non-compliant in the week - slakpiinstances status eq 4 - ratio gt 10 % - medium.
- D365-SERVICE-ENDPOINT-FAILING - service endpoint unauthenticated, plain HTTP, or with failed posts - serviceendpoints authtype, url; asyncoperations operationtype 59 failures - any - medium.
- D365-SHAREPOINT-SITE-INVALID - document management site not valid - sharepointsites validationstatus - ne valid - low.
- D365-TABLE-SIZE-GROWTH - table row count growing past the agreed rate - RetrieveTotalRecordCount for threshold-listed tables, store comparison - growth gt threshold - medium.
- D365-LOG-TABLE-UNBOUNDED - a listed log table with no recurring bulk-delete job - RetrieveTotalRecordCount + bulkdeleteoperations recurrencepattern - rows gt threshold and no job - medium.
- D365-RETENTION-JOB-MISSING - no recurring bulk delete or retention policy for a data type in the schedule - bulkdeleteoperations, retentionconfigs - count lt 1 per threshold-listed type - medium.

Identity and access
- D365-SYSADMIN-TOO-MANY - more System Administrator (and System Customizer) holders than allowed - roles `$filter=name eq 'System Administrator'&$expand=systemuserroles_association` - enabled human holders gt threshold - high.
- D365-SYSADMIN-DISABLED-USER - disabled user holding an admin role - same expand, isdisabled eq true - any - medium.
- D365-VENDOR-ACCOUNT-STANDING-ADMIN - account matching the vendor pattern with a standing admin role - systemusers domainname match threshold pattern + roles - any - medium.
- D365-APP-USER-UNKNOWN - application user not in the recorded integration list - systemusers applicationid ne null - applicationid notin threshold list - medium.
- D365-APP-USER-SECRET-AUTH - application user whose app registration carries a client secret - applicationid joined in the store to Q-APPS passwordCredentials - notempty - medium.
- D365-DISABLED-USER-WITH-ROLE - disabled user still holding roles - systemusers isdisabled eq true with roles - any - low.
- D365-DISABLED-USER-OWNS-RECORDS - records owned by disabled users - per-user `$count` on core tables (for_each) - gt 0 - low.
- D365-REVIEW-IDENTITY-OVERPRIVILEGED - Keeper's own identity holds System Administrator - WhoAmI + roles of the caller - any - low.
- D365-ROOT-BU-USERS - users parked in the root business unit - systemusers grouped by _businessunitid_value vs businessunits parent empty - count gt threshold - medium.
- D365-ROLE-GLOBAL-DEPTH-PII - role with Organization depth on personal-data tables held by many users - RetrieveRolePrivilegesRole (for_each role) PrivilegeDepth Global on prvRead/prvWrite/prvDelete/prvShare/prvExportToExcel - holders gt 5 % of users - high.
- D365-DIRECT-SHARES-HIGH - direct record shares above the bound - principalobjectaccessset `$apply groupby count` - gt threshold - low.
- D365-CLASSIC-WORKFLOW-OWNER-DISABLED - activated classic process owned by a disabled user - workflows statecode 1 `$expand ownerid` - isdisabled eq true - medium.
- D365-CASE-OWNER-DISABLED - active cases owned by disabled users - incidents statecode 0 grouped by owner joined to systemusers - any - medium.
- D365-QUEUE-NO-MEMBERS - active queue with fewer than two active members - queues `$expand queuemembership_association` - count lt 2 - medium.
- D365-IP-FIREWALL-OFF - IP firewall not enforced on production - organizations enableipbasedfirewallrule - eq false (audit mode = low) - medium.
- D365-COOKIE-BINDING-OFF - IP cookie binding off - organizations enableipbasedcookiebinding - eq false - low.
- D365-ATTACHMENT-BLOCKLIST-WEAK - blocked attachment list missing executable types or upload size too large - organizations blockedattachments, maxuploadfilesize - threshold list notcontains / gt - low.
- D365-BOT-INVENTORY - Copilot Studio agent (review list: owner, channels, knowledge) - bots, botcomponents - each: any - low.
- D365-BOT-NO-AUTH - published agent with internal knowledge and no authentication - bots authenticationmode eq 0 with knowledge components - any - medium.

Customisation lifecycle
- D365-CLASSIC-WORKFLOW-ACTIVE - active classic workflow or action (inventory, growth = finding) - workflows statecode 1, category in (0, 3) - count gt previous run - low.
- D365-UNMANAGED-SOLUTION-IN-PROD - unmanaged solution with components in production - solutions ismanaged eq false, isvisible eq true - any - medium.
- D365-PUBLISHER-UNKNOWN - publisher not in the recorded list - publishers uniquename - notin threshold list - medium.
- D365-ISV-SOLUTION-STALE - third-party solution older than a year - solutions expand publisherid, installedon - age-gt 365 - low.
- D365-SOLUTION-IMPORT-NO-CHANGE - solution import into production without a change record - msdyn_solutionhistories over 365 d, later joined to ITSM change rows - no match - medium.
- D365-APP-NOT-IN-SOLUTION - a threshold-listed critical app or flow outside any solution - solutioncomponents componenttype 300 / 29 - absent - low.
- D365-PLUGIN-NOT-SANDBOXED - plug-in assembly outside sandbox isolation or unmanaged - pluginassemblies isolationmode ne 2 or ismanaged eq false - any - medium.
- D365-ENVVAR-TEST-URL-IN-PROD - environment variable value matching the test-host pattern - environmentvariablevalues value match threshold - any - medium.
- D365-CONNECTION-REF-PERSONAL - connection reference owned by a person - connectionreferences `_ownerid_value` joined to systemusers applicationid null - any - medium.
- D365-SECRET-IN-PLAIN-VARIABLE - secret-like name in a String environment variable or plug-in step configuration - environmentvariabledefinitions type ne secret and schemaname match pattern; sdkmessageprocessingsteps configuration match pattern (names only) - any - high.
- D365-WEBRESOURCE-HARDCODED-HOST / D365-DEPRECATED-CLIENT-API - web resource content with hard-coded hosts or removed client APIs - webresourceset content (base64; decoding and text search is an engine gap) - match pattern - low / medium.
- D365-DUPLICATE-RULE-MISSING - no published duplicate rule on the resident or organisation table - duplicaterules statecode eq 1 - count lt 1 per table - low.
- D365-CUSTOM-TABLE-UNUSED - custom table with no rows or no change in a year - EntityDefinitions IsCustomEntity + per-table `$count`, max(modifiedon) - 0 rows or age-gt 365 - low.


---

## Defender XDR, Defender for Endpoint, Defender for Office, information protection


New proposals in the format of `docs\proposals\microsoft-cloud.md`. Tenant-free: every pattern,
list and host is a generic default or a `threshold.<name>` setting. Device-side rules use Keeper's
per-host protocols (cim, registry, eventlog) and go into `rules\workstations.yaml` /
`rules\windows-server.yaml`; Graph security rules go into a new `rules\defender.yaml` on the
`graph` integration (or `m365.yaml` if the author prefers one file); two store joins go wherever
the cross-system rules live.

Conventions: "Q-MPSTATUS" = the existing `SELECT * FROM MSFT_MpComputerStatus` query of
WS-DEFENDER-RTP-OFF / WINSRV-DEFENDER-RTP-OFF (namespace root/Microsoft/Windows/Defender);
"Q-MPPREF" = the `SELECT * FROM MSFT_MpPreference` query proposed in windows-estate.md for
WS-DEFENDER-MAPS-OFF (shared by every MpPreference rule below). Every device-side rule has a server
twin with the WSRV-/WINSRV- prefix unless stated otherwise.

---

## Device-side Defender state (cim / registry / eventlog)

### WSRV-DEFENDER-NOT-ONBOARDED
- Catches: a Windows server (or, as a twin of the proposed WS-REG-MDE-ONBOARDED, any host) that is
  not onboarded to Defender for Endpoint: the onboarding state value is missing or not 1, or the
  Sense service is absent or not running. On the two older server releases the modern unified agent
  installs the same Sense service, so "Sense absent on a supported server" also catches the retired
  monitoring-agent onboarding. Servers are where directories, backups and shares live; one without
  EDR is the attacker's staging host.
- Severity: high (critical for a domain controller - `operatingSystem`/role match in evidence).
- Source: windows-server.yaml; two queries on the same targets: registry `hive: HKLM`, `path:
  SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status`, `values: [OnboardingState,
  OrgId]` (OrgId reported as "set", never the value); cim `SELECT Name, State, StartMode FROM
  Win32_Service WHERE Name = 'Sense'`, key host. Two rules sharing one id family:
  WSRV-DEFENDER-NOT-ONBOARDED (registry) and WSRV-DEFENDER-SENSE-STOPPED (cim).
- Permission: scan account local read on the host (registry read, CIM read).
- Condition: registry rule - `exists` false or OnboardingState ne 1; cim rule - count none, or
  State ne Running. Exceptions (appliances, vendor-managed hosts) are accepted risks, not rule
  changes.
- Refs: CIS-Controls-v8:13.7, NIST-800-53:SI-4, NIST-800-53:SI-3, MITRE-ATTACK:T1562.001.
- Fix: onboard with the modern unified agent (older releases) or the built-in sensor (current
  releases) through the management tool of record; retire or isolate hosts whose OS cannot run it.
- Confidence: verified - https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-onboarding
  (OnboardingState = 1 under the Status key); Sense service name verified on the same page.

### WS-DEFENDER-SCAN-STALE
- Catches: a device whose quick scan is overdue or older than N days, or whose last scan did not
  complete. Without completed scans only real-time protection stands, and a failing scan usually
  means a broken engine or a scheduled task someone disabled.
- Severity: low (medium when the full scan is also older than 90 days).
- Source: workstations.yaml; cim; shared query Q-MPSTATUS; fields QuickScanOverdue, QuickScanAge,
  FullScanOverdue, FullScanAge, QuickScanEndTime, FullScanEndTime, AMRunningMode.
- Permission: CIM read.
- Condition: AMRunningMode match `^Normal` and (QuickScanOverdue eq true or QuickScanAge gt 7,
  threshold `workstations.defender-quick-scan-max-age-days`). Passive-mode devices are n/a (the
  other engine scans). Evidence: both scan end times.
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.1.
- Fix: restore the scheduled scan setting in the antivirus policy; if scans keep failing, repair
  the platform (WS-DEFENDER-PLATFORM-OLD).
- Confidence: verified property names -
  https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus (QuickScanAge,
  QuickScanOverdue, FullScanAge, FullScanOverdue).

### WS-DEFENDER-SENSE-CLOUD-ERRORS
- Catches: a device whose Defender for Endpoint sensor logged cloud-connectivity failures in the
  last day (events 5, 6 and 7 of the sensor channel: contacting the service failed, onboarding
  contact failed, onboarding parameters unreadable). A device can look onboarded in every console
  while sending no telemetry; a proxy, TLS inspection or firewall change shows here first, per
  device, before the portal marks the sensor impaired.
- Severity: medium (high when the count per host exceeds the flood threshold).
- Source: workstations.yaml; eventlog; `log: Microsoft-Windows-SENSE/Operational`, `ids: [5, 6,
  7]`, `days: 1`, `max: 200`; key `{host}`; count judged per host.
- Permission: event-log read on the host.
- Condition: count ge 12 (threshold `workstations.sense-cloud-errors-per-day`); a host without
  the channel returns no rows (not onboarded - WSRV-DEFENDER-NOT-ONBOARDED / WS-REG-MDE-ONBOARDED
  catch that).
- Refs: NIST-800-53:SI-4, NIST-800-53:SC-7, CIS-Controls-v8:13.7.
- Fix: put the Defender for Endpoint and antivirus cloud URLs on the proxy/inspection bypass list;
  check the WinHTTP proxy the service uses; rerun the client analyzer.
- Confidence: verified event ids -
  https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes.

### WS-DEFENDER-NDR-EVENT-FLOOD
- Catches: a device whose low-privilege app container operational log receives a flood of events
  (hundreds per second from the network detection component when it runs without its expected user
  rights). The log wraps in seconds and hides every other event in it; the root cause is usually a
  user-rights policy applied to the wrong scope.
- Severity: medium.
- Source: workstations.yaml; eventlog; `log:
  Microsoft-Windows-LessPrivilegedAppContainer/Operational`, `days: 1`, `max: 500`; key
  `{host}`; count per host.
- Permission: event-log read.
- Condition: count ge 500 in one day (threshold `workstations.lpac-events-per-day`); a result at
  the cap is partial and must count as the flood, not as unknown - the YAML author should set
  `max` above the threshold so the comparison stays exact.
- Refs: NIST-800-53:AU-4, NIST-800-53:SI-4.
- Fix: restore the service account rights the component needs (remove the user-rights policy from
  workstation scope); confirm the log stops wrapping.
- Confidence: likely (channel name from the Windows event-log inventory; the flood signature is an
  observation, not documented) -
  https://learn.microsoft.com/en-us/defender-endpoint/network-protection (component description).

### WS-DEFENDER-EVT-REMEDIATION-FAILED
- Catches: malware detected in the last 7 days where the remediation action failed or the engine
  hit a critical error (events 1008, 1118, 1119), plus repeated detections of the same threat on
  one device (1116/1117 recurring). A detection that was not cleaned is a live infection; a threat
  detected on three days running means the source is still there.
- Severity: high.
- Source: workstations.yaml; eventlog; `log: Microsoft-Windows-Windows Defender/Operational`,
  `ids: [1008, 1116, 1117, 1118, 1119]`, `days: 7`, `max: 500`; key `{host}|{id}|{Threat Name}`
  (the named event-data field); evidence: path, user, action, error.
- Permission: event-log read.
- Condition: `each: { field: id, op: in, value: [1008, 1118, 1119] }`; a second rule
  WS-DEFENDER-EVT-REPEAT-DETECTION over the same fetch with a per-key count ge 3 (needs the
  per-key row count the engine does not expose yet - until then keep the single-event rule).
- Refs: NIST-800-53:SI-3, NIST-800-53:IR-4, MITRE-ATTACK:T1204.
- Fix: full scan and investigation of the device; isolate if the action keeps failing; find the
  recurring source (share, USB, mail).
- Confidence: verified event ids - https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
  (event-data field names such as Threat Name and Path: likely).

### WS-DEFENDER-ASR-EVENTS
- Catches: attack-surface-reduction rule events in the last 7 days: 1121 (blocked) and 1122
  (audited), per host and rule id. Audit events show which rules can move to block without breaking
  business apps; block events show attacks stopped and candidates for narrow exclusions. A review
  list, not a verdict.
- Severity: info (low when 1121 count per rule and host exceeds the threshold).
- Source: workstations.yaml; eventlog; same channel as above, `ids: [1121, 1122]`, `days: 7`;
  key `{host}|{id}|{ID}` (the rule GUID field in event data); evidence: process, path, user.
- Permission: event-log read.
- Condition: `each: any` (review list); tenants that do not want the noise set the rule to
  disabled or raise the per-key count threshold once the engine exposes counts.
- Refs: NIST-800-53:SI-3, NIST-800-53:CM-7, CIS-Controls-v8:10.5, MITRE-ATTACK:T1059.
- Fix: review the triggering processes; add narrow exclusions for genuine business apps, then
  move the rule from audit to block.
- Confidence: verified event ids -
  https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-operationalize
  (event-data field for the rule GUID: likely).

### WS-DEFENDER-ASR-NOT-BLOCK
- Catches: a device where a standard-protection attack-surface-reduction rule is not in block
  mode. The three standard-protection rules (credential theft from the local security authority,
  abuse of exploited vulnerable signed drivers, persistence through WMI event subscription) have
  almost no false positives; the Office/email/script rules follow after an audit period.
- Severity: medium (high for the three standard-protection rules).
- Source: workstations.yaml; cim; shared query Q-MPPREF; fields AttackSurfaceReductionRules_Ids
  (array of GUIDs) and AttackSurfaceReductionRules_Actions (parallel array: 0 off, 1 block, 2
  audit, 6 warn).
- Permission: CIM read (admin rights on the device, as for exclusions).
- Condition: `AttackSurfaceReductionRules_Ids` notcontains <rule GUID> - one rule per GUID in the
  threshold list `workstations.asr-required-rule-ids` (default: the three standard-protection
  GUIDs); the "present but in audit" case needs the parallel-array pairing the engine cannot do
  (gap) - until then the evidence prints both arrays and the rule fires only on absence.
- Refs: NIST-800-53:SI-3, NIST-800-53:CM-7, CIS-Controls-v8:10.5, MITRE-ATTACK:T1003.001,
  MITRE-ATTACK:T1546.003.
- Fix: deploy the standard-protection rules in block mode through the endpoint-security
  attack-surface-reduction policy; stage the others through audit (WS-DEFENDER-ASR-EVENTS).
- Confidence: verified property names and GUIDs -
  https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference.

### WS-DEFENDER-PASSIVE-NO-EDR-BLOCK
- Catches: a device where Defender antivirus is in passive mode (another engine is primary) and
  EDR in block mode is not active, while the Sense sensor is running. In passive mode Defender
  detects but does not remediate; EDR block mode lets it still block what its EDR sees. The tenant
  toggle is portal-only; the per-device effect is readable.
- Severity: medium.
- Source: workstations.yaml; cim; shared query Q-MPSTATUS; field AMRunningMode (values include
  "Normal", "Passive Mode", "EDR Block Mode", "SxS Passive Mode").
- Permission: CIM read.
- Condition: AMRunningMode match `Passive` and notmatch `EDR Block`. Evidence names the running
  mode; pair with WS-AV-MULTIPLE to show the primary engine.
- Refs: NIST-800-53:SI-3, NIST-800-53:SI-4, MITRE-ATTACK:T1562.001.
- Fix: enable EDR in block mode in the endpoint settings (tenant-wide), or make Defender the
  active engine on devices without another product.
- Confidence: verified mode strings -
  https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
  and https://learn.microsoft.com/en-us/defender-endpoint/edr-in-block-mode.

### WS-DEFENDER-LOCAL-ADMIN-MERGE
- Catches: a device where locally added exclusions and settings still merge with policy
  (DisableLocalAdminMerge false). Wherever users are local administrators, a local exclusion is one
  command away for the user or for malware running as them; with merge disabled only policy
  exclusions count.
- Severity: medium (high in estates where every user is a local administrator).
- Source: workstations.yaml; cim; shared query Q-MPPREF; field DisableLocalAdminMerge.
- Permission: CIM read.
- Condition: DisableLocalAdminMerge eq false (absent → n/a).
- Refs: NIST-800-53:CM-6, NIST-800-53:AC-6, CIS-Controls-v8:4.1, MITRE-ATTACK:T1562.001.
- Fix: set "configure local administrator merge behavior for lists" to disabled in the antivirus
  policy (one channel - policy or Group Policy, not both).
- Confidence: verified -
  https://learn.microsoft.com/en-us/defender-endpoint/configure-local-policy-overrides-microsoft-defender-antivirus.

### WS-DEFENDER-CFA-OFF
- Catches: controlled folder access off on a workstation (EnableControlledFolderAccess 0). It
  blocks unknown processes from changing documents and is the cheapest native ransomware control;
  it needs an allow list for business apps, so the audit mode (2) is a legitimate intermediate
  state and passes.
- Severity: low.
- Source: workstations.yaml; cim; shared query Q-MPPREF; fields EnableControlledFolderAccess
  (0 off, 1 block, 2 audit, 3 block disk modification only, 4 audit disk modification only),
  ControlledFolderAccessAllowedApplications (array, evidence).
- Permission: CIM read.
- Condition: EnableControlledFolderAccess eq 0. Tenants that decided against it record one accepted
  exception on the rule.
- Refs: NIST-800-53:SI-3, NIST-800-53:CP-9, CIS-Controls-v8:10.5, MITRE-ATTACK:T1486.
- Fix: roll out in audit mode, review the audited events, then block with the allowed-app list.
- Confidence: verified -
  https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders.

### WS-DEFENDER-SIGNATURE-UPDATE-SLOW
- Catches: a device that checks for security-intelligence updates less than every N hours, or
  whose fallback order has no Microsoft source after the internal update server. Devices checking
  once a day are a day behind an outbreak; without the Microsoft fallback an unreachable internal
  server means no updates at all (WS-DEFENDER-SIG-OLD then fires later, this rule fires before).
- Severity: low.
- Source: workstations.yaml; cim; shared query Q-MPPREF; fields SignatureUpdateInterval (hours;
  0 = use the scheduled time only), SignatureFallbackOrder (pipe-separated text),
  SignatureDefinitionUpdateFileSharesSources.
- Permission: CIM read.
- Condition: SignatureUpdateInterval gt 4 (threshold `workstations.signature-update-max-hours`)
  or SignatureUpdateInterval eq 0, or SignatureFallbackOrder notmatch `MicrosoftUpdateServer|MMPC`.
- Refs: NIST-800-53:SI-3(2), CIS-Controls-v8:10.2.
- Fix: set the update interval and a fallback order that ends with a Microsoft source in the
  antivirus policy.
- Confidence: verified -
  https://learn.microsoft.com/en-us/defender-endpoint/manage-protection-update-schedule-microsoft-defender-antivirus
  and ...manage-protection-updates-microsoft-defender-antivirus (fallback order values).

### WSRV-DEFENDER-AUTO-EXCLUSIONS-OFF
- Catches: a server where the automatic server-role exclusions are disabled (DisableAutoExclusions
  true), or where a third-party engine is primary but Defender was not forced passive (the
  ForceDefenderPassiveMode registry value absent or 0 while another antivirus is installed - the
  server twin of WS-AV-MULTIPLE already reports two engines; this adds the switch). On servers
  Defender does not switch to passive by itself; two engines scanning the same files corrupt
  databases and slow directory services, and missing role exclusions do the same.
- Severity: medium.
- Source: windows-server.yaml; cim shared query Q-MPPREF (server twin) field
  DisableAutoExclusions; registry `hive: HKLM`, `path: SOFTWARE\Policies\Microsoft\Windows
  Advanced Threat Protection`, `values: [ForceDefenderPassiveMode]`.
- Permission: CIM and registry read.
- Condition: rule 1 - DisableAutoExclusions eq true; rule 2 (WINSRV-DEFENDER-PASSIVE-NOT-FORCED)
  - a store join of the registry row with the WINSRV-AV-MULTIPLE rows (two products registered)
  where ForceDefenderPassiveMode absent or ne 1 - or, simpler, evidence only: the registry row is
  reported next to the AV-MULTIPLE finding.
- Refs: NIST-800-53:SI-3, NIST-800-53:CM-6.
- Fix: re-enable automatic exclusions; set ForceDefenderPassiveMode = 1 by policy on servers that
  keep another primary engine, or remove the other engine.
- Confidence: verified -
  https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows-server
  (passive mode registry value) and ...configure-server-exclusions-microsoft-defender-antivirus.

### WS-DEFENDER-EVT-PROTECTION-CHANGED
- Catches: protection turned off or weakened on a device in the last 7 days as the engine itself
  logged it: real-time protection disabled (5001), real-time configuration changed (5004),
  configuration changed including exclusions (5007 whose message names an exclusion value),
  malware/virus scanning disabled (5010, 5012), and a tamper-protection block (5013). Turning the
  engine off or adding an exclusion is the step before ransomware; local administrators can try it.
- Severity: high for 5001/5010/5012; medium for 5004/5007 with an exclusion; low for 5013 (the
  attempt was blocked - still worth a look).
- Source: workstations.yaml; eventlog; `log: Microsoft-Windows-Windows Defender/Operational`,
  `ids: [5001, 5004, 5007, 5010, 5012, 5013]`, `days: 7`; key `{host}|{id}|{recordId}`; evidence:
  old and new value fields.
- Permission: event-log read.
- Condition: `each: { any: [ {field: id, op: in, value: [5001, 5010, 5012, 5013]}, {all: [
  {field: id, op: in, value: [5004, 5007]}, {field: "New Value", op: match, value:
  "Exclusions|DisableRealtimeMonitoring"} ]} ] }` (event-data field names to confirm on the first
  run). A policy deployment that legitimately changes settings is matched by its date and
  accepted; the point is the ones nobody planned.
- Refs: NIST-800-53:SI-4, NIST-800-53:SI-7, NIST-800-53:AU-6, MITRE-ATTACK:T1562.001.
- Fix: investigate the device and the initiating account; enforce tamper protection and
  DisableLocalAdminMerge; re-apply the policy.
- Confidence: verified event ids - https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
  (5007 field names: likely).

### WS-REG-SMARTSCREEN-OFF
- Catches: a device where SmartScreen for apps and files, or for the browser, is off or can be
  overridden by the user. SmartScreen is the last native filter in front of a downloaded installer
  or a phishing page; a policy that disables it (often "for performance" or because another web
  filter exists) removes it from every device regardless of which other layer is supposed to
  cover it.
- Severity: low (medium when no other web-filtering layer is recorded).
- Source: workstations.yaml; registry; `hive: HKLM`, `path:
  SOFTWARE\Policies\Microsoft\Windows\System`, `values: [EnableSmartScreen, ShellSmartScreenLevel]`;
  second query `path: SOFTWARE\Policies\Microsoft\Edge`, `values: [SmartScreenEnabled,
  SmartScreenPuaEnabled, PreventSmartScreenPromptOverride]`; key host.
- Permission: registry read.
- Condition: EnableSmartScreen eq 0, or ShellSmartScreenLevel ne Block (when set), or
  SmartScreenEnabled eq 0, or PreventSmartScreenPromptOverride eq 0 (when set). Absent values =
  defaults (on, warn) = pass for the "off" part; the evidence says "not enforced by policy".
- Refs: NIST-800-53:SI-3, NIST-800-53:SC-7, CIS-Controls-v8:9.2, MITRE-ATTACK:T1204.002.
- Fix: enforce SmartScreen (block level, no override) through the endpoint-security or
  browser policy; record which web-filtering layer is of record so the two do not fight.
- Confidence: verified value names -
  https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen and
  https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#smartscreenenabled.

---

## Graph security rules (`rules\defender.yaml`, integration graph)

### DEFENDER-MDI-SENSOR-UNHEALTHY
- Catches: a Defender for Identity sensor whose health is not healthy, or whose deployment is not
  complete. An unhealthy sensor on a domain controller means no detection of directory attacks on
  that controller, while every dashboard still shows the sensor "installed".
- Severity: high (notHealthyHigh), medium (notHealthyMedium), low (notHealthyLow or deployment
  pending).
- Source: defender.yaml; beta; `/security/identities/sensors`; select id, displayName,
  sensorType, healthStatus, deploymentStatus, version, domainName, createdDateTime; key id, name
  displayName; refresh 6h. New query (shared with DEFENDER-MDI-DC-NOT-COVERED).
- Permission: SecurityIdentitiesSensors.Read.All (application).
- Condition: healthStatus ne healthy or deploymentStatus ne finished. Severity by healthStatus
  value map.
- Refs: NIST-800-53:SI-4, NIST-800-53:AU-12, CIS-Controls-v8:8.2, MITRE-ATTACK:T1003.006.
- Fix: open the sensor's health issues (next rule); fix the service, the auditing, the
  connectivity or the service-account problem named there.
- Confidence: verified resource and enums -
  https://learn.microsoft.com/en-us/graph/api/resources/security-sensor?view=graph-rest-beta.

### DEFENDER-MDI-HEALTH-ISSUE-OPEN
- Catches: an open Defender for Identity health issue - sensor outdated, auditing not configured
  as required on a domain controller, directory-service-account problems, connectivity, clock
  skew. Several of these silently disable specific detections (missing object or advanced auditing
  removes whole alert families) while the sensor stays "healthy".
- Severity: by the issue's severity (high/medium/low); auditing and service-account types raise
  one level.
- Source: defender.yaml; beta; `/security/identities/healthIssues`; filter `status eq 'open'`;
  select id, displayName, healthIssueType, issueTypeId, severity, status, createdDateTime,
  lastModifiedDateTime, domainNames, sensorDNSNames, description, recommendations; key id, name
  displayName; refresh 6h. New query.
- Permission: SecurityIdentitiesHealth.Read.All (application).
- Condition: status eq open and createdDateTime age-gt 7 (threshold
  `defender.mdi-health-issue-max-open-days`; high severity fires at once with threshold 0 per
  severity map). Evidence: sensor names, recommendations.
- Refs: NIST-800-53:SI-4, NIST-800-53:AU-2, NIST-800-53:AU-12, NIST-800-53:IA-5.
- Fix: apply the recommendation text: audit policy and object SACLs for the auditing types,
  update path for outdated sensors, group-managed service account for the account types.
- Confidence: verified -
  https://learn.microsoft.com/en-us/graph/api/resources/security-healthissue?view=graph-rest-beta
  (filter on status: likely).

### DEFENDER-MDI-DC-NOT-COVERED
- Catches: a domain controller (and, by threshold pattern, a certificate-services or
  directory-sync host) with no Defender for Identity sensor. Detection coverage of directory
  attacks is only as wide as the set of controllers with a sensor; a controller added after the
  rollout, or a sensor removed with a rebuild, is a blind spot nobody announces.
- Severity: high.
- Source: cross-system (store); joins the newest `defender` run's sensor rows
  (entity_type sensor, attrs displayName, sensorType, healthStatus) with the newest
  `active-directory` run's computer rows where `userAccountControl` has the server-trust flag
  8192 (domain controllers) or `dNSHostName` matches threshold
  `cross.mdi-expected-host-pattern` (certificate-services and sync hosts). Match on the short
  host name, upper-cased, as in the cross-system proposals.
- Permission: none beyond the two scans.
- Condition: a controller row with no sensor row (anti-join), or a sensor row whose healthStatus
  ne healthy for that controller (evidence). Both sides must have a usable newest run (the
  cross-system convention); otherwise no rows.
- Refs: NIST-800-53:SI-4, NIST-800-53:AU-12, CIS-Controls-v8:8.2, MITRE-ATTACK:T1003.006.
- Fix: install the sensor on the uncovered host; remove sensor records of decommissioned hosts.
- Confidence: likely (join only; the sensor displayName carries the host name per the resource
  doc above).

### DEFENDER-SECURESCORE-CONTROL-OPEN
- Catches: a Secure Score control that is not implemented (score below its maximum) in the newest
  score, listed with its category, cost and user impact - the cheapest native posture backlog,
  including the identity-posture assessments from Defender for Identity. The week-on-week score
  trend the old check wanted needs a comparison across two rows (engine gap); per-control gaps do
  not.
- Severity: low (medium when implementationCost eq low and userImpact eq low - the free wins).
- Source: defender.yaml; v1.0; `/security/secureScores?$top=1` with `items:` pointing at the
  newest score's `controlScores` array (one row per control; if the engine cannot address a nested
  array as items, read `/security/secureScoreControlProfiles` instead and use controlStateUpdates
  / maxScore with the score from the first query as evidence); fields controlName, score,
  controlCategory, implementationStatus, description; joined by controlName to
  `/security/secureScoreControlProfiles` (select id, title, controlCategory, maxScore,
  implementationCost, userImpact, service, deprecated, controlStateUpdates); key controlName.
- Permission: SecurityEvents.Read.All (application).
- Condition: score lt maxScore (two fields - engine gap; until then `implementationStatus` match
  `notImplemented|partial` or `score eq 0`), and deprecated eq false, and controlStateUpdates[].state
  notin [ThirdParty, Ignored] (accepted in the portal).
- Refs: NIST-800-53:CA-7, NIST-800-53:RA-5, CIS-Controls-v8:7.1.
- Fix: work the control through the matching Keeper rule where one exists; otherwise follow the
  profile's remediation text.
- Confidence: verified field names -
  https://learn.microsoft.com/en-us/graph/api/resources/securescore?view=graph-rest-1.0 and
  ...securescorecontrolprofile?view=graph-rest-1.0; nested `items` addressing is an engine
  question.

### DEFENDER-RBAC-RESPONSE-RIGHTS-BROAD
- Catches: a Defender unified-RBAC role that grants response or live-response rights (remediate,
  isolate, run scripts, manage security settings, manage indicators) and is assigned to more
  principals than the threshold, to a group with many members, or to a guest or disabled account.
  Live response runs code as SYSTEM on any device; it belongs to a handful of named analysts.
- Severity: high (critical when the assignment includes a guest or a disabled account).
- Source: defender.yaml; beta; `/roleManagement/defender/roleDefinitions` (select id,
  displayName, isBuiltIn, isEnabled, rolePermissions) and `/roleManagement/defender/roleAssignments`
  (expand principal with id, displayName, userPrincipalName, accountEnabled, userType,
  select roleDefinitionId, principalId, directoryScopeId, appScopeId); key assignment id. New
  queries.
- Permission: RoleManagement.Read.Defender (application) - to add to the permissions table.
- Condition: roleDefinition `rolePermissions[].allowedResourceActions` match threshold
  `defender.rbac-response-action-pattern` (default `(live|response|remediat|isolat|manage)` over
  the action strings - confirm the exact strings on the first run), and per role count gt 4
  (threshold `defender.rbac-response-max-holders`) or principal.userType eq Guest or
  principal.accountEnabled eq false.
- Refs: NIST-800-53:AC-6(1), NIST-800-53:AC-6(5), CIS-Controls-v8:6.8, MITRE-ATTACK:T1098.
- Fix: split roles by tier (read, investigate, respond); assign through groups whose membership
  is reviewed; remove guests and leavers.
- Confidence: likely (unified RBAC exposed as a unifiedRbacApplication in beta; action strings
  not re-read) -
  https://learn.microsoft.com/en-us/graph/api/resources/unifiedrbacapplication?view=graph-rest-beta.

### DEFENDER-APPPERM-MDE-API
- Catches: an application granted application permissions on the Defender for Endpoint API
  resource - in particular the write roles (isolate machines, run live response, read/write
  indicators, read/write alerts, custom detections). An app with these rights can isolate every
  device or allow-list every file; its secret is as valuable as a security administrator's
  password. Same shape as the Exchange and SharePoint resource rules in microsoft-cloud.md.
- Severity: high for write roles; medium for read roles (review list).
- Source: entra.yaml or defender.yaml; v1.0;
  `/servicePrincipals(appId='fc780465-2017-40d4-a0c5-307022471b92')/appRoleAssignedTo`; top 999;
  fields id, principalType, principalDisplayName, principalId, appRoleId, createdDateTime; key id,
  name principalDisplayName. The role names come from a second query
  `/servicePrincipals(appId='fc780465-2017-40d4-a0c5-307022471b92')?$select=appRoles` for the
  evidence; the write-role ids are the threshold list `defender.mde-api-write-role-ids` (empty
  default; the author fills it from the appRoles row on the first run - the ids are Microsoft
  constants, so they can then be baked in).
- Permission: Application.Read.All.
- Condition: principalType eq ServicePrincipal and appRoleId in threshold
  `defender.mde-api-write-role-ids` (high); any row is the medium review list.
- Refs: NIST-800-53:AC-6, NIST-800-53:IA-9, CIS-Controls-v8:6.8, MITRE-ATTACK:T1098.001.
- Fix: keep only the integrations that need the right (SIEM/SOAR), read-only where possible;
  remove unknown grants and rotate the app's credentials.
- Confidence: resource app id verified (first-party application ids list) -
  https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in;
  role ids: confirm on first run.

### DEFENDER-USER-REPORT-PENDING
- Catches: a user-reported email threat submission that has no result after N days. Staff reports
  are the earliest phishing signal; a submission nobody triaged is a report into the void, and a
  confirmed phish with no tenant block keeps arriving.
- Severity: low (medium when the submission is older than 5 days).
- Source: defender.yaml; v1.0; `/security/threatSubmission/emailThreats`; filter
  `createdDateTime ge {DAYS_AGO:14}`; select id, createdDateTime, category, contentType, status,
  result, source, recipientEmailAddress, subject, adminReview; key id, name subject; refresh 1d.
  New query.
- Permission: ThreatSubmission.Read.All (application).
- Condition: source eq user and status in [notStarted, running] and createdDateTime age-gt 2
  (threshold `defender.user-report-max-pending-days`); evidence hides the recipient address when
  the tenant's privacy setting asks for it.
- Refs: NIST-800-53:IR-6, NIST-800-53:IR-4, CIS-Controls-v8:17.2.
- Fix: triage the submission; block the sender or URL; tell the reporter.
- Confidence: verified resource and enums -
  https://learn.microsoft.com/en-us/graph/api/resources/security-emailthreatsubmission?view=graph-rest-1.0
  (filter support on createdDateTime: likely).

### DEFENDER-INCIDENT-RESOLVED-UNCLASSIFIED
- Catches: an incident resolved in the last 30 days without a classification or determination.
  Incidents closed as "unknown" teach nothing, cannot be reported, and hide true positives that
  deserved a root cause.
- Severity: low.
- Source: defender.yaml (or the same file as M365-SECURITY-INCIDENT-OPEN); v1.0;
  `/security/incidents`; filter `status eq 'resolved' and lastUpdateDateTime ge {DAYS_AGO:30}`;
  select id, displayName, severity, status, classification, determination, assignedTo,
  lastUpdateDateTime; key id, name displayName. Second query on the same endpoint (different
  filter).
- Permission: SecurityIncident.Read.All.
- Condition: classification eq unknown or determination eq unknown.
- Refs: NIST-800-53:IR-5, NIST-800-53:IR-8, CIS-Controls-v8:17.4.
- Fix: reopen and close with a classification; make the classification a mandatory step of the
  triage procedure.
- Confidence: verified enum names -
  https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0.

### DEFENDER-ATTACK-SIM-STALE
- Catches: no attack-simulation campaign completed in the last N days. Users are the last filter;
  a simulation measures the click rate and trains the people who click. A tenant that uses an
  external vendor instead records that as an accepted exception.
- Severity: low.
- Source: defender.yaml; v1.0; `/security/attackSimulation/simulations`; select id, displayName,
  status, attackType, attackTechnique, launchDateTime, completionDateTime; key id, name
  displayName; refresh 7d. New query.
- Permission: AttackSimulation.Read.All (application).
- Condition: must-exist - count lt 1 where status eq completed and completionDateTime age-lt 180
  (threshold `defender.attack-sim-max-age-days`).
- Refs: NIST-800-53:AT-2, NIST-800-53:AT-2(1), CIS-Controls-v8:14.2.
- Fix: schedule a campaign with the training payload; review the click and compromise rates.
- Confidence: verified -
  https://learn.microsoft.com/en-us/graph/api/resources/simulation?view=graph-rest-1.0.

(TLS interception of the Defender cloud endpoints - the regional sensor gateway, the command host,
the antivirus cloud-protection host and the SmartScreen host, from the documented URL list - is
M365-ENDPOINT-TLS-INTERCEPTED in the Microsoft 365 admin section; add those hosts to its endpoint
list and raise the severity for them to high, because the sensor and the antivirus cloud refuse
inspected connections: no telemetry and no cloud verdicts for every device behind that proxy. The
per-device symptom is WS-DEFENDER-SENSE-CLOUD-ERRORS. Reference:
https://learn.microsoft.com/en-us/defender-endpoint/configure-proxy-internet)

### DEFENDER-IDENTITY-LICENCE-SHORTFALL
- Catches: the enabled-user count exceeds the prepaid units of the service plans that license
  Defender for Identity and Defender for Cloud Apps (both are licensed per protected user, not per
  administrator). Monitoring a whole directory on a small security-suite bundle is a true-up
  finding.
- Severity: low (a licensing position, not a security gap).
- Source: cross-system (store); join the newest `m365` run's subscribedSkus rows (attrs
  prepaidUnits.enabled, servicePlans[].servicePlanName) filtered to plans matching threshold
  `m365.identity-protection-plan-pattern` (default `ATA|ADALLOM_S_STANDALONE|ADALLOM_S_O365`)
  against the count of enabled member users from the `entra` run.
- Permission: none beyond the two scans.
- Condition: SUM(prepaidUnits.enabled) lt COUNT(enabled members) (computed in SQL as a single
  row with `shortfall` = difference; `each: { field: shortfall, op: gt, value: 0 }`).
- Refs: NIST-800-53:SA-4, NIST-800-53:PM-3.
- Fix: confirm the licensing position with the vendor account team; buy or descope.
- Confidence: likely (service plan names from the licensing reference) -
  https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference.

---

## Information protection and labelling

### AIP-SCANNER-VERSION-OLD
- Catches: an information-protection scanner host whose installed scanner build is the retired
  generation (the unified-labeling scanner) or an old release of the current one. The retired
  scanner gets no fixes; the current one updates only when someone runs the installer.
- Severity: high for the retired generation; medium for an old current release.
- Source: windows-server.yaml; registry; `hive: HKLM`, `path:
  SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, `subkeys: true` then the subkey values
  DisplayName, DisplayVersion, InstallDate (one row per subkey) - never Win32_Product; targets:
  servers whose entity `role` or name matches threshold `aip.scanner-host-pattern`; key
  `{host}|{DisplayName}`.
- Permission: registry read.
- Condition: DisplayName match `Information Protection.*Scanner` and (DisplayName match
  `Azure Information Protection` [retired generation] or DisplayVersion notmatch threshold
  `aip.scanner-current-version-pattern`). Version comparison is text (engine gap: no version op).
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22, CIS-Controls-v8:2.2.
- Fix: install the current scanner release on the host; retire the old generation.
- Confidence: guess on the uninstall display name; retirement verified -
  https://learn.microsoft.com/en-us/purview/deploy-scanner (current product) and the labeling
  client retirement notice linked from it.

### AIP-SCANNER-EVENTLOG-ERRORS
- Catches: errors from the scanner in the last 7 days on its host (authentication failures to the
  tenant, SQL errors, repository access failures). The scanner stops silently; its event log is the
  only server-side signal.
- Severity: low (medium for a recurring signature).
- Source: windows-server.yaml; eventlog; `log: Application`, `providers:` the scanner's provider
  name (threshold `aip.scanner-event-provider`, empty default - confirm on the first run; the
  classic client used its own log named after the product), level error/warning, `days: 7`; same
  targets as above; key `{host}|{provider}|{id}`.
- Permission: event-log read.
- Condition: `each: any` grouped by id (per-key count is an engine gap; one finding per signature
  through the key template).
- Refs: NIST-800-53:AU-6, NIST-800-53:SI-4.
- Fix: per signature - token/credential refresh, SQL permissions, repository read rights.
- Confidence: guess (provider/channel name not documented in one place) -
  https://learn.microsoft.com/en-us/purview/deploy-scanner-manage (scanner logs section).

### WS-REG-OFFICE-BUILD-OLD
- Catches: a PC whose Microsoft 365 Apps build is below the minimum for built-in sensitivity
  labelling (or below the oldest supported build of its channel). Removing the retired labelling
  add-in from such a PC removes labelling altogether; an old build also misses security fixes.
- Severity: medium.
- Source: workstations.yaml; registry; `hive: HKLM`, `path:
  SOFTWARE\Microsoft\Office\ClickToRun\Configuration`, `values: [VersionToReport, CDNBaseUrl,
  UpdateChannel, Platform]`; key host.
- Permission: registry read.
- Condition: VersionToReport notmatch threshold `workstations.office-supported-build-pattern`
  (default a regex for the current and previous channel builds; the tenant updates it per cycle
  - a version op is an engine gap). Absent key = no click-to-run Office = n/a. Evidence prints the
  channel URL.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:2.2, CIS-Controls-v8:7.4.
- Fix: move the device to a current channel build through the update ring; then remove the
  add-in (WS-REG-AIP-ADDIN-ENABLED).
- Confidence: verified value names -
  https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/overview-update-channels (channel
  URLs) and the ClickToRun configuration key described in Office deployment docs (likely).

### WS-REG-AIP-ADDIN-ENABLED
- Catches: a PC where the retired labelling add-in is still loaded in Office (LoadBehavior 3 under
  the add-in keys) or where the policy that makes Office use built-in labelling is not set. Both
  the add-in and built-in labelling active means double prompts and inconsistent labels; the
  add-in alone means a retired component doing the labelling.
- Severity: medium.
- Source: workstations.yaml; registry; `hive: HKLM`, `path:
  SOFTWARE\Microsoft\Office\Word\Addins\MSIP.WordAddin`, `values: [LoadBehavior]` (and the Excel,
  PowerPoint and Outlook twins; also the WOW6432Node path on 32-bit Office); second query `hive:
  HKU`, `path: SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security\Labels`, `values:
  [UseOfficeForLabelling]`; key host.
- Permission: registry read (HKU needs the user hives loaded - the logged-on user only; the engine
  reports others as n/a).
- Condition: LoadBehavior eq 3 (add-in active), or UseOfficeForLabelling absent or ne 1 on a PC
  where the add-in key exists.
- Refs: NIST-800-53:SA-22, NIST-800-53:CM-7, CIS-Controls-v8:2.3.
- Fix: set the built-in labelling policy through cloud policy or Group Policy; uninstall the
  add-in (part of the retired client package).
- Confidence: likely - https://learn.microsoft.com/en-us/purview/sensitivity-labels-aip
  (migration guidance names the policy setting; add-in registry key from the Office add-in model).

### AIP-CONTAINER-LABELS-OFF
- Catches: the directory setting that lets sensitivity labels apply to groups, teams and sites is
  off (EnableMIPLabels false or absent in the unified-group settings template). Container labels
  are the only way to tie guest access and external sharing to a classification per site; off,
  every site has the tenant default.
- Severity: low (a decision; accepted exception when deliberately off).
- Source: m365.yaml or defender.yaml; v1.0; `/groupSettings`; fields id, displayName,
  templateId, values (array of name/value); key id, name displayName. New query (also useful for
  the other unified-group settings).
- Permission: Directory.Read.All.
- Condition: must-exist - count lt 1 where displayName eq Group.Unified and `values[].name`
  eq EnableMIPLabels and the paired value eq true - the pairing inside one array of objects is an
  engine gap; until then: count lt 1 where displayName eq Group.Unified (no settings object =
  default = off), and evidence prints the values array for the human to read.
- Refs: NIST-800-53:AC-16, NIST-800-53:AC-21, CIS-Controls-v8:3.7.
- Fix: enable the setting, then publish container labels in the label policy.
- Confidence: verified setting name -
  https://learn.microsoft.com/en-us/graph/api/resources/groupsetting?view=graph-rest-1.0 and
  ...group-settings-template (Group.Unified, EnableMIPLabels).

### AIP-BYOK-KEY-UNPROTECTED
- Catches: a tenant-key (bring-your-own-key) Key Vault key that is disabled, expires within N
  days, or lives in a vault without soft-delete and purge protection. A disabled or deleted BYOK
  key makes every protected document and mail unreadable, permanently.
- Severity: critical (disabled or deleted), high (expiry within 180 days or no purge protection).
- Source: azure.yaml (azure integration, http ARM); `path:
  /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01`
  (fields name, properties.enableSoftDelete, properties.enablePurgeProtection) and per vault
  `for_each` → `/subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}/keys?api-version=2023-07-01`
  (fields name, properties.attributes.enabled, properties.attributes.exp, properties.keyUri);
  key `{vault}|{name}`. Which key is the tenant key: threshold `aip.tenant-key-name-pattern`
  (empty default = every key in vaults matching `aip.tenant-key-vault-pattern`); the rule is n/a
  when both are empty (tenant on Microsoft-managed keys).
- Permission: Reader on the subscription (ARM key metadata; no data-plane access needed).
- Condition: attributes.enabled eq false, or attributes.exp until-lt 180 (epoch seconds - date
  parsing from epoch is an engine gap; the ARM response also carries `expires` as text in some
  versions - confirm), or the vault's enablePurgeProtection ne true.
- Refs: NIST-800-53:SC-12, NIST-800-53:SC-12(1), NIST-800-53:CP-9, CIS-Controls-v8:11.3.
- Fix: enable purge protection on the vault; re-enable the key; plan rotation before expiry and
  keep the backup documented.
- Confidence: likely - https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/keys/list
  (ARM keys list) and https://learn.microsoft.com/en-us/purview/byok-encryption (requirements).

### SCCM-DEPLOYMENT-RETIRED-APP  (sccm.yaml - id outside this group's prefixes; rename as the site pack prefers)
- Catches: a required application deployment whose application name matches the retired-software
  pattern (retired labelling client, its document-viewer plug-in, any product the vendor has
  withdrawn). A required deployment keeps installing the retired product on every new device and
  loops on devices where detection fails.
- Severity: high.
- Source: sccm.yaml; http AdminService; `path: /wmi/SMS_ApplicationAssignment`; fields
  AssignmentID, ApplicationName, CollectionName, OfferTypeID (0 required, 2 available),
  EnforcementDeadline, Enabled, CreationTime; key AssignmentID, name ApplicationName.
- Permission: AdminService read (the site's read-only role).
- Condition: Enabled eq true and OfferTypeID eq 0 and ApplicationName match threshold
  `sccm.retired-app-pattern` (default `Azure Information Protection|AIP (Plugin|Viewer)`).
- Refs: NIST-800-53:CM-7, NIST-800-53:SA-22, CIS-Controls-v8:2.3.
- Fix: retire the deployment and the application; replace with the built-in capability or the
  current product's package.
- Confidence: likely - https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/apps/sms_applicationassignment.

---

## Rules once mde-api exists

Base URL https://api.securitycenter.microsoft.com/api, application token for the resource
`https://api.securitycenter.microsoft.com`, GET only, OData paging.

- MDE-SENSOR-IMPAIRED - device with healthStatus in (ImpairedCommunication, NoSensorData,
  NoSensorDataImpairedCommunication) seen in 7 days; `/machines` select computerDnsName,
  healthStatus, onboardingStatus, lastSeen, osPlatform; each row; high.
- MDE-DEVICE-CAN-BE-ONBOARDED - discovered device with onboardingStatus eq CanBeOnboarded (or
  Unsupported with a supported OS string); `/machines`; medium.
- MDE-VULN-EXPLOITABLE-OLD - vulnerability with publicExploit true, severity Critical, exposed
  machines gt 0, publishedOn age-gt 30; `/vulnerabilities?$filter=publicExploit eq true`; high.
- MDE-EXPOSURE-SCORE-HIGH - `/exposureScore` score gt threshold; low. Trend = engine gap.
- MDE-RECOMMENDATION-TOP-OPEN - `/recommendations` status Active, severityScore ge threshold,
  exposedMachinesCount gt 0; low (review list).
- MDE-INDICATOR-ALLOW-STALE - `/indicators` action eq Allowed and (expirationTime absent or
  until-lt 0) ; medium.
- MDE-BASELINE-PROFILE-NONE - `/baselineProfiles` count none; low.
- MDE-ACTION-PENDING - `/machineactions?$filter=status eq 'Pending'` creationDateTimeUtc age-gt
  1; medium.
- MDE-ACTION-UNEXPLAINED - `/machineactions` in 7 days with requestorComment empty; low.
- MDE-RESPONSE-DRILL-STALE - no Succeeded Isolate/Unisolate/RunAntiVirusScan/
  CollectInvestigationPackage action on the test machine (threshold id) in 365 days; low.
- MDE-DEVICE-INACTIVE-RECORD - `/machines` healthStatus eq Inactive and lastSeen age-gt 30; low;
  duplicates by computerDnsName need a per-key count (engine gap).
- MDE-DEVICE-UNTAGGED-SERVER - osPlatform match `WindowsServer` and machineTags empty or
  rbacGroupName eq the default group; low.
- MDE-SERVER-LICENCE-SHORTFALL - count of onboarded servers (`/machines` osPlatform match
  WindowsServer, onboardingStatus Onboarded) gt the server-licence units from subscribedSkus (store
  join); medium.

## Rules once defender-xdr-api exists (advanced hunting and Cloud Apps)

Advanced hunting is a POST (`/security/runHuntingQuery` on Graph, or
https://api.security.microsoft.com/api/advancedhunting/run); Keeper's runners are GET-only, so
this needs a hunting runner whose KQL comes from the rule text and whose rows are the table it
returns. The Cloud Apps REST API (https://<tenant-region>.portal.cloudappsecurity.com/api/v1,
token for the Cloud Apps resource) is GET-able for activities, discovery and policies.

- XDR-EMAIL-THREAT-DELIVERED - EmailEvents 7 days, ThreatTypes has Phish or Malware and
  LatestDeliveryLocation inbox; count per recipient; medium.
- XDR-EMAIL-SPOOF-OWN-DOMAIN-DELIVERED - EmailEvents inbound, sender domain in own accepted
  domains, DMARC fail, delivered to inbox; medium.
- XDR-URL-CLICK-ALLOWED-MALICIOUS - UrlClickEvents ActionType ClickAllowed and ThreatTypes
  Phish/Malware; high.
- XDR-POST-DELIVERY-ACTION-FAILED - EmailPostDeliveryEvents ActionResult ne Success; medium.
- XDR-IDENTITY-NTLMV1-OR-CLEARTEXT-LDAP - IdentityLogonEvents Protocol Ntlm with NTLM V1 field,
  or LDAP clear-text binds; medium; review list by source host.
- XDR-IDENTITY-HONEYTOKEN-MISSING - IdentityInfo Tags has no Honeytoken; low.
- XDR-TAMPERING-ATTEMPT - DeviceEvents ActionType TamperingAttempt, DeviceRegistryEvents on the
  exclusions key; high (the device-side twin is WS-DEFENDER-EVT-PROTECTION-CHANGED).
- XDR-ADMIN-TOOL-REMEDIATED - DeviceFileEvents FileDeleted by the engine processes under an
  administration path (threshold); low.
- MDCA-M365-CONNECTOR-STALE - newest activity from the Microsoft 365 connector older than 2 h;
  medium.
- MDCA-DISCOVERED-APP-RISKY-UNSANCTIONED - discovered app with risk score le 5 and users gt
  threshold and tag neither sanctioned nor unsanctioned; medium.
- MDCA-ANOMALY-POLICY-DISABLED - built-in anomaly policy with enabled false; medium.

## Rules once exo-powershell exists (Defender for Office policies)

Exchange Online PowerShell (certificate app-only, module v3, REST-backed cmdlets); every rule is a
Get-* cmdlet whose objects become rows. Where ScubaGear tests the same control the imported
SCUBA-FAILED row already fires; these are the native equivalents and the gaps ScubaGear leaves.

- MDO-PRESET-NOT-ALL-USERS - Get-EOPProtectionPolicyRule / Get-ATPProtectionPolicyRule: no
  Enabled Standard or Strict rule whose scope covers all accepted domains; high.
- MDO-PRIORITY-NOT-STRICT - priority accounts (Get-User -IsVIP) not in the Strict preset scope;
  medium.
- MDO-PRIORITY-PROTECTION-OFF - Get-EmailTenantSettings EnablePriorityAccountProtection false, or
  a priority account that is disabled; medium.
- MDO-ANTIPHISH-WEAK - Get-AntiPhishPolicy: targeted user/domain protection off, mailbox
  intelligence protection off, HonorDmarcPolicy false, PhishThresholdLevel lt 2, safety tips off;
  medium.
- MDO-ANTISPAM-WEAK - Get-HostedContentFilterPolicy: HighConfidencePhishAction ne Quarantine,
  BulkThreshold gt 6, QuarantineRetentionPeriod lt 30, ZAP off; medium.
- MDO-ANTISPAM-ALLOWED-SENDERS - AllowedSenderDomains or AllowedSenders not empty; medium.
- MDO-CONNECTION-FILTER-ALLOW - Get-HostedConnectionFilterPolicy IPAllowList not empty or
  EnableSafeList true; medium.
- MDO-OUTBOUND-SPAM-NO-NOTIFY - Get-HostedOutboundSpamFilterPolicy NotifyOutboundSpam false or
  recipients not a monitored mailbox (store join with Entra users for disabled recipients); low.
- MDO-MALWARE-FILTER-WEAK - Get-MalwareFilterPolicy EnableFileFilter false, FileTypes size-lt
  threshold, ZapEnabled false, admin notifications off; medium.
- MDO-SAFE-ATTACHMENTS-NOT-ALL - Get-SafeAttachmentPolicy/Rule: no enabled Block policy for all
  recipients; Get-AtpPolicyForO365 EnableATPForSPOTeamsODB false or EnableSafeDocs false; medium.
- MDO-SAFE-LINKS-WEAK - Get-SafeLinksPolicy: email/Teams/Office off, AllowClickThrough true,
  TrackClicks false, DoNotRewriteUrls size-gt threshold; medium.
- MDO-TEAMS-ZAP-OFF - Get-TeamsProtectionPolicy ZapEnabled false; low.
- MDO-QUARANTINE-USER-RELEASE-HIGH-RISK - Get-QuarantinePolicy with PermissionToRelease on the
  tag used for high-confidence phish or malware; medium.
- MDO-TABL-ALLOW-STALE - Get-TenantAllowBlockListItems -Allow with no ExpirationDate and
  LastUsedDate age-gt 45, or a consumer/own domain; medium.
- MDO-SPOOF-ALLOW-UNKNOWN - Get-SpoofIntelligenceInsight Action Allow with unknown
  infrastructure; medium (review list).
- MDO-ADVANCED-DELIVERY-BROAD - SecOps/phish-sim override rules beyond the threshold lists;
  medium.
- MDO-REPORT-SUBMISSION-OFF - Get-ReportSubmissionPolicy EnableReportToMicrosoft false or no
  reporting mailbox; low.
- MDO-PROTECTION-RULE-EXCLUSIONS - any ExceptIf* on protection rules naming a priority account;
  medium.
- MDO-ARC-SEALER-MISSING - Get-ArcConfig ArcTrustedSealers empty while an inbound gateway
  connector exists; low.
- MDO-QUARANTINE-RELEASE-REQUESTS-OLD - Get-QuarantineMessage ReleaseStatus RequestedRelease older
  than 3 days; low.
- MDO-ROLEGROUP-RELEASE-RIGHTS-BROAD - Get-RoleGroupMember for the hygiene/quarantine groups:
  members beyond threshold or disabled; medium.
- MDO-POLICY-CHANGE-RECENT - Search-UnifiedAuditLog 7 days, the Set-*/New-* operations of the
  policies above; medium (review list).
- MDO-POLICY-SCOPE-UNLICENSED - recipients in Safe Links/Safe Attachments scope without the
  Defender for Office service plan (store join with Entra users); medium.

## Rules once purview-powershell exists (labels, DLP, protection service)

Security & Compliance PowerShell (Connect-IPPSSession, certificate app-only) plus the protection
service module (AIPService) for the tenant key, super users and onboarding controls.

- AIP-PROTECTION-SERVICE-DISABLED - Get-AipService status ne Enabled; high.
- AIP-SUPER-USERS-ENABLED - Get-AipServiceSuperUserFeature Enabled with super users gt 2; high.
- AIP-RMS-ADMINS-STALE - Get-AipServiceRoleBasedAdministrator entries not current users (store
  join with Entra); medium.
- AIP-ONBOARDING-CONTROL-UNEXPECTED - Get-AipServiceOnboardingControlPolicy differs from the
  recorded decision; low.
- AIP-TENANT-KEY-BYOK-UNDOCUMENTED - Get-AipServiceKeys topology BYOK without an attestation
  row; medium.
- AIP-DOCUMENT-TRACKING-STATE - Get-AipServiceDocumentTrackingFeature; low (record).
- AIP-LABEL-NO-LOCALISED-NAME - Get-Label LocaleSettings missing the organisation's language
  (threshold); medium.
- AIP-LABEL-POLICY-NOT-ALL-USERS - Get-LabelPolicy not published to all, no default label, no
  justification requirement; medium.
- AIP-LABEL-ENCRYPTION-ANY-AUTHENTICATED - Get-Label EncryptionRightsDefinitions grant to
  AuthenticatedUsers on the highest labels, or EncryptionOfflineAccessDays gt 7; medium.
- AIP-SIT-JURISDICTION-UNUSED - the jurisdiction's identity/bank/health sensitive information
  types (threshold) absent from every scanner, auto-labelling and DLP rule; medium.
- AIP-AUTOLABEL-POLICY-NONE - Get-AutoSensitivityLabelPolicy none, or all in simulation for more
  than N days; low.
- AIP-DLP-NOT-LABEL-BASED - Get-DlpComplianceRule with no label condition where labels exist;
  low.
- AIP-LABEL-CHANGE-RECENT - Search-UnifiedAuditLog label and label-policy operations 30 days;
  medium (review list).
- AIP-LABEL-ACTIVITY-ABSENT - Export-ActivityExplorerData 30 days returns no label activity;
  medium.
- AIP-LABEL-DOWNGRADE-NO-JUSTIFICATION - Export-ActivityExplorerData removal/downgrade without
  justification text; medium.
- AIP-ALERT-MASS-DOWNGRADE-MISSING - Get-ProtectionAlert has no enabled alert on label removal
  with a monitored recipient; medium.
- AIP-FEATURE-UNLICENSED - auto-labelling or other premium features configured while users
  lack the service plan (store join with subscribedSkus / user plans); medium.
- DEFENDER-NOTIFICATION-RECIPIENT-DEAD - Get-ProtectionAlert NotifyUser addresses joined to Entra
  users: disabled, missing or personal-admin accounts; medium.

## Rules once winrm-powershell exists (scanner host cmdlets)

The scanner's own cmdlets (Get-ScannerContentScan, Get-ScannerRepository, Get-ScanStatus, the
report files) run only on the scanner host; a WinRM runner that executes a fixed read-only script
and returns objects would unlock them: content-scan jobs finished on schedule, scan errors per
repository, incremental-scan setting, repository list versus the file-server share inventory
(store join), preserve-metadata setting, network-discovery results, and sensitive-type findings
joined to the share ACL map.


---

## Known issues that became rules

### ENTRA-MFA-AUTHENTICATOR-ADDED-RECENT
- Catches: a Microsoft Authenticator registration created in the last N days on an enabled member account. A new registration is the normal end of a helpdesk reset, and also the normal end of a social-engineered one: the attacker's phone becomes a second factor that survives the next password change. Listing them daily is how the extra device is noticed the morning after.
- Severity: info (medium when the account holds a directory role; join with the role-assignment rows later).
- Source: entra.yaml; v1.0; `for_each` over the shared users query (enabled members) -> `/users/{id}/authentication/microsoftAuthenticatorMethods`; fields id, displayName, deviceTag, phoneAppVersion, createdDateTime; key `{parent.id}|{id}`, name parent userPrincipalName. One new per-object fetch; the rule below reuses its rows.
- Permission: UserAuthenticationMethod.Read.All (application).
- Condition: createdDateTime age-lt 7 (threshold `entra.authenticator-new-days`).
- Refs: MITRE-ATTACK:T1098.005, NIST-800-53:IA-5, NIST-800-53:AC-2(4).
- Fix: confirm with the person that the device is theirs; otherwise remove the method, reset the password and revoke sessions.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/authentication-list-microsoftauthenticatormethods?view=graph-rest-1.0 (createdDateTime on the method resource: likely; if absent, drop this rule and keep the count rule).

### ENTRA-MFA-AUTHENTICATOR-DEVICES-MANY
- Catches: a user with more Authenticator registrations than one person plausibly carries. Several devices on one account are either a shared account, a person who never removed old phones, or an attacker's phone added after a reset.
- Severity: medium (high when the account holds a directory role).
- Source: cross-system.yaml (store), reading the rows of the per-object fetch above: `SELECT parent id, COUNT(*) AS devices, GROUP_CONCAT(deviceTag) FROM row_seen of the newest entra run WHERE entity_type = 'authenticator-method' GROUP BY parent id`; key = user id. The engine has no count-per-parent for graph `for_each`, so the count lives in the store rule.
- Permission: as above.
- Condition: devices gt 2 (threshold `entra.authenticator-max-devices`).
- Refs: MITRE-ATTACK:T1098.005, NIST-800-53:IA-5, CIS-Controls-v8:6.3.
- Fix: keep the current device, remove the rest, revoke refresh tokens; make "remove old authenticators" part of the reset procedure.
- Confidence: verified for the store mechanics (RULES.md); likely for the method fields.

### ENTRA-USER-EXTERNAL-WORKER-UNCLASSIFIED
- Catches: an enabled account that represents an external worker (member of the tenant's vendor or contractor groups, threshold `entra.external-worker-group-ids`) with no employeeType or companyName. Without those two attributes nobody can say which supplier owns the account, so it never expires with the contract, it cannot be put in a dynamic group, and an access review has no reviewer to route it to.
- Severity: medium.
- Source: entra.yaml; v1.0; `for_each` over the threshold group list -> `/groups/{id}/members/microsoft.graph.user?$select=id,userPrincipalName,accountEnabled,employeeType,companyName,employeeHireDate,createdDateTime`; key id, name userPrincipalName. Broader variant with no threshold: the shared users query extended with employeeType and companyName, condition employeeType empty on every enabled member (noisy in tenants that never filled it; keep it as a separate low rule).
- Permission: User.Read.All, GroupMember.Read.All.
- Condition: accountEnabled true and (employeeType empty or companyName empty).
- Refs: NIST-800-53:AC-2, NIST-800-53:PS-7, CIS-Controls-v8:5.1, CIS-Controls-v8:6.2.
- Fix: fill employeeType and companyName from the contract, set an account expiry, move the group to a dynamic membership rule on those attributes, and give the group an access review.
- Confidence: verified field names - https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0 ; likely for `$select` on the members cast.

### XS-HOST-LOCAL-GROUP-MEMBER-LEAVER
- Catches: a domain account that is a member of a privileged local group on a server or workstation (Administrators, Remote Desktop Users, Backup Operators, Hyper-V Administrators, and product groups such as the directory-synchronisation administrators group; pattern threshold `windows.privileged-local-group-pattern`) while the account is disabled, expired, sits in a leavers OU, or no longer exists (the membership shows as an orphaned SID). The existing local-Administrators rules see unexpected names; this sees members who left.
- Severity: medium (high when the group is Administrators or the host is a tier-0 server).
- Source: windows-server.yaml and workstations.yaml: one new cim query `SELECT GroupComponent, PartComponent FROM Win32_GroupUser` (per host; key `{host}|{PartComponent}`; the rule itself is `each: any` filtered to the group pattern so the rows reach the store - or `count: { op: gt, value: 100000 }` if a collect-only rule is wanted); cross-system.yaml: a store rule joining those rows (parse domain and name out of PartComponent) to the AD users CTE on sAMAccountName, with the leaver-OU pattern threshold already used by the hybrid pack; also SIDs that match no AD object (PartComponent Name starts with `S-1-5-21`).
- Permission: cim read on the hosts (as the existing WS-/WINSRV-LOCALADMIN rules); ldap read.
- Condition: state ne ok, where state is disabled / expired / leaver-OU / orphaned.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:AC-6, CIS-Controls-v8:5.3, CIS-Controls-v8:6.2.
- Fix: remove the member; grant the role through a domain group that the leaver process already covers.
- Confidence: likely - https://learn.microsoft.com/en-us/windows/win32/cimwin32a/win32-groupuser

(The command-prompt block policy and the MDM diagnostics event-log checks from the known issues are
INTUNE-POLICY-CMD-BLOCK-BROAD and WS-EVT-MDM-POLICY-ERRORS / WS-EVT-MDM-AUTOENROLL-FAIL in the Intune
section. One addition to the first: also match custom OMA-URI profiles whose omaUri carries the
ADMX_Shell/DisableCMD policy, not only settings-catalog policies.)

### M365-ROOM-ACCOUNT-NO-SIGNIN
- Catches: a resource account licensed for meeting-room devices with no successful sign-in for N days. The device is signed out or down (password expired, a Conditional Access or MFA change caught it), and the room is simply "not working" until someone complains.
- Severity: medium.
- Source: m365.yaml; shared users query (assignedLicenses, signInActivity, accountEnabled already selected).
- Permission: User.Read.All, AuditLog.Read.All (signInActivity).
- Condition: accountEnabled true and `assignedLicenses[].skuId` in threshold `m365.room-device-sku-ids` (defaults: the Teams Rooms Pro and Teams Rooms Basic SKU ids from the licensing reference) and signInActivity.lastSuccessfulSignInDateTime age-gt 2 (threshold `m365.room-signin-max-days`) or absent.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-2.
- Fix: sign the device in again; set the resource account's password not to expire and exclude it from interactive-MFA policies by its own policy (device-based).
- Confidence: verified fields (already used); SKU ids likely - https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference

(The device-side view - a Teams Rooms device reported offline or critical - is
M365-TEAMS-ROOM-UNHEALTHY in the Microsoft 365 admin section; M365-TEAMS-ROOM-ACCOUNT-PASSWORD-EXPIRES
there covers the usual cause.)

## Rules once exo-powershell exists (from the known issues)
- EXO-FORWARD-INTO-OTHER-USER: a mailbox forwarding (ForwardingAddress / ForwardingSmtpAddress, or an inbox rule ForwardTo / RedirectTo) into another person's mailbox; Get-Mailbox + Get-InboxRule; condition target resolves to an internal UserMailbox not owned by the same person; medium (internal copies of a colleague's mail are a privacy matter even under a no-external-forwarding policy).
- EXO-AUTOREPLY-STALE: Get-MailboxAutoReplyConfiguration; AutoReplyState Scheduled with EndTime in the past, or Enabled for more than N days on a shared mailbox; low.
- EXO-DISABLED-USER-MAILBOX-OPEN: a disabled account whose mailbox is still a UserMailbox with any CAS protocol enabled (Get-CASMailbox) instead of converted to shared with protocols off; joined with Entra accountEnabled; medium.

---

## Integrations to add

Ranked by the number of old checks each one unlocks (primary blocker; "also" counts rows whose
primary blocker is another integration but which need this one too, and rows now judged only
through an imported scanner report). Every integration is read-only by construction: Get-* and
Search-* cmdlets or GET endpoints only; a runner refuses anything else. Secrets go into Keeper's
vault as for any http integration; a credential only ever goes to its own endpoint.

### 1. exo-powershell - Exchange Online (135 old checks; also 6 unified-audit-log rows of the SharePoint section, 5 of the Microsoft 365 admin section, 3 of the Power Platform section, and 19 Defender for Office rows)
- API: the Exchange Online management REST endpoint behind the `ExchangeOnlineManagement` 3.x
  module (`https://outlook.office365.com/adminapi/beta/{tenant-id}/...` - semi-public; the safe form
  is to host the module in-process and marshal its objects into rows, no child process).
- Auth: app-only certificate; the app registration holds `Exchange.ManageAsApp` on the Office 365
  Exchange Online resource and is assigned the *View-Only Organization Management* role (plus
  *View-Only Audit Logs* for `Search-UnifiedAuditLog`). Never Exchange Administrator.
- Endpoints (cmdlets): `Get-EXOMailbox` / `-MailboxStatistics` / `-MailboxPermission` /
  `-RecipientPermission` / `-MailboxFolderPermission` / `-MailboxFolderStatistics` with
  `-PropertySets`, `Get-EXORecipient`, `Get-CASMailbox`, `Get-CASMailboxPlan`, `Get-Mailbox`
  (forwarding, auto-reply via `Get-MailboxAutoReplyConfiguration`), `Get-InboxRule`,
  `Get-InboundConnector` / `Get-OutboundConnector`, `Get-TransportRule`, `Get-TransportConfig`,
  `Get-AcceptedDomain`, `Get-RemoteDomain`, `Get-OrganizationConfig`, `Get-OwaMailboxPolicy`,
  `Get-AuthenticationPolicy`, `Get-HostedOutboundSpamFilterPolicy` / `-Rule`,
  `Get-MailboxAuditBypassAssociation`, `Get-RoleGroup` / `Get-RoleGroupMember`,
  `Get-ManagementRoleAssignment`, `Get-ManagementScope`, `Get-ApplicationAccessPolicy`,
  `Get-DkimSigningConfig`, `Get-MobileDevice`, `Get-MigrationBatch` / `Get-MigrationEndpoint`,
  `Get-JournalRule`, `Get-DistributionGroup`, `Get-DynamicDistributionGroup`, `Get-UnifiedGroup`,
  `Get-MessageTraceV2` / `Get-MessageTraceDetailV2` (10-day windows, 90 days of history),
  `Get-MailflowStatusReport`, `Get-MailDetailTransportRuleReport`, `Search-UnifiedAuditLog`
  (ReturnLargeSet paging); Defender for Office policies: `Get-AntiPhishPolicy` / `-Rule`,
  `Get-HostedContentFilterPolicy` / `-Rule`, `Get-HostedConnectionFilterPolicy`,
  `Get-MalwareFilterPolicy` / `-Rule`, `Get-SafeLinksPolicy` / `-Rule`, `Get-SafeAttachmentPolicy`
  / `-Rule`, `Get-EOPProtectionPolicyRule`, `Get-ATPProtectionPolicyRule`, `Get-QuarantinePolicy`,
  `Get-QuarantineMessage`, `Get-TenantAllowBlockListItems`, `Get-SpoofIntelligenceInsight`,
  `Get-ReportSubmissionPolicy`, `Get-TeamsProtectionPolicy`, `Get-EmailTenantSettings`,
  `Get-ArcConfig`, `Get-ExternalInOutlook`.
- Unlocks: mail flow and queue health, forwarding in all its forms, mailbox permissions and
  delegation, protocol and authentication posture, mailbox auditing, retention and hold coverage,
  connector and transport-rule drift, mail-filter posture natively rather than through an imported
  scanner report, quarantine and allow-list hygiene, tenant change evidence from the unified audit log.

### 2. power-platform-admin-api - Power Platform, Power BI and Fabric administration (76 old checks; 37 of them are Power BI / Fabric and deserve their own integration name, `powerbi-admin-api`, because the prerequisite differs)
- API: Power Platform API and the BAP, Flow, PowerApps, Power BI and Fabric admin REST APIs.
- Auth: an app registration with a certificate or secret, granted the Power Platform API scope
  (`https://api.powerplatform.com/.default`) and registered once as a Power Platform management
  application; for Power BI / Fabric the same app holds `Tenant.Read.All` on the Power BI service
  and is a member of the security group named in the Fabric admin setting that allows service
  principals to use the read-only admin APIs.
- Base URLs and endpoints: `https://api.powerplatform.com` (licensing/tenantCapacity, powerpages),
  `https://api.bap.microsoft.com` (providers/Microsoft.BusinessAppPlatform/scopes/admin/environments,
  environments/{id}/backups, lifecycleOperations, listTenantSettings - a read-only POST;
  providers/PowerPlatform.Governance/v2/policies, v1/tenants/{id}/tenantIsolationPolicy),
  `https://api.flow.microsoft.com` (scopes/admin/environments/{id}/v2/flows, runs, owners),
  `https://api.powerapps.com` (scopes/admin/environments/{id}/apps, permissions, connections, apis),
  `https://api.powerbi.com` (v1.0/myorg/admin/groups, datasets, activityevents, tenantsettings;
  v2.0/myorg/gatewayclusters, datasources, permissions), `https://api.fabric.microsoft.com`
  (v1/admin/tenantsettings). One integration type with several endpoints, or one integration per
  base URL, so the "credential goes only to its endpoint" guard holds.
- Unlocks: tenant capacity and per-environment consumption, environment inventory and state,
  tenant settings and data-loss-prevention policies, flows, apps, connections and their owners,
  Power BI tenant settings, workspaces, datasets, gateways and activity events.

### 3. dataverse-web-api - Dataverse environments and Dynamics 365 (49 old checks)
- API: the Dataverse Web API of each environment, `https://<environment-host>/api/data/v9.2`; one
  http endpoint per environment (or `for_each` over the environment list once integration 2 exists).
- Auth: an application user in every environment to be read, created from the same app
  registration, holding a custom read-only security role (organization, systemuser, role, audit,
  asyncoperation, bulkdeleteoperation, solution, workflow, bot, mailbox, serviceendpoint, and the
  personal-data tables for counts only) - never System Administrator. Token audience is the
  environment URL.
- Endpoints: organizations, EntityDefinitions and Attributes, audits (with `$apply`),
  asyncoperations, plugintracelogs, bulkdeleteoperations, retentionconfigs, solutions, publishers,
  solutioncomponents, msdyn_solutionhistories, pluginassemblies, sdkmessageprocessingsteps,
  webresourceset, environmentvariabledefinitions / -values, connectionreferences, workflows, roles
  with systemuserroles_association, systemusers, businessunits, principalobjectaccessset,
  mailboxes, emailserverprofiles, serviceendpoints, sharepointsites, slakpiinstances, incidents,
  queues, duplicaterules, bots, botcomponents; functions WhoAmI, RetrieveTotalRecordCount,
  RetrieveRolePrivilegesRole; `$count` per table.
- Unlocks: audit posture and volume, job / plug-in / mailbox health, roles and users per
  environment, customisation lifecycle and secrets hygiene, retention jobs, table growth.

### 4. purview-powershell - Security & Compliance (29 old checks; also 3 Exchange, 2 SharePoint and 1 Teams row, and the information-protection service)
- API: Security & Compliance PowerShell (`Connect-IPPSSession`, base
  `https://ps.compliance.protection.outlook.com`) hosted in-process like integration 1; plus the
  protection service (`AIPService` module, service-principal sign-in, `https://admin.<region>.aadrm.com`).
- Auth: the same app-only certificate with the *Compliance Administrator* (read) role; a service
  principal for the protection service.
- Endpoints (cmdlets): `Get-RetentionCompliancePolicy -DistributionDetail`,
  `Get-RetentionComplianceRule`, `Get-ComplianceTag`, `Get-DlpCompliancePolicy` / `-Rule`,
  `Get-DlpSensitiveInformationType`, `Get-Label`, `Get-LabelPolicy`,
  `Get-AutoSensitivityLabelPolicy` / `-Rule`, `Get-ProtectionAlert`, `Get-ComplianceCase`,
  `Get-CaseHoldPolicy`, `Get-RoleGroup` / `Get-RoleGroupMember` (compliance role groups),
  `Get-AdminAuditLogConfig`, `Get-UnifiedAuditLogRetentionPolicy`, `Export-ActivityExplorerData`;
  `Get-AipService`, `Get-AipServiceKeys`, `Get-AipServiceSuperUser`,
  `Get-AipServiceRoleBasedAdministrator`, `Get-AipServiceOnboardingControlPolicy`,
  `Get-AipServiceDocumentTrackingFeature`, `Get-AipServiceAdminLog`.
- Unlocks: retention and DLP coverage per workload, policy distribution health, label posture,
  compliance role membership, audit retention, protection-service governance (super users, key custody).

### 5. winrm-powershell - read-only remoting to named servers (28 old checks: 20 on the directory-sync server, 7 on the information-protection scanner host, 1 on the on-premises gateway host)
- API: WS-Management (5985/5986) running a fixed, signed, read-only script on the host and
  returning objects as rows - the one per-host protocol Keeper lacks (cim, registry, eventlog and
  tls cover the rest).
- Auth: Kerberos with a dedicated read-only account that is a member of the product's read group
  on the host (for example the sync engine's admin group, which is the only way to call its
  cmdlets), never a local administrator where the product allows less.
- Endpoints (cmdlets): sync engine - `Get-ADSyncScheduler`, `Get-ADSyncConnector`,
  `Get-ADSyncConnectorStatistics`, `Get-ADSyncRunProfileResult`, `Get-ADSyncRunStepResult`,
  `Get-ADSyncRule`, `Get-ADSyncGlobalSettings`, `Get-ADSyncAutoUpgrade`,
  `Get-ADSyncAADPasswordSyncConfiguration`, `Get-ADSyncAADPasswordResetConfiguration`; file
  headers under the engine's program-data folder; the local certificate store; `Get-Acl` on
  directory objects (the ldap runner refuses security descriptors); server-originated
  connectivity probes. Scanner host - `Get-ScannerContentScan`, `Get-ScannerRepository`,
  `Get-ScanStatus`, latest report summary.
- Unlocks: scheduler, connector, filtering, rule and run-history health of directory sync; the
  accidental-delete threshold state from the server side; scanner job health and coverage; every
  ACL-based check.

### 6. spo-admin-rest - SharePoint tenant and site administration (27 old checks; also 21 rows now covered only through the imported ScubaGear report)
- API: the tenant admin site REST (`https://<tenant>-admin.sharepoint.com/_api/`: SPO.Tenant
  properties, SPOSitePropertiesEnumerable, site lock/quota/admins/sharing level) and per-site REST
  (`/_api/web`, lists, versioning, access requests, unique permissions) - what
  `Microsoft.Online.SharePoint.PowerShell` and `PnP.PowerShell` call.
- Auth: an app registration with a certificate holding the SharePoint-resource application
  permission for tenant administration (Sites.FullControl.All on the SharePoint resource is what
  the admin API demands - record it as an accepted exception to ENTRA-APPPERM-SHAREPOINT-FULL-CONTROL),
  or delegated SharePoint Administrator through a service account.
- Unlocks: tenant sharing, link, guest, label, malware and custom-script settings absent from the
  Graph `sharepointSettings` resource; per-site sharing level, lock state, quota, admins, claims and
  labels; library versioning, access requests and unique-permission sprawl.

### 7. teams-powershell - Teams policies (16 old checks; also 10 rows now covered only through the imported ScubaGear report)
- API: the `MicrosoftTeams` module (`Connect-MicrosoftTeams -CertificateThumbprint`) hosted
  in-process; Graph v1.0 `/teamwork/teamsAppSettings` and beta `/teamwork/devices` already cover
  the app-setting and device rows and stay on the graph integration.
- Auth: app registration with a certificate and the Teams administration application permissions.
- Endpoints (cmdlets): `Get-CsTenantFederationConfiguration`, `Get-CsTeamsClientConfiguration`,
  `Get-CsTeamsMeetingPolicy`, `Get-CsTeamsMessagingPolicy`, `Get-CsTeamsAppPermissionPolicy`,
  `Get-CsTeamsAppSetupPolicy`, `Get-CsTeamsChannelsPolicy`, `Get-CsTeamsEventsPolicy`,
  `Get-CsTeamsUpgradeConfiguration`, `Get-CsOnlineUser` (policy assignments), `Get-CsOnlineVoiceUser`.
- Unlocks: federation and guest capability, meeting lobby / anonymous / recording defaults,
  messaging and app governance, upgrade mode, voice inventory.

### 8. mde-api - Defender for Endpoint (12 old checks)
- API: `https://api.securitycenter.microsoft.com/api`.
- Auth: client-credentials token with the application roles Machine.Read.All,
  Vulnerability.Read.All, SecurityRecommendation.Read.All, Score.Read.All, Alert.Read.All,
  Ti.ReadWrite used read-only (indicators have no read-only role).
- Endpoints: /machines, /machines/{id}/vulnerabilities, /vulnerabilities, /recommendations,
  /exposureScore, /indicators, /machineactions, /baselineProfiles, /deviceavinfo.
- Unlocks: sensor health and onboarding coverage per device, vulnerability and exposure backlog,
  response-action audit, indicator hygiene, server licence shortfall.

### 9. defender-xdr-api - advanced hunting and Defender for Cloud Apps (11 old checks)
- API: Graph `/security/runHuntingQuery` (a POST) or `https://api.security.microsoft.com/api/advancedhunting/run`;
  Cloud Apps `https://<tenant-region>.portal.cloudappsecurity.com/api/v1` (activities, discovery,
  policies).
- Auth: application token with ThreatHunting.Read.All (Graph) or AdvancedHunting.Read.All (XDR
  API); a token for the Cloud Apps resource with its own read permissions.
- Note: the hunting call is a POST; Keeper's http and graph runners refuse writes, so this needs a
  deliberate read-only-query exception or its own runner.
- Unlocks: email threat and click telemetry, identity protocol telemetry (NTLMv1, clear-text LDAP),
  tampering and registry telemetry across the estate, shadow-IT discovery and anomaly-policy state.

### 10. aws - cloud-hosted server facts (6 old checks; infrastructure scope, listed for completeness)
- API: EC2, Backup, Cost Explorer, IAM / SSO regional endpoints; read-only SSO role. Unlocks:
  security groups and network ACLs of the sync-server instance, backup recovery points and plan
  options, instance right-sizing evidence, permission-set evaluation.

### 11. admin-center-export - portal-only reports through the `file` protocol (5 old checks; also 2 Exchange, 2 Intune and 4 SharePoint rows as a fallback)
- Not an API: a documented import name per report (device enrolment managers, EWS usage, SMTP AUTH
  clients, OneDrive sync health and client versions, Call Quality Dashboard, OneDrive access
  delegation) dropped into `imports\` by a person and read by `file` rules. No code beyond the names.

### 12. azure-arm - rules on the existing `azure` integration (3 old checks)
- The integration exists; the rules do not. Provider `Microsoft.ADHybridHealthService` (Connect
  Health services, lastUpdated, alerts, notification settings), Application Insights request counts,
  Key Vault key properties for a customer-managed tenant key, Intune diagnostic settings.

### 13. Minor, outside the vocabulary (flagged so nothing is lost)
- **dns-resolver** (0 primary, 5 secondary): in-process DNS from the collector (autodiscover CNAME,
  MX per accepted domain, smart-host resolution, partner MTA-STS TXT). No auth.
- **graph-export-jobs** (0 primary, 2 partial): Intune report export jobs are POST, poll, download
  (`/deviceManagement/reports/exportJobs`); same Graph app; would unlock per-setting compliance and
  configuration reports and install status by app.
- **keepit-api** (2): SaaS-backup coverage and anomaly state of the Power Platform environments.
- **azure-devops-api** (1): repository, branch policy and pipeline of the Dynamics customisations.
- **mscommerce-api** (1): the self-service purchase policy per product, a small GET API behind the
  MSCommerce module (Entra token with the licensing service audience).
