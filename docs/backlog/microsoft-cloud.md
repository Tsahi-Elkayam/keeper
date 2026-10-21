# Backlog - Microsoft cloud (Entra ID, Intune, Microsoft 365)

Checks that `rules/entra.yaml`, `rules/intune.yaml` and `rules/m365.yaml` cannot express yet, one
line each: the check, what it needs, and where it came from. After the backlog: the Microsoft Graph
permissions each rule file needs, the licences some rules depend on, the thresholds, and the details
to confirm on the first real run.

Source labels: `entra-checks` = the legacy Entra deep-scan catalogue (check id), `cis` = the legacy
CIS-mapped M365 checks (benchmark item id), `review` = the legacy M365 expert review list (item id),
`field` = a problem seen in a real estate (described generically), `request` = asked for directly.

## Engine gaps - the data is in Graph, the engine cannot use it yet

### "At least one row must match" - done, with what remains

`count.where` is now in the engine, and the Conditional Access baselines are must-exist rules: each
counts the enforced policies that carry the whole baseline on their own and fails when there is
none. Done: ENTRA-CA-BASELINE-MFA-ALL-USERS (cis 5.2.2.2), -MFA-ADMINS (5.2.2.1),
-PHISHING-RESISTANT-ADMINS (review ENT-CA-003), -LEGACY-AUTH-BLOCKED (5.2.2.3),
-DEVICE-CODE-BLOCKED (5.2.2.12), -AUTH-TRANSFER-BLOCKED (5.2.2.17), -SIGNIN-RISK (5.2.2.7),
-USER-RISK (5.2.2.6), -GUEST-MFA, -COMPLIANT-DEVICE (5.2.2.9), -REGISTER-SECURITY-INFO (5.2.2.10),
-INTUNE-ENROLLMENT-MFA (5.2.2.11), -ADMIN-SESSION-LIMITS (5.2.2.4), -REAUTH-ALL-USERS (5.2.2.13),
-ADMIN-PORTALS-MFA (review ENT-CA-009), -MFA-AZURE-MANAGEMENT (review ENT-CA-010),
-WORKLOAD-IDENTITY-BLOCK, -UNKNOWN-PLATFORMS-BLOCKED; INTUNE-COMPLIANCE-WINDOWS-NONE-WIDE,
INTUNE-COMPLIANCE-IOS-NONE / -MACOS-NONE / -ANDROID-NONE, INTUNE-ESEC-*-NONE (one per endpoint
security family, LAPS and baselines), INTUNE-UPDATE-RING-NONE; ENTRA-AU-NO-RESTRICTED-MANAGEMENT,
ENTRA-LIFECYCLE-NO-LEAVER-WORKFLOW. What one policy row still cannot express:

- Coverage split over several policies (for example admin roles divided between two policies, or MFA for all users built from per-app policies) - needs a union across rows (each role covered by some enforced policy). Today such a tenant gets a finding; the evidence shows how many policies were read. Source: cis 5.2.2.1; review ENT-CA-002.
- Admin session limits on every privileged role (only Global Administrator is required today). Source: cis 5.2.2.4.
- The baselines do not judge user and group exclusions (they would have to be compared with the emergency-access accounts), and a grant with operator OR that offers MFA or a compliant device still counts as MFA (ENTRA-CA-ADMIN-MFA-OR-DEVICE flags that per policy). Source: review ENT-CA-013, ENT-CA-016.
- A compliance policy exists for every platform that has managed devices (for example no iOS compliance policy while iPhones are enrolled) - a join of compliance policies with managed devices. Partial: INTUNE-COMPLIANCE-IOS-NONE / -MACOS-NONE / -ANDROID-NONE report a missing policy whether or not such devices exist (a tenant without the platform accepts the finding). Source: field (Apple devices with no compliance policy and no Apple MDM at all).
- Endpoint security per family counts only policies on the settings-catalog API (configurationPolicies); policies created with the older template API (`/deviceManagement/intents`) are not read, so a tenant whose antivirus policy is an old intent gets an INTUNE-ESEC finding. Reading intents (and their settings) is a second query per family. Source: proposal.

### Comparing two fields of the same row, or arithmetic - done for compares, what remains

`value: { field: <other>, times, plus }` is in the engine. Done with it: M365-SKU-OVERASSIGNED
(entra-checks ENTRA-LIC-7, review LIC-001), M365-SKU-NO-HEADROOM (field: suite pools fully consumed),
M365-SKU-UNUSED-UNITS-MANY (ENTRA-LIC-1), ENTRA-USER-MAIL-UPN-MISMATCH and ENTRA-USER-UPN-ONPREM-MISMATCH
(ENTRA-ATR, field: a SaaS VPN seat quota consumed twice), M365-MAILBOX-NEAR-QUOTA,
M365-SPO-SITE-STORAGE-HIGH and M365-ONEDRIVE-ACCOUNT-STORAGE-HIGH (used against quota). A threshold on
such a leaf replaces the whole computed value, so the ratios (90 %, 80 %, 2 %) are fixed in the rules;
a `times` threshold would make them tunable. Still open:

- Date arithmetic on a field (deleted + 30 days as a deadline, endDateTime - startDateTime as a lifetime).
- Client secret created with a lifetime above 24 months (endDateTime - startDateTime). Partial: ENTRA-APP-SECRET-LONG-LIVED and ENTRA-SP-SECRET-LONG-LIVED flag any secret that still ends more than 730 days ahead, using `age-lt` with a negative value (no `until-gt` op is needed for "more than N days ahead"); the lifetime at creation needs field arithmetic. Source: entra-checks ENTRA-APP-3; review ENT-APP-005.
- PIM activation longer than N hours and app-policy maxLifetime above N days - ISO 8601 durations (PT8H, P180D) need a duration comparison. Source: entra-checks ENTRA-RL-*-2; cis 5.1.5.4, 5.1.5.6; review ENT-PIM-003. (The provisioning job interval is handled with a pattern of accepted values instead: ENTRA-PROVISIONING-JOB-REDUCED-SCHEDULE.)
- Severity that depends on a second field or on a count: provisioning failures per app above N events (high), legacy-protocol sign-ins per account, an app registration with more than twice the allowed secrets, a quarantined provisioning job whose error is a credential error (critical). A template key already groups the rows into one finding per key; the engine would need to expose `{rows}` per key and allow a severity range on it. Source: proposal.
- Compliance policy reach as a total (success + failed + error + pending). Partial: INTUNE-COMPLIANCE-WINDOWS-NONE-WIDE tests each count separately.
- Secure Score below a percentage (currentScore / maxScore). Source: entra-checks ENTRA-POL-3; review ENT-LOG-005.

### Conditions on one array element

Each leaf over an array path fires when any element matches; two leaves cannot be pinned to the same
element, and `daysLeft` / `deadline` read the first element only. Workaround now in use: a `match`
leaf on an array of objects is tested against each element's JSON text, so lookaheads pin two
properties to one element - `(?=.*"name":"EnableGroupCreation")(?=.*"value":"false")`. Used by
M365-GROUP-CREATION-UNRESTRICTED, ENTRA-GROUP-NAMING-POLICY-NONE, AIP-CONTAINER-LABELS-OFF (directory
settings name/value pairs), INTUNE-COMPLIANCE-NO-BLOCK-ACTION (the block action's grace period),
INTUNE-ASSIGNMENT-ALL-NO-FILTER(-COMPLIANCE) (target @odata.type with no filter id),
ENTRA-GROUP-NONUSER-MEMBER (member @odata.type) and M365-LICENSE-ADVANCED-AUDIT-PLAN-DISABLED (plan id
with its state). It depends on the property order and spelling of Graph's JSON and on the serializer
escaping only non-ASCII and HTML characters; an engine-side "same element" condition would be cleaner.

- Severity and deadline of the credential-expiry rules follow the FIRST secret or certificate listed, not the soonest. Needs a `min` (soonest date) for `daysLeft` and `deadline`. Affects ENTRA-APP-SECRET-EXPIRY, ENTRA-APP-CERT-EXPIRY, ENTRA-SP-SAML-CERT-EXPIRY, ENTRA-SP-SECRET-EXPIRY (the evidence lists every end date). Source: request.
- "Credential expires within N days AND a newer credential does not exist" (expiry without a replacement) - the latest end date must be within N days. Source: entra-checks ENTRA-APP-2. Today any expiring or expired credential fires, which also flags expired leftovers (worth removing anyway).
- PIM role settings by rule id - done by reading `/policies/roleManagementPolicies/{policyId}/rules` per role (one row per PIM rule, the role assignment as parent): ENTRA-PIM-ACTIVATION-NO-MFA, -NO-JUSTIFICATION, -LONG, ENTRA-PIM-ELIGIBILITY-PERMANENT-ALLOWED. Still open: notification recipients, and an authentication-context rule counting as MFA (it is another row). Source: entra-checks ENTRA-RL-*-2; review ENT-PIM-002..005.
- Directory settings as name/value pairs (`/groupSettings` values) - Group.Unified done (group creation, naming policy, labels for groups). Still open: guests as group owners (Group.Unified AllowGuestsToBeGroupOwner), and the Password Rule Settings template (5cf42378-d67d-4f36-ba46-e8b86229381d: custom banned passwords, on-premises mode, smart lockout threshold and duration) - its setting names are not documented on Microsoft Learn (only third-party sources list EnableBannedPasswordCheck, BannedPasswordList, LockoutThreshold, LockoutDurationInSeconds, BannedPasswordCheckOnPremisesMode); read them from a tenant's `/groupSettingTemplates` once, then the rules are ENTRA-PASSWORD-BANNED-LIST-OFF (count lt 1 where the template's object has the check on and a non-empty list), ENTRA-PASSWORD-LOCKOUT-THRESHOLD-HIGH (> 10) and ENTRA-PASSWORD-LOCKOUT-DURATION-SHORT (< 60 s) with the element-text technique above. Source: cis 5.2.3.2, 5.2.3.3, 5.2.3.8, 5.2.3.9, 5.1.3.3; entra-checks ENTRA-GRP-16; review ENT-ID-010, ENT-ID-012, ENT-ID-016, ENT-ID-017; proposal.
- App management policy restrictions: the restriction type is checked, its maxLifetime and state are not (same element). Source: cis 5.1.5.4, 5.1.5.6.
- Users licensed partly directly and partly through groups (an element with assignedByGroup null next to one without). Partial: M365-LICENSE-DIRECT-ONLY. Source: entra-checks ENTRA-LIC-4; review LIC-003.
- Authentication method enabled for all users (includeTargets id all_users) versus a named migration group, for SMS and Voice severity. Source: entra-checks ENTRA-AM-1.
- Federated identity credentials: a broad subject on an external issuer (issuer and subject of the same credential). ENTRA-APP-FEDERATED-CREDENTIAL-BROAD-SUBJECT tests the subjects whatever their issuer, -EXTERNAL the issuers whatever their subject. Source: proposal.
- Compliance scheduled actions (actionType block with its grace period) and app-management restriction state and maxLifetime pairs. Source: proposal.

### Joins across queries

One query per rule; no lookup of another query's rows.

- Privileged role holders with no successful sign-in in N days (roleAssignments x users.signInActivity). Source: entra-checks ENTRA-ROLE-4, ENTRA-RL-*-3; review ENT-PIM-010; request. Partial: ENTRA-PIM-ALERT-ACTIVE (PIM's own stale-admin alert, P2).
- Privileged role holders without a phishing-resistant method, per role. Partial: ENTRA-MFA-ADMIN-* use the registration report's isAdmin flag (any role). Source: entra-checks ENTRA-ROLE-3, ENTRA-RL-*-4.
- Members with no MFA, excluding disabled accounts (the registration report has no accountEnabled). Source: cis 5.2.3.4; entra-checks ENTRA-ACC-11. ENTRA-MFA-MEMBER-NOT-CAPABLE includes disabled accounts.
- Disabled users still in groups assigned to enterprise apps (app assignments x transitive group members x accountEnabled). Source: request; field (disabled users kept consuming the seat quota of a SaaS VPN through app-assigned groups). Partial: ENTRA-USER-DISABLED-APP-ASSIGNED (direct assignments only).
- App-assigned groups that are empty (a group's appRoleAssignments and its members in one rule; Graph may not allow two expands on directory objects, and members/$count is not a documented group filter). Source: request; field (access groups created and assigned to an app but never filled).
- Two groups assigned to the same app where one should have replaced the other (a second, forgotten way in). Source: field (an all-staff group left assigned to a SaaS app next to its dedicated access group).
- App registration owners who are inactive (applications x owners x users.signInActivity). Partial: ENTRA-APP-OWNER-DISABLED-OR-GUEST (owners expanded with accountEnabled and userType). Source: entra-checks ENTRA-APP-11; review ENT-APP-010.
- High-impact Graph permissions on apps unused for 90 days (Graph grants x servicePrincipalSignInActivities x service principals). Source: entra-checks ENTRA-APP-12, ENTRA-APP-10; review ENT-APP-009.
- Unused applications (proposal ENTRA-SP-SIGNIN-STALE): beta `/reports/servicePrincipalSignInActivities` gives lastSignInActivity per appId, but it includes Microsoft's own applications, so on its own every rarely used Microsoft app becomes a finding. Needs a store join with the service principal inventory (appOwnerOrganizationId not a Microsoft tenant); apps that never signed in are absent from the report (ENTRA-APP-CREDENTIALS-ALL-EXPIRED covers part of them). Permission AuditLog.Read.All. Source: proposal; entra-checks ENTRA-APP-12.
- New hires in none of the app-access groups (proposal ENTRA-USER-NEW-NOT-IN-ACCESS-GROUP). `transitiveMemberOf` has no documented `$expand` on users and expands stop at 20 items; and with the access-group list empty (it is tenant-specific) "in none of the listed groups" fires for every new user. Needs a store set difference: users created in the last N days (user inventory, createdDateTime) minus members of groups that have app role assignments, or minus the source objects the provisioning log shows as exported. Source: proposal; field (a new hire never provisioned because the access group was a one-time copy).
- A group gaining recent joiners while assigned to no application (proposal ENTRA-GROUP-RECENT-JOINERS-NO-APP). One level of for_each over groups → `/groups/{id}/members/microsoft.graph.user?$filter=createdDateTime ge {DAYS_AGO:30}` is possible, but the condition "at least N recent members per group" needs a count per parent, and without it every unassigned security group that gained one member (most groups grant no app) is a finding. ENTRA-GROUP-ONBOARDING-NOT-ASSIGNED covers the named onboarding groups. Source: proposal.
- New hires the provisioning job skipped or never exported: join the provisioning-log rows (ENTRA-PROVISIONING-*-RECENT, keyed jobId and sourceIdentity.id) or the provisioning-job rows (key `{parent.id}|{id}`, the job id equals the log's jobId) with the user inventory's createdDateTime. Source: proposal; field.
- Conditional Access policies referencing deleted users, groups or roles; owners of CA exclusion groups; dynamic exclusion groups on user-editable attributes. Source: entra-checks ENTRA-CA-2, ENTRA-GRP-17; review ENT-CA-015, ENT-CA-016.
- External or vendor accounts inside an all-staff group that drives app access (group members x employeeType or OU); the all-staff group id would be a threshold. Source: field (vendor accounts and leavers found in an all-staff group that provisioned users into a SaaS app).
- Licensing groups that contain disabled or guest members (group x members). Partial: M365-LICENSE-DISABLED-VIA-GROUP (seen from the user side). Source: entra-checks ENTRA-GRP-18; field (licensing groups that never exclude leavers).
- Users of a restricted SKU who are not eligible for it (SKU x department or job attributes). Partial: M365-LICENSE-WATCHLIST-SKU (tenant fills the SKU list). Source: field (education SKUs handed out to non-academic staff as a cheaper stand-in); review LIC-005.
- Synchronised accounts in a leavers OU joined to AD state, and AD-versus-Entra staleness. Handled in `rules/hybrid-identity.yaml` over the store, joining AD objectSid to Entra onPremisesSecurityIdentifier (the Entra side is the user inventory query, see below).
- Microsoft 365 Apps / Teams Rooms device accounts whose device stopped signing in (account x device sign-ins). Source: field (a meeting-room account that silently stopped signing in when its password aged out). Partial: ENTRA-USER-CLOUD-PASSWORD-OLD.

### Aggregation across rows, traversal, history

- Duplicate device names, duplicate hybrid-join objects, duplicate Intune records per serial number. Source: entra-checks ENTRA-DEV-3; review ENT-DEV-002, INT-007; field (many duplicate serials in a Windows estate).
- Duplicate values across users (employee id, mail, mobile phone, display name, group display name). Source: entra-checks ENTRA-ATR (uniqueness family), ENTRA-GRP-12.
- Spelling variants of one attribute value (department, company, job title). Source: entra-checks ENTRA-ATR (consistency family).
- Group nesting loops and depth (a group that contains itself, two groups that contain each other). Source: entra-checks ENTRA-GRP-7; field (self-nested and mutually nested app-access groups).
- Dynamic group rules comparing against values no user has. Source: entra-checks ENTRA-GRP-9.
- Eligible roles never activated (eligibility x PIM request history). Source: entra-checks ENTRA-PRV-2.
- Many Authenticator registrations on one account after a reset (a likely attacker-registered method). Source: field (accounts with several Authenticator registrations and a personal mailbox as recovery email); review ENT-AM-012. Needs per-user `/users/{id}/authentication/microsoftAuthenticatorMethods` (iteration, UserAuthenticationMethod.Read.All).

### Log endpoints - relative dates are in, what remains

`{DAYS_AGO:n}` now bounds the log endpoints. Done: ENTRA-SIGNIN-LEGACY-AUTH-SUCCESS-RECENT,
ENTRA-SIGNIN-RISKY-SUCCESS-RECENT, ENTRA-AUDIT-ROLE-ASSIGNMENT-RECENT, ENTRA-AUDIT-TIER0-ROLE-ASSIGNMENT-RECENT,
ENTRA-PROVISIONING-*-RECENT. Still open:

- Sign-in attempts against disabled or dormant accounts, per attempt (source IP, app, error) from `/auditLogs/signIns`. The log can be read now; "dormant" comes from the user inventory, so it is a store join. Partial: ENTRA-USER-STALE-SIGNIN-ATTEMPTS and ENTRA-USER-DISABLED-SIGNIN-ATTEMPTS read the last attempt from signInActivity. Source: request; field (a burst of interactive attempts over a few days on hundreds of dormant paid accounts, most with no success since - consistent with a spray). Note: Entra keeps sign-in logs for 30 days; older evidence lives only in a SIEM export.
- Password-spray evidence (failed attempts grouped by user above N) needs a count per key. Sign-ins from unexpected countries: done as ENTRA-SIGNIN-FOREIGN-SUCCESS-RECENT with a home-country pattern threshold (unset = checks nothing, while the sign-in window is still read). Source: review ENT-IDP-005, ENT-IDP-006, EXO-008.
- Directory changes other than role grants by unexpected actors: tenant-level domain, federation, partner and company changes (M365-AUDIT-TENANT-CHANGE-RECENT) and sync settings (ENTRA-SYNC-AUDIT-SETTINGS-CHANGED-RECENT) are done; app credentials added and Conditional Access changes are still open. Source: entra-checks ENTRA-PRV-3; review ENT-LOG-003, ENT-PIM-012.
- Risk detections of the last N days: done as ENTRA-RISK-DETECTION-OPEN-RECENT. Source: review ENT-IDP-002.

### Per-object endpoints (for_each, one level)

`for_each` is in: the SaaS provisioning job rules (ENTRA-PROVISIONING-JOB-*) read
`/servicePrincipals/{id}/synchronization/jobs` for every enterprise app (Synchronization.Read.All).
Still open:

- Federated domain federatedIdpMfaBehavior (proposal ENTRA-DOMAIN-FEDERATION-MFA-TRUSTED: high when the behaviour is not rejectMfaByFederatedIdp - unset means acceptIfMfaDoneByFederatedIdp - or passiveSignInUri is plain http). Not written: `/domains` ignores `$filter` (Graph known issue), so a `for_each` asks every domain, and `/domains/{id}/federationConfiguration` answers 404 for managed domains, which makes the result partial every day (failed when no domain is federated). Needs a `for_each` filter on the listed rows (authenticationType eq Federated) or 404-as-empty for children. Permission Domain-InternalFederation.Read.All. The signing certificate comes back as base64, so its expiry needs certificate parsing in the runner. Partial: ENTRA-DOMAIN-FEDERATED lists the federated domains. Source: entra-checks ENTRA-TEN-13; review ENT-TEN-005; proposal.
- Provisioning job schema (proposal ENTRA-PROVISIONING-MAPPING-SUSPECT: attribute mappings that use expressions, single matching attribute) - `/servicePrincipals/{sp}/synchronization/jobs/{job}/schema` needs two levels (service principal, then job), and the mappings are nested arrays (synchronizationRules[].objectMappings[].attributeMappings[]) that would need flattening with their parent and a "count of elements where" op. Reshape option: a store rule that turns the job rows into a list of (sp, job) pairs for a second scan. Source: proposal; field (one attribute mapping rejected by the target failed thousands of objects).
- Defender state per Windows device (proposal INTUNE-DEVICE-DEFENDER-RTP-OFF / -SIGNATURES-OVERDUE / -TAMPER-OFF: windowsProtectionState.realTimeProtectionEnabled, signatureUpdateOverdue, tamperProtectionEnabled). `$expand=windowsProtectionState` on the managed-device list is not documented (the relationship is); the per-device navigation `/deviceManagement/managedDevices/{id}/windowsProtectionState` returns one object (one row now that the runner fix is in), and one call per Windows device is capped at 2000 per scan. Try the list expand first. Permission DeviceManagementManagedDevices.Read.All. Source: proposal.
- App install failures (proposals INTUNE-APP-REQUIRED-INSTALL-FAILING, INTUNE-APP-DEVICE-INSTALL-ERROR). Not written: beta `/deviceAppManagement/mobileApps/{id}/installSummary` and `/deviceStatuses` are marked deprecated (May 2023) on Microsoft Learn, and the replacement Intune reports API is POST (export jobs). Needs a read-only POST runner for the reports API. Source: review INT-004; request; field (the install-status report call returned BadRequest); proposal.
- Per-user inbox rules (`/users/{id}/mailFolders/inbox/messageRules`) - iteration over every mailbox. See "Not in Graph" for forwarding.
- SAML app claim configuration (whether a groups claim is emitted, which attributes map to the NameID) - per service principal claims-mapping policies and app optional claims. Source: field (group-based access to a SaaS app whose groups claim was never verified).
- Many Authenticator registrations per user (see "Aggregation" above) is a `for_each` over users now, but needs a count of rows per parent.

### Field paths, runner and protocol

- **Fixed: single-object Graph responses are one row now** (GraphRunner passes `items` only when the rule sets it; plain values become `{ value }` rows). The original note, kept for the confirmation list: GraphRunner always passed `items: value`; `RowValues.ItemsOf` then looks for a `value` property and returns no rows when the body is one object. Every rule on a singleton endpoint therefore sees nothing and records no finding, which reads as a pass: /policies/authorizationPolicy, /policies/authenticationMethodsPolicy (rules without `items`, v1.0 and beta), /policies/identitySecurityDefaultsEnforcementPolicy, /adminConsentRequestPolicy, /defaultAppManagementPolicy, /authenticationFlowsPolicy, /deviceRegistrationPolicy, /crossTenantAccessPolicy/default, /admin/sharepoint/settings, beta /admin/forms and /admin/appsAndServices, /deviceManagement (v1.0 and beta), /deviceManagement/applePushNotificationCertificate, /deviceManagement/deviceCompliancePolicyDeviceStateSummary, beta /teamwork/teamsAppSettings, /admin/microsoft365Apps/installationOptions. Fix: pass `items` only when the rule sets it, so ItemsOf falls back to the OData `value` array or the root object (it already does). A run where a singleton query returns 0 rows should also be flagged as suspicious. Source: code reading during this rule batch.
- **Empty threshold list = rule not configured.** Rules that key on a tenant list (ENTRA-GROUP-ONBOARDING-NOT-ASSIGNED with `entra.onboarding-group-ids`, M365-LICENSE-WATCHLIST-SKU with `m365.watch-sku-ids`) match nothing while the list is empty and look like a pass. The engine should record them as "not configured" (n/a with a reason) instead. Source: proposal.
- Field paths split on every dot, so OData annotations such as `@odata.type` cannot be addressed. ENTRA-DEVREG-JOINER-LOCAL-ADMIN, ENTRA-GROUP-NONUSER-MEMBER and INTUNE-ASSIGNMENT-ALL-NO-FILTER work around it by matching the JSON text of the object or array element. Needs a quoted path segment.
- Graph `Prefer` headers cannot be sent: newer enum members (eDiscovery case operations exportReport, exportResult, purgeData, holdPolicySync) come back as unknownFutureValue, so M365-EDISCOVERY-EXPORT-RECENT sees contentExport only.
- A polymorphic beta list read in full (beta `/deviceManagement/deviceConfigurations` with no `$select`) returns every profile type, including properties that can hold secrets (Wi-Fi pre-shared keys, kiosk exit codes; whether Graph masks them is not documented). The rules that need beta-only profile types are therefore not written (see the catalogue port below) until the runner filters Graph secret properties or `isof()` with a derived-type `$select` is confirmed.
- `for_each` lists come only from Graph: a list from a threshold (named emergency-access accounts, public mailboxes, critical sites) cannot drive the per-object calls, and a parent the child answers 404 for (a managed domain asked for its federation configuration) makes the result partial instead of empty.
- The runner's secret-attribute list is LDAP-oriented; Graph secret properties are not filtered. These rules keep them out of every `$select` (VPP `token`, enrolment profile `tokenValue`, `wifiPassword`, Autopilot `deviceAccountPassword`, Managed Google Play `companyCodes` enrolment tokens, managed device `activationLockBypassCode`) and select only metadata of Intune scripts (never `detectionScriptContent`, `remediationScriptContent`, `scriptContent`, which may embed credentials). Add them to the runner's list so a tenant rule cannot select them either. Endpoints that do not support `$select` (sign-in, provisioning and Defender logs, synchronization jobs) return their full objects; none of them carries a secret value.
- Fan-out of `for_each`: the provisioning job rules ask every enterprise app (up to 1000; `for_each.max`) for its jobs once a day. A tenant with more apps gets a partial result with the reason; a narrower list (a tag or a tenant list of provisioned apps) would need either a filter Graph supports or a store-fed list.
- Expanded relationships return at most 20 items; ENTRA-ROLEGROUP-LARGE therefore keeps its threshold below 20.
- Partial reads: a delegated identity without an activated PIM role gets a subset back with no error (seen with Exchange Online; Graph role-gated reads can behave the same). Use application permissions for the Graph integration; the engine could also warn when a query returns far fewer rows than the previous run. Source: field.
- Device-code sign-in is blocked by Conditional Access in well-run tenants, so the Graph integration must not depend on it (certificate-based app sign-in). Source: field.

## Catalogue port (docs/proposals/catalog-microsoft-cloud.md, October 2026)

The "new" entries of the old Microsoft-cloud catalogue that today's protocols can read are rules now:
entra.yaml 71, intune.yaml 38, m365.yaml 21, and two new files - rules/defender.yaml (5, Graph security
API) and rules/entra-connect.yaml (19, cim/registry/eventlog on the sync servers named in the cim
integration's `targets` option). Field names and permissions were checked on Microsoft Learn; what Learn
does not state is in "To confirm on the first real run". This section keeps what was changed, what was
not written and why, and where the rest belongs.

### Changed while porting

- One rule per check instead of families: ENTRA-PIM-ACTIVATION-WEAK became ENTRA-PIM-ACTIVATION-NO-MFA, -NO-JUSTIFICATION, -LONG and ENTRA-PIM-ELIGIBILITY-PERMANENT-ALLOWED (approval stays ENTRA-PIM-NO-APPROVAL, whose role list is a threshold); the attribute families are one rule each (ENTRA-USER-ATTR-MISSING, ENTRA-USER-ATTR-FORMAT with one threshold per pattern), not one rule per attribute.
- ENTRA-USER-ATTR-FORMAT leaves out mobile and business phone formats (would copy every phone number into the store for a low check) and the mixed-script check (its default named one script, a tenant fact). ENTRA-USER-ATTR-MISSING leaves out the immutable id (always set on synchronised users) and mail.
- ENTRA-BREAKGLASS-WEAK-METHODS reads the registration report (methodsRegistered) instead of a per-account call, because `for_each` cannot walk a threshold list.
- Directory-sync account pattern defaults to `^Sync_`: MSOL_ and AAD_ accounts are on-premises AD accounts.
- ENTRA-USER-UPN-ONMICROSOFT is limited to synchronised or licensed members (dedicated admin and emergency-access accounts are often on onmicrosoft.com by design). ENTRA-USER-PRIMARY-ADDRESS-ONMICROSOFT matches the `SMTP:` prefix case-sensitively; the proposal's pattern would have matched every secondary alias.
- ENTRA-SYNC-RETIRED-FEATURE-ON reads groupWriteBackEnabled only (group writeback v2, decommissioned); Microsoft 365 group writeback (v1) still works and is part of ENTRA-SYNC-WRITEBACK-ENABLED. passwordWritebackEnabled is documented as not in use and is left out. The sync interval fields are beta only (ENTRA-SYNC-INTERVAL-LONG reads beta).
- ENTRA-GROUP-NONUSER-MEMBER flags groups that mix users with devices or contacts (pure device groups are normal). ENTRA-GROUP-NO-DESCRIPTION and M365-GROUP-NO-SENSITIVITY-LABEL are tenant-level counts with a sample, not one finding per group. M365-GROUP-NAME-OR-DESCRIPTION-POOR keeps the name half (the description half is ENTRA-GROUP-NO-DESCRIPTION).
- ENTRA-SIGNIN-BLOCKED-DEVICE-COMPLIANCE-RECENT filters on conditionalAccessStatus eq 'failure' and judges the error codes in the rule (`or` on status/errorCode is not documented).
- M365-INBOX-RULE-FORWARD-OR-HIDE is two rules: M365-INBOX-RULE-FORWARD (high) and M365-INBOX-RULE-HIDE-KEYWORD (medium, without invoice/payment in the default keywords, which legitimate filing rules use).
- M365-TEAMS-ROOM-ACCOUNT-PASSWORD-EXPIRES leaves out synchronised room accounts (AD policy applies). Teams Rooms SKU defaults cover Pro, Basic, their no-audio variants, Standard and Premium.
- INTUNE-COMPLIANCE-NO-BLOCK-ACTION: every policy has exactly one block action, so the rule judges its grace period. INTUNE-DEVICE-ACTION-PENDING-STALE, -STORAGE-LOW and -OWNERSHIP-MISMATCH read beta managed devices (managementState and the Android Enterprise enrolment types are beta only); the ownership rule leaves out user-driven Windows enrolment types. INTUNE-MAA-POLICY-NONE requires a device-wipe approval policy. INTUNE-RETIRED-FEATURE-IN-USE, INTUNE-MAM-OFFLINE-WIPE-LONG, INTUNE-APPLE-TOKEN-PERSONAL-ACCOUNT, INTUNE-POLICY-NAME-NONCONFORMING and INTUNE-ASSIGNMENT-ALL-NO-FILTER are one rule per object family (suffixed ids).
- Existing rule fixed: INTUNE-ENROLL-ESP-USE-ON-FAILURE read v1.0, where the enrolment status page settings do not exist, so it could never fire; it reads beta now (and INTUNE-ENROLL-ESP-NONE with it).
- DEFENDER-ATTACK-SIM-STALE counts status succeeded (there is no completed); DEFENDER-MDI-SENSOR-UNHEALTHY uses the documented deploymentStatus values; DEFENDER-USER-REPORT-PENDING is beta (the resource has no v1.0).
- ECSYNC: the .NET minimum is 4.7.2 (version history 2.4.18.0), the version is read from miiserver.exe (the uninstall key's values are not readable, see below) and split into ECSYNC-VERSION-RETIRED and ECSYNC-VERSION-BELOW-MINIMUM (2.6.84.0, services stop after 7 April 2027); ECSYNC-APPLOG-ERRORS reads one day (the event runner cannot filter by level, and password sync logs info events constantly); ECSYNC-PHS-HEARTBEAT-EVENTS-MISSING uses event 654 (the 30-minute heartbeat) instead of 656/657; ECSYNC-LOGON-RIGHT-BROAD leaves out network logon (baselines grant it to Authenticated Users); ECSYNC-COHOSTED-SOFTWARE's approved list holds only Microsoft and common platform agents (the proposal's default named an estate's own products); ECSYNC-BROWSER-INSTALLED is told by browser update services; ECSYNC-ADSYNC-GROUP-MEMBER-UNEXPECTED reads ADSyncAdmins only.
- Merged duplicates: M365-IDLE-SESSION-TIMEOUT-OFF into ENTRA-IDLE-SESSION-TIMEOUT-NONE (plus -LONG); M365-SPO-UNMANAGED-DEVICE-CA-MISSING into ENTRA-CA-BASELINE-APP-ENFORCED-RESTRICTIONS; ENTRA-CA-BASELINE-MOBILE-APPROVED-CLIENT into ENTRA-CA-BASELINE-APP-PROTECTION; M365-ONEDRIVE-DELETED-USER-NEAR-PURGE into ENTRA-USER-DELETED-PURGE-SOON; M365-GROUP-OWNER-DISABLED into ENTRA-GROUP-OWNER-DISABLED; ENTRA-GROUP-DISTRIBUTION-NO-OWNER-OR-EMPTY into ENTRA-GROUP-NO-OWNER and ENTRA-GROUP-EMPTY; M365-SKU-IDLE-SEATS into M365-SKU-UNUSED-UNITS-MANY; D365-SKU-NO-HEADROOM into M365-SKU-NO-HEADROOM; M365-TEAMS-ROOM-ACCOUNT-NO-SIGNIN into M365-ROOM-ACCOUNT-NO-SIGNIN; M365-SECURE-SCORE-ACTION-OPEN and DEFENDER-SECURESCORE-CONTROL-OPEN are one check (not written, below).

### Not written - the source cannot give it, or the proposal was wrong

- ENTRA-SSPR-OFF: authorizationPolicy.allowedToUseSSPR is about administrators only (Learn); the users' SSPR scope has no Graph read.
- ENTRA-ADMIN-CENTER-NOT-RESTRICTED: beta `/admin/entra/uxSetting` has no application permission (delegated Global Administrator only).
- ENTRA-USER-SYNC-LAGGING: whether onPremisesLastSyncDateTime moves every cycle or only when the object changes is not documented; the latter would flag every unchanged synchronised user. Orphaned objects are the AD-side join (XS-USER-SYNCED-AD-GONE).
- ENTRA-SYNC-ACCOUNT-SIGNIN-STALE: duplicate of ENTRA-SYNC-STALE (the tenant's own last-sync time); with application-based authentication (2.5.76.0 and later) the sync user account is idle by design (ENTRA-SYNC-ACCOUNT-IDLE flags it as a leftover).
- ENTRA-SYNC-CLOUD-SYNC-OVERLAP, ENTRA-PTA-AGENTS-FEW, ENTRA-PTA-AGENT-INACTIVE: the agent groups need OnPremisesPublishingProfiles.ReadWrite.All (no read-only permission exists); Keeper's identity stays read-only.
- ENTRA-MFA-AUTHENTICATOR-ADDED-RECENT: createdDateTime of an Authenticator method is null unless it is registered for passwordless phone sign-in, so most new registrations would be invisible. The count variant (ENTRA-MFA-AUTHENTICATOR-DEVICES-MANY) needs a per-parent count (store).
- ENTRA-ADMIN-ACCOUNT-MAIL-ENABLED: the licence half is ENTRA-ROLE-LICENSED-HOLDER; the mail-enabled group half is a store join; showInAddressList semantics are a guess.
- M365-SECURE-SCORE-ACTION-OPEN / DEFENDER-SECURESCORE-CONTROL-OPEN: controlScore documents no maximum or percentage; judging a control needs the control profiles' maxScore joined by control name (store), and `$top=1` on secureScores may still page.
- M365-SHARED-MAILBOX-OVER-FREE-CAP: covered by M365-MAILBOX-NEAR-QUOTA (the report's quotas follow the licence; an unlicensed shared mailbox stops at 50 GB).
- M365-PARTNER-CONTRACT-PRESENT: `/contracts` exists in partner tenants only. M365-PARTNER-SIGNIN-RECENT: crossTenantAccessType is beta only and not documented as filterable. D365-PARTNER-GDAP-PRIVILEGED: reading delegatedAdminRelationships from the customer tenant is not documented.
- M365-THIRD-PARTY-STORAGE-ENABLED (service principal c1f33bc0-...) and M365-TEAMS-WEBHOOK-CONNECTOR-INSTALLED (app 203a1e2c-...): neither id is documented on Learn, and installedApps filtering on teamsApp/id is not documented.
- M365-TEAMS-ROOM-SOFTWARE-OUTDATED, M365-TEAMS-ROOM-UNHEALTHY: the beta teamworkDevice API was deprecated in November 2025. Needs the Teams Rooms Pro management portal API as its own integration.
- M365-CALENDAR-DEFAULT-PERMISSION-WIDE: Calendars.Read (every meeting of every user) is disproportionate for a hygiene check; the exo-powershell form (Get-MailboxFolderPermission with View-Only roles) is in the list below.
- M365-SPO-PRESERVATION-HOLD-LARGE, M365-SPO-CLASSIC-SITE-ACTIVE: guesses (hidden library in `/drives`, template names in the report).
- INTUNE-APP-REQUIRED-INSTALL-FAILING, INTUNE-APP-DEVICE-INSTALL-ERROR: deprecated endpoints (see per-object endpoints above).
- INTUNE-WIFI-PROFILE-PSK, INTUNE-ANDROID-OWNER-RESTRICTIONS-WEAK, INTUNE-ANDROID-SYSTEM-UPDATE-POSTPONED, INTUNE-CERT-PROFILE-RENEWAL-LOW, INTUNE-TRUSTED-ROOT-PROFILE-REVIEW: these profile types exist only in beta, and a full beta read of device configurations may carry secrets (runner section above). securityAllowDebuggingFeatures does not exist; the other field names are confirmed (securityDeveloperSettingsEnabled, appsAllowInstallFromUnknownSources, factoryResetBlocked, systemUpdateInstallType postpone/deviceDefault, renewalThresholdPercentage, certificateValidityPeriodScale/Value, certFileName, destinationStore, wifiSecurityType).
- INTUNE-MDM-USER-SCOPE-ALL: `/policies/mobileDeviceManagementPolicies` supports delegated permissions only.
- INTUNE-APPCONFIG-OUTLOOK-ACCOUNTS-OPEN: the allowed-accounts keys belong to MDM app configuration, not managed-app configuration custom settings; confidence too low.
- INTUNE-WIN32-APP-DETECTION-NOT-VERSIONED: guessed detection-rule fields, and detectionRules carry script content.
- INTUNE-POLICY-CMD-BLOCK-BROAD: guessed settingDefinitionId text.
- INTUNE-AGENT-APP-VERSION-OLD: `$filter` on detectedApps is not documented and the unfiltered list is every app on every device.
- ENTRA-ACCESS-REVIEW-SETTINGS-WEAK per-role coverage: one review per privileged role needs a map threshold or a store rule; the settings half is written.
- ECSYNC-BUNDLED-COMPONENT-OLD: the registry runner returns subkey names only, so DisplayVersion under the uninstall key is unreadable (and Win32_Product is never used). Needs subkey values in the registry runner.
- ECSYNC-LOGON-FROM-UNAPPROVED-HOST, ECSYNC-LOGON-BY-UNAPPROVED-ACCOUNT: the event runner filters by id and provider only; 4624 and 4672 on a server are mostly network and service logons that fill any cap in minutes. Needs event-data conditions (LogonType 2 and 10) in the XPath.
- ECSYNC-CONFIG-EXPORT-STALE: a `file` rule, which the cim integration cannot run; it belongs in a files-integration pack (imports\entra-connect\*.json).
- DEFENDER-RBAC-RESPONSE-RIGHTS-BROAD: the action strings are unconfirmed and the per-role holder count is a store join.
- Proposals that need `for_each` over a threshold list: M365-ALERT-MAILBOX-UNTRIAGED, M365-MAILBOX-AUTOREPLY-STALE, M365-SPO-CRITICAL-SITE-UNREACHABLE, ENTRA-USER-EXTERNAL-WORKER-UNCLASSIFIED.

### Store joins - specified, belong in rules/cross-system.yaml or rules/hybrid-identity.yaml

Not part of the files of this port (a store rule needs a file with integration keeper). Each is
specified in the proposal under its id; the inputs are rows the graph and cim packs already collect
unless noted.

- Roles: ENTRA-PIM-ELIGIBILITY-NEVER-ACTIVATED (eligibility instances x roleAssignmentScheduleRequests selfActivate, needs that query), ENTRA-ROLE-HOLDER-INACTIVE (role assignments x user inventory signInActivity), ENTRA-ROLE-HOLDERS-TOO-MANY (holders per role against a cap map), ENTRA-ROLE-HOLDER-NO-ADMIN-ACTIVITY (needs a directoryAudits fetch), AZ-OWNER-HOLDER-STALE-OR-GUEST (azure role assignments x Entra users).
- Conditional Access: ENTRA-CA-REQUIRED-LOCATION-UNUSED, ENTRA-CA-DANGLING-REFERENCE, ENTRA-GROUP-CA-REFERENCED-WEAK.
- Users: ENTRA-USER-CLOUD-ONLY-MEMBER (gate on the organisation's sync flag), ENTRA-USER-ATTR-DUPLICATE, ENTRA-USER-ATTR-VALUE-VARIANTS, ENTRA-USER-MANAGER-DISABLED and ENTRA-USER-MANAGER-LOOP (manager id from the M365-USER-NO-MANAGER query x user inventory; the manager expand carries no accountEnabled), ENTRA-ADMIN-ACCOUNT-MAIL-ENABLED (group half), ENTRA-MFA-AUTHENTICATOR-DEVICES-MANY (needs the per-user Authenticator fetch), M365-TENANT-CONTACT-ACCOUNT-DISABLED.
- Applications: ENTRA-APPPERM-TIER0-UNUSED-APP (needs the servicePrincipalSignInActivities fetch), ENTRA-APP-REQUESTED-NOT-GRANTED.
- Groups and devices: ENTRA-GROUP-NAME-DUPLICATE, ENTRA-GROUP-DISABLED-MEMBER, ENTRA-GROUP-GUEST-MEMBER, ENTRA-GROUP-NESTING-DEEP, ENTRA-DEVICE-NAME-DUPLICATE, XS-INTUNE-DEVICE-DUPLICATE-SERIAL.
- Licences: M365-SKU-PLAN-DISABLED-WIDELY, M365-TEAMS-ADDON-LICENSE-UNUSED (needs the Teams user activity report), XS-INTUNE-DEVICE-USER-UNLICENSED, DEFENDER-IDENTITY-LICENCE-SHORTFALL.
- Mailboxes: M365-SHARED-MAILBOX-SIGNIN-ENABLED, M365-RESOURCE-MAILBOX-SIGNIN-RECENT, M365-MAILBOX-USER-DISABLED-NOT-CONVERTED, M365-MAILBOX-INACTIVE - the beta mailbox usage report carries no recipientType (Learn), so each needs the mailbox type from exo-powershell or from per-user `mailboxSettings/userPurpose` (beta, MailboxSettings.Read).
- Intune and Defender: XS-COMPUTER-AD-ACTIVE-NOT-IN-INTUNE, XS-DEVICE-WINDOWS-NO-LAPS-BACKUP (INTUNE-LAPS-BACKUP-STALE rows x Intune devices), XS-DEVICE-ENCRYPTED-NO-RECOVERY-KEY (ENTRA-BITLOCKER-KEY-OLD rows x Intune devices; add azureADDeviceId to the managed-device select), INTUNE-BASELINE-TEMPLATE-SUPERSEDED (needs the configurationPolicyTemplates fetch), DEFENDER-MDI-DC-NOT-COVERED (DEFENDER-MDI-SENSOR-UNHEALTHY rows x AD domain controllers).
- Hybrid identity (hybrid-identity.yaml): HYB-USER-SYNCED-NO-CONSISTENCY-GUID, HYB-USER-AD-PRIVILEGED-SYNCED (both need AD inventory attributes: mS-DS-ConsistencyGuid, adminCount, memberOf).

### Entries for other rule files

- workstations.yaml (cim, registry, eventlog): WS-EVT-MDM-AUTOENROLL-FAIL, WS-EVT-MDM-POLICY-ERRORS, WS-REG-MDM-AUTOENROLL, WS-REG-MDM-WINS-OVER-GP, WS-REG-LEGACY-LAPS-ENABLED, WS-REG-ESU-NOT-LICENSED, WS-REG-INSPECTION-ROOT-TRUSTED, M365-ONEDRIVE-KFM-NOT-ENFORCED, WS-DEFENDER-SCAN-STALE, WS-DEFENDER-SENSE-CLOUD-ERRORS, WS-DEFENDER-NDR-EVENT-FLOOD, WS-DEFENDER-EVT-REMEDIATION-FAILED, WS-DEFENDER-ASR-EVENTS, WS-DEFENDER-ASR-NOT-BLOCK, WS-DEFENDER-PASSIVE-NO-EDR-BLOCK, WS-DEFENDER-LOCAL-ADMIN-MERGE, WS-DEFENDER-CFA-OFF, WS-DEFENDER-SIGNATURE-UPDATE-SLOW, WS-DEFENDER-EVT-PROTECTION-CHANGED, WS-REG-SMARTSCREEN-OFF, WS-REG-OFFICE-BUILD-OLD, WS-REG-AIP-ADDIN-ENABLED (22).
- windows-server.yaml: WSRV-DEFENDER-NOT-ONBOARDED and -SENSE-STOPPED, WSRV-DEFENDER-AUTO-EXCLUSIONS-OFF, M365-APPS-SHARED-ACTIVATION-OFF, PP-GATEWAY-SERVICE-ERRORS, PP-GATEWAY-HOST-TLS-LEGACY, PP-GATEWAY-HOST-DOTNET-OLD, AIP-SCANNER-VERSION-OLD (uninstall-key values: same registry gap as above), AIP-SCANNER-EVENTLOG-ERRORS, XS-HOST-LOCAL-GROUP-MEMBER-LEAVER (with its store half) (10).
- active-directory.yaml and a domain-controller eventlog file: HYB-SYNC-CONNECTOR-ACCOUNT-MULTIPLE, HYB-SYNC-CONNECTOR-ACCOUNT-PRIVILEGED, HYB-SYNC-DOMAIN-GROUPS-UNPROTECTED, HYB-HYBRID-JOIN-SCP-MISSING, AD-EXCHANGE-SERVER-UNSUPPORTED, AD-EXCHANGE-AUTODISCOVER-SCP-STALE, HYB-SYNC-ACCOUNT-LOGON-FOREIGN-HOST, HYB-SYNC-CONNECTOR-UNSIGNED-LDAP-BIND (8).
- azure.yaml: AZURE-INTUNE-DIAGNOSTIC-SETTINGS-NONE, AIP-BYOK-KEY-UNPROTECTED (plus the Azure half of AZ-OWNER-HOLDER-STALE-OR-GUEST). certificates.yaml: M365-ENDPOINT-TLS-INTERCEPTED. sccm.yaml: SCCM-DEPLOYMENT-RETIRED-APP. obligations.yaml: D365-RELEASE-WAVE-REGRESSION-TEST, PP-GATEWAY-RECOVERY-KEY-ATTESTED. A files pack (GPO XML import, element names a guess): M365-APPS-MACROS-INTERNET-NOT-BLOCKED, M365-APPS-SECURITY-BASELINE-UNSET.

## Not in Microsoft Graph - needs another API or protocol

- Exchange Online (Exchange Online PowerShell or the Exchange admin API, read-only roles): external mail forwarding estate-wide - mailbox ForwardingSmtpAddress / ForwardingAddress, inbox rules including hidden ones, transport rules, remote-domain auto-forward, outbound spam policy auto-forwarding mode; a documented exception list becomes a threshold. Source: request; field (a no-forwarding policy with dozens of external forwards found by a manual sweep, and one approved external forward that a sweep must not break).
- Exchange Online: mailbox auditing, audit bypass, unified audit log ingestion, SMTP AUTH and modern auth settings, OWA policies, shared mailboxes with sign-in allowed, external sender tagging, DKIM, anti-malware, anti-spam and connection filter policies, Defender for Office presets. Source: cis 1.2.2, 1.3.9, 2.1.2..2.1.15, 2.4.x, 3.1.1, 6.1.x, 6.2.x, 6.3.2, 6.5.x.
- DNS (SPF, DMARC, DKIM publication for every accepted domain) - a DNS protocol runner. Source: cis 2.1.8, 2.1.9, 2.1.10.
- Purview (Security & Compliance PowerShell): DLP policies, sensitivity label policies, retention, alert policies. Source: cis 3.2.1..3.2.3, 3.3.1, 2.4.1.
- Defender XDR and Defender for Endpoint APIs (separate audience from Graph): onboarding versus inventory, sensor health, tamper protection, ASR, vulnerability exposure, Defender for Identity sensors. Graph incidents and alerts are rules now (M365-SECURITY-INCIDENT-OPEN, M365-SECURITY-ALERT-OPEN). Source: review XDR-001..XDR-016.
- Teams admin (Teams PowerShell): external access and federation, meeting policies (anonymous join, lobby, external control), app permission policies, messaging policies. Source: cis 8.1.2..8.6.1.
- SharePoint settings exposed only through SharePoint Online PowerShell: B2B integration, default link type and permission, guest link expiry, OneDrive-specific sharing level, sites with Anyone links. Source: cis 7.2.2, 7.2.7, 7.2.9..7.2.11.
- Power Platform and Dataverse (Power Platform admin API): database, log and file capacity against entitlement, audit and plug-in trace retention, DLP policies, environments; who receives the capacity alerts. Source: field (Dataverse log storage several times over entitlement and growing weekly, alerts going to one administrator's mailbox); review PP-004.
- Fabric / Power BI tenant settings (Fabric admin API). Source: cis 9.1.1..9.1.12; review PP-009.
- Entra settings with no Graph read: per-user MFA state list (per-user endpoint only, beta), restrict access to the Entra admin centre, SSPR scope, registration and notification settings, owners managing membership requests, LinkedIn connections, stay-signed-in prompt. Source: cis 5.1.2.1, 5.1.2.4, 5.1.3.3, 5.2.4.1, 5.2.4.3..5.2.4.5; review ENT-ID-022, ENT-TEN-006.
- Entra Connect server state (version, auto-upgrade, sync rules, OU scope, Connect Health alerts) - needs the server (WinRM/CIM) or the Connect Health portal. Source: review EC-001, EC-013, EC-014.
- Third-party SaaS consoles that hold Microsoft 365 data or access (backup, VPN, ITSM): admin accounts outside Entra SSO, departed administrators still holding admin or contact roles, stuck or oversized backup jobs, seat quotas. Needs each vendor's API as its own integration. Source: field (a cloud backup console with local admin logins, a departed administrator still primary contact, a backup job running far past its normal size).
- GDAP / delegated admin partner relationships seen from the customer tenant - `tenantRelationships/delegatedAdminRelationships` is a partner-side API; customer-side read is not confirmed. Source: review ADM-005.
- Microsoft 365 usage reports (`/reports/get*Detail`) return CSV unless the beta JSON format is used, and anonymise names by tenant setting. Source: review TEAMS-006, LIC-007.
- Intune: the values inside settings catalog and endpoint security policies (local administrator group policies that add but never remove, command-prompt and registry blocks that also break installers, LAPS rotation, BitLocker options, ASR rule modes), policies targeted at the wrong enrolment type, compliance coverage per group. Needs per-policy settings reads (`configurationPolicies/{id}/settings`, one level of for_each, but the setting instances are deeply nested) and joins. Done: existence and assignment per endpoint security family (INTUNE-ESEC-*), app protection data transfer, PIN and assignment (INTUNE-MAM-*), device clean-up rule (INTUNE-CLEANUP-RULE-OFF), feature-update targets (INTUNE-FEATURE-UPDATE-PROFILE-EOS). Source: review INT-019..INT-029, INT-037; field.

### Rules once the integration exists - specifications from the catalogue port

One line per check (id - what - read - condition - severity), kept as the specification the
integration work should implement first. Counts are checks of the old catalogue that wait for the
integration. Every integration is read-only by construction (Get-* and Search-* cmdlets, GET endpoints).

**exo-powershell - Exchange Online PowerShell V3 (149).** App-only certificate, Exchange.ManageAsApp
plus the View-Only Organization Management role (View-Only Audit Logs for Search-UnifiedAuditLog);
never Exchange Administrator. File `rules/exchange-online.yaml`, one query per cmdlet, rows = objects.

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
- EXO-ADMIN-AUDIT-OFF: AdminAuditLogEnabled ne true - Get-AdminAuditLogConfig; low (UnifiedAuditLogIngestionEnabled on the same object is the native form of ScubaGear MS.EXO.17.1).
- EXO-AUDIT-SAMPLE-MISSING: Search-UnifiedAuditLog -ResultSize 1 for each core RecordType over the last 24-72 h returns nothing; count none per record type; medium.
- EXO-AUDIT-ROLE-HOLDERS: Get-ManagementRoleAssignment -Role 'View-Only Audit Logs','Audit Logs' RoleAssignee outside the expected role groups; low.

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
- EXO-CALENDAR-DEFAULT-PERMISSION-WIDE (from M365-CALENDAR-DEFAULT-PERMISSION-WIDE): Default or Anonymous calendar entry above free/busy (AvailabilityOnly) - Get-EXOMailboxFolderPermission on the Calendar folder; medium.
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
- EXO-AUTOREPLY-STALE: AutoReplyState Scheduled with EndTime in the past, or Enabled for more than N days on a shared or listed public mailbox (hidden-rule and text-hash variant of the proposal M365-MAILBOX-AUTOREPLY-STALE) - Get-MailboxAutoReplyConfiguration; medium.
- EXO-BOOKINGS-OPEN: BookingsEnabled with BookingsMailboxCreationEnabled true on the default OWA policy - Get-OrganizationConfig, Get-OwaMailboxPolicy; low.
- EXO-ORG-APP-REVIEW: centrally deployed add-ins - Get-App -OrganizationApp DisplayName, ProviderName, Enabled, DefaultStateForUser; each any (review list); low.
- EXO-CUSTOMER-LOCKBOX-OFF: CustomerLockBoxEnabled ne true - Get-OrganizationConfig; low (native form of the Maester CIS 1.3.6 test).

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
- EXO-FOLDER-DEFAULT-PERMISSION-WIDE: Default/Anonymous on Inbox above None - Get-EXOMailboxFolderPermission; medium.
- EXO-MAILBOX-FORWARDING-SET: ForwardingSmtpAddress/ForwardingAddress set outside the allow pattern - Get-EXOMailbox; high.
- EXO-INBOX-RULE-HIDDEN-FORWARD: hidden or error-state rules that forward/redirect/delete (Graph misses hidden) - Get-InboxRule -IncludeHidden; high.
- EXO-FORWARD-INTO-OTHER-USER: mailbox forwarding or an inbox rule ForwardTo/RedirectTo into another person's internal mailbox - Get-Mailbox, Get-InboxRule; medium.
- EXO-ADMIN-MAILBOX-FORWARDING: admin-pattern accounts with forwarding or DL membership - Get-EXOMailbox, Get-DistributionGroupMember; medium.
- EXO-POWERSHELL-OPEN-TO-USERS: RemotePowerShellEnabled true on non-admin users - Get-User; low.
- EXO-SENSITIVE-MAILBOX-NO-EXCLUSIVE-SCOPE: VIP mailboxes not covered by an exclusive management scope - Get-ManagementScope -Exclusive, Get-User -IsVIP; low.
- EXO-ROLE-MAILBOX-DELEGATE-RIGHTS-MISSING: role mailbox delegate without FullAccess and SendAs - per threshold list; low.
- EXO-SHARED-MAILBOX-NO-ENABLED-DELEGATE: shared mailbox whose FullAccess holders are all disabled or absent - Get-EXOMailboxPermission + users join; low.
- EXO-SHARED-MAILBOX-SIGNIN-ENABLED: Get-EXOMailbox -RecipientTypeDetails SharedMailbox joined in the store to Entra users with accountEnabled 1; medium (native form of CIS 1.2.2; also the proposals M365-SHARED-MAILBOX-SIGNIN-ENABLED and M365-RESOURCE-MAILBOX-SIGNIN-RECENT).
- EXO-DISABLED-USER-MAILBOX-OPEN: disabled account whose mailbox is still a UserMailbox with any CAS protocol enabled - Get-CASMailbox joined with Entra accountEnabled; medium (also the proposal M365-MAILBOX-USER-DISABLED-NOT-CONVERTED).
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
- EXO-ADDRESS-ONMICROSOFT-OR-FOREIGN-DOMAIN: full-recipient variant of ENTRA-USER-PRIMARY-ADDRESS-ONMICROSOFT (contacts, mail users, public folders) - Get-EXORecipient; low.
- EXO-CONTACT-STALE: visible mail contact in no list, unchanged > 3 years, or used as a forwarding target - Get-MailContact, Get-MailUser; low.
- EXO-ADMIN-MAILBOX-VISIBLE-IN-GAL: admin/service pattern recipients with HiddenFromAddressListsEnabled false - Get-EXORecipient; low.
- EXO-MIGRATION-LEFTOVERS: endpoints for retired servers, duplicate MailUser for a cloud mailbox - Get-MigrationEndpoint, Get-EXORecipient; low.
- EXO-CONFIG-EXPORT: no rule - the scan's row_seen of the connector, rule, domain and policy queries is the dated configuration export.

Unified audit log, SharePoint and OneDrive (Search-UnifiedAuditLog, View-Only Audit Logs; last N days)
- UAL-SPO-INGESTION-GAP: zero records for a SharePoint, OneDrive or Teams record type in 24 h; medium.
- UAL-SPO-LABEL-DOWNGRADE: label removed or downgraded on a file; low.
- UAL-SPO-ANYONE-LINK-LIVE: anonymous links created and not removed in 90 days; high when the tenant forbids them.
- UAL-SPO-EXTERNAL-SHARE-SPIKE: external shares per user over threshold or over the baseline; medium.
- UAL-SPO-MASS-FILE-ACTIVITY: downloads, deletions or renames per user per day over threshold; high.
- UAL-SPO-BROAD-PERMISSION-GRANT: Everyone claims or site-admin grants added in 7 days; medium.

Defender for Office 365 policies (Get-* cmdlets; where ScubaGear tests the same control the imported row already fires)
- MDO-PRESET-NOT-ALL-USERS: no Enabled Standard or Strict rule whose scope covers all accepted domains - Get-EOPProtectionPolicyRule / Get-ATPProtectionPolicyRule; high.
- MDO-PRIORITY-NOT-STRICT: priority accounts (Get-User -IsVIP) not in the Strict preset scope; medium.
- MDO-PRIORITY-PROTECTION-OFF: EnablePriorityAccountProtection false, or a priority account that is disabled - Get-EmailTenantSettings; medium.
- MDO-ANTIPHISH-WEAK: targeted user/domain protection off, mailbox intelligence protection off, HonorDmarcPolicy false, PhishThresholdLevel lt 2, safety tips off - Get-AntiPhishPolicy; medium.
- MDO-ANTISPAM-WEAK: HighConfidencePhishAction ne Quarantine, BulkThreshold gt 6, QuarantineRetentionPeriod lt 30, ZAP off - Get-HostedContentFilterPolicy; medium.
- MDO-ANTISPAM-ALLOWED-SENDERS: AllowedSenderDomains or AllowedSenders not empty; medium.
- MDO-CONNECTION-FILTER-ALLOW: IPAllowList not empty or EnableSafeList true - Get-HostedConnectionFilterPolicy; medium.
- MDO-OUTBOUND-SPAM-NO-NOTIFY: NotifyOutboundSpam false or recipients not a monitored mailbox (store join with Entra users for disabled recipients) - Get-HostedOutboundSpamFilterPolicy; low.
- MDO-MALWARE-FILTER-WEAK: EnableFileFilter false, FileTypes size-lt threshold, ZapEnabled false, admin notifications off - Get-MalwareFilterPolicy; medium.
- MDO-SAFE-ATTACHMENTS-NOT-ALL: no enabled Block policy for all recipients; EnableATPForSPOTeamsODB false or EnableSafeDocs false - Get-SafeAttachmentPolicy/Rule, Get-AtpPolicyForO365; medium.
- MDO-SAFE-LINKS-WEAK: email/Teams/Office off, AllowClickThrough true, TrackClicks false, DoNotRewriteUrls size-gt threshold - Get-SafeLinksPolicy; medium.
- MDO-TEAMS-ZAP-OFF: ZapEnabled false - Get-TeamsProtectionPolicy; low.
- MDO-QUARANTINE-USER-RELEASE-HIGH-RISK: PermissionToRelease on the tag used for high-confidence phish or malware - Get-QuarantinePolicy; medium.
- MDO-TABL-ALLOW-STALE: allow entries with no ExpirationDate and LastUsedDate age-gt 45, or a consumer/own domain - Get-TenantAllowBlockListItems -Allow; medium.
- MDO-SPOOF-ALLOW-UNKNOWN: Action Allow with unknown infrastructure - Get-SpoofIntelligenceInsight; medium (review list).
- MDO-ADVANCED-DELIVERY-BROAD: SecOps/phish-sim override rules beyond the threshold lists; medium.
- MDO-REPORT-SUBMISSION-OFF: EnableReportToMicrosoft false or no reporting mailbox - Get-ReportSubmissionPolicy; low.
- MDO-PROTECTION-RULE-EXCLUSIONS: any ExceptIf* on protection rules naming a priority account; medium.
- MDO-ARC-SEALER-MISSING: ArcTrustedSealers empty while an inbound gateway connector exists - Get-ArcConfig; low.
- MDO-QUARANTINE-RELEASE-REQUESTS-OLD: ReleaseStatus RequestedRelease older than 3 days - Get-QuarantineMessage; low.
- MDO-ROLEGROUP-RELEASE-RIGHTS-BROAD: members of the hygiene/quarantine role groups beyond threshold or disabled - Get-RoleGroupMember; medium.
- MDO-POLICY-CHANGE-RECENT: Set-*/New-* operations of the policies above in 7 days - Search-UnifiedAuditLog; medium (review list).
- MDO-POLICY-SCOPE-UNLICENSED: recipients in Safe Links/Safe Attachments scope without the Defender for Office service plan (store join with Entra users); medium.

**purview-powershell - Security & Compliance PowerShell and the protection service (31).** Connect-IPPSSession hosted in-process, app-only certificate with a read-only compliance role; the AIPService module for the protection service.
- PURVIEW-AUDIT-RETENTION-SHORT: no audit retention policy keeps the core workloads' records for a year - Get-UnifiedAuditLogRetentionPolicy Enabled, RecordTypes, RetentionDuration; must-exist per core record type; medium.
- PURVIEW-LABEL-POLICY-NONE: no published label policy with a default label and downgrade justification - Get-LabelPolicy Mode, Settings (defaultlabelid, requiredowngradejustification); must-exist; medium.
- PURVIEW-DLP-POLICY-NOT-ENFORCED: no DLP policy in Mode Enable covering mail, sites, OneDrive and Teams with the sensitive-information types the tenant names in a threshold - Get-DlpCompliancePolicy, Get-DlpComplianceRule; must-exist; medium.
- PURVIEW-DLP-COPILOT-NONE: Copilot SKU present and no enabled DLP policy with the Copilot location - Get-DlpCompliancePolicy; must-exist; low.
- PURVIEW-RETENTION-LABEL-NONE: no retention label published or auto-applied - Get-ComplianceTag, Get-RetentionCompliancePolicy; must-exist; low.
- PURVIEW-ROLEGROUP-MEMBER-REVIEW: members of the compliance, records, information-protection and eDiscovery role groups - Get-RoleGroupMember; each any (review list), with a disabled-member variant joined to Entra; medium.
- PURVIEW-RETENTION-WORKLOAD-UNCOVERED: a workload (mail, sites, OneDrive, groups, Teams channels and chats) with no enabled retention policy - Get-RetentionCompliancePolicy -DistributionDetail; must-exist per workload; high.
- PURVIEW-RETENTION-SPO-NOT-ALL: no enabled retention policy with SharePoint and OneDrive locations set to All and distribution status success; high.
- PURVIEW-RETENTION-TEAMS-NONE: no enabled retention policy covering Teams channel, chat and private-channel messages; medium.
- PURVIEW-POLICY-DISTRIBUTION-ERROR: retention, label or DLP policy whose DistributionStatus is Error, or Pending for longer than a week - Get-RetentionCompliancePolicy, Get-DlpCompliancePolicy, Get-LabelPolicy; each; medium.
- PURVIEW-ALERT-POLICY-ROUTING: default alert policies disabled or notifying an address outside the monitored list - Get-ProtectionAlert Disabled, NotifyUser, Severity; each; high.
- PURVIEW-ALERT-POLICY-OFF-OR-UNROUTED: built-in SharePoint/OneDrive alert policies disabled or notifying a disabled or personal mailbox; medium.
- PURVIEW-AUDIT-ROLE-HOLDERS: members of the audit reader / audit manager role groups - Get-RoleGroup, Get-RoleGroupMember; review list; low.
- AIP-PROTECTION-SERVICE-DISABLED: Get-AipService status ne Enabled; high.
- AIP-SUPER-USERS-ENABLED: Get-AipServiceSuperUserFeature Enabled with super users gt 2; high.
- AIP-RMS-ADMINS-STALE: Get-AipServiceRoleBasedAdministrator entries not current users (store join with Entra); medium.
- AIP-ONBOARDING-CONTROL-UNEXPECTED: Get-AipServiceOnboardingControlPolicy differs from the recorded decision; low.
- AIP-TENANT-KEY-BYOK-UNDOCUMENTED: Get-AipServiceKeys topology BYOK without an attestation row; medium.
- AIP-DOCUMENT-TRACKING-STATE: Get-AipServiceDocumentTrackingFeature; low (record).
- AIP-LABEL-NO-LOCALISED-NAME: Get-Label LocaleSettings missing the organisation's language (threshold); medium.
- AIP-LABEL-POLICY-NOT-ALL-USERS: Get-LabelPolicy not published to all, no default label, no justification requirement; medium.
- AIP-LABEL-ENCRYPTION-ANY-AUTHENTICATED: Get-Label EncryptionRightsDefinitions grant to AuthenticatedUsers on the highest labels, or EncryptionOfflineAccessDays gt 7; medium.
- AIP-SIT-JURISDICTION-UNUSED: the jurisdiction's identity/bank/health sensitive information types (threshold) absent from every scanner, auto-labelling and DLP rule; medium.
- AIP-AUTOLABEL-POLICY-NONE: Get-AutoSensitivityLabelPolicy none, or all in simulation for more than N days; low.
- AIP-DLP-NOT-LABEL-BASED: Get-DlpComplianceRule with no label condition where labels exist; low.
- AIP-LABEL-CHANGE-RECENT: Search-UnifiedAuditLog label and label-policy operations 30 days; medium (review list).
- AIP-LABEL-ACTIVITY-ABSENT: Export-ActivityExplorerData 30 days returns no label activity; medium.
- AIP-LABEL-DOWNGRADE-NO-JUSTIFICATION: Export-ActivityExplorerData removal/downgrade without justification text; medium.
- AIP-ALERT-MASS-DOWNGRADE-MISSING: Get-ProtectionAlert has no enabled alert on label removal with a monitored recipient; medium.
- AIP-FEATURE-UNLICENSED: auto-labelling or other premium features configured while users lack the service plan (store join with subscribedSkus / user plans); medium.
- DEFENDER-NOTIFICATION-RECIPIENT-DEAD: Get-ProtectionAlert NotifyUser addresses joined to Entra users: disabled, missing or personal-admin accounts; medium.

**spo-admin-rest - SharePoint tenant and site administration (41).** The tenant admin REST behind Get-SPOTenant / Get-SPOSite / Get-SPOUser and per-site `_api/web`; certificate app with the SharePoint-resource tenant permission (an accepted exception to ENTRA-APPPERM-SHAREPOINT-FULL-CONTROL).
- SPO-ADMIN-POOL-STORAGE-HIGH: pooled storage used over quota percentage; StorageQuota vs sum of site StorageUsageCurrent; gt 85 % medium, 90 % high, 98 % critical.
- SPO-ADMIN-POOL-GROWTH-FAST: projected months to full under 12, from run-over-run used storage.
- SPO-ADMIN-SITE-NEAR-QUOTA: site StorageUsageCurrent / StorageQuota ge 95 %; medium.
- SPO-ADMIN-VERSION-LIMIT-NONE: no tenant version policy (EnableAutoExpirationVersionTrim false and MajorVersionLimit unset); low.
- SPO-ADMIN-SITE-LOCKED: site LockState in [ReadOnly, NoAccess] and not in an archive allow list; medium.
- SPO-ADMIN-LEGACY-APP-AUTH: DisableCustomAppAuthentication false; medium.
- SPO-ADMIN-INFOPATH-LIBRARY: per active site, list BaseTemplate eq 115; medium.
- SPO-ADMIN-SITE-SHARING-WIDER-THAN-TENANT: site SharingCapability wider than the tenant decision; medium (Anyone on a site = high).
- SPO-ADMIN-ONEDRIVE-SHARING-OPEN: OneDriveSharingCapability eq ExternalUserAndGuestSharing; medium.
- SPO-ADMIN-DEFAULT-LINK-TYPE-WIDE: DefaultSharingLinkType eq AnonymousAccess (or Internal when the decision is Direct); medium.
- SPO-ADMIN-DEFAULT-LINK-EDIT: DefaultLinkPermission eq Edit; low.
- SPO-ADMIN-ANYONE-LINK-NO-EXPIRY: RequireAnonymousLinksExpireInDays unset or gt 30 while Anyone sharing is allowed; medium.
- SPO-ADMIN-ANYONE-LINK-EDIT: File/FolderAnonymousLinkType eq Edit; medium.
- SPO-ADMIN-GUEST-CODE-REAUTH-LONG: EmailAttestationRequired false or EmailAttestationReAuthDays gt 15; medium.
- SPO-ADMIN-GUEST-NO-EXPIRY: ExternalUserExpirationRequired false or ExternalUserExpireInDays gt 90; medium.
- SPO-ADMIN-SHARE-GROUP-RESTRICTION-NONE: no WhoCanShare group restriction set; low.
- SPO-ADMIN-B2B-INTEGRATION-OFF: EnableAzureADB2BIntegration false; medium.
- SPO-ADMIN-INFECTED-DOWNLOAD-ALLOWED: DisallowInfectedFileDownload false; medium.
- SPO-ADMIN-CUSTOM-SCRIPT-ALLOWED: site DenyAddAndCustomizePages ne Enabled on OneDrives and self-service sites, or DelayDenyAddAndCustomizePagesEnforcement true; medium.
- SPO-ADMIN-OWNER-NOTIFICATIONS-OFF: any of NotifyOwnersWhenInvitationsAccepted, NotifyOwnersWhenItemsReshared, OwnerAnonymousNotification false; low.
- SPO-ADMIN-PEOPLE-PICKER-OPEN: ShowPeoplePickerSuggestionsForGuestUsers true or ShowEveryoneClaim / ShowAllUsersClaim true; medium.
- SPO-ADMIN-LABEL-INTEGRATION-OFF: EnableAIPIntegration false; medium.
- SPO-ADMIN-SITE-UNLABELLED: site SensitivityLabel empty on active non-group sites; low.
- SPO-ADMIN-NEW-FILES-NOT-SENSITIVE: MarkNewFilesSensitiveByDefault ne BlockExternalSharing while a DLP policy covers SharePoint; low.
- SPO-ADMIN-RESTRICTED-SEARCH-UNDECIDED: restricted search / restricted access control state against the tenant's recorded decision when a Copilot SKU is present; medium.
- SPO-ADMIN-SENSITIVE-SITE-NO-RAC: listed sensitive sites without RestrictedAccessControl; low.
- SPO-ADMIN-ONEDRIVE-QUOTA-EXCEPTION: personal site StorageQuota ne the tenant default; low.
- SPO-ADMIN-NONGROUP-SITE-NO-ADMIN: non-group site with no enabled site collection admin; medium.
- SPO-ADMIN-EVERYONE-CLAIM-GRANTED: site user claims matching Everyone / Everyone-except-external; high on labelled-confidential sites.
- SPO-ADMIN-SITE-ADMIN-DISABLED: site collection admin whose account is disabled; low.
- SPO-ADMIN-ONEDRIVE-EXTRA-ADMIN: personal site with a non-owner site admin older than 90 days; medium.
- SPO-ADMIN-SPFX-PERMISSION-REQUEST-PENDING: pending SPFx permission requests; low.
- SPO-ADMIN-ACCESS-REQUEST-EMAIL-DEAD: site RequestAccessEmail set to a disabled or missing account; low.
- SPO-ADMIN-IP-ENFORCEMENT-UNDECIDED: IPAddressEnforcement state against the recorded decision; info.
- SPO-ADMIN-SENSITIVE-SITE-DEVICE-POLICY: listed sensitive sites without ConditionalAccessPolicy limited/blocked or an authentication context; low.
- SPO-ADMIN-LIBRARY-VERSIONING-OFF: per site, document library EnableVersioning false or MajorVersionLimit lt 100; medium.
- SPO-ADMIN-UNIQUE-PERMISSIONS-HEAVY: library with more than N uniquely permissioned items; low.
- SPO-ADMIN-LIBRARY-TOO-LARGE: list ItemCount over the sync or view threshold; low.
- SPO-ADMIN-DELETED-SITE-NEAR-PURGE: deleted site with DaysRemaining lt 14; low.
- SPO-ADMIN-EXTRA-STORAGE-MISMATCH: extra-storage SKU units against pool usage; low.
- SPO-ADMIN-SAM-FEATURE-UNLICENSED: RestrictedAccessControl / restricted search in use without a SharePoint Advanced Management or Copilot SKU; low.

**teams-powershell - Teams policies (25).** The MicrosoftTeams module (Get-Cs* policies and configurations, Get-CsOnlineUser) hosted in-process, certificate app.
- TEAMS-UPGRADE-NOT-TEAMS-ONLY: global upgrade policy mode ne TeamsOnly or any user not TeamsOnly; low.
- TEAMS-FEDERATION-OPEN: AllowFederatedUsers true with no allowed-domain list; medium.
- TEAMS-CONSUMER-ACCESS-ON: AllowTeamsConsumer or AllowTeamsConsumerInbound true; medium.
- TEAMS-TRIAL-TENANT-ACCESS-OPEN: ExternalAccessWithTrialTenants ne Blocked or AllowPublicUsers true; medium.
- TEAMS-GUEST-CAPABILITIES-WIDE: guest private calling, Meet Now or message deletion allowed; medium.
- TEAMS-EMAIL-INTO-CHANNEL-ON: AllowEmailIntoChannel true without a restricted sender list; low.
- TEAMS-THIRD-PARTY-STORAGE-ON: any of the cloud-storage switches true; low.
- TEAMS-ANONYMOUS-JOIN-UNDECIDED: DisableAnonymousJoin against the recorded decision; low.
- TEAMS-MEETING-POLICY-ANON-START: AllowAnonymousUsersToStartMeeting true in any policy; medium.
- TEAMS-MEETING-POLICY-LOBBY-OPEN: AutoAdmittedUsers eq Everyone in any policy; medium.
- TEAMS-MEETING-POLICY-PSTN-BYPASS: AllowPSTNUsersToBypassLobby true; low.
- TEAMS-MEETING-POLICY-ANON-CHAT: MeetingChatEnabledType eq Enabled; low.
- TEAMS-MEETING-POLICY-EVERYONE-PRESENTS: DesignatedPresenterRoleMode eq EveryoneUserOverride; low.
- TEAMS-MEETING-POLICY-EXTERNAL-CONTROL: AllowExternalParticipantGiveRequestControl true; medium.
- TEAMS-MEETING-POLICY-UNTRUSTED-CHAT: AllowExternalNonTrustedMeetingChat true; low.
- TEAMS-MEETING-POLICY-RECORDING-DEFAULT: global AllowCloudRecording true, no expiry days, or storage outside region; low.
- TEAMS-CUSTOM-POLICY-WEAKER-THAN-GLOBAL: any custom meeting/messaging policy weaker than Global on the security properties; medium (compare each property to a fixed value, or field-to-field across rows).
- TEAMS-USER-REPORTING-OFF: AllowSecurityEndUserReporting false; low.
- TEAMS-SECURITY-REPORTING-OFF: Get-CsTeamsMessagingPolicy AllowSecurityEndUserReporting ne true on the global policy, with EXO Get-ReportSubmissionPolicy ReportChatMessageEnabled; low.
- TEAMS-SIDELOADING-ALLOWED: AllowSideLoading true in a policy not assigned to a developer group; low.
- TEAMS-CHANNEL-EXTERNAL-SHARING-ON: AllowChannelSharingToExternalUser or AllowUserToParticipateInExternalSharedChannel true without a partner decision; low.
- TEAMS-EVENTS-PUBLIC-BY-DEFAULT: global events policy EventAccessType eq Everyone; low.
- TEAMS-VOICE-INVENTORY: PSTN gateways, voice routes and enterprise-voice users as an info row; info.
- TEAMS-ANON-APP-INTERACTION-ON: DisableAppInteractionForAnonymousUsers false; low.
- TEAMS-LARGE-TEAM-UNGOVERNED: team over N members with fewer than two owners or no moderation on the general channel; low.

**power-platform-admin-api - Power Platform administration (59), and powerbi-admin-api (34).** Power Platform API and the BAP, Flow, PowerApps, Power BI and Fabric admin REST APIs; an app registered as a Power Platform management application, and for Power BI / Fabric a member of the security group allowed to use the read-only admin APIs. `listTenantSettings` is a read-only POST (runner exception needed). The 93 one-line specifications are in docs/proposals/catalog-microsoft-cloud.md, section "Rules once power-platform-admin-api exists" (capacity and health, tenant settings, data policies and isolation, environments, apps flows and connections, Power BI / Fabric).

**dataverse-web-api - Dataverse environments and Dynamics 365 (53).** `GET /api/data/v9.2/...` per environment, an application user with a custom read-only security role in each environment. The one-line specifications (audit and logging, health, identity and access, customisation lifecycle) are in the proposal's section "Rules once dataverse-web-api exists".

**mde-api - Defender for Endpoint (13).** `https://api.securitycenter.microsoft.com/api`, client credentials with Machine.Read.All, Vulnerability.Read.All, SecurityRecommendation.Read.All, Score.Read.All, Alert.Read.All (indicators have no read-only role).
- MDE-SENSOR-IMPAIRED: device with healthStatus in (ImpairedCommunication, NoSensorData, NoSensorDataImpairedCommunication) seen in 7 days - /machines; high.
- MDE-DEVICE-CAN-BE-ONBOARDED: discovered device with onboardingStatus eq CanBeOnboarded - /machines; medium.
- MDE-VULN-EXPLOITABLE-OLD: vulnerability with publicExploit true, severity Critical, exposed machines gt 0, publishedOn age-gt 30 - /vulnerabilities; high.
- MDE-EXPOSURE-SCORE-HIGH: /exposureScore score gt threshold; low.
- MDE-RECOMMENDATION-TOP-OPEN: /recommendations status Active, severityScore ge threshold, exposedMachinesCount gt 0; low.
- MDE-INDICATOR-ALLOW-STALE: /indicators action eq Allowed and expirationTime absent or past; medium.
- MDE-BASELINE-PROFILE-NONE: /baselineProfiles count none; low.
- MDE-ACTION-PENDING: /machineactions status Pending older than a day; medium.
- MDE-ACTION-UNEXPLAINED: /machineactions in 7 days with requestorComment empty; low.
- MDE-RESPONSE-DRILL-STALE: no succeeded isolate/scan/collect action on the test machine (threshold id) in 365 days; low.
- MDE-DEVICE-INACTIVE-RECORD: /machines healthStatus eq Inactive and lastSeen age-gt 30; low.
- MDE-DEVICE-UNTAGGED-SERVER: osPlatform match WindowsServer and machineTags empty or the default device group; low.
- MDE-SERVER-LICENCE-SHORTFALL: onboarded servers gt the server-licence units from subscribedSkus (store join); medium.

**defender-xdr-api - advanced hunting and Defender for Cloud Apps (12).** Hunting is a POST (`/security/runHuntingQuery`); needs a read-only hunting runner. Cloud Apps REST is GET-able with its own token.
- XDR-EMAIL-THREAT-DELIVERED: EmailEvents 7 days, ThreatTypes Phish or Malware delivered to the inbox; count per recipient; medium.
- XDR-EMAIL-SPOOF-OWN-DOMAIN-DELIVERED: inbound mail from an own accepted domain failing DMARC delivered to the inbox; medium.
- XDR-URL-CLICK-ALLOWED-MALICIOUS: UrlClickEvents ClickAllowed on Phish/Malware; high.
- XDR-POST-DELIVERY-ACTION-FAILED: EmailPostDeliveryEvents ActionResult ne Success; medium.
- XDR-IDENTITY-NTLMV1-OR-CLEARTEXT-LDAP: IdentityLogonEvents NTLMv1 or clear-text LDAP binds; medium; review list by source host.
- XDR-IDENTITY-HONEYTOKEN-MISSING: IdentityInfo Tags has no Honeytoken; low.
- XDR-TAMPERING-ATTEMPT: DeviceEvents TamperingAttempt, DeviceRegistryEvents on the exclusions key; high.
- XDR-ADMIN-TOOL-REMEDIATED: DeviceFileEvents FileDeleted by the engine under an administration path (threshold); low.
- MDCA-M365-CONNECTOR-STALE: newest activity from the Microsoft 365 connector older than 2 h; medium.
- MDCA-DISCOVERED-APP-RISKY-UNSANCTIONED: discovered app with risk score le 5, users gt threshold, neither sanctioned nor unsanctioned; medium.
- MDCA-ANOMALY-POLICY-DISABLED: built-in anomaly policy with enabled false; medium.
- M365-APPS-PERPETUAL-OFFICE-PRESENT: software inventory rows of a perpetual Office release past end of support; count some; high (or the SCCM inventory path).

**winrm-powershell - read-only remoting to named servers.** A fixed, signed, read-only script on the host returning objects: the sync engine's own cmdlets (Get-ADSyncScheduler, -Connector, -ConnectorStatistics, -RunProfileResult, -Rule, -GlobalSettings, -AutoUpgrade, -AADPasswordSyncConfiguration) for scheduler, connector, filtering, rule and run-history health and the auto-upgrade state; the information-protection scanner's cmdlets (content-scan jobs, repository errors, incremental-scan setting, repository list against the share inventory); `Get-Acl` on directory objects (the ldap runner refuses security descriptors).

**admin-center-export - portal-only reports through the file protocol (4).**
- ONEDRIVE-SYNC-HEALTH-ERRORS: devices with sync errors over N percent, or any error type over N devices; low.
- ONEDRIVE-SYNC-CLIENT-OLD: devices on a sync build older than six months; low.
- TEAMS-CALL-QUALITY-POOR: poor-stream rate over target overall or per building; low.
- ONEDRIVE-ACCESS-DELEGATION-OFF: manager access or secondary owner not configured; medium.

**Others.** mscommerce-api (1): M365-SELF-SERVICE-PURCHASE-ALLOWED - a product whose self-service purchase policy is not Disabled; medium. Teams Rooms Pro management API (2): M365-TEAMS-ROOM-SOFTWARE-OUTDATED and M365-TEAMS-ROOM-UNHEALTHY, after the Graph teamworkDevice API's deprecation. dns-resolver, graph-export-jobs (the Intune reports, POST then download), keepit-api and azure-devops-api as listed in the proposal's "Integrations to add".

## Proposed and not implemented, by decision

- ENTRA-AUTHZ-MSOL-POWERSHELL-ALLOWED (authorizationPolicy.blockMsolPowerShell): the setting guards the MSOnline and AzureAD PowerShell modules, which Microsoft retired in 2025; a finding would point at a path that no longer works. Source: proposal.

## Graph permissions

The integration should be an app registration with these **application** permissions, all read-only,
admin-consented, signed in with a certificate. Delegated use works with the same scopes as delegated
permissions, but the signed-in admin also needs a reader role (Global Reader covers most; Security
Reader for Identity Protection; PIM reads need the role active), and role-gated reads can come back
partial without an error - prefer application permissions.

### rules/entra.yaml

| Endpoint (GET) | Rules | Application permission |
|---|---|---|
| /roleManagement/directory/roleAssignments (+ $expand=principal) | ENTRA-ROLE-GA-*, -PRA-*, -GUEST-, -DISABLED-, -SYNCED-, -LICENSED-, -SERVICE-PRINCIPAL- | RoleManagement.Read.Directory, plus Directory.Read.All so the expanded principals carry their properties |
| /roleManagement/directory/roleAssignmentScheduleInstances | ENTRA-ROLE-PERMANENT-TIER0 | RoleAssignmentSchedule.Read.Directory (or RoleManagement.Read.Directory) |
| /roleManagement/directory/roleEligibilityScheduleInstances, /roleEligibilitySchedules | ENTRA-ROLE-GA-ELIGIBLE-TOO-MANY, ENTRA-ROLE-ELIGIBLE-NO-END | RoleEligibilitySchedule.Read.Directory (or RoleManagement.Read.Directory) |
| /policies/roleManagementPolicyAssignments | ENTRA-PIM-NO-APPROVAL | RoleManagementPolicy.Read.Directory |
| beta /identityGovernance/roleManagementAlerts/alerts | ENTRA-PIM-ALERT-ACTIVE | RoleManagementAlert.Read.Directory |
| /roleManagement/directory/roleDefinitions?$filter=isBuiltIn eq false | ENTRA-ROLE-CUSTOM-DANGEROUS-ACTIONS | RoleManagement.Read.Directory |
| /identity/conditionalAccess/policies, /namedLocations | ENTRA-CA-*, ENTRA-NAMEDLOC-* | Policy.Read.All |
| /policies/identitySecurityDefaultsEnforcementPolicy, /authorizationPolicy, /authenticationMethodsPolicy (v1.0 and beta), /authenticationStrengthPolicies, /adminConsentRequestPolicy, /defaultAppManagementPolicy, /tokenLifetimePolicies, /authenticationFlowsPolicy, /crossTenantAccessPolicy/default | ENTRA-SECURITY-DEFAULTS-OFF, ENTRA-AUTHZ-*, ENTRA-AUTHM-*, ENTRA-AUTHSTRENGTH-CUSTOM-WEAK, ENTRA-CONSENT-WORKFLOW-OFF, ENTRA-APPPOLICY-*, ENTRA-TOKEN-LIFETIME-CUSTOM, ENTRA-SELF-SERVICE-SIGNUP-ON, ENTRA-XTAP-* | Policy.Read.All |
| /policies/permissionGrantPolicies | ENTRA-PERMISSION-GRANT-POLICY-CUSTOM | Policy.Read.PermissionGrant |
| /policies/deviceRegistrationPolicy | ENTRA-DEVREG-* | Policy.Read.DeviceConfiguration |
| /reports/authenticationMethods/userRegistrationDetails | ENTRA-MFA-* | AuditLog.Read.All |
| /users with signInActivity (user inventory) | ENTRA-USER-INACTIVE, ENTRA-GUEST-INACTIVE, ENTRA-USER-*-SIGNIN-ATTEMPTS, ENTRA-USER-SYNCED-NO-SID, ENTRA-USER-EXTERNAL-MEMBER, ENTRA-GUEST-CONSUMER-DOMAIN | User.Read.All + AuditLog.Read.All |
| /users (hygiene attributes, $expand=appRoleAssignments, guests $expand=sponsors) | ENTRA-GUEST-INVITE-PENDING, ENTRA-USER-WEAK-PASSWORD-ALLOWED, ENTRA-USER-CLOUD-PASSWORD-OLD, ENTRA-USER-DISABLED-PASSWORD-RESET, ENTRA-USER-ENABLED-IN-LEAVER-OU, ENTRA-SYNC-PROVISIONING-ERROR, ENTRA-USER-DISABLED-APP-ASSIGNED, ENTRA-GUEST-NO-SPONSOR | User.Read.All |
| /identityProtection/riskyUsers | ENTRA-RISKY-USER-OPEN | IdentityRiskyUser.Read.All |
| /identityProtection/riskyServicePrincipals | ENTRA-SP-RISKY | IdentityRiskyServicePrincipal.Read.All (needs Workload ID Premium) |
| /applications (+ $expand=owners with nested select, $expand=federatedIdentityCredentials), /servicePrincipals, /servicePrincipals(appId=...)/appRoleAssignedTo for Graph, Exchange Online and SharePoint Online | ENTRA-APP-*, ENTRA-SP-*, ENTRA-APPPERM-* | Application.Read.All (owners' accountEnabled and userType: User.Read.All, already granted) |
| /servicePrincipals/{id}/synchronization/jobs (for_each over enterprise apps) | ENTRA-PROVISIONING-JOB-* | Synchronization.Read.All (403 without it: the rules record unknown) |
| /auditLogs/provisioning | ENTRA-PROVISIONING-*-RECENT | AuditLog.Read.All + Directory.Read.All |
| /auditLogs/signIns | ENTRA-SIGNIN-* | AuditLog.Read.All (Entra ID P1) |
| /auditLogs/directoryAudits | ENTRA-AUDIT-* | AuditLog.Read.All |
| /identity/customAuthenticationExtensions | ENTRA-CUSTOM-AUTH-EXTENSION-PRESENT | CustomAuthenticationExtension.Read.All |
| /directory/administrativeUnits | ENTRA-AU-NO-RESTRICTED-MANAGEMENT | AdministrativeUnit.Read.All (or Directory.Read.All) |
| /identityGovernance/lifecycleWorkflows/workflows | ENTRA-LIFECYCLE-NO-LEAVER-WORKFLOW | LifecycleWorkflows.Read.All (needs Entra ID Governance) |
| /domains (same query as m365.yaml) | ENTRA-DOMAIN-FEDERATED | Domain.Read.All |
| /oauth2PermissionGrants | ENTRA-CONSENT-TENANT-WIDE-BROAD, ENTRA-CONSENT-USER-HIGH-RISK | DelegatedPermissionGrant.Read.All (or Directory.Read.All) |
| /groups (+ owners / members / appRoleAssignments expand), /groupLifecyclePolicies | ENTRA-GROUP-*, ENTRA-ROLEGROUP-* | GroupMember.Read.All (Group.Read.All also works); a group's appRoleAssignments need Directory.Read.All (already granted) |
| /devices | ENTRA-DEVICE-* | Device.Read.All |
| /organization (v1.0 and beta) | ENTRA-SYNC-STALE, ENTRA-SYNC-PASSWORD-HASH-STALE, ENTRA-TENANT-NO-* | Organization.Read.All |
| /directory/onPremisesSynchronization | ENTRA-SYNC-PASSWORD-HASH-OFF, ENTRA-SYNC-HARD-MATCH-TAKEOVER-OPEN | OnPremDirectorySynchronization.Read.All |
| /identityGovernance/accessReviews/definitions | ENTRA-ACCESS-REVIEWS-NONE | AccessReview.Read.All |
| beta /directory/recommendations | ENTRA-RECOMMENDATION-ACTIVE | DirectoryRecommendations.Read.All |

Union for entra.yaml: RoleManagement.Read.Directory, RoleAssignmentSchedule.Read.Directory,
RoleEligibilitySchedule.Read.Directory, RoleManagementPolicy.Read.Directory,
RoleManagementAlert.Read.Directory, Directory.Read.All, Policy.Read.All, Policy.Read.PermissionGrant,
Policy.Read.DeviceConfiguration, AuditLog.Read.All, User.Read.All, IdentityRiskyUser.Read.All,
Application.Read.All, DelegatedPermissionGrant.Read.All, GroupMember.Read.All, Device.Read.All,
Organization.Read.All, OnPremDirectorySynchronization.Read.All, AccessReview.Read.All,
DirectoryRecommendations.Read.All, IdentityRiskyServicePrincipal.Read.All, Synchronization.Read.All,
CustomAuthenticationExtension.Read.All, AdministrativeUnit.Read.All, LifecycleWorkflows.Read.All,
Domain.Read.All. (Directory.Read.All alone covers users, groups, apps, devices, organization and role
assignments, but not the policy, PIM, audit, risk, synchronization, governance or review scopes.)

### rules/intune.yaml

| Endpoint (GET) | Rules | Application permission |
|---|---|---|
| /deviceManagement/managedDevices | INTUNE-DEVICE-* | DeviceManagementManagedDevices.Read.All |
| /deviceManagement/deviceCompliancePolicies (v1.0 and beta, with assignments or deviceStatusOverview), /deviceCompliancePolicyDeviceStateSummary, /deviceConfigurations (assignments, deviceStatusOverview), /deviceConfigurationDeviceStateSummaries, /deviceManagement (settings), beta /configurationPolicies, beta /windowsFeatureUpdateProfiles, beta /ndesConnectors | INTUNE-COMPLIANCE-*, INTUNE-CONFIG-*, INTUNE-UPDATE-RING-*, INTUNE-FEATURE-UPDATE-PROFILE-EOS, INTUNE-ESEC-*, INTUNE-CONFIGPOLICY-UNASSIGNED, INTUNE-NDES-CONNECTOR-INACTIVE, INTUNE-NO-POLICY-MEANS-COMPLIANT, INTUNE-COMPLIANCE-VALIDITY-LONG | DeviceManagementConfiguration.Read.All |
| /deviceManagement (subscriptionState, applePushNotificationCertificate; beta managedDeviceCleanupSettings), /deviceEnrollmentConfigurations, /applePushNotificationCertificate, beta /depOnboardingSettings, beta /windowsAutopilotDeviceIdentities, beta /windowsAutopilotDeploymentProfiles, beta /androidManagedStoreAccountEnterpriseSettings, beta /androidDeviceOwnerEnrollmentProfiles, /mobileThreatDefenseConnectors | INTUNE-SUBSCRIPTION-NOT-ACTIVE, INTUNE-CLEANUP-RULE-OFF, INTUNE-ENROLL-*, INTUNE-APNS-*, INTUNE-DEP-*, INTUNE-AUTOPILOT-*, INTUNE-MGP-*, INTUNE-ANDROID-PROFILE-TOKEN-EXPIRED, INTUNE-MTD-* | DeviceManagementServiceConfig.Read.All |
| beta /deviceManagement/deviceHealthScripts, beta /deviceManagementScripts (metadata and runSummary only) | INTUNE-REMEDIATION-SCRIPT-ERRORS, INTUNE-PLATFORM-SCRIPT-ERRORS | DeviceManagementScripts.Read.All (403 without it; some tenants answer with DeviceManagementConfiguration.Read.All - confirm on first run) |
| /deviceAppManagement/vppTokens | INTUNE-VPP-* | DeviceManagementServiceConfig.Read.All (DeviceManagementApps.Read.All on some tenants - confirm on first run) |
| /deviceAppManagement/iosManagedAppProtections, /androidManagedAppProtections | INTUNE-MAM-* | DeviceManagementApps.Read.All |

Union for intune.yaml: DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All, DeviceManagementScripts.Read.All.
The tenant needs an active Intune licence for any of these to answer.

### rules/m365.yaml

| Endpoint (GET) | Rules | Application permission |
|---|---|---|
| /subscribedSkus | M365-SKU-* | Organization.Read.All (LicenseAssignment.Read.All also works) |
| /directory/subscriptions | M365-SUBSCRIPTION-* | Organization.Read.All |
| /users with signInActivity (user inventory) | M365-LICENSED-USER-*, M365-LICENSED-GUEST, M365-LICENSE-OVERLAP-*, M365-LICENSE-WATCHLIST-SKU | User.Read.All + AuditLog.Read.All |
| /users (licenseAssignmentStates) | M365-LICENSE-ASSIGNMENT-ERROR, M365-LICENSE-DISABLED-VIA-GROUP, M365-LICENSE-DIRECT-ONLY | User.Read.All |
| /groups?$filter=hasMembersWithLicenseErrors eq true | M365-LICENSE-GROUP-ERRORS | GroupMember.Read.All |
| /admin/serviceAnnouncement/issues | M365-SERVICE-ISSUE-OPEN | ServiceHealth.Read.All |
| /admin/serviceAnnouncement/messages | M365-MESSAGE-ACTION-DUE | ServiceMessage.Read.All |
| /admin/sharepoint/settings | M365-SPO-* | SharePointTenantSettings.Read.All |
| /domains | M365-DOMAIN-* | Domain.Read.All |
| beta /admin/appsAndServices | M365-OFFICE-STORE-OR-TRIALS-OPEN | OrgSettings-AppsAndServices.Read.All |
| beta /admin/forms | M365-FORMS-PHISHING-SCAN-OFF | OrgSettings-Forms.Read.All |
| beta /teamwork/teamsAppSettings | M365-TEAMS-RSC-USER-CONSENT | TeamworkAppSettings.Read.All |
| /admin/microsoft365Apps/installationOptions | M365-APPS-UPDATE-CHANNEL-SLOW | OrgSettings-Microsoft365Install.Read.All |
| /security/incidents | M365-SECURITY-INCIDENT-OPEN | SecurityIncident.Read.All |
| /security/alerts_v2 | M365-SECURITY-ALERT-OPEN | SecurityAlert.Read.All |

Union for m365.yaml: Organization.Read.All, User.Read.All, AuditLog.Read.All, GroupMember.Read.All,
ServiceHealth.Read.All, ServiceMessage.Read.All, SharePointTenantSettings.Read.All, Domain.Read.All,
OrgSettings-AppsAndServices.Read.All, OrgSettings-Forms.Read.All, TeamworkAppSettings.Read.All,
OrgSettings-Microsoft365Install.Read.All, SecurityIncident.Read.All, SecurityAlert.Read.All.

### Licences some rules need

- Entra ID P1: signInActivity (every staleness and sign-in-attempt rule), the sign-in log (ENTRA-SIGNIN-*), Conditional Access, the registration details report, role-assignable groups.
- Entra ID P2 (or ID Governance): PIM schedules, PIM policies and alerts, risky users, risk levels in the sign-in log (others see `hidden`), risk-based CA, access reviews.
- Entra ID Governance: Lifecycle Workflows (ENTRA-LIFECYCLE-NO-LEAVER-WORKFLOW).
- Intune: every rule in intune.yaml.
- Workload ID Premium: some app management policy restrictions on service principals, risky service principals (ENTRA-SP-RISKY), workload-identity Conditional Access (ENTRA-CA-BASELINE-WORKLOAD-IDENTITY-BLOCK).
- Microsoft Defender XDR (any Defender plan that feeds the portal): M365-SECURITY-*.
- Without the licence the query fails and the rule records "unknown" with Graph's reason - never a pass.

## The user inventory query

One reusable query, system `entra`, entity type `user`, also used verbatim by m365.yaml so it is
fetched once. It is the Entra side of the AD-to-Entra join (`objectSid = onPremisesSecurityIdentifier`):

    path: /users
    select: [id, userPrincipalName, accountEnabled, userType, createdDateTime, onPremisesSyncEnabled,
             onPremisesSecurityIdentifier, signInActivity, assignedLicenses, mail, onPremisesSamAccountName]
    top: 500   (Graph's maximum page size when signInActivity is selected)
    key: id, name: userPrincipalName

Fields may be added to the select (the cross-system rules read mail and onPremisesSamAccountName as
well), never removed or renamed: rules/hybrid-identity.yaml reads onPremisesSecurityIdentifier,
accountEnabled and signInActivity from the stored rows. The select must stay identical in every rule
that uses the query.

signInActivity carries lastSuccessfulSignInDateTime, lastSignInDateTime and
lastNonInteractiveSignInDateTime (Graph does not allow selecting sub-properties). Staleness is judged
on lastSuccessfulSignInDateTime only; the two attempt fields are used only to detect attempts against
dormant or disabled accounts.

## Thresholds

| Threshold | Default | Rule(s) |
|---|---|---|
| entra.global-admin-max / -min | 4 / 2 | ENTRA-ROLE-GA-TOO-MANY / -TOO-FEW |
| entra.global-admin-eligible-max | 4 | ENTRA-ROLE-GA-ELIGIBLE-TOO-MANY |
| entra.privileged-role-admin-max | 2 | ENTRA-ROLE-PRA-TOO-MANY |
| entra.tier0-role-ids, entra.privileged-role-ids, entra.approval-required-role-ids | role template ids (see the file header) | role rules |
| entra.ca-report-only-days / entra.ca-disabled-days | 30 / 90 | ENTRA-CA-REPORT-ONLY-STALE / -DISABLED-STALE |
| entra.ca-max-excluded-users | 5 | ENTRA-CA-MANY-EXCLUDED-USERS |
| entra.admin-signin-frequency-hours | 4 | ENTRA-CA-BASELINE-ADMIN-SESSION-LIMITS |
| entra.reauth-max-days | 7 | ENTRA-CA-BASELINE-REAUTH-ALL-USERS |
| entra.wide-cidr-pattern | IPv4 /0 to /15 | ENTRA-NAMEDLOC-WIDE-TRUSTED-RANGE |
| entra.tap-max-lifetime-minutes | 480 | ENTRA-AUTHM-TAP-LONG-LIFETIME |
| entra.user-inactive-days / entra.guest-inactive-days | 90 / 90 | staleness rules |
| entra.signin-attempt-window-days | 14 | ENTRA-USER-*-SIGNIN-ATTEMPTS |
| entra.guest-invite-max-days | 30 | ENTRA-GUEST-INVITE-PENDING |
| entra.password-max-age-days | 365 | ENTRA-USER-CLOUD-PASSWORD-OLD |
| entra.disabled-reset-window-days | 30 | ENTRA-USER-DISABLED-PASSWORD-RESET |
| entra.leaver-ou-pattern | OU names containing disabl, leaver, terminat, deprovision, former | ENTRA-USER-ENABLED-IN-LEAVER-OU |
| entra.risky-user-max-days | 7 | ENTRA-RISKY-USER-OPEN |
| entra.app-credential-notice-days / entra.saml-cert-notice-days | 45 / 60 | credential expiry rules |
| entra.graph-tier0-app-role-ids / entra.graph-data-app-role-ids | Graph app role ids (see the file) | ENTRA-APPPERM-* |
| entra.consent-broad-scope-pattern / entra.consent-user-risky-scope-pattern | scope regexes | ENTRA-CONSENT-* |
| entra.device-quota-max | 10 | ENTRA-DEVREG-QUOTA-HIGH |
| entra.rolegroup-max-members | 10 (keep below 20) | ENTRA-ROLEGROUP-LARGE |
| entra.device-stale-days / entra.device-active-days | 90 / 30 | device rules |
| entra.windows-unsupported-build-pattern | builds below 22631 | ENTRA-DEVICE-WINDOWS-UNSUPPORTED |
| entra.sync-max-age-days / entra.password-sync-max-age-days | 0.125 (3 hours) | sync rules |
| intune.device-stale-days | 30 | device rules |
| intune.windows-, ios-, android-, macos-unsupported-(build/version)-pattern | below 22631 / 18 / 13 / 14 | OS support rules |
| intune.android-patch-max-age-days | 90 | INTUNE-DEVICE-ANDROID-PATCH-OLD |
| intune.mgmt-cert-notice-days / intune.grace-notice-days | 30 / 3 | INTUNE-DEVICE-MGMT-CERT-EXPIRY / -GRACE-ENDING |
| intune.compliance-min-devices | 10 | INTUNE-COMPLIANCE-WINDOWS-NONE-WIDE |
| intune.pin-min-length | 6 | INTUNE-COMPLIANCE-SHORT-PIN |
| intune.compliance-validity-max-days | 30 | INTUNE-COMPLIANCE-VALIDITY-LONG |
| intune.config-error-devices-max / -conflict-devices-max | 0 / 0 | INTUNE-CONFIG-DEVICES-* |
| intune.apple-token-notice-days / intune.dep-sync-max-age-days | 30 / 7 | Apple rules |
| intune.consumer-account-pattern | gmail / googlemail | INTUNE-MGP-CONSUMER-ACCOUNT |
| intune.enrollment-token-notice-days | 7 | INTUNE-ANDROID-PROFILE-TOKEN-EXPIRED |
| intune.mtd-heartbeat-max-age-days | 1 | INTUNE-MTD-CONNECTOR-UNHEALTHY |
| m365.free-sku-ids | Microsoft free and trial SKU ids (see the file) | paid-licence rules |
| m365.overlap-office-lower/higher-sku-ids, m365.overlap-ems-lower/higher-sku-ids | suite SKU ids | M365-LICENSE-OVERLAP-* |
| m365.watch-sku-ids | empty (tenant fills) | M365-LICENSE-WATCHLIST-SKU |
| m365.licensed-inactive-days | 90 | M365-LICENSED-USER-INACTIVE |
| m365.subscription-notice-days / m365.trial-notice-days | 60 / 30 | subscription rules |
| m365.message-action-notice-days / -overdue-days | 60 / 30 | M365-MESSAGE-ACTION-DUE |
| entra.first-party-tenant-ids | Microsoft's tenants f8cdef31-a31e-4b4a-93e4-5f571e91255a, 72f988bf-86f1-41af-91ab-2d7cd011db47 | ENTRA-SP-FIRST-PARTY-CREDENTIAL |
| entra.custom-role-dangerous-action-pattern | credential, owner, password, authentication-method, app-role, role and group-membership update actions | ENTRA-ROLE-CUSTOM-DANGEROUS-ACTIONS |
| entra.exchange-app-role-ids / entra.sharepoint-app-role-ids | full_access_as_app, Exchange.ManageAsApp / Sites.FullControl.All, Sites.ReadWrite.All (see the file) | ENTRA-APPPERM-EXCHANGE-*, -SHAREPOINT-* |
| entra.secret-long-lived-age-days | -730 (an age: negative = days ahead) | ENTRA-APP-SECRET-LONG-LIVED, ENTRA-SP-SECRET-LONG-LIVED |
| entra.app-max-secrets | 2 | ENTRA-APP-MANY-SECRETS |
| entra.federated-issuer-allow-pattern / entra.federated-subject-broad-pattern | Entra issuers / wildcard or ':pull_request' subjects | ENTRA-APP-FEDERATED-CREDENTIAL-* |
| entra.authstrength-weak-combination-pattern | combinations containing sms, voice or email | ENTRA-AUTHSTRENGTH-CUSTOM-WEAK |
| entra.consumer-mail-pattern | common consumer mail domains in the guest UPN | ENTRA-GUEST-CONSUMER-DOMAIN |
| entra.dynamic-rule-external-attribute-pattern / -member-guard-pattern | guest-controlled user attributes / userType -eq Member | ENTRA-GROUP-DYNAMIC-GUEST-CONTROLLED-ATTRIBUTE |
| entra.onboarding-group-ids | empty (tenant fills; empty = checks nothing) | ENTRA-GROUP-ONBOARDING-NOT-ASSIGNED |
| entra.audit-role-activity-pattern / entra.tier0-role-id-pattern | role grants excluding PIM requests and activations / the tier-0 template ids as a regex | ENTRA-AUDIT-*-ROLE-ASSIGNMENT-RECENT |
| entra.provisioning-max-successive-failures | 0 | ENTRA-PROVISIONING-JOB-FAILING |
| entra.provisioning-export-max-age-days | 14 | ENTRA-PROVISIONING-JOB-STALE-EXPORT |
| entra.provisioning-interval-ok-pattern | PT1M to PT40M | ENTRA-PROVISIONING-JOB-REDUCED-SCHEDULE |
| entra.provisioning-payload-error-pattern / -conflict-error-pattern | bad request / invalid payload; entry conflict / already exists (matched on errorInformation) | ENTRA-PROVISIONING-PAYLOAD-REJECTED-RECENT, -MATCH-CONFLICT-RECENT, -FAILURES-RECENT |
| entra.provisioning-skip-not-entitled-pattern | NotEffectivelyEntitled | ENTRA-PROVISIONING-SKIPPED-NOT-ENTITLED-RECENT |
| m365.alert-max-open-days | 1 | M365-SECURITY-ALERT-OPEN |
| m365.onedrive-deleted-retention-min-days | 90 | M365-SPO-DELETED-ONEDRIVE-RETENTION-SHORT |
| intune.laps-template-name-pattern | LAPS / local administrator password | INTUNE-ESEC-LAPS-NONE |
| intune.quality-update-deadline-max-days / intune.quality-deferral-max-days | 7 / 7 | INTUNE-UPDATE-RING-NO-DEADLINE / -QUALITY-DEFERRAL-LONG |
| intune.feature-update-eos-notice-days | 90 | INTUNE-FEATURE-UPDATE-PROFILE-EOS |
| intune.profile-error-devices-max / intune.script-error-devices-max | 0 / 0 | INTUNE-CONFIG-PROFILE-ERRORS / INTUNE-*-SCRIPT-ERRORS |
| intune.connector-max-age-days | 1 | INTUNE-NDES-CONNECTOR-INACTIVE |
| intune.unknown-compliance-devices-max | 0 | INTUNE-COMPLIANCE-UNKNOWN-DEVICES |

The OS-support patterns reflect vendor support as of October 2026 and need updating as releases age.

## To confirm on the first real run

Property names and endpoints were checked against the Microsoft Graph documentation, but these
behaviours are documented loosely and should be confirmed on the first collection (a wrong one shows
as n/a or as a failed query, never as a silent pass, except where noted):

- `$expand=principal` on role assignments returns accountEnabled, userType, onPremisesSyncEnabled and assignedLicenses of user principals (the documented example shows the first two). If assignedLicenses is missing, ENTRA-ROLE-LICENSED-HOLDER evaluates n/a.
- `conditions.authenticationFlows.transferMethods` is documented in v1.0; confirm it is returned on the list call (if not, the device-code and authentication-transfer baselines count no policy and report every policy as unjudged).
- The Microsoft Intune Enrollment app id used by ENTRA-CA-BASELINE-INTUNE-ENROLLMENT-MFA (d4ebce55-015a-49b5-a083-c84d1797ae8c) matches the policy's includeApplications entry.
- `grantControls.authenticationStrength.allowedCombinations` is returned inline on the policy list (ENTRA-CA-BASELINE-PHISHING-RESISTANT-ADMINS reads it).
- The nested `@odata.type` of `azureADJoin.localAdmins.registeringUsers` is returned (ENTRA-DEVREG-JOINER-LOCAL-ADMIN matches on it; if absent the rule passes silently).
- `$expand=deviceStatusOverview` on compliance policies and `$expand=applePushNotificationCertificate` on deviceManagement are accepted.
- `/deviceManagement` exposes subscriptionState in v1.0.
- The beta admin endpoints (`/admin/forms`, `/admin/appsAndServices`) return their settings at the top level or wrapped in `value`; the rules accept both.
- `$expand=appRoleAssignments` on a filtered `/users` list, and `$expand=owners` / `members` with a filter on `/groups`, page as expected.
- **Single-object endpoints return rows at all** (see the runner bug above): until it is fixed, every rule on a singleton endpoint passes silently. Check the coverage counts of those queries first.
- SaaS provisioning (ENTRA-PROVISIONING-*): `/servicePrincipals/{id}/synchronization/jobs` answers 200 with an empty list for enterprise apps without provisioning (an error there would make the job rules partial or unknown); the tag filter `WindowsAzureActiveDirectoryIntegratedApp` covers the provisioned apps (gallery and non-gallery); the job `id` equals the provisioning log's `jobId`; `schedule.interval` of a normal job is `PT40M`; the provisioning log accepts `provisioningStatusInfo/status eq '...'` (not listed as filterable) and `activityDateTime gt` (the doc lists eq, contains, gt, lt - no ge); `servicePrincipal` in a log row is an object (the doc's table says collection; the evidence reads both forms, the finding name only the object form); the skip text "NotEffectivelyEntitled" appears in `provisioningSteps[].description` or `.details`.
- Sign-in log: the `or` chains on `clientAppUsed` and `riskLevelDuringSignIn` are accepted (each property documents `eq` only), and the legacy client names match the values the tenant logs (Exchange ActiveSync, IMAP4, POP3, Authenticated SMTP, Other clients, ...).
- Defender alerts: the combined filter `(status eq 'new' or status eq 'inProgress') and (severity eq 'high' or severity eq 'medium')` is accepted.
- `$expand=owners($select=id,userPrincipalName,accountEnabled,userType)` on `/applications` returns accountEnabled and userType for user owners (nested select on owners is documented; derived-type properties are not stated); `$expand=federatedIdentityCredentials` on the list is documented.
- The Exchange Online and SharePoint Online app role ids in entra.yaml match the resources' appRoles (compare with `/servicePrincipals(appId='...')?$select=appRoles`).
- Role grant audit events: the activity names match the pattern (direct, scoped and PIM assignments) and the tier-0 template id appears in targetResources' JSON for both direct and PIM grants.
- `allowedCombinations` of an authentication strength come as strings such as `password,sms`.
- Intune beta: `$expand=runSummary` on deviceHealthScripts and deviceManagementScripts lists, `$expand=deviceStatusOverview` on the deviceConfigurations list, `$select` together with `$expand=assignments` on windowsAutopilotDeploymentProfiles (both outOfBoxExperienceSetting and the deprecated outOfBoxExperienceSettings) and windowsFeatureUpdateProfiles; managedDeviceCleanupSettings.deviceInactivityBeforeRetirementInDays is empty or 0 when no rule is set; ndesConnectors is beta only.
- Endpoint security families: platforms is reported as `windows10` for Windows policies; the LAPS template display name matches the pattern.
- Enrolment configurations: the Windows Hello for Business row carries pinMinimumLength, state and securityDeviceRequired; the enrolment status page row carries showInstallationProgress and allowDeviceUseOnInstallFailure.
- Teams app settings (beta) return isChatResourceSpecificConsentEnabled (v1.0 has only the personal-scope setting); report suspicious activity settings (beta) return state and includeTarget.id.
