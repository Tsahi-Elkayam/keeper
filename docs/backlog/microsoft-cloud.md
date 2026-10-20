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
-ADMIN-PORTALS-MFA (review ENT-CA-009); INTUNE-COMPLIANCE-WINDOWS-NONE-WIDE. What one policy row
still cannot express:

- Coverage split over several policies (for example admin roles divided between two policies, or MFA for all users built from per-app policies) - needs a union across rows (each role covered by some enforced policy). Today such a tenant gets a finding; the evidence shows how many policies were read. Source: cis 5.2.2.1; review ENT-CA-002.
- Admin session limits on every privileged role (only Global Administrator is required today). Source: cis 5.2.2.4.
- The baselines do not judge user and group exclusions (they would have to be compared with the emergency-access accounts), and a grant with operator OR that offers MFA or a compliant device still counts as MFA (ENTRA-CA-ADMIN-MFA-OR-DEVICE flags that per policy). Source: review ENT-CA-013, ENT-CA-016.
- MFA for Azure management as its own resource - covered only through an all-resources MFA policy. Source: review ENT-CA-010.
- A compliance policy exists for every platform that has managed devices (for example no iOS compliance policy while iPhones are enrolled) - a join of compliance policies with managed devices. Source: field (Apple devices with no compliance policy and no Apple MDM at all).

### Comparing two fields of the same row, or arithmetic

Conditions compare a field with a literal or a threshold, never with another field. Proposed: an
operand `ref: <field path>` and simple arithmetic (`sum`, `ratio`).

- Licence SKU over-assigned (consumedUnits > prepaidUnits.enabled). Source: entra-checks ENTRA-LIC-7; review LIC-001; request.
- Licence pool exhausted - no headroom for joiners (consumedUnits = prepaidUnits.enabled). Source: field (all paid suite pools fully consumed); review LIC-001.
- Largely unused paid seats as waste (consumed / enabled below a ratio). Source: entra-checks ENTRA-LIC-1; request. Partial: M365-SKU-PAID-UNASSIGNED (none assigned at all).
- UPN differs from primary mail - the same person counted twice by a provisioning target that keys on mail while sign-in keys on UPN. Source: entra-checks ENTRA-ATR (mail vs UPN); field (seat quota of a SaaS VPN consumed twice by such accounts).
- Client secret valid for more than 24 months (endDateTime - startDateTime). Source: entra-checks ENTRA-APP-3; review ENT-APP-005. Also needs an `until-gt` op as an alternative (date more than N days ahead).
- PIM activation longer than N hours and app-policy maxLifetime above N days - ISO 8601 durations (PT8H, P180D) need a duration comparison. Source: entra-checks ENTRA-RL-*-2; cis 5.1.5.4, 5.1.5.6; review ENT-PIM-003.
- Compliance policy reach as a total (success + failed + error + pending). Partial: INTUNE-COMPLIANCE-WINDOWS-NONE-WIDE tests each count separately.
- Secure Score below a percentage (currentScore / maxScore). Source: entra-checks ENTRA-POL-3; review ENT-LOG-005.

### Conditions on one array element

Each leaf over an array path fires when any element matches; two leaves cannot be pinned to the same
element, and `daysLeft` / `deadline` read the first element only.

- Severity and deadline of the credential-expiry rules follow the FIRST secret or certificate listed, not the soonest. Needs a `min` (soonest date) for `daysLeft` and `deadline`. Affects ENTRA-APP-SECRET-EXPIRY, ENTRA-APP-CERT-EXPIRY, ENTRA-SP-SAML-CERT-EXPIRY, ENTRA-SP-SECRET-EXPIRY (the evidence lists every end date). Source: request.
- "Credential expires within N days AND a newer credential does not exist" (expiry without a replacement) - the latest end date must be within N days. Source: entra-checks ENTRA-APP-2. Today any expiring or expired credential fires, which also flags expired leftovers (worth removing anyway).
- PIM role settings by rule id: MFA or authentication context on activation, justification, maximum activation duration, permanent eligibility allowed, notification recipients (rule id + value pairs inside policy.rules). Source: entra-checks ENTRA-RL-*-2; review ENT-PIM-002..005. Only approval is a rule (ENTRA-PIM-NO-APPROVAL), because only the approval rule carries a `setting` object.
- Directory settings as name/value pairs (`/groupSettings` values): Microsoft 365 group creation restricted, guests as group owners, naming policy, custom banned passwords, on-premises password protection mode, smart lockout threshold and duration. Source: cis 5.2.3.2, 5.2.3.3, 5.2.3.8, 5.2.3.9, 5.1.3.3; entra-checks ENTRA-GRP-16; review ENT-ID-010, ENT-ID-012, ENT-ID-016, ENT-ID-017.
- App management policy restrictions: the restriction type is checked, its maxLifetime and state are not (same element). Source: cis 5.1.5.4, 5.1.5.6.
- Users licensed partly directly and partly through groups (an element with assignedByGroup null next to one without). Partial: M365-LICENSE-DIRECT-ONLY. Source: entra-checks ENTRA-LIC-4; review LIC-003.
- Authentication method enabled for all users (includeTargets id all_users) versus a named migration group, for SMS and Voice severity. Source: entra-checks ENTRA-AM-1.

### Joins across queries

One query per rule; no lookup of another query's rows.

- Privileged role holders with no successful sign-in in N days (roleAssignments x users.signInActivity). Source: entra-checks ENTRA-ROLE-4, ENTRA-RL-*-3; review ENT-PIM-010; request. Partial: ENTRA-PIM-ALERT-ACTIVE (PIM's own stale-admin alert, P2).
- Privileged role holders without a phishing-resistant method, per role. Partial: ENTRA-MFA-ADMIN-* use the registration report's isAdmin flag (any role). Source: entra-checks ENTRA-ROLE-3, ENTRA-RL-*-4.
- Members with no MFA, excluding disabled accounts (the registration report has no accountEnabled). Source: cis 5.2.3.4; entra-checks ENTRA-ACC-11. ENTRA-MFA-MEMBER-NOT-CAPABLE includes disabled accounts.
- Disabled users still in groups assigned to enterprise apps (app assignments x transitive group members x accountEnabled). Source: request; field (disabled users kept consuming the seat quota of a SaaS VPN through app-assigned groups). Partial: ENTRA-USER-DISABLED-APP-ASSIGNED (direct assignments only).
- App-assigned groups that are empty (a group's appRoleAssignments and its members in one rule; Graph may not allow two expands on directory objects, and members/$count is not a documented group filter). Source: request; field (access groups created and assigned to an app but never filled).
- Two groups assigned to the same app where one should have replaced the other (a second, forgotten way in). Source: field (an all-staff group left assigned to a SaaS app next to its dedicated access group).
- App registration owners who are disabled, guests or inactive (applications x owners x users). Source: entra-checks ENTRA-APP-11; review ENT-APP-010.
- High-impact Graph permissions on apps unused for 90 days (Graph grants x servicePrincipalSignInActivities x service principals). Source: entra-checks ENTRA-APP-12, ENTRA-APP-10; review ENT-APP-009.
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

### Relative dates in queries

A `$filter` value is a literal; there is no `{now-7d}` macro, so log endpoints cannot be bounded.

- Sign-in attempts against disabled or dormant accounts, per attempt (source IP, app, error) from `/auditLogs/signIns`. Partial: ENTRA-USER-STALE-SIGNIN-ATTEMPTS and ENTRA-USER-DISABLED-SIGNIN-ATTEMPTS read the last attempt from signInActivity. Source: request; field (a burst of interactive attempts over a few days on hundreds of dormant paid accounts, most with no success since - consistent with a spray). Note: Entra keeps sign-in logs for 30 days; older evidence lives only in a SIEM export.
- Password-spray evidence (failed attempts grouped by user), legacy-protocol sign-ins, sign-ins from unexpected countries. Source: review ENT-IDP-005, ENT-IDP-006, EXO-008.
- Directory changes by unexpected actors in the last N days (`/auditLogs/directoryAudits`). Source: entra-checks ENTRA-PRV-3; review ENT-LOG-003, ENT-PIM-012.
- Risk detections of the last N days. Source: review ENT-IDP-002.

### Per-object endpoints (one GET per rule)

- Federated domain signing certificate expiry and federatedIdpMfaBehavior (`/domains/{id}/federationConfiguration`). Source: entra-checks ENTRA-TEN-13; review ENT-TEN-005.
- SaaS provisioning (SCIM) job state, quarantine and errors (`/servicePrincipals/{id}/synchronization/jobs`, Synchronization.Read.All). Source: field (provisioning configuration of a SaaS VPN unreadable without that permission; a new hire never provisioned because the access group was a one-time copy).
- App install failures (beta `/deviceAppManagement/mobileApps/{id}/installSummary` per app, or the POST-based Intune reports API). Source: review INT-004; request; field (the install-status report call returned BadRequest).
- Configuration profile status per profile (`/deviceConfigurations/{id}/deviceStatusOverview`). Partial: INTUNE-CONFIG-DEVICES-IN-ERROR / -IN-CONFLICT (tenant summary). Source: review INT-003.
- Remediation and platform scripts with errors (needs DeviceManagementScripts.Read.All, 403 without it). Source: review INT-005; field.
- Per-user inbox rules (`/users/{id}/mailFolders/inbox/messageRules`) - iteration over every mailbox. See "Not in Graph" for forwarding.
- SAML app claim configuration (whether a groups claim is emitted, which attributes map to the NameID) - per service principal claims-mapping policies and app optional claims. Source: field (group-based access to a SaaS app whose groups claim was never verified).

### Field paths, runner and protocol

- Field paths split on every dot, so OData annotations such as `@odata.type` cannot be addressed. ENTRA-DEVREG-JOINER-LOCAL-ADMIN works around it by matching the object's JSON text. Needs a quoted path segment.
- The runner's secret-attribute list is LDAP-oriented; Graph secret properties are not filtered. These rules keep them out of every `$select` (VPP `token`, enrolment profile `tokenValue`, `wifiPassword`, Autopilot `deviceAccountPassword`, Managed Google Play `companyCodes` enrolment tokens, managed device `activationLockBypassCode`). Add them to the runner's list so a tenant rule cannot select them either.
- Expanded relationships return at most 20 items; ENTRA-ROLEGROUP-LARGE therefore keeps its threshold below 20.
- Partial reads: a delegated identity without an activated PIM role gets a subset back with no error (seen with Exchange Online; Graph role-gated reads can behave the same). Use application permissions for the Graph integration; the engine could also warn when a query returns far fewer rows than the previous run. Source: field.
- Device-code sign-in is blocked by Conditional Access in well-run tenants, so the Graph integration must not depend on it (certificate-based app sign-in). Source: field.

## Not in Microsoft Graph - needs another API or protocol

- Exchange Online (Exchange Online PowerShell or the Exchange admin API, read-only roles): external mail forwarding estate-wide - mailbox ForwardingSmtpAddress / ForwardingAddress, inbox rules including hidden ones, transport rules, remote-domain auto-forward, outbound spam policy auto-forwarding mode; a documented exception list becomes a threshold. Source: request; field (a no-forwarding policy with dozens of external forwards found by a manual sweep, and one approved external forward that a sweep must not break).
- Exchange Online: mailbox auditing, audit bypass, unified audit log ingestion, SMTP AUTH and modern auth settings, OWA policies, shared mailboxes with sign-in allowed, external sender tagging, DKIM, anti-malware, anti-spam and connection filter policies, Defender for Office presets. Source: cis 1.2.2, 1.3.9, 2.1.2..2.1.15, 2.4.x, 3.1.1, 6.1.x, 6.2.x, 6.3.2, 6.5.x.
- DNS (SPF, DMARC, DKIM publication for every accepted domain) - a DNS protocol runner. Source: cis 2.1.8, 2.1.9, 2.1.10.
- Purview (Security & Compliance PowerShell): DLP policies, sensitivity label policies, retention, alert policies. Source: cis 3.2.1..3.2.3, 3.3.1, 2.4.1.
- Defender XDR and Defender for Endpoint APIs (separate audience from Graph): onboarding versus inventory, sensor health, tamper protection, ASR, vulnerability exposure, Defender for Identity sensors. Graph `/security/incidents` and `/security/alerts_v2` are readable and could become rules next (SecurityIncident.Read.All, SecurityAlert.Read.All). Source: review XDR-001..XDR-016.
- Teams admin (Teams PowerShell): external access and federation, meeting policies (anonymous join, lobby, external control), app permission policies, messaging policies. Source: cis 8.1.2..8.6.1.
- SharePoint settings exposed only through SharePoint Online PowerShell: B2B integration, default link type and permission, guest link expiry, OneDrive-specific sharing level, sites with Anyone links. Source: cis 7.2.2, 7.2.7, 7.2.9..7.2.11.
- Power Platform and Dataverse (Power Platform admin API): database, log and file capacity against entitlement, audit and plug-in trace retention, DLP policies, environments; who receives the capacity alerts. Source: field (Dataverse log storage several times over entitlement and growing weekly, alerts going to one administrator's mailbox); review PP-004.
- Fabric / Power BI tenant settings (Fabric admin API). Source: cis 9.1.1..9.1.12; review PP-009.
- Entra settings with no Graph read: per-user MFA state list (per-user endpoint only, beta), restrict access to the Entra admin centre, SSPR scope, registration and notification settings, owners managing membership requests, LinkedIn connections, stay-signed-in prompt. Source: cis 5.1.2.1, 5.1.2.4, 5.1.3.3, 5.2.4.1, 5.2.4.3..5.2.4.5; review ENT-ID-022, ENT-TEN-006.
- Entra Connect server state (version, auto-upgrade, sync rules, OU scope, Connect Health alerts) - needs the server (WinRM/CIM) or the Connect Health portal. Source: review EC-001, EC-013, EC-014.
- Third-party SaaS consoles that hold Microsoft 365 data or access (backup, VPN, ITSM): admin accounts outside Entra SSO, departed administrators still holding admin or contact roles, stuck or oversized backup jobs, seat quotas. Needs each vendor's API as its own integration. Source: field (a cloud backup console with local admin logins, a departed administrator still primary contact, a backup job running far past its normal size).
- GDAP / delegated admin partner relationships seen from the customer tenant - `tenantRelationships/delegatedAdminRelationships` is a partner-side API; customer-side read is not confirmed. Source: review ADM-005.
- Microsoft 365 usage reports (`/reports/get*Detail`) return CSV unless the beta JSON format is used, and anonymise names by tenant setting. Source: review TEAMS-006, LIC-007.
- Intune: settings catalog and endpoint security content (local administrator group policies that add but never remove, command-prompt and registry blocks that also break installers, LAPS, BitLocker, ASR), policies targeted at the wrong enrolment type, compliance coverage per group, app protection policies with no protections, device clean-up rule, feature-update targets. Needs per-policy settings reads (configurationPolicies/{id}/settings) and joins. Source: review INT-019..INT-029, INT-037; field.

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
| /identity/conditionalAccess/policies, /namedLocations | ENTRA-CA-*, ENTRA-NAMEDLOC-* | Policy.Read.All |
| /policies/identitySecurityDefaultsEnforcementPolicy, /authorizationPolicy, /authenticationMethodsPolicy (v1.0 and beta), /adminConsentRequestPolicy, /defaultAppManagementPolicy, /tokenLifetimePolicies, /authenticationFlowsPolicy, /crossTenantAccessPolicy/default | ENTRA-SECURITY-DEFAULTS-OFF, ENTRA-AUTHZ-*, ENTRA-AUTHM-*, ENTRA-CONSENT-WORKFLOW-OFF, ENTRA-APPPOLICY-*, ENTRA-TOKEN-LIFETIME-CUSTOM, ENTRA-SELF-SERVICE-SIGNUP-ON, ENTRA-XTAP-* | Policy.Read.All |
| /policies/permissionGrantPolicies | ENTRA-PERMISSION-GRANT-POLICY-CUSTOM | Policy.Read.PermissionGrant |
| /policies/deviceRegistrationPolicy | ENTRA-DEVREG-* | Policy.Read.DeviceConfiguration |
| /reports/authenticationMethods/userRegistrationDetails | ENTRA-MFA-* | AuditLog.Read.All |
| /users with signInActivity (user inventory) | ENTRA-USER-INACTIVE, ENTRA-GUEST-INACTIVE, ENTRA-USER-*-SIGNIN-ATTEMPTS, ENTRA-USER-SYNCED-NO-SID | User.Read.All + AuditLog.Read.All |
| /users (hygiene attributes, $expand=appRoleAssignments) | ENTRA-GUEST-INVITE-PENDING, ENTRA-USER-WEAK-PASSWORD-ALLOWED, ENTRA-USER-CLOUD-PASSWORD-OLD, ENTRA-USER-DISABLED-PASSWORD-RESET, ENTRA-USER-ENABLED-IN-LEAVER-OU, ENTRA-SYNC-PROVISIONING-ERROR, ENTRA-USER-DISABLED-APP-ASSIGNED | User.Read.All |
| /identityProtection/riskyUsers | ENTRA-RISKY-USER-OPEN | IdentityRiskyUser.Read.All |
| /applications, /servicePrincipals, /servicePrincipals(appId=...)/appRoleAssignedTo | ENTRA-APP-*, ENTRA-SP-*, ENTRA-APPPERM-* | Application.Read.All |
| /oauth2PermissionGrants | ENTRA-CONSENT-TENANT-WIDE-BROAD, ENTRA-CONSENT-USER-HIGH-RISK | DelegatedPermissionGrant.Read.All (or Directory.Read.All) |
| /groups (+ owners / members expand), /groupLifecyclePolicies | ENTRA-GROUP-*, ENTRA-ROLEGROUP-* | GroupMember.Read.All (Group.Read.All also works) |
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
DirectoryRecommendations.Read.All. (Directory.Read.All alone covers users, groups, apps, devices,
organization and role assignments, but not the policy, PIM, audit, risk or review scopes.)

### rules/intune.yaml

| Endpoint (GET) | Rules | Application permission |
|---|---|---|
| /deviceManagement/managedDevices | INTUNE-DEVICE-* | DeviceManagementManagedDevices.Read.All |
| /deviceManagement/deviceCompliancePolicies (v1.0 and beta), /deviceConfigurations, /deviceConfigurationDeviceStateSummaries, /deviceManagement (settings) | INTUNE-COMPLIANCE-*, INTUNE-CONFIG-*, INTUNE-NO-POLICY-MEANS-COMPLIANT, INTUNE-COMPLIANCE-VALIDITY-LONG | DeviceManagementConfiguration.Read.All |
| /deviceManagement (subscriptionState, applePushNotificationCertificate), /deviceEnrollmentConfigurations, /applePushNotificationCertificate, beta /depOnboardingSettings, beta /windowsAutopilotDeviceIdentities, beta /androidManagedStoreAccountEnterpriseSettings, beta /androidDeviceOwnerEnrollmentProfiles, /mobileThreatDefenseConnectors | INTUNE-SUBSCRIPTION-NOT-ACTIVE, INTUNE-ENROLL-*, INTUNE-APNS-*, INTUNE-DEP-*, INTUNE-AUTOPILOT-*, INTUNE-MGP-*, INTUNE-ANDROID-PROFILE-TOKEN-EXPIRED, INTUNE-MTD-* | DeviceManagementServiceConfig.Read.All |
| /deviceAppManagement/vppTokens | INTUNE-VPP-* | DeviceManagementServiceConfig.Read.All (DeviceManagementApps.Read.All on some tenants - confirm on first run) |
| /deviceAppManagement/iosManagedAppProtections, /androidManagedAppProtections | INTUNE-MAM-* | DeviceManagementApps.Read.All |

Union for intune.yaml: DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All. The tenant needs an active
Intune licence for any of these to answer.

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

Union for m365.yaml: Organization.Read.All, User.Read.All, AuditLog.Read.All, GroupMember.Read.All,
ServiceHealth.Read.All, ServiceMessage.Read.All, SharePointTenantSettings.Read.All, Domain.Read.All,
OrgSettings-AppsAndServices.Read.All, OrgSettings-Forms.Read.All.

### Licences some rules need

- Entra ID P1: signInActivity (every staleness and sign-in-attempt rule), Conditional Access, the registration details report, role-assignable groups.
- Entra ID P2 (or ID Governance): PIM schedules, PIM policies and alerts, risky users, risk-based CA, access reviews.
- Intune: every rule in intune.yaml.
- Workload ID Premium: some app management policy restrictions on service principals.
- Without the licence the query fails and the rule records "unknown" with Graph's reason - never a pass.

## The user inventory query

One reusable query, system `entra`, entity type `user`, also used verbatim by m365.yaml so it is
fetched once. It is the Entra side of the AD-to-Entra join (`objectSid = onPremisesSecurityIdentifier`):

    path: /users
    select: [id, userPrincipalName, accountEnabled, userType, createdDateTime, onPremisesSyncEnabled,
             onPremisesSecurityIdentifier, signInActivity, assignedLicenses]
    top: 500   (Graph's maximum page size when signInActivity is selected)
    key: id, name: userPrincipalName

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
