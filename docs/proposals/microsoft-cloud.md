# Proposals - Microsoft cloud (Entra ID, Intune, Microsoft 365)

Checks to add to `rules/entra.yaml`, `rules/intune.yaml` and `rules/m365.yaml`, written as specs for
whoever writes the YAML. Nothing here is tenant-specific: tenant facts (group ids, app ids, patterns)
are `threshold.<name>` settings, empty by default where no safe default exists. Microsoft's own
well-known ids (role templates, first-party app ids, Graph app-role ids, tenant ids) are fine.

Each entry: id, what it catches and why, severity, data source (file, Graph version, path, query
options, fields, whether an existing query already returns them), permission, condition in words,
refs (canonical: `NIST-800-53:XX-n`, `CIS-M365:n.n.n`, `CIS-Controls-v8:n.n`, `MITRE-ATTACK:Tnnnn`),
fix, and confidence in the field names (verified = read in the Microsoft Learn page linked; likely =
from documentation memory, page not re-read; guess = behaviour not documented, confirm on first run).

Conventions used below:

- "shared query" names a query that already exists verbatim in the rule files, so the new rule adds
  no fetch. The ones referenced: **Q-USERS** (`/users` select id, userPrincipalName, accountEnabled,
  userType, createdDateTime, onPremisesSyncEnabled, onPremisesSecurityIdentifier, signInActivity,
  assignedLicenses; top 500), **Q-APPS** (`/applications` select id, appId, displayName,
  signInAudience, createdDateTime, passwordCredentials, keyCredentials, web, spa,
  isFallbackPublicClient, disabledByMicrosoftStatus; top 999), **Q-SPS** (`/servicePrincipals`
  select id, appId, displayName, accountEnabled, servicePrincipalType, appOwnerOrganizationId,
  preferredSingleSignOnMode, passwordCredentials, keyCredentials, appRoleAssignmentRequired,
  notificationEmailAddresses, disabledByMicrosoftStatus; top 999), **Q-CA**
  (`/identity/conditionalAccess/policies`, no select), **Q-ROLES-EXPAND**
  (`/roleManagement/directory/roleAssignments` expand principal), **Q-AUTHM**
  (`/policies/authenticationMethodsPolicy` items authenticationMethodConfigurations), **Q-AUTHZ**
  (`/policies/authorizationPolicy`), **Q-XTAP** (`/policies/crossTenantAccessPolicy/default`),
  **Q-DOMAINS** (`/domains` select id, authenticationType, isVerified, isDefault, isInitial,
  passwordValidityPeriodInDays, supportedServices), **Q-MDEVICES** (`/deviceManagement/managedDevices`
  with the 18-field select), **Q-COMPLIANCE-BETA** (beta `/deviceManagement/deviceCompliancePolicies`,
  no select), **Q-COMPLIANCE-ASSIGN** (`/deviceManagement/deviceCompliancePolicies` expand
  assignments), **Q-DEVICECONFIG** (`/deviceManagement/deviceConfigurations` expand assignments),
  **Q-MAM-IOS** / **Q-MAM-ANDROID** (`/deviceAppManagement/iosManagedAppProtections`,
  `/androidManagedAppProtections`, no select), **Q-SPO** (`/admin/sharepoint/settings`).
- "Tier-0 role ids", "privileged role ids", "Graph tier-0 app-role ids" are the lists already in
  `entra.yaml` (thresholds `entra.tier0-role-ids`, `entra.privileged-role-ids`,
  `entra.graph-tier0-app-role-ids`).
- Two engine features being added are assumed where stated: **per-object queries**
  (`for_each: { query: <another query>, field: id }` with `{id}` in the path) and **relative dates**
  (`{DAYS_AGO:n}`, `{NOW}` in path, params and `$filter`).

---

## Priority 1 - identity attack paths and active security signals

### ENTRA-SP-FIRST-PARTY-CREDENTIAL
- Catches: a credential (secret or certificate) added to the service principal of a Microsoft
  first-party application. Legitimate first-party apps never carry tenant-added credentials; one
  there is the classic post-breach backdoor (whoever holds it signs in as that Microsoft app with all
  the permissions the tenant already granted it, invisibly).
- Severity: critical.
- Source: entra.yaml; v1.0; shared query Q-SPS (fields appOwnerOrganizationId, passwordCredentials,
  keyCredentials already selected).
- Permission: Application.Read.All.
- Condition: appOwnerOrganizationId in [f8cdef31-a31e-4b4a-93e4-5f571e91255a,
  72f988bf-86f1-41af-91ab-2d7cd011db47] (Microsoft service tenants, threshold
  `entra.first-party-tenant-ids`) and (passwordCredentials notempty or keyCredentials notempty).
- Refs: MITRE-ATTACK:T1098.001, NIST-800-53:IA-5, NIST-800-53:AC-6.
- Fix: treat as an incident - record who added it (directory audit "Update service principal"),
  remove the credential, revoke the app's refresh tokens, review sign-ins by that app.
- Confidence: verified field names (Q-SPS already runs); the two tenant ids are Microsoft constants
  (likely; https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in).

### ENTRA-SP-RISKY
- Catches: a workload identity Identity Protection has flagged (leaked credential, anomalous
  sign-in, suspicious activity) that nobody remediated or dismissed.
- Severity: by riskLevel - high: high, medium: medium.
- Source: entra.yaml; v1.0; `/identityProtection/riskyServicePrincipals`; fields riskState,
  riskLevel, riskDetail, riskLastUpdatedDateTime, isEnabled, appId, displayName, servicePrincipalType;
  key id, name displayName. New query.
- Permission: IdentityRiskyServicePrincipal.Read.All. Needs Workload Identities Premium (riskDetail is
  `hidden` without it; riskLevel still returned).
- Condition: riskState in [atRisk, confirmedCompromised] and riskLevel in [high, medium].
- Refs: MITRE-ATTACK:T1078.004, NIST-800-53:IR-4, NIST-800-53:SI-4.
- Fix: rotate every credential of the app, review its recent sign-ins and grants, then confirm
  compromised or dismiss in Identity Protection.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/riskyserviceprincipal?view=graph-rest-1.0

### ENTRA-ROLE-CUSTOM-DANGEROUS-ACTIONS
- Catches: a custom directory role whose allowed actions reach credential or role management
  (add app credentials, reset passwords, manage role assignments, edit role-assignable group
  membership). Custom roles are outside every "Global Administrator count" review, and AzureHound
  walks them as edges to tenant takeover.
- Severity: high.
- Source: entra.yaml; v1.0; `/roleManagement/directory/roleDefinitions`; filter `isBuiltIn eq false`;
  fields id, displayName, isBuiltIn, isEnabled, rolePermissions (allowedResourceActions); key id,
  name displayName. New query.
- Permission: RoleManagement.Read.Directory.
- Condition: isEnabled true and `rolePermissions[].allowedResourceActions` match regex (threshold
  `entra.custom-role-dangerous-action-pattern`, default
  `(applications/credentials/update|servicePrincipals/credentials/update|servicePrincipals/synchronizationCredentials|users/password/update|users/authenticationMethods|roleAssignments/|roleDefinitions/|groups/members/update|groups/owners/update|/allTasks)`).
- Refs: MITRE-ATTACK:T1098.003, NIST-800-53:AC-6(5), CIS-Controls-v8:6.8.
- Fix: cut the role to the actions the job needs; if it needs these actions, treat its holders as
  tier-0 (PIM, phishing-resistant MFA, separate admin accounts).
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/unifiedroledefinition?view=graph-rest-1.0

### ENTRA-APPPERM-EXCHANGE-APP-ACCESS
- Catches: an application granted Exchange Online application permissions that read or impersonate
  every mailbox (`full_access_as_app`, `Exchange.ManageAsApp`). ENTRA-APPPERM-* only look at Graph;
  the EWS/Exchange resource is the other door to all mail.
- Severity: high.
- Source: entra.yaml; v1.0;
  `/servicePrincipals(appId='00000002-0000-0ff1-ce00-000000000000')/appRoleAssignedTo`; top 999;
  fields principalType, principalDisplayName, appRoleId, createdDateTime; key id. New query (same
  shape as the Graph one, different resource).
- Permission: Application.Read.All.
- Condition: principalType eq ServicePrincipal and appRoleId in threshold
  `entra.exchange-app-role-ids` (default: dc890d15-9560-4a4c-9b7f-a736ec74ec40 full_access_as_app,
  dc50a0fb-09a3-484d-be87-e023b12c6440 Exchange.ManageAsApp).
- Refs: MITRE-ATTACK:T1114.002, MITRE-ATTACK:T1528, NIST-800-53:AC-6, NIST-800-53:AC-3.
- Fix: replace with Exchange application RBAC scoped to the mailboxes needed (management scopes), or
  document the app and lock its owners and credentials down.
- Confidence: path pattern verified (existing rule); the two role ids are from the Exchange Online
  service principal manifest and need confirming on the first run (likely) -
  https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth

### ENTRA-APPPERM-SHAREPOINT-FULL-CONTROL
- Catches: an application granted SharePoint Online application permissions over every site
  (`Sites.FullControl.All` / `Sites.ReadWrite.All` on the SharePoint resource, not Graph).
- Severity: high.
- Source: entra.yaml; v1.0;
  `/servicePrincipals(appId='00000003-0000-0ff1-ce00-000000000000')/appRoleAssignedTo`; top 999;
  same fields as above. New query.
- Permission: Application.Read.All.
- Condition: principalType eq ServicePrincipal and appRoleId in threshold
  `entra.sharepoint-app-role-ids` (default: 678536fe-1083-478a-9c59-b99265e6b0d3
  Sites.FullControl.All, fbcd29d2-fcca-4405-aded-518d457caae4 Sites.ReadWrite.All).
- Refs: MITRE-ATTACK:T1530, NIST-800-53:AC-6, NIST-800-53:AC-3.
- Fix: move to Sites.Selected with per-site grants; remove grants of apps no longer used.
- Confidence: role ids likely (SharePoint Online service principal manifest); confirm on first run.

### ENTRA-APP-TIER0-REQUESTED-WITH-OWNERS
- Catches: an app registration whose manifest requests a tenant-takeover Graph application
  permission and that has owners. An owner can add a credential and act with everything the app has
  been granted; owners are rarely reviewed as administrators. (Requested is not granted - pair with
  ENTRA-APPPERM-TIER0, which sees grants but not owners.)
- Severity: high.
- Source: entra.yaml; v1.0; `/applications`; select id, appId, displayName, requiredResourceAccess;
  expand `owners($select=id,userPrincipalName)`; top 999; key id, name displayName. New query
  (Q-APPS cannot carry the expand without changing nine rules; keep separate).
- Permission: Application.Read.All (owners' UPN needs Directory.Read.All or User.Read.All).
- Condition: `requiredResourceAccess[].resourceAccess[].id` in the Graph tier-0 app-role id list and
  owners notempty. Evidence lists owners.
- Refs: MITRE-ATTACK:T1098.001, NIST-800-53:AC-6(5), CIS-Controls-v8:6.8.
- Fix: remove human owners from tier-0 apps (manage through PIM-held Application Administrator) or
  keep owners few, named and on admin accounts.
- Confidence: likely; `$expand=owners` on a list is documented for applications, nested select on
  the expand to confirm on first run - https://learn.microsoft.com/en-us/graph/api/application-list-owners?view=graph-rest-1.0

### ENTRA-APP-FEDERATED-CREDENTIAL-EXTERNAL
- Catches: an app registration that trusts tokens from an external issuer (GitHub Actions, another
  cloud, an arbitrary OIDC issuer) through a federated identity credential - a credential-less way
  in that never expires and is not covered by the app management policy. A wildcard or
  pull-request subject on a GitHub issuer is the known misconfiguration.
- Severity: medium (high when subject contains `*` or `pull_request`).
- Source: entra.yaml; v1.0; `/applications`; select id, appId, displayName; expand
  `federatedIdentityCredentials`; top 999; key `{id}|{federatedIdentityCredentials[].name}` or the
  app id with the credentials listed in evidence. New query.
- Permission: Application.Read.All.
- Condition: `federatedIdentityCredentials[].issuer` notmatch
  `^https://(login\.microsoftonline\.com|sts\.windows\.net)/` (threshold
  `entra.federated-issuer-allow-pattern`); severity high when `federatedIdentityCredentials[].subject`
  match `(\*|pull_request)`.
- Refs: MITRE-ATTACK:T1098.001, NIST-800-53:IA-5, NIST-800-53:AC-20.
- Fix: keep the issuer and subject exact (one repository, one branch or environment); delete
  credentials of pipelines no longer in use.
- Confidence: field names verified; list-level `$expand=federatedIdentityCredentials` likely (per
  app endpoint documented) - https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-1.0.
  If the list refuses the expand, use the per-object feature: `for_each` Q-APPS →
  `/applications/{id}/federatedIdentityCredentials`.

### ENTRA-APP-SECRET-LONG-LIVED
- Catches: a client secret that is still valid for more than two years from today - it will not
  be rotated and it outlives the project, the owner and the policy. Closes backlog item "client
  secret valid for more than 24 months" without the arithmetic: "end date more than N days away" is
  `not: { until-lt: N }`.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-APPS (passwordCredentials selected).
- Permission: Application.Read.All.
- Condition: passwordCredentials notempty and not (`passwordCredentials[].endDateTime` until-lt 730,
  threshold `entra.secret-max-remaining-days`). Note: with array leaves "not any-element-within-730"
  means every secret is far out; for "any secret far out" the engine needs an `until-gt` op (gap).
  Decide which reading the YAML author wants; the stricter "any" needs the op.
- Refs: CIS-M365:5.1.5.4, NIST-800-53:IA-5(1), MITRE-ATTACK:T1098.001.
- Fix: replace with a certificate or a federated credential; otherwise recreate the secret with a
  lifetime of 180 days or less and enable the app management policy lifetime cap.
- Confidence: verified (fields already in use). Same spec applies to Q-SPS for ENTRA-SP-SECRET-LONG-LIVED.

### ENTRA-APP-MANY-SECRETS
- Catches: an app registration carrying more than N active secrets. Secret sprawl means nobody
  knows which system uses which; an extra secret is also exactly what an attacker adds to persist.
- Severity: low (medium above 2x the threshold).
- Source: entra.yaml; v1.0; shared query Q-APPS.
- Permission: Application.Read.All.
- Condition: passwordCredentials size-gt 2 (threshold `entra.app-max-secrets`). Expired secrets count
  too (they should be deleted anyway); the evidence lists end dates.
- Refs: MITRE-ATTACK:T1098.001, NIST-800-53:IA-5.
- Fix: keep at most two (current and next during rotation); delete the rest after confirming the
  consumer.
- Confidence: verified.

### ENTRA-CUSTOM-AUTH-EXTENSION-PRESENT
- Catches: a custom authentication extension (token issuance start, attribute collection) is
  configured - an HTTP call-out that can add claims to every token. Legitimate but rare; an
  unexplained one is persistence.
- Severity: medium (review list; accept once documented).
- Source: entra.yaml; v1.0; `/identity/customAuthenticationExtensions`; fields id, displayName,
  endpointConfiguration (targetUrl), authenticationConfiguration, createdDateTime (if present); key
  id, name displayName. New query.
- Permission: CustomAuthenticationExtension.Read.All (Application.Read.All also lists them).
- Condition: `each: any` (every extension is a finding until accepted).
- Refs: MITRE-ATTACK:T1556, NIST-800-53:CM-6, NIST-800-53:IA-5.
- Fix: confirm the owner and the target URL; delete extensions no app uses.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/customauthenticationextension?view=graph-rest-1.0

### ENTRA-CA-MFA-EXCLUDES-ROLES
- Catches: an enforced MFA policy that excludes directory roles. Excluded roles are exactly the
  accounts an attacker wants, and role exclusions are usually "temporary" ones that stayed.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-CA.
- Permission: Policy.Read.All.
- Condition: state enabled and (grantControls.builtInControls contains mfa or
  grantControls.authenticationStrength.id exists) and conditions.users.excludeRoles notempty.
- Refs: CIS-M365:5.2.2.1, NIST-800-53:IA-2(1), NIST-800-53:AC-6(5).
- Fix: remove the role exclusion; give the excluded role its own stricter policy (phishing-resistant
  strength) instead of none.
- Confidence: verified (fields already used in the file).

### ENTRA-CA-MFA-EXCLUDES-APPS
- Catches: an all-users MFA policy that excludes named applications. Each excluded app is a
  password-only door; the baseline rule already refuses to count such a policy, this one names the
  apps so the gap can be fixed.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-CA.
- Permission: Policy.Read.All.
- Condition: state enabled and conditions.users.includeUsers contains All and (mfa grant or
  authentication strength) and conditions.applications.excludeApplications notempty.
- Refs: CIS-M365:5.2.2.2, NIST-800-53:IA-2(1).
- Fix: remove the app exclusion, or cover the app with its own policy (device or location based).
- Confidence: verified.

### ENTRA-CA-BASELINE-MFA-AZURE-MANAGEMENT
- Catches: no enforced policy requires MFA for Azure management (ARM, portal, CLI). Closes backlog
  item "MFA for Azure management as its own resource" (review ENT-CA-010): a policy counts if it
  targets All users (or all roles as in the admin baseline), includes the Windows Azure Service
  Management API app `797f4846-ba00-4fd7-ba43-dac1f8f63013` or All resources, and grants MFA or an
  authentication strength, with no risk conditions.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-CA.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where state enabled and includeUsers contains All and
  (includeApplications contains 797f4846-ba00-4fd7-ba43-dac1f8f63013 or contains All) and
  (mfa or authenticationStrength) and signInRiskLevels empty and userRiskLevels empty.
- Refs: NIST-800-53:IA-2(1), NIST-800-53:AC-17, MITRE-ATTACK:T1078.004.
- Fix: create a policy: users All, target resource Windows Azure Service Management API, grant MFA
  (phishing-resistant for subscription owners).
- Confidence: verified (app id is a Microsoft constant).

### ENTRA-AUTHSTRENGTH-CUSTOM-WEAK
- Catches: a custom authentication strength that admits telephony or email combinations
  (sms, voice, email, password+sms). A policy that "requires an authentication strength" looks
  strong in every review while accepting the weakest factor.
- Severity: medium.
- Source: entra.yaml; v1.0; `/policies/authenticationStrengthPolicies`; fields id, displayName,
  policyType, allowedCombinations; key id, name displayName. New query.
- Permission: Policy.Read.All.
- Condition: policyType eq custom and `allowedCombinations` match `(sms|voice|email)` (threshold
  `entra.authstrength-weak-combination-pattern`).
- Refs: NIST-800-53:IA-2(1), NIST-800-53:IA-2(6), MITRE-ATTACK:T1621.
- Fix: remove the telephony and email combinations from the custom strength, or delete it and use
  the built-in strengths.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy?view=graph-rest-1.0

### ENTRA-XTAP-DIRECT-CONNECT-INBOUND-OPEN
- Catches: default cross-tenant settings allow B2B direct connect inbound from any organisation
  (Teams shared channels with every tenant on earth). Microsoft's default is blocked, so "allowed"
  here was set on purpose and is rarely meant tenant-wide.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-XTAP (no select; field
  b2bDirectConnectInbound.usersAndGroups.accessType, b2bDirectConnectInbound.applications.accessType).
- Permission: Policy.Read.All.
- Condition: b2bDirectConnectInbound.usersAndGroups.accessType eq allowed or
  b2bDirectConnectInbound.applications.accessType eq allowed.
- Refs: NIST-800-53:AC-20, NIST-800-53:AC-21, MITRE-ATTACK:T1199.
- Fix: block direct connect in the default settings and allow it per named partner.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/crosstenantaccesspolicyconfigurationdefault?view=graph-rest-1.0
  (note: automaticUserConsentSettings is always false on the default object - not a rule there;
  partner-level inbound sync consent is a candidate for a `for_each` over `/policies/crossTenantAccessPolicy/partners`).

### ENTRA-DOMAIN-FEDERATED
- Catches: a verified domain authenticates through federation (AD FS or a third-party IdP). The
  federation server's signing key is then a tenant-wide "golden SAML" key, and its MFA behaviour
  decides whether Entra trusts MFA claims blindly. Not wrong, but every federated domain must be a
  known, reviewed fact.
- Severity: medium (review; accept with the owner and the key-rotation date recorded).
- Source: entra.yaml; v1.0; shared query Q-DOMAINS (authenticationType, isVerified selected).
- Permission: Domain.Read.All.
- Condition: isVerified true and authenticationType eq Federated.
- Refs: MITRE-ATTACK:T1606.002, MITRE-ATTACK:T1484.002, NIST-800-53:IA-5(2), NIST-800-53:SC-12.
- Fix: confirm the federation server is patched, its signing certificate rotation date is known and
  `federatedIdpMfaBehavior` is `rejectMfaByFederatedIdp` (per-domain endpoint, backlog); plan the
  move to password hash sync plus cloud MFA.
- Confidence: verified (fields already selected).

### ENTRA-USER-EXTERNAL-MEMBER
- Catches: an external account (UPN carries `#EXT#`) whose userType is Member. A guest promoted to
  member gets member-level directory read, group creation and whatever "all members" policies grant,
  while its credentials and lifecycle stay in another tenant.
- Severity: medium.
- Source: entra.yaml; v1.0; shared query Q-USERS.
- Permission: User.Read.All.
- Condition: userType eq Member and userPrincipalName contains `#EXT#` and accountEnabled true.
- Refs: NIST-800-53:AC-2(9), NIST-800-53:AC-6, MITRE-ATTACK:T1078.004.
- Fix: convert back to Guest, or create a real member account for the person.
- Confidence: verified.

### ENTRA-APP-OWNER-DISABLED-OR-GUEST
- Catches: an app registration owned by a disabled account or a guest. Ownership of an app is a
  credential-adding right; a disabled owner is a leaver who keeps a key, a guest owner is an
  outsider who keeps one. Partially closes backlog item ENTRA-APP-11 / ENT-APP-010 (inactive owners
  still need the sign-in join).
- Severity: medium.
- Source: entra.yaml; v1.0; `/applications`; select id, appId, displayName; expand
  `owners($select=id,userPrincipalName,accountEnabled,userType)`; top 999 (same query as
  ENTRA-APP-TIER0-REQUESTED-WITH-OWNERS if the select is merged - do that, one fetch).
- Permission: Application.Read.All + User.Read.All (or Directory.Read.All).
- Condition: `owners[].accountEnabled` eq false or `owners[].userType` eq Guest.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:AC-2(9), MITRE-ATTACK:T1098.001.
- Fix: replace the owner; make owner removal part of the leaver process.
- Confidence: guess on whether a nested `$select` of user-typed properties is honoured on a
  directoryObject expand (ENTRA-ROLE-DISABLED-HOLDER depends on the same behaviour and is listed "to
  confirm" in the backlog). If not, the per-object feature covers it: `for_each` Q-APPS →
  `/applications/{id}/owners/microsoft.graph.user?$select=...`.

### M365-SECURITY-INCIDENT-OPEN
- Catches: an active Defender XDR incident of medium or high severity. The pack reads
  configuration; this is the one place where Microsoft tells you an attack is happening now. Closes
  the backlog note "security/incidents could become rules next".
- Severity: by severity field - high: high, medium: medium; critical stays critical.
- Source: m365.yaml (or a new `rules/defender-xdr.yaml` on the same graph integration); v1.0;
  `/security/incidents`; filter `status eq 'active'`; select id, displayName, severity, status,
  classification, determination, createdDateTime, lastUpdateDateTime, assignedTo, incidentWebUrl;
  key id, name displayName; refresh 1h. New query.
- Permission: SecurityIncident.Read.All.
- Condition: status eq active and severity in [high, medium, critical]; and assignedTo empty raises
  the evidence "unassigned".
- Refs: NIST-800-53:IR-4, NIST-800-53:IR-6, CIS-Controls-v8:17.4.
- Fix: open the incident, assign it, work the alerts; do not resolve without a classification.
- Confidence: verified field names from the incident resource (likely for filter support on status) -
  https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0

### M365-SECURITY-ALERT-OPEN
- Catches: a Defender alert (alerts_v2) that is new or in progress for longer than N days - alerts
  not grouped into an incident, or stuck.
- Severity: by severity (high/medium/low); informational dropped.
- Source: same file; v1.0; `/security/alerts_v2`; filter `status ne 'resolved'`; select id, title,
  severity, status, category, serviceSource, detectionSource, createdDateTime, lastUpdateDateTime,
  incidentId, assignedTo; key id, name title; refresh 1h. New query.
- Permission: SecurityAlert.Read.All.
- Condition: status in [new, inProgress] and severity in [high, medium] and createdDateTime age-gt 1
  (threshold `m365.alert-max-open-days`).
- Refs: NIST-800-53:IR-4, NIST-800-53:SI-4, CIS-Controls-v8:17.4.
- Fix: triage in the Defender portal; resolve with a classification.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0

### ENTRA-SIGNIN-LEGACY-AUTH-SUCCESS-RECENT  (needs relative dates)
- Catches: successful sign-ins over legacy protocols in the last N days - proof that the block
  policy is missing, excluded or bypassed for these accounts, per account and protocol.
- Severity: high.
- Source: entra.yaml; v1.0; `/auditLogs/signIns`; filter
  `createdDateTime ge {DAYS_AGO:7} and status/errorCode eq 0 and clientAppUsed in ('Exchange ActiveSync','IMAP4','POP3','SMTP','Authenticated SMTP','Other clients','Exchange Web Services','MAPI Over HTTP','Offline Address Book','Outlook Anywhere (RPC over HTTP)')`;
  select id, userPrincipalName, userId, appDisplayName, clientAppUsed, ipAddress, createdDateTime,
  conditionalAccessStatus; key `{userId}|{clientAppUsed}`; name userPrincipalName; maxPages a
  tenant-sized cap. New query. Sign-in logs keep 30 days (7 with P1 missing).
- Permission: AuditLog.Read.All + Directory.Read.All.
- Condition: `each: any` (every row is a problem); evidence names app, protocol, IP.
- Refs: CIS-M365:5.2.2.3, MITRE-ATTACK:T1078.004, MITRE-ATTACK:T1110.003, NIST-800-53:IA-2(1).
- Fix: find the client (often a printer, scanner or old mail app), move it to modern auth or to a
  scoped exception, then confirm the block policy covers the account.
- Confidence: likely (filter on clientAppUsed and status/errorCode is documented) -
  https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0

### ENTRA-SIGNIN-RISKY-SUCCESS-RECENT  (needs relative dates)
- Catches: successful sign-ins with high or medium sign-in risk in the last N days - risk-based
  Conditional Access either does not exist or was satisfied; each one is an account to look at
  today, not a policy to fix next quarter.
- Severity: high (high risk) / medium (medium risk).
- Source: entra.yaml; v1.0; `/auditLogs/signIns`; filter
  `createdDateTime ge {DAYS_AGO:7} and status/errorCode eq 0 and riskLevelDuringSignIn in ('high','medium')`;
  select id, userPrincipalName, userId, appDisplayName, ipAddress, location, riskLevelDuringSignIn,
  riskState, riskEventTypes_v2, createdDateTime; key `{userId}|{riskLevelDuringSignIn}`. Shares
  nothing with the rule above (different filter). Needs Entra ID P2 for real risk levels.
- Permission: AuditLog.Read.All + Directory.Read.All.
- Condition: `each: any`.
- Refs: CIS-M365:5.2.2.7, MITRE-ATTACK:T1078.004, NIST-800-53:SI-4, NIST-800-53:IR-4.
- Fix: review the sign-in; if not the user's, reset the password, revoke sessions, review MFA
  methods; then make the sign-in risk policy enforced.
- Confidence: likely (same page as above).

### ENTRA-AUDIT-ROLE-ASSIGNMENT-RECENT  (needs relative dates)
- Catches: directory role additions in the last N days (member added to role, eligible assignment
  created), as a daily review list. Role grants are the step every takeover ends with; seeing them
  the next morning is the whole point of "what to do today".
- Severity: info (medium when the role is tier-0).
- Source: entra.yaml; v1.0; `/auditLogs/directoryAudits`; filter
  `activityDateTime ge {DAYS_AGO:2} and category eq 'RoleManagement' and result eq 'success'`;
  select id, activityDisplayName, activityDateTime, initiatedBy, targetResources, result; key id;
  name activityDisplayName. New query.
- Permission: AuditLog.Read.All.
- Condition: activityDisplayName match `^(Add member to role|Add eligible member to role|Add scoped member to role|Add member to role outside of PIM)` (threshold
  `entra.audit-role-activity-pattern`); evidence shows initiator and target.
- Refs: MITRE-ATTACK:T1098.003, NIST-800-53:AC-2(4), NIST-800-53:AU-6, CIS-Controls-v8:8.11.
- Fix: confirm each grant against a change record; remove the ones nobody asked for.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0

---

## Priority 1 - the SCIM provisioning case (joiners who never reached the SaaS app)

The case, generic: a SaaS app provisioned from Entra by SCIM. The job sat in quarantine for days at
one attempt a day; thousands of objects failed with HTTP 400 "invalid patch request payload" from one
attribute mapping the target rejected; hundreds failed "user already exists with email" because the
target held a user with the same email under another username while matching was by UPN; new hires
were skipped "not assigned to the application" because onboarding still filled an old group that was
no longer assigned to the app, while the assigned group was filled by hand. SSO and the app
assignment itself were fine. Every part below becomes a rule; the first three need the per-object
feature, the audit ones need relative dates.

Shared base query for the per-object rules, **Q-SP-PROVISIONED**: Q-SPS filtered to service
principals that can have a job. Graph has no "has provisioning job" filter; use
`$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')` (gallery and non-gallery
enterprise apps) and let the per-object call return an empty `value` for apps without a job (an
empty job list is "no job", not a failure). Alternative: a tenant threshold list
`entra.provisioned-sp-ids` to keep the fan-out small.

### ENTRA-PROVISIONING-JOB-QUARANTINE
- Catches: a provisioning job in quarantine. In quarantine Entra drops to one attempt a day and
  stops creating users; the admin mail about it goes to the notification address on the job, which
  is often a person who left.
- Severity: high (critical when quarantine.reason is credential-related: `EncounteredIdentityNotFound`
  excluded, `EncounteredUnauthorized`/`InvalidCredentials` style reasons).
- Source: entra.yaml; v1.0; `for_each: { query: Q-SP-PROVISIONED, field: id }` →
  `/servicePrincipals/{id}/synchronization/jobs`; fields id, templateId, schedule.state,
  schedule.interval, status.code, status.countSuccessiveCompleteFailures, status.quarantine
  (reason, currentBegan, seriesBegan, seriesCount, nextAttempt, error), status.lastExecution
  (state, timeBegan, timeEnded, countExported, countExports, error), status.lastSuccessfulExecution,
  status.lastSuccessfulExecutionWithExports, status.steadyStateLastAchievedTime,
  status.synchronizedEntryCountByType, status.troubleshootingUrl; key `{sp}|{id}` (the engine must
  carry the parent id into the row); name = parent displayName. Rows: one per job per service
  principal. All five provisioning-job rules share this one per-object fetch.
- Permission: Synchronization.Read.All (application) - add to the permissions table; without it
  the call is 403 and the rules record unknown.
- Condition: status.code eq Quarantine. Evidence: reason, currentBegan, seriesCount, nextAttempt,
  troubleshootingUrl.
- Refs: NIST-800-53:AC-2, NIST-800-53:SI-4, CIS-Controls-v8:5.1.
- Fix: open the provisioning logs for the job, fix the cause (credentials, mapping, target
  errors), then restart the job to clear the quarantine; set a monitored mailbox as the job's
  notification address.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/synchronization-synchronizationstatus?view=graph-rest-1.0
  and https://learn.microsoft.com/en-us/graph/api/resources/synchronization-synchronizationjob?view=graph-rest-1.0
  (quarantine sub-fields: likely - https://learn.microsoft.com/en-us/graph/api/resources/synchronization-synchronizationquarantine?view=graph-rest-1.0).

### ENTRA-PROVISIONING-JOB-FAILING
- Catches: a job not in quarantine yet but failing repeatedly - the last execution ended in error,
  or N successive complete failures. This is the day-before-quarantine signal.
- Severity: medium (high when countSuccessiveCompleteFailures ge 3).
- Source: same per-object fetch as above.
- Permission: Synchronization.Read.All.
- Condition: status.code eq Active and (status.countSuccessiveCompleteFailures gt 0 (threshold
  `entra.provisioning-max-successive-failures`, default 0) or status.lastExecution.state eq Failed
  or status.lastExecution.error exists).
- Refs: NIST-800-53:SI-4, NIST-800-53:AC-2.
- Fix: read lastExecution.error and the provisioning log; fix before the quarantine threshold.
- Confidence: verified (state enum of synchronizationTaskExecution: likely -
  https://learn.microsoft.com/en-us/graph/api/resources/synchronization-synchronizationtaskexecution?view=graph-rest-1.0).

### ENTRA-PROVISIONING-JOB-STALE-EXPORT
- Catches: a job that is Active but has not exported anything for N days. A job can be "healthy"
  while every object is skipped: nobody new is in scope, or the scoping group is wrong. Exactly the
  "onboarding fills the wrong group" symptom seen from the job's side.
- Severity: medium.
- Source: same per-object fetch.
- Permission: Synchronization.Read.All.
- Condition: status.code eq Active and (status.lastSuccessfulExecutionWithExports absent or
  status.lastSuccessfulExecutionWithExports.timeEnded age-gt 14, threshold
  `entra.provisioning-export-max-age-days`). Tenants with no joiners for weeks accept this with a
  longer threshold.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.1.
- Fix: compare the job's scope (assigned groups) with where onboarding puts new users; provision
  one new hire on demand to prove the path.
- Confidence: verified field; the timestamp sub-field (timeEnded) likely.

### ENTRA-PROVISIONING-JOB-PAUSED
- Catches: a configured job that is Paused, NotRun or NotConfigured on an enterprise app that is
  assigned and enabled - provisioning was set up and then stopped, or never started; users of the
  app are being created by hand without anyone deciding that.
- Severity: medium (low for NotConfigured).
- Source: same per-object fetch; the parent's accountEnabled from Q-SPS.
- Permission: Synchronization.Read.All.
- Condition: status.code in [Paused, NotRun, NotConfigured] (schedule.state ne Active also counts).
- Refs: NIST-800-53:AC-2, NIST-800-53:CM-3.
- Fix: start the job, or delete it and record that the app is provisioned manually.
- Confidence: verified.

### ENTRA-PROVISIONING-JOB-REDUCED-SCHEDULE
- Catches: schedule.interval longer than the normal 40-minute cycle (a job throttled by quarantine
  or set to a long interval) - changes land in the app hours or a day late.
- Severity: low.
- Source: same per-object fetch; field schedule.interval (ISO 8601 duration, e.g. PT40M).
- Permission: Synchronization.Read.All.
- Condition: schedule.interval ne `PT40M` (threshold `entra.provisioning-expected-interval`).
  Duration comparison is an engine gap; equality on the text is enough here.
- Refs: NIST-800-53:AC-2.
- Fix: clear the quarantine; reset the schedule.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/synchronization-synchronizationschedule?view=graph-rest-1.0

### ENTRA-PROVISIONING-FAILURES-RECENT  (needs relative dates)
- Catches: provisioning failures in the last N days, grouped per app and error code, with the
  target's reason text. This is where "invalid patch request payload" (a rejected attribute mapping)
  and "user already exists with email" (a matching-attribute mismatch) show up by name and count.
- Severity: high when the count per app exceeds the threshold, else medium.
- Source: entra.yaml; v1.0; `/auditLogs/provisioning`; filter
  `activityDateTime ge {DAYS_AGO:7} and provisioningStatusInfo/status eq 'failure'`; select id,
  activityDateTime, provisioningAction, provisioningStatusInfo, servicePrincipal, sourceIdentity,
  targetIdentity, targetSystem, jobId, cycleId, provisioningSteps; key
  `{servicePrincipal[].id}|{provisioningStatusInfo.errorInformation.errorCode}` (one finding per app
  and error code; the engine's template key groups rows and the evidence carries the row count and a
  sample reason); maxPages capped. New query. Permission note: the log API returns at most the last
  30 days.
- Permission: AuditLog.Read.All.
- Condition: `each: any` keyed as above; severity high when the grouped row count ge 50 (threshold
  `entra.provisioning-failures-high-count`) - needs the engine to expose the per-key row count
  (see gaps; until then one finding per row with the first N rows). Error texts to match (threshold
  regexes, examples only): `errorInformation.reason` match `invalid patch|already exists|duplicate`
  raises the evidence hint "mapping rejected by target" / "matching attribute mismatch".
- Refs: NIST-800-53:AC-2, NIST-800-53:SI-4, CIS-Controls-v8:5.1.
- Fix: for "invalid patch/payload": remove or correct the attribute mapping the target rejects
  (look at the step details for the attribute name); for "already exists": add the target's email as
  a second matching attribute or clean the duplicate in the target; then restart the job.
- Confidence: verified resource and filterable properties (activityDateTime; provisioningStatusInfo
  filter likely) - https://learn.microsoft.com/en-us/graph/api/resources/provisioningobjectsummary?view=graph-rest-1.0,
  https://learn.microsoft.com/en-us/graph/api/resources/provisioningstatusinfo?view=graph-rest-1.0,
  errorInformation fields likely - https://learn.microsoft.com/en-us/graph/api/resources/provisioningerrorinfo?view=graph-rest-1.0.

### ENTRA-PROVISIONING-SKIPPED-NOT-ASSIGNED-RECENT  (needs relative dates)
- Catches: objects skipped in the last N days because the user is not assigned to the application
  (Entra's "NotEffectivelyEntitled" skip). A skipped new hire is the exact failure of the case: the
  user exists, the app exists, the job runs, and the person is not in the group that is assigned.
- Severity: medium (high when the same user is skipped repeatedly).
- Source: entra.yaml; v1.0; `/auditLogs/provisioning`; filter
  `activityDateTime ge {DAYS_AGO:7} and provisioningStatusInfo/status eq 'skipped'`; same select as
  above; key `{servicePrincipal[].id}|{sourceIdentity.id}`. Second query on the same endpoint
  (different filter); if the engine can filter client-side, fetch failures and skips in one call
  with `status ne 'success'` and split by condition.
- Permission: AuditLog.Read.All.
- Condition: `provisioningSteps[].description` match `NotEffectivelyEntitled|not assigned|not in scope`
  (threshold `entra.provisioning-skip-not-assigned-pattern`) or
  `provisioningSteps[].details` match the same.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.1, CIS-Controls-v8:6.1.
- Fix: add the user (or the group onboarding fills) to the app's assignment; fix the onboarding
  step that fills the wrong group (see the two rules below).
- Confidence: skip-reason text is likely (observed in the portal and the provisioning log export,
  not an enum) - https://learn.microsoft.com/en-us/graph/api/resources/provisioningstep?view=graph-rest-1.0.
  Confirm the exact wording on the first run and fix the default pattern.

### ENTRA-USER-NEW-NOT-IN-ACCESS-GROUP  (needs relative dates)
- Catches: an enabled member created in the last N days who is in none of the groups that grant
  the provisioned apps. The direct detector for "new hire missing from the assigned group".
- Severity: medium.
- Source: entra.yaml; v1.0; `/users`; filter
  `createdDateTime ge {DAYS_AGO:30} and accountEnabled eq true and userType eq 'Member'`; select id,
  userPrincipalName, createdDateTime, department, employeeType; expand `transitiveMemberOf($select=id)`;
  key id, name userPrincipalName. New query (small: only recent users).
- Permission: User.Read.All + GroupMember.Read.All.
- Condition: `transitiveMemberOf[].id` notin threshold `entra.access-group-ids` (the tenant fills it
  with the group ids assigned to its provisioned apps; empty list = rule n/a, never a pass).
  Generic alternative without a threshold: a `store` rule joining row_seen of this query with
  row_seen of ENTRA-GROUP-APP-ASSIGNED-RECENT-JOINERS below (set difference) - see gaps.
- Refs: NIST-800-53:AC-2(1), CIS-Controls-v8:6.1, CIS-Controls-v8:5.1.
- Fix: add the user to the access group; fix the onboarding step so it targets the assigned group.
- Confidence: likely (`$expand=transitiveMemberOf` on users is documented; the createdDateTime
  filter on users is supported) - https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0

### ENTRA-GROUP-ONBOARDING-NOT-ASSIGNED  (threshold list)
- Catches: a group that onboarding fills (tenant-named) that is no longer assigned to any
  application. The "stale onboarding group": joiners keep landing in it and nothing happens.
- Severity: high (it silently breaks every new hire).
- Source: entra.yaml; v1.0; `/groups`; filter `id in (<threshold list>)` or `for_each` over the
  threshold list `entra.onboarding-group-ids` → `/groups/{id}/appRoleAssignments`; fields id,
  resourceId, resourceDisplayName, principalDisplayName; key `{group}` (parent).
- Permission: GroupMember.Read.All (Group.Read.All) + Application.Read.All.
- Condition: per group, count none (no appRoleAssignments). Empty threshold = n/a.
- Refs: NIST-800-53:AC-2(1), CIS-Controls-v8:6.1.
- Fix: assign the group to the app again, or point onboarding at the assigned group and retire
  this one.
- Confidence: verified (group appRoleAssignments is a v1.0 relationship) -
  https://learn.microsoft.com/en-us/graph/api/group-list-approleassignments?view=graph-rest-1.0

### ENTRA-GROUP-RECENT-JOINERS-NO-APP  (needs per-object queries and relative dates; generic form)
- Catches: any group that gained N or more members created in the last 30 days and is assigned to no
  application - the stale onboarding group found without naming it.
- Severity: medium.
- Source: entra.yaml; v1.0; step 1 `/groups?$filter=securityEnabled eq true&$select=id,displayName`
  with `$expand=appRoleAssignments($select=id)` (if two expands on groups are refused, keep
  appRoleAssignments as the expand and get members per object); step 2 `for_each` groups where
  appRoleAssignments empty → `/groups/{id}/members/microsoft.graph.user?$filter=createdDateTime ge {DAYS_AGO:30}&$count=true&$select=id`
  with `consistency: eventual`; key = group id; rows = recent members.
- Permission: GroupMember.Read.All + Application.Read.All.
- Condition: per group, count ge 5 (threshold `entra.onboarding-recent-joiners-min`) rows.
- Refs: NIST-800-53:AC-2(1), CIS-Controls-v8:6.1.
- Fix: as above.
- Confidence: likely (createdDateTime filter on members with advanced query is documented for
  users; on the members cast it needs `ConsistencyLevel: eventual`) -
  https://learn.microsoft.com/en-us/graph/aad-advanced-queries. The fan-out is one call per
  unassigned security group - bound it with a page cap or the threshold list rule above.

### ENTRA-PROVISIONING-MAPPING-SUSPECT  (needs chained per-object queries)
- Catches: attribute mappings in a job's schema that use expressions (functions) or flow
  attributes the target commonly rejects, and matching rules that key on a single attribute. It is a
  review list, not a verdict: the real evidence is the error log above; this shows where to look.
- Severity: low (info).
- Source: entra.yaml; v1.0; `for_each` over the jobs fetched above →
  `/servicePrincipals/{sp}/synchronization/jobs/{id}/schema`; rows: one per
  `synchronizationRules[].objectMappings[].attributeMappings[]` would need the engine to flatten
  nested arrays with parent context (gap); until then one row per schema with array leaves. Fields:
  synchronizationRules[].objectMappings[].attributeMappings[].targetAttributeName,
  .matchingPriority, .source.type, .source.expression, .flowType; objectMappings[].enabled, .scope.
- Permission: Synchronization.Read.All.
- Condition: `source.type` eq Function (an expression) or `source.expression` match threshold
  `entra.provisioning-suspect-expression-pattern` (empty by default; the tenant adds the
  expression that failed once, so the check follows the "seen once, check everywhere" rule); the
  single-matching-attribute case needs "count of elements with matchingPriority gt 0 eq 1" (gap).
- Refs: NIST-800-53:AC-2, NIST-800-53:CM-3.
- Fix: test the expression with "provision on demand" on one user; remove mappings the target
  rejects; add the target's email as a second matching attribute when the target keys on it.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/synchronization-synchronizationschema?view=graph-rest-1.0,
  https://learn.microsoft.com/en-us/graph/api/resources/synchronization-attributemapping?view=graph-rest-1.0

### ENTRA-SP-SSO-NO-ASSIGNMENT already exists; nothing to add for SSO in this case.

---

## Priority 2 - identity hardening, Intune security

### ENTRA-AU-NO-RESTRICTED-MANAGEMENT
- Catches: no restricted-management administrative unit exists. Without one, every User or
  Helpdesk Administrator can reset the password and MFA of the emergency-access and admin accounts;
  a restricted AU is the only Entra-native way to fence them.
- Severity: low (medium in tenants with many helpdesk admins).
- Source: entra.yaml; v1.0; `/directory/administrativeUnits`; select id, displayName,
  isMemberManagementRestricted, visibility, membershipType; key id, name displayName. New query.
- Permission: AdministrativeUnit.Read.All (Directory.Read.All also).
- Condition: must-exist - count lt 1 where isMemberManagementRestricted eq true.
- Refs: NIST-800-53:AC-6(5), NIST-800-53:AC-2(7), MITRE-ATTACK:T1098.
- Fix: create a restricted management AU holding the emergency-access and tier-0 admin accounts;
  assign scoped roles explicitly.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/administrativeunit?view=graph-rest-1.0

### ENTRA-AUTHZ-MSOL-POWERSHELL-ALLOWED
- Catches: the legacy MSOnline/Azure AD Graph PowerShell access is not blocked for non-admins.
  Those modules enumerate the whole directory with any user credential (ROADtools' first step) and
  bypass newer Graph consent controls.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-AUTHZ; field blockMsolPowerShell.
- Permission: Policy.Read.All.
- Condition: blockMsolPowerShell eq false (or absent → n/a).
- Refs: NIST-800-53:AC-6, NIST-800-53:CM-7, MITRE-ATTACK:T1087.004.
- Fix: set blockMsolPowerShell to true (admins keep access).
- Confidence: verified field (authorizationPolicy) - https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0

### ENTRA-AUTHM-REPORT-SUSPICIOUS-OFF
- Catches: "report suspicious activity" is not enabled, so a user who gets an MFA push they did not
  ask for has no button that raises the account's risk to high and blocks it.
- Severity: low.
- Source: entra.yaml; beta (the setting exists only in beta);
  `/policies/authenticationMethodsPolicy`; field reportSuspiciousActivitySettings.state,
  .includeTarget.id; key id. Same beta query as ENTRA-AUTHM-SYSTEM-PREFERRED-OFF (reuse).
- Permission: Policy.Read.All.
- Condition: reportSuspiciousActivitySettings.state ne enabled, or includeTarget.id ne all_users.
- Refs: CIS-M365:5.2.3.3, NIST-800-53:IR-6, MITRE-ATTACK:T1621.
- Fix: enable it for all users; route the raised risk into the user-risk policy.
- Confidence: verified property on the beta resource - https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy?view=graph-rest-beta
  (state/includeTarget sub-fields likely - https://learn.microsoft.com/en-us/graph/api/resources/reportsuspiciousactivitysettings?view=graph-rest-beta).

### ENTRA-GUEST-CONSUMER-DOMAIN
- Catches: guests invited from consumer mail domains. A gmail guest is an identity with no
  organisation behind it: no MFA you can trust, no leaver process, often a former employee's
  personal address.
- Severity: low (medium when the guest is in a privileged or app-assigned group - join, later).
- Source: entra.yaml; v1.0; shared query Q-USERS (userPrincipalName encodes the invited address).
- Permission: User.Read.All.
- Condition: userType eq Guest and accountEnabled true and userPrincipalName match
  `_(gmail|googlemail|outlook|hotmail|live|yahoo|icloud|proton(mail)?)\.com#EXT#` (threshold
  `entra.consumer-mail-pattern`).
- Refs: NIST-800-53:AC-2(9), NIST-800-53:AC-20, CIS-Controls-v8:6.2.
- Fix: replace with a guest from the partner's organisational tenant, or document the exception
  and give it an access review.
- Confidence: verified.

### ENTRA-CA-BASELINE-WORKLOAD-IDENTITY-BLOCK
- Catches: no enforced policy restricts where single-tenant service principals may sign in from.
  A leaked app secret then works from anywhere; a workload-identity policy limits it to the known
  egress ranges. Needs Workload Identities Premium.
- Severity: low.
- Source: entra.yaml; v1.0; shared query Q-CA; fields
  conditions.clientApplications.includeServicePrincipals, grantControls, conditions.locations.
- Permission: Policy.Read.All.
- Condition: must-exist - count lt 1 where state enabled and
  conditions.clientApplications.includeServicePrincipals contains ServicePrincipalsInMyTenant and
  grantControls.builtInControls contains block and conditions.locations.excludeLocations notempty.
- Refs: NIST-800-53:AC-17, NIST-800-53:SC-7, MITRE-ATTACK:T1078.004.
- Fix: create a workload-identity policy blocking all service principals except from trusted named
  locations; exclude the identities that must roam.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-1.0

### INTUNE-ESEC-ANTIVIRUS-NONE / -FIREWALL-NONE / -DISK-ENCRYPTION-NONE / -EDR-NONE / -ASR-NONE  (five rules, one query)
- Catches: no assigned endpoint-security policy of the family (Antivirus, Firewall, Disk
  encryption, Endpoint detection and response, Attack surface reduction) exists for Windows. These
  are the Defender settings visible in Graph without reading each setting: the settings-catalog
  policy carries its template family. Closes part of the backlog "settings catalog and endpoint
  security content" (existence and assignment; not the settings' values).
- Severity: medium each (EDR and Antivirus high in tenants with Defender for Endpoint licences).
- Source: intune.yaml; beta (configurationPolicies are beta only);
  `/deviceManagement/configurationPolicies`; select id, name, platforms, technologies, isAssigned,
  settingCount, templateReference, createdDateTime, lastModifiedDateTime; key id, name name. New
  query shared by the five rules and the two below.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: must-exist per rule - count lt 1 where isAssigned eq true and platforms contains
  windows10 and templateReference.templateFamily eq <endpointSecurityAntivirus |
  endpointSecurityFirewall | endpointSecurityDiskEncryption |
  endpointSecurityEndpointDetectionAndResponse | endpointSecurityAttackSurfaceReduction>.
- Refs: NIST-800-53:SI-3, NIST-800-53:SC-7, NIST-800-53:SC-28, NIST-800-53:SI-4, NIST-800-53:CM-7;
  CIS-Controls-v8:10.1, 4.5, 3.6, 13.7, 10.5 respectively; MITRE-ATTACK:T1562.001 for AV/EDR.
- Fix: create the endpoint security policy from its template (or a security baseline) and assign it
  to all Windows devices; check the per-device report for errors.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationpolicytemplatereference?view=graph-rest-beta
  and ...devicemanagementconfigurationpolicy?view=graph-rest-beta (isAssigned, platforms).

### INTUNE-ESEC-LAPS-NONE
- Catches: no assigned Windows LAPS policy (account protection family with the LAPS template).
  ENTRA-DEVREG-LAPS-OFF checks the Entra switch; without the Intune policy no password is ever
  backed up.
- Severity: medium.
- Source: same query as above.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: must-exist - count lt 1 where isAssigned true and templateReference.templateFamily eq
  endpointSecurityAccountProtection and templateReference.templateDisplayName match `LAPS`
  (threshold `intune.laps-template-name-pattern`).
- Refs: CIS-M365:5.1.4.5, NIST-800-53:IA-5(1), MITRE-ATTACK:T1078.003.
- Fix: create the LAPS policy (backup to Entra, rotation 30 days or less) and assign it.
- Confidence: templateDisplayName text likely ("Local admin password solution (Windows LAPS)").

### INTUNE-ESEC-BASELINE-NONE
- Catches: no assigned security baseline (templateFamily baseline) exists. A baseline is the
  cheapest way to close the hundreds of unset hardening settings the field review found.
- Severity: low.
- Source: same query.
- Condition: must-exist - count lt 1 where isAssigned true and templateReference.templateFamily
  eq baseline.
- Refs: NIST-800-53:CM-6, CIS-Controls-v8:4.1.
- Fix: deploy the Windows security baseline (and the Defender and Edge baselines) to a pilot, then
  broadly.
- Confidence: verified enum.

### INTUNE-COMPLIANCE-IOS-NONE / -ANDROID-NONE / -MACOS-NONE  (three rules, shared query)
- Catches: no assigned compliance policy for the platform. Approximates the backlog item
  "compliance policy exists for every platform that has managed devices": the device-count half
  needs a join, so a tenant with no such devices accepts the finding once. The platform is told by
  type-specific fields because `@odata.type` is not addressable (gap).
- Severity: medium.
- Source: intune.yaml; v1.0; shared query Q-COMPLIANCE-ASSIGN (expand assignments; no select, all
  typed fields come back).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: must-exist - count lt 1 where assignments notempty and the platform marker exists:
  iOS = `passcodeBlockSimple` exists; macOS = `systemIntegrityProtectionEnabled` exists; Android =
  `securityRequireSafetyNetAttestationBasicIntegrity` exists (Android work profile and device owner
  policies are beta-only types - use Q-COMPLIANCE-BETA plus `$expand=assignments` for the Android
  rule, or accept legacy-Android-only coverage in v1.0).
- Refs: CIS-M365:4.1, NIST-800-53:CM-6, NIST-800-53:AC-19.
- Fix: create and assign the platform's compliance policy (passcode, encryption, OS minimum,
  jailbreak/root block, threat level).
- Confidence: verified field names (windows10/macOS pages read; iOS and Android pages likely) -
  https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-macoscompliancepolicy?view=graph-rest-1.0

### INTUNE-COMPLIANCE-NO-THREAT-LEVEL
- Catches: a compliance policy that ignores the device threat level while a threat-defence
  connector exists; a device with active malware stays compliant and keeps its Conditional Access
  pass. (Pair with INTUNE-MTD-NONE: with no connector this rule is moot.)
- Severity: medium.
- Source: intune.yaml; beta; shared query Q-COMPLIANCE-BETA (the Windows
  deviceThreatProtectionEnabled field is beta-only).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: deviceThreatProtectionEnabled eq false (absent → n/a for policy types without it).
- Refs: NIST-800-53:SI-3, NIST-800-53:SI-4, CIS-Controls-v8:10.1.
- Fix: enable "require the device to be at or under the machine risk score" (Windows) / threat
  level (mobile) in each compliance policy.
- Confidence: verified for macOS (v1.0); Windows field beta likely.

### INTUNE-COMPLIANCE-MOBILE-NO-PASSWORD
- Catches: a mobile compliance policy that does not require a device passcode at all.
- Severity: medium.
- Source: intune.yaml; beta; Q-COMPLIANCE-BETA.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: any of: passcodeRequired eq false (iOS); (securityBlockJailbrokenDevices exists and
  passwordRequired eq false) (Android types); (systemIntegrityProtectionEnabled exists and
  passwordRequired eq false) (macOS).
- Refs: NIST-800-53:IA-5(1), NIST-800-53:AC-19, CIS-Controls-v8:4.3.
- Fix: require a passcode of 6 digits or more with a short inactivity lock.
- Confidence: verified (macOS/Windows), likely (iOS/Android field names).

### INTUNE-COMPLIANCE-WINDOWS-NO-AV
- Catches: a Windows compliance policy that requires neither Defender/antivirus nor real-time
  protection, so a PC with AV disabled is compliant.
- Severity: medium.
- Source: intune.yaml; beta; Q-COMPLIANCE-BETA (fields defenderEnabled, rtpEnabled,
  antivirusRequired, antiSpywareRequired, activeFirewallRequired, tpmRequired are beta-only on
  windows10CompliancePolicy).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: bitLockerEnabled exists (Windows marker) and defenderEnabled eq false and rtpEnabled eq
  false and antivirusRequired eq false.
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.1, MITRE-ATTACK:T1562.001.
- Fix: turn on "Microsoft Defender Antimalware", "real-time protection" and "antivirus required" in
  the policy.
- Confidence: likely (beta windows10CompliancePolicy) -
  https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows10compliancepolicy?view=graph-rest-beta

### INTUNE-COMPLIANCE-WINDOWS-NO-HEALTH-ATTESTATION
- Catches: a Windows compliance policy that requires none of the device-health attestation
  checks (secure boot, code integrity, BitLocker via DHA, early-launch antimalware) nor a TPM.
- Severity: low.
- Source: intune.yaml; v1.0; Q-COMPLIANCE-ASSIGN (fields verified in v1.0).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: bitLockerEnabled exists and bitLockerEnabled eq false and secureBootEnabled eq false
  and codeIntegrityEnabled eq false and earlyLaunchAntiMalwareDriverEnabled eq false.
- Refs: NIST-800-53:SI-7, NIST-800-53:SC-28, CIS-Controls-v8:3.6.
- Fix: require secure boot and code integrity (and BitLocker) through device health attestation.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows10compliancepolicy?view=graph-rest-1.0

### INTUNE-COMPLIANCE-MACOS-WEAK
- Catches: a macOS compliance policy that requires neither FileVault, the firewall nor System
  Integrity Protection.
- Severity: medium.
- Source: intune.yaml; v1.0; Q-COMPLIANCE-ASSIGN.
- Condition: systemIntegrityProtectionEnabled exists and (storageRequireEncryption eq false or
  firewallEnabled eq false or systemIntegrityProtectionEnabled eq false).
- Refs: NIST-800-53:SC-28, NIST-800-53:SC-7, NIST-800-53:SI-7.
- Fix: require all three in the macOS policy.
- Confidence: verified (page read).

### INTUNE-COMPLIANCE-ANDROID-NO-ENCRYPTION
- Catches: an Android compliance policy that does not require storage encryption.
- Severity: medium.
- Source: intune.yaml; beta; Q-COMPLIANCE-BETA.
- Condition: securityRequireSafetyNetAttestationBasicIntegrity exists and storageRequireEncryption
  eq false.
- Refs: NIST-800-53:SC-28, NIST-800-53:AC-19.
- Fix: require encryption (Android Enterprise devices are encrypted by default; the setting still
  documents the requirement for legacy enrolments).
- Confidence: likely.

### INTUNE-UPDATE-RING-NONE
- Catches: no assigned Windows Update ring. Without a ring, update behaviour is whatever the
  device's local policy says - usually deferred by users forever.
- Severity: medium.
- Source: intune.yaml; v1.0; shared query Q-DEVICECONFIG (expand assignments, typed fields
  returned). The ring is a windowsUpdateForBusinessConfiguration row, told by
  `qualityUpdatesDeferralPeriodInDays` existing.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: must-exist - count lt 1 where qualityUpdatesDeferralPeriodInDays exists and
  assignments notempty.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.3.
- Fix: create a pilot and a broad update ring; assign the broad ring to all Windows devices.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowsupdateforbusinessconfiguration?view=graph-rest-1.0

### INTUNE-UPDATE-RING-QUALITY-PAUSED
- Catches: an update ring with quality (security) updates paused. Pauses are set during an
  incident and forgotten; Microsoft lifts them after 35 days, but that is 35 days of no patches.
- Severity: medium (high when the pause expiry is more than 14 days away).
- Source: Q-DEVICECONFIG.
- Condition: qualityUpdatesPaused eq true and assignments notempty; deadline
  qualityUpdatesPauseExpiryDateTime.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.3.
- Fix: resume quality updates; if a specific update breaks something, use the rollback or a
  targeted exclusion instead of a pause.
- Confidence: verified.

### INTUNE-UPDATE-RING-NO-DEADLINE
- Catches: an assigned ring with no quality-update deadline (deadlineForQualityUpdatesInDays absent
  or 0 with automaticUpdateMode userDefined), so users can postpone restarts indefinitely.
- Severity: low.
- Source: Q-DEVICECONFIG.
- Condition: qualityUpdatesDeferralPeriodInDays exists and assignments notempty and
  (deadlineForQualityUpdatesInDays absent or deadlineForQualityUpdatesInDays gt 7, threshold
  `intune.quality-update-deadline-max-days`) - 0 means "install at the deadline immediately", so
  only absent and large values fail.
- Refs: NIST-800-53:SI-2(2), CIS-Controls-v8:7.3.
- Fix: set a quality-update deadline of 3-7 days and a grace period of 1-2 days.
- Confidence: verified.

### INTUNE-FEATURE-UPDATE-PROFILE-EOS
- Catches: a feature-update profile that pins devices to a Windows version at or past its end of
  support. Closes the backlog item "feature-update targets".
- Severity: by endOfSupportDate - past: high; within 90 days: medium.
- Source: intune.yaml; beta; `/deviceManagement/windowsFeatureUpdateProfiles`; select id,
  displayName, featureUpdateVersion, endOfSupportDate, installFeatureUpdatesOptional,
  lastModifiedDateTime; expand assignments; key id, name displayName; deadline endOfSupportDate.
  New query.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: assignments notempty and endOfSupportDate until-lt 90 (threshold
  `intune.feature-update-eos-notice-days`).
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22.
- Fix: retarget the profile to a serviced release.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-softwareupdate-windowsfeatureupdateprofile?view=graph-rest-beta

### INTUNE-AUTOPILOT-PROFILE-USER-ADMIN
- Catches: an Autopilot deployment profile that makes the enrolling user a local administrator
  (userType administrator). Every new PC then ships with its owner as admin - the install-rights
  and malware problem at the source.
- Severity: medium.
- Source: intune.yaml; beta (profiles are beta only);
  `/deviceManagement/windowsAutopilotDeploymentProfiles`; select id, displayName,
  outOfBoxExperienceSetting, preprovisioningAllowed, deviceNameTemplate, lastModifiedDateTime;
  expand assignments; key id, name displayName. New query.
- Permission: DeviceManagementServiceConfig.Read.All.
- Condition: outOfBoxExperienceSetting.userType eq administrator (fall back to
  outOfBoxExperienceSettings.userType, deprecated) and assignments notempty.
- Refs: CIS-M365:5.1.4.4, NIST-800-53:AC-6(1), MITRE-ATTACK:T1078.003.
- Fix: set the user account type to Standard; grant local admin through Entra LAPS or a managed
  group where needed.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-windowsautopilotdeploymentprofile?view=graph-rest-beta

### INTUNE-MAM-DATA-TRANSFER-OPEN  (-IOS, -ANDROID: two rules)
- Catches: an app protection policy that lets corporate data leave managed apps (transfer to any
  app, clipboard to any app, Save As allowed, backup allowed). An MAM policy with these open is
  the "no protections" case from the backlog.
- Severity: medium.
- Source: intune.yaml; v1.0; shared queries Q-MAM-IOS and Q-MAM-ANDROID (no select, all fields).
- Permission: DeviceManagementApps.Read.All.
- Condition: allowedOutboundDataTransferDestinations eq allApps or
  allowedOutboundClipboardSharingLevel eq allApps or saveAsBlocked eq false or dataBackupBlocked eq
  false.
- Refs: NIST-800-53:AC-19, NIST-800-53:SC-28, NIST-800-53:AC-20(3), CIS-Controls-v8:3.1.
- Fix: set transfer and clipboard to managed apps only, block Save As except to OneDrive/SharePoint,
  block backup.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-managedappprotection?view=graph-rest-1.0

### INTUNE-MAM-NO-PIN  (-IOS, -ANDROID)
- Catches: an app protection policy without an app PIN (or with PIN but no root/jailbreak block
  through deviceComplianceRequired).
- Severity: medium.
- Source: same shared queries.
- Condition: pinRequired eq false or deviceComplianceRequired eq false.
- Refs: NIST-800-53:IA-5(1), NIST-800-53:AC-19, NIST-800-53:SI-7.
- Fix: require a 6-digit PIN with biometric override, block rooted and jailbroken devices.
- Confidence: verified.

### INTUNE-MAM-UNASSIGNED  (-IOS, -ANDROID)
- Catches: an app protection policy assigned to nobody - written, never rolled out.
- Severity: low.
- Source: same shared queries; field isAssigned (targetedManagedAppProtection).
- Condition: isAssigned eq false.
- Refs: NIST-800-53:CM-6.
- Fix: assign to the user groups it was written for, or delete it.
- Confidence: likely (isAssigned on targetedManagedAppProtection) -
  https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-targetedmanagedappprotection?view=graph-rest-1.0

### INTUNE-DEVICE-DEFENDER-RTP-OFF / -SIGNATURES-OVERDUE / -TAMPER-OFF  (three rules, one query)
- Catches: Windows devices whose Defender state reports real-time protection off, signatures out
  of date, or tamper protection off (and, as evidence, deviceState critical / rebootPending).
  This is Defender per device, read from Intune, without the Defender API.
- Severity: RTP off: high; tamper off: medium; signatures overdue: medium.
- Source: intune.yaml; v1.0; `/deviceManagement/managedDevices`; filter
  `operatingSystem eq 'Windows'`; select id, deviceName, userPrincipalName, lastSyncDateTime;
  expand windowsProtectionState; key id, name deviceName. New query (separate from Q-MDEVICES because
  of the expand).
- Permission: DeviceManagementManagedDevices.Read.All.
- Condition: lastSyncDateTime age-lt 30 and (windowsProtectionState.realTimeProtectionEnabled eq
  false | windowsProtectionState.signatureUpdateOverdue eq true |
  windowsProtectionState.tamperProtectionEnabled eq false). Absent windowsProtectionState → n/a.
- Refs: NIST-800-53:SI-3, NIST-800-53:SI-3(2), MITRE-ATTACK:T1562.001, CIS-Controls-v8:10.1, 10.2.
- Fix: enforce through the Antivirus and tamper-protection endpoint security policies; investigate
  devices that keep turning it off.
- Confidence: field names verified (v1.0) -
  https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-windowsprotectionstate?view=graph-rest-1.0;
  `$expand=windowsProtectionState` on the LIST is a guess (documented per device). If refused:
  `for_each` Q-MDEVICES (Windows rows) → `/deviceManagement/managedDevices/{id}/windowsProtectionState`.

### INTUNE-REMEDIATION-SCRIPT-ERRORS
- Catches: a remediation (proactive remediation) script whose detection or remediation errors on
  devices. Closes backlog item INT-005 (the permission is the only blocker).
- Severity: medium.
- Source: intune.yaml; beta; `/deviceManagement/deviceHealthScripts`; select id, displayName,
  publisher, isGlobalScript, runAsAccount, lastModifiedDateTime; expand runSummary; key id, name
  displayName. New query.
- Permission: DeviceManagementScripts.Read.All (403 without it - add to the permissions table).
- Condition: runSummary.detectionScriptErrorDeviceCount gt 0 or
  runSummary.remediationScriptErrorDeviceCount gt 0 or runSummary.remediationFailedDeviceCount gt 0
  (threshold `intune.script-error-devices-max`, default 0).
- Refs: NIST-800-53:CM-6, NIST-800-53:SI-2.
- Fix: open the script's device status, read the error output, fix the script or the device.
- Confidence: verified (runSummary relationship; its count field names likely) -
  https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-devicehealthscript?view=graph-rest-beta,
  https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-devicehealthscriptrunsummary?view=graph-rest-beta

### INTUNE-CONFIG-PROFILE-ERRORS
- Catches: per configuration profile, devices in error or failed. Closes backlog item INT-003
  (per-profile status; the tenant summary rules stay).
- Severity: medium.
- Source: intune.yaml; v1.0; shared query Q-DEVICECONFIG with the expand extended to
  `assignments,deviceStatusOverview` (one fetch for the unassigned rule, the update-ring rules and
  this one).
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: deviceStatusOverview.errorCount gt 0 or deviceStatusOverview.failedCount gt 0
  (threshold `intune.profile-error-devices-max`, default 0).
- Refs: NIST-800-53:CM-6.
- Fix: open the profile's device status and fix the failing setting.
- Confidence: likely (deviceStatusOverview is an inherited relationship on deviceConfiguration; the
  compliance equivalent is already used and listed "to confirm").

### INTUNE-NDES-CONNECTOR-INACTIVE
- Catches: a certificate connector (NDES/PKCS) that is inactive or has not connected for N days -
  SCEP/PKCS certificate issuance to devices silently stops (Wi-Fi, VPN).
- Severity: medium.
- Source: intune.yaml; v1.0; `/deviceManagement/ndesConnectors`; select id, displayName, state,
  lastConnectionDateTime; key id, name displayName. New query.
- Permission: DeviceManagementConfiguration.Read.All.
- Condition: state eq inactive or lastConnectionDateTime age-gt 1 (threshold
  `intune.connector-max-age-days`).
- Refs: NIST-800-53:SC-17, NIST-800-53:SI-4.
- Fix: check the connector service and its account on the server; reinstall or re-enrol it.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-ndesconnector?view=graph-rest-1.0

---

## Priority 3 - hygiene, cost, maintenance

### ENTRA-GUEST-NO-SPONSOR
- Catches: a guest with no sponsor, so nobody is accountable for renewing or removing them.
- Severity: low.
- Source: entra.yaml; v1.0; `/users`; filter `userType eq 'Guest'`; select id, userPrincipalName,
  createdDateTime, accountEnabled; expand `sponsors($select=id)`; top 999; key id. New query.
- Permission: User.Read.All.
- Condition: accountEnabled true and sponsors empty.
- Refs: NIST-800-53:AC-2(9), CIS-Controls-v8:6.2.
- Fix: set the inviter or the owning team as sponsor; require a sponsor in the invitation flow.
- Confidence: verified (`sponsors` supports `$expand`) - https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0

### ENTRA-SP-SIGNIN-STALE
- Catches: an application that has not signed in (as itself or on behalf of users) for N days,
  from the service-principal sign-in activity report - the unused-app half of backlog item
  ENTRA-APP-12 (the "with high-impact permissions" half still needs the join).
- Severity: low.
- Source: entra.yaml; beta (report exists only in beta); `/reports/servicePrincipalSignInActivities`;
  fields id, appId, lastSignInActivity.lastSignInDateTime,
  applicationAuthenticationClientSignInActivity.lastSignInDateTime,
  delegatedClientSignInActivity.lastSignInDateTime; key appId. New query. Note: apps that never
  signed in are absent from the report, so this rule cannot see them - keep ENTRA-APP-CREDENTIALS-ALL-EXPIRED.
- Permission: AuditLog.Read.All.
- Condition: lastSignInActivity.lastSignInDateTime age-gt 90 (threshold `entra.app-inactive-days`).
- Refs: NIST-800-53:AC-2(3), NIST-800-53:CM-8(3).
- Fix: confirm with the owner; remove grants and credentials, then delete the app.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipalsigninactivity?view=graph-rest-beta

### ENTRA-CA-TARGETS-NOBODY
- Catches: an enabled policy whose user scope is empty (no users, groups, roles or external users
  included) - it protects nothing but looks like a control.
- Severity: low.
- Source: Q-CA.
- Condition: state enabled and conditions.users.includeUsers empty and includeGroups empty and
  includeRoles empty and includeGuestsOrExternalUsers absent.
- Refs: NIST-800-53:CM-3.
- Fix: scope or delete it.
- Confidence: verified.

### ENTRA-CA-RESILIENCE-DEFAULTS-OFF
- Catches: an enabled policy with resilience defaults disabled; during an Entra outage its users
  are blocked instead of served from the backup authentication service.
- Severity: low (availability).
- Source: Q-CA; field sessionControls.disableResilienceDefaults.
- Condition: state enabled and sessionControls.disableResilienceDefaults eq true.
- Refs: NIST-800-53:CP-2, NIST-800-53:CP-10.
- Fix: re-enable resilience defaults unless the policy relies on real-time risk.
- Confidence: verified field (conditionalAccessSessionControls).

### ENTRA-CA-BASELINE-UNKNOWN-PLATFORMS-BLOCKED
- Catches: no enforced policy blocks device platforms other than the ones the organisation
  supports (include all platforms, exclude the supported ones, grant block). Unknown platforms
  (Linux, unrecognised user agents) otherwise get the weakest treatment.
- Severity: low.
- Source: Q-CA.
- Condition: must-exist - count lt 1 where state enabled and includeUsers contains All and
  conditions.platforms.includePlatforms contains all and conditions.platforms.excludePlatforms
  notempty and grantControls.builtInControls contains block.
- Refs: NIST-800-53:AC-19, NIST-800-53:CM-7.
- Fix: create the block-unknown-platforms policy in report-only first, then enforce.
- Confidence: verified.

### ENTRA-GROUP-DYNAMIC-GUEST-CONTROLLED-ATTRIBUTE
- Catches: a dynamic group whose rule matches on attributes a guest's home tenant controls (mail,
  otherMails, displayName, givenName, surname, companyName) without excluding guests. A partner can
  put themselves in the group - and in whatever the group grants.
- Severity: low (medium when the group is role-assignable or app-assigned - join, later).
- Source: entra.yaml; v1.0; shared query used by ENTRA-GROUP-DYNAMIC-PAUSED (membershipRule,
  groupTypes selected).
- Condition: groupTypes contains DynamicMembership and membershipRule match
  `user\.(mail|otherMails|proxyAddresses|displayName|givenName|surname|companyName)\b` and
  membershipRule notmatch `userType\s*-?eq\s*"?Member"?` (threshold patterns
  `entra.dynamic-rule-external-attribute-pattern`, `entra.dynamic-rule-member-guard-pattern`).
- Refs: NIST-800-53:AC-2(9), NIST-800-53:AC-3, MITRE-ATTACK:T1199.
- Fix: add `(user.userType -eq "Member")` to the rule or key it on an admin-set attribute
  (extensionAttribute, employeeId, department from HR).
- Confidence: verified.

### ENTRA-LIFECYCLE-NO-LEAVER-WORKFLOW
- Catches: no enabled Lifecycle Workflow for leavers - offboarding is a manual checklist, and the
  pack's "disabled user still has X" findings are the proof it is skipped.
- Severity: low (needs Entra ID Governance).
- Source: entra.yaml; v1.0; `/identityGovernance/lifecycleWorkflows/workflows`; select id,
  displayName, category, isEnabled, isSchedulingEnabled; key id, name displayName. New query.
- Permission: LifecycleWorkflows.Read.All.
- Condition: must-exist - count lt 1 where category eq leaver and isEnabled true and
  isSchedulingEnabled true.
- Refs: NIST-800-53:PS-4, NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- Fix: enable the built-in "real-time employee termination" and "post-offboarding" templates.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/identitygovernance-workflow?view=graph-rest-1.0

### INTUNE-COMPLIANCE-NO-OS-MINIMUM
- Catches: an assigned compliance policy with no minimum OS version, so the "unsupported OS"
  device findings have no enforcement behind them.
- Severity: low.
- Source: Q-COMPLIANCE-BETA (all platforms).
- Condition: osMinimumVersion absent or empty (policy types with the field).
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22.
- Fix: set the minimum to the oldest release still receiving security updates.
- Confidence: verified (field present on every platform policy read).

### INTUNE-COMPLIANCE-UNKNOWN-DEVICES
- Catches: devices in compliance state unknown or not evaluated (tenant summary) - never judged.
- Severity: low.
- Source: intune.yaml; v1.0; `/deviceManagement/deviceCompliancePolicyDeviceStateSummary`; fields
  unknownDeviceCount, notApplicableDeviceCount, compliantDeviceCount, nonCompliantDeviceCount,
  errorDeviceCount, conflictDeviceCount, inGracePeriodCount, configManagerCount; key id. New query.
- Condition: unknownDeviceCount gt 0 (threshold `intune.unknown-compliance-devices-max`).
- Refs: NIST-800-53:CM-6, NIST-800-53:CM-8.
- Fix: force a sync; devices stuck unknown usually have a broken MDM certificate (see
  INTUNE-DEVICE-MGMT-CERT-EXPIRY).
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicecompliancepolicydevicestatesummary?view=graph-rest-1.0

### INTUNE-UPDATE-RING-QUALITY-DEFERRAL-LONG
- Catches: a broad ring deferring quality updates more than N days (default 7) - a month of
  known-exploited vulnerabilities on every PC.
- Severity: low.
- Source: Q-DEVICECONFIG.
- Condition: qualityUpdatesDeferralPeriodInDays gt 7 (threshold `intune.quality-deferral-max-days`)
  and assignments notempty. Pilot rings are expected to be 0; a long deferral on every ring is the
  finding - the evidence shows the ring name.
- Refs: NIST-800-53:SI-2(2), CIS-Controls-v8:7.3.
- Fix: 0-3 days pilot, 7 days broad; use deadlines rather than long deferrals.
- Confidence: verified.

### INTUNE-UPDATE-RING-MICROSOFT-PRODUCTS-OFF
- Catches: a ring with "updates for other Microsoft products" off, so Office, SQL and .NET
  servicing never arrives through Windows Update.
- Severity: low.
- Source: Q-DEVICECONFIG.
- Condition: microsoftUpdateServiceAllowed eq false and assignments notempty.
- Refs: NIST-800-53:SI-2.
- Fix: turn it on.
- Confidence: verified.

### INTUNE-ENROLL-NO-OS-MINIMUM
- Catches: platform enrolment restrictions with no minimum OS version, so out-of-support devices
  can still enrol and immediately fail compliance (or pass, with secureByDefault off).
- Severity: low.
- Source: intune.yaml; v1.0; shared query of INTUNE-ENROLL-* (`/deviceManagement/deviceEnrollmentConfigurations`).
- Condition: for each of windowsRestriction, iosRestriction, androidRestriction, macOSRestriction:
  restriction exists and platformBlocked eq false and osMinimumVersion empty.
- Refs: NIST-800-53:SI-2, CIS-M365:4.2.
- Fix: set the minimum version per platform in the default restriction.
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentplatformrestriction?view=graph-rest-1.0

### INTUNE-ENROLL-WHFB-WEAK
- Catches: the Windows Hello for Business enrolment configuration is disabled, or enabled with a
  PIN shorter than 6 or without requiring a TPM.
- Severity: low.
- Source: same enrolment query; the row is a deviceEnrollmentWindowsHelloForBusinessConfiguration
  (told by `pinMinimumLength` existing).
- Condition: pinMinimumLength exists and (state eq disabled or (state eq enabled and
  (pinMinimumLength lt 6 or securityDeviceRequired eq false))).
- Refs: NIST-800-53:IA-2(6), NIST-800-53:IA-5(1), CIS-Controls-v8:6.5.
- Fix: enable WHfB with TPM required and a 6+ digit PIN (passkeys for admins).
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentwindowshelloforbusinessconfiguration?view=graph-rest-1.0

### INTUNE-ENROLL-ESP-USE-ON-FAILURE
- Catches: the enrolment status page lets the user into the desktop when app installation
  fails (allowDeviceUseOnInstallFailure), so a PC without its security apps is usable.
- Severity: low.
- Source: same enrolment query; row is windows10EnrollmentCompletionPageConfiguration (told by
  `showInstallationProgress` existing).
- Condition: showInstallationProgress exists and allowDeviceUseOnInstallFailure eq true.
- Refs: NIST-800-53:CM-2, NIST-800-53:CM-6.
- Fix: block use on failure and collect logs; make the security apps the blocking apps.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-windows10enrollmentcompletionpageconfiguration?view=graph-rest-1.0

### INTUNE-DEVICE-IOS-CORPORATE-UNSUPERVISED
- Catches: a corporate-owned iPhone/iPad that is not supervised, so the restrictive
  configuration (app blocking, activation lock bypass, silent app install) does not apply.
- Severity: low.
- Source: intune.yaml; v1.0; shared query Q-MDEVICES with `isSupervised` added to the select (one
  fetch, 15 rules).
- Condition: operatingSystem match `^(iOS|iPadOS)$` and managedDeviceOwnerType eq company and
  isSupervised eq false and lastSyncDateTime age-lt 30.
- Refs: NIST-800-53:AC-19, NIST-800-53:CM-6.
- Fix: add the device to Apple Business Manager and re-enrol through automated device enrolment.
- Confidence: verified field (managedDevice.isSupervised).

### INTUNE-CLEANUP-RULE-OFF
- Catches: no device clean-up rule, so stale device records (INTUNE-DEVICE-STALE) never go away by
  themselves. Closes the backlog item "device clean-up rule".
- Severity: low.
- Source: intune.yaml; beta; `/deviceManagement`; select id, managedDeviceCleanupSettings; key id.
  New (beta) query.
- Permission: DeviceManagementServiceConfig.Read.All.
- Condition: managedDeviceCleanupSettings.deviceInactivityBeforeRetirementInDays absent or empty
  (the value is a string; `gt 90` once a number compare on text is confirmed).
- Refs: NIST-800-53:CM-8(3).
- Fix: set the rule to 90 days (or the stale threshold in use).
- Confidence: verified - https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevicecleanupsettings?view=graph-rest-beta

### INTUNE-PLATFORM-SCRIPT-ERRORS
- Catches: a PowerShell platform script with devices in error.
- Severity: low.
- Source: intune.yaml; beta; `/deviceManagement/deviceManagementScripts`; select id, displayName,
  runAsAccount, enforceSignatureCheck; expand runSummary; key id. New query.
- Permission: DeviceManagementScripts.Read.All (beta: DeviceManagementConfiguration.Read.All also
  listed; confirm).
- Condition: runSummary.errorDeviceCount gt 0.
- Refs: NIST-800-53:CM-6.
- Fix: read the device run states; fix or retire the script.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-devicemanagementscript?view=graph-rest-beta

### INTUNE-CONFIGPOLICY-UNASSIGNED
- Catches: a settings-catalog or endpoint-security policy assigned to nobody.
- Severity: low.
- Source: the beta configurationPolicies query above.
- Condition: isAssigned eq false.
- Refs: NIST-800-53:CM-2.
- Fix: assign or delete.
- Confidence: verified.

### M365-DOMAIN-DEFAULT-IS-INITIAL
- Catches: the tenant's default domain is still the initial `onmicrosoft.com` domain, so every new
  user and group gets an onmicrosoft address unless someone remembers to change it.
- Severity: low.
- Source: m365.yaml; v1.0; shared query Q-DOMAINS.
- Condition: isDefault eq true and isInitial eq true.
- Refs: NIST-800-53:CM-6.
- Fix: set the organisation's verified domain as default.
- Confidence: verified.

### M365-SPO-DELETED-ONEDRIVE-RETENTION-SHORT
- Catches: a deleted user's OneDrive is kept fewer than N days (Microsoft's default is 30), so a
  leaver's files are gone before the manager asks for them.
- Severity: low.
- Source: m365.yaml; v1.0; shared query Q-SPO; field deletedUserPersonalSiteRetentionPeriodInDays.
- Condition: deletedUserPersonalSiteRetentionPeriodInDays lt 90 (threshold
  `m365.onedrive-deleted-retention-min-days`).
- Refs: NIST-800-53:CP-9, NIST-800-53:PS-4.
- Fix: set the retention to 90-365 days.
- Confidence: verified field (sharepointSettings) - https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0

### M365-SPO-USER-SITE-CREATION
- Catches: any user can create SharePoint sites, which multiplies ownerless sites and external
  sharing surfaces.
- Severity: low.
- Source: Q-SPO; field isSiteCreationEnabled.
- Condition: isSiteCreationEnabled eq true.
- Refs: NIST-800-53:AC-6, NIST-800-53:CM-11.
- Fix: turn user site creation off and route requests through a provisioning process.
- Confidence: verified.

### M365-TEAMS-RSC-USER-CONSENT
- Catches: users may grant Teams apps resource-specific consent to chats and personal scope, so
  a malicious or over-permissioned app reads chat content with one click.
- Severity: low.
- Source: m365.yaml; v1.0; `/teamwork/teamsAppSettings`; fields
  isChatResourceSpecificConsentEnabled, isUserPersonalScopeResourceSpecificConsentEnabled; key id.
  New query.
- Permission: TeamworkAppSettings.Read.All.
- Condition: isChatResourceSpecificConsentEnabled eq true or
  isUserPersonalScopeResourceSpecificConsentEnabled eq true.
- Refs: CIS-M365:8.4.1, NIST-800-53:AC-6, NIST-800-53:CM-11.
- Fix: turn both off; publish approved apps through the Teams app catalogue.
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/teamsappsettings?view=graph-rest-1.0

### M365-APPS-UPDATE-CHANNEL-SLOW
- Catches: Microsoft 365 Apps are on the Semi-Annual channel, so Office security fixes arrive
  months late.
- Severity: low.
- Source: m365.yaml; v1.0; `/admin/microsoft365Apps/installationOptions`; fields updateChannel,
  appsForWindows, appsForMac; key id. New query.
- Permission: OrgSettings-Microsoft365Install.Read.All.
- Condition: updateChannel eq semiAnnual.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.4.
- Fix: move to Monthly Enterprise (or Current).
- Confidence: likely - https://learn.microsoft.com/en-us/graph/api/resources/m365appsinstallationoptions?view=graph-rest-1.0

---

## Permissions to add to the backlog's table

| Endpoint (GET) | Rules | Application permission |
|---|---|---|
| /identityProtection/riskyServicePrincipals | ENTRA-SP-RISKY | IdentityRiskyServicePrincipal.Read.All (Workload ID Premium) |
| /roleManagement/directory/roleDefinitions | ENTRA-ROLE-CUSTOM-DANGEROUS-ACTIONS | RoleManagement.Read.Directory |
| /servicePrincipals(appId=EXO)/appRoleAssignedTo, (appId=SPO)/... | ENTRA-APPPERM-EXCHANGE-*, -SHAREPOINT-* | Application.Read.All |
| /applications $expand=owners, federatedIdentityCredentials | ENTRA-APP-TIER0-REQUESTED-WITH-OWNERS, -OWNER-DISABLED-OR-GUEST, -FEDERATED-CREDENTIAL-EXTERNAL | Application.Read.All (+ User.Read.All for owner properties) |
| /identity/customAuthenticationExtensions | ENTRA-CUSTOM-AUTH-EXTENSION-PRESENT | CustomAuthenticationExtension.Read.All |
| /policies/authenticationStrengthPolicies | ENTRA-AUTHSTRENGTH-CUSTOM-WEAK | Policy.Read.All |
| /directory/administrativeUnits | ENTRA-AU-NO-RESTRICTED-MANAGEMENT | AdministrativeUnit.Read.All |
| /servicePrincipals/{id}/synchronization/jobs (+ /schema) | ENTRA-PROVISIONING-JOB-*, -MAPPING-SUSPECT | Synchronization.Read.All |
| /auditLogs/provisioning | ENTRA-PROVISIONING-FAILURES-RECENT, -SKIPPED-NOT-ASSIGNED-RECENT | AuditLog.Read.All |
| /auditLogs/signIns, /auditLogs/directoryAudits | ENTRA-SIGNIN-*, ENTRA-AUDIT-ROLE-ASSIGNMENT-RECENT | AuditLog.Read.All + Directory.Read.All |
| /users $expand=transitiveMemberOf, sponsors; /groups/{id}/appRoleAssignments, /members | ENTRA-USER-NEW-NOT-IN-ACCESS-GROUP, ENTRA-GUEST-NO-SPONSOR, ENTRA-GROUP-ONBOARDING-*, -RECENT-JOINERS-NO-APP | User.Read.All, GroupMember.Read.All, Application.Read.All |
| beta /reports/servicePrincipalSignInActivities | ENTRA-SP-SIGNIN-STALE | AuditLog.Read.All |
| /identityGovernance/lifecycleWorkflows/workflows | ENTRA-LIFECYCLE-NO-LEAVER-WORKFLOW | LifecycleWorkflows.Read.All |
| /security/incidents, /security/alerts_v2 | M365-SECURITY-INCIDENT-OPEN, -ALERT-OPEN | SecurityIncident.Read.All, SecurityAlert.Read.All |
| beta /deviceManagement/configurationPolicies | INTUNE-ESEC-*, INTUNE-CONFIGPOLICY-UNASSIGNED | DeviceManagementConfiguration.Read.All |
| beta /deviceManagement/windowsFeatureUpdateProfiles | INTUNE-FEATURE-UPDATE-PROFILE-EOS | DeviceManagementConfiguration.Read.All |
| beta /deviceManagement/windowsAutopilotDeploymentProfiles | INTUNE-AUTOPILOT-PROFILE-USER-ADMIN | DeviceManagementServiceConfig.Read.All |
| /deviceManagement/managedDevices $expand=windowsProtectionState | INTUNE-DEVICE-DEFENDER-* | DeviceManagementManagedDevices.Read.All |
| beta /deviceManagement/deviceHealthScripts, /deviceManagementScripts | INTUNE-REMEDIATION-SCRIPT-ERRORS, INTUNE-PLATFORM-SCRIPT-ERRORS | DeviceManagementScripts.Read.All |
| /deviceManagement/ndesConnectors, /deviceCompliancePolicyDeviceStateSummary, beta /deviceManagement (managedDeviceCleanupSettings) | INTUNE-NDES-CONNECTOR-INACTIVE, INTUNE-COMPLIANCE-UNKNOWN-DEVICES, INTUNE-CLEANUP-RULE-OFF | DeviceManagementConfiguration.Read.All / DeviceManagementServiceConfig.Read.All |
| /teamwork/teamsAppSettings | M365-TEAMS-RSC-USER-CONSENT | TeamworkAppSettings.Read.All |
| /admin/microsoft365Apps/installationOptions | M365-APPS-UPDATE-CHANNEL-SLOW | OrgSettings-Microsoft365Install.Read.All |

New thresholds: entra.first-party-tenant-ids, entra.custom-role-dangerous-action-pattern,
entra.exchange-app-role-ids, entra.sharepoint-app-role-ids, entra.federated-issuer-allow-pattern,
entra.secret-max-remaining-days (730), entra.app-max-secrets (2),
entra.authstrength-weak-combination-pattern, entra.consumer-mail-pattern,
entra.audit-role-activity-pattern, entra.access-group-ids (empty), entra.onboarding-group-ids
(empty), entra.onboarding-recent-joiners-min (5), entra.provisioned-sp-ids (empty),
entra.provisioning-max-successive-failures (0), entra.provisioning-export-max-age-days (14),
entra.provisioning-expected-interval (PT40M), entra.provisioning-failures-high-count (50),
entra.provisioning-skip-not-assigned-pattern, entra.provisioning-suspect-expression-pattern (empty),
entra.app-inactive-days (90), entra.dynamic-rule-*-pattern, m365.alert-max-open-days (1),
m365.onedrive-deleted-retention-min-days (90), intune.laps-template-name-pattern,
intune.quality-update-deadline-max-days (7), intune.quality-deferral-max-days (7),
intune.feature-update-eos-notice-days (90), intune.script-error-devices-max (0),
intune.profile-error-devices-max (0), intune.connector-max-age-days (1),
intune.unknown-compliance-devices-max (0).

## Backlog items these proposals close or move

- Closed (with the stated approximation): MFA for Azure management (ENT-CA-010); client secret
  valid beyond 24 months (ENTRA-APP-3, as "more than N days left"); compliance policy per platform
  (existence half); app protection policies with no protections (INT-02x); device clean-up rule;
  feature-update targets; configuration profile status per profile (INT-003); remediation and
  platform scripts with errors (INT-005, permission named); Defender XDR incidents and alerts;
  app owners disabled or guest (ENTRA-APP-11, pending the expand-select behaviour); endpoint
  security content existence (not values).
- Moved from "engine gap" to "needs the two new features": SaaS provisioning job state and
  schema (per-object), sign-in attempts and legacy-protocol sign-ins and role changes in the last N
  days (relative dates), unused apps (partly, via the beta sign-in report).
- Still open: everything that compares two fields or divides (licence over-assignment, Secure
  Score ratio), PIM role settings and directory settings (element pinning), group nesting loops,
  duplicate values, federation configuration per domain (now doable with for_each over Q-DOMAINS →
  `/domains/{id}/federationConfiguration` - worth adding next: signingCertificate expiry and
  federatedIdpMfaBehavior).

## Engine gaps that blocked or weakened rules

1. **Same-element conditions on arrays.** PIM role settings (`policy.rules[]` by rule id with
   enabledRules / maximumDuration), directory settings name/value pairs, compliance scheduled
   actions (actionType block with gracePeriodHours), attribute mappings (matchingPriority with
   targetAttributeName), federated credentials (issuer with subject). Proposed: `any_element:
   { path: policy.rules, where: <condition on the element> }` and `count_elements` for "exactly one
   matching attribute".
2. **`until-gt` / "more than N days ahead".** ENTRA-APP-SECRET-LONG-LIVED approximates it with
   `not: until-lt`, which reads "all elements" instead of "any element".
3. **Duration values (ISO 8601).** schedule.interval PT40M, PIM maximumDuration PT8H, MAM
   periodOfflineBeforeWipeIsEnforced P90D, app policy maxLifetime P180D. Proposed: `duration-gt` /
   `duration-lt` with the value in hours.
4. **Grouped findings with counts.** Audit-log rules need "one finding per key with the row count"
   (failures per app and error code, sign-ins per user and protocol). The template key gives the
   grouping; the engine should expose `{rows}` per key and allow `count` thresholds per key.
5. **Nested `for_each` (two levels)** for job → schema, and the parent fields carried into child
   rows (`{sp}` id and displayName in the job rows). Also a bound on fan-out (page cap or
   threshold list) so a tenant with 2,000 service principals does not make 2,000 calls daily.
6. **Set difference across queries** (new users minus members of app-assigned groups; disabled
   users inside app-assigned groups). A `store` rule over `row_seen` can do it today if the
   expands land in row attributes; worth a worked example in RULES.md.
7. **`@odata.type` is not addressable** (field paths split on dots). Platform detection falls back
   to marker fields; a quoted path segment would make it explicit.
8. **List-level `$expand` behaviour** for windowsProtectionState, federatedIdentityCredentials and
   owner sub-selects is undocumented; the runner should report "expand ignored" as unknown rather
   than return rows with the field absent (which evaluates n/a silently).
9. **Graph secret properties** (synchronization job credentials are never returned by Graph, but
   `synchronizationJobSettings` may contain tokens): add `synchronizationJobSettings`,
   `secretValue`, `tokenValue`, `wifiPassword`, `deviceAccountPassword`, `activationLockBypassCode`
   to the runner's refusal list so a tenant rule cannot select them.
10. **Empty threshold list = n/a, never pass.** Several rules key on tenant lists
    (`entra.access-group-ids`, `entra.onboarding-group-ids`); the engine must mark the rule
    "not configured" rather than "nothing found".
