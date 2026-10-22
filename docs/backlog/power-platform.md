# Backlog - Power Platform

Legacy checks from `_archive\_health-20261020\Keeper\catalog\checks-POWERPLAT.csv` (122 rows; no
`(Restored1)` duplicate was present in the rows) that `rules/power-platform.yaml` cannot express, one
line each: the check, what it needs, and the source CheckId.

`rules/power-platform.yaml` reads through the `power-platform` integration type, whose token is for
`https://service.powerapps.com/` and which may only **GET** `https://api.bap.microsoft.com`. That host
serves exactly two GET families the rule file uses - the admin environment list and the v2 data
policies - so the 12 rules cover environment state and governance (health, Managed Environments,
security group, backup retention, trial lifecycle, region, naming) and the tenant-wide DLP posture
(a policy must exist, HTTP/web connectors must be blocked, recent policy changes flagged). Everything
below needs something that type cannot do.

Source labels: `POWERPLAT-*` = the legacy CheckId; `field` = a problem seen in this estate. After the
backlog: the thresholds the rule file defines, and what to confirm on the first real run.

## Needs a read-POST the power-platform type does not answer (listTenantSettings)

The tenant-settings family is read with `POST /providers/Microsoft.BusinessAppPlatform/listTenantSettings`.
The `power-platform` type answers no read-POST (its `ReadPosts` is empty), and the HTTP runner is GET
unless the type allows the exact POST path, so none of these can be written until the type is given
`listTenantSettings` as a read-POST (the body is empty, so it is a pure read).

- Environment creation restricted to admins (`disableEnvironmentCreationByNonAdminUsers`). Source: POWERPLAT-CFG-001.
- Trial and developer environment creation restricted (`disableTrial/DeveloperEnvironmentCreationByNonAdminUsers`). Source: POWERPLAT-CFG-002.
- Capacity allocation by environment admins disabled (`disableCapacityAllocationByEnvironmentAdmins`). Source: POWERPLAT-CFG-003.
- Share apps with Everyone disabled (`powerApps.disableShareWithEveryone`). Source: POWERPLAT-CFG-004.
- Guests cannot make apps or flows (`powerApps.enableGuestsToMake`). Source: POWERPLAT-CFG-005.
- Connection sharing with everyone disabled (`powerApps.disableConnectionSharingWithEveryone`). Source: POWERPLAT-CFG-006.
- Default-environment routing and maker landing (`governance.enableDefaultEnvironmentRouting`, maker-match, create-from-image/Figma). Source: POWERPLAT-CFG-007.
- Disabled users removed from all environments (`userManagementSettings.enableDeleteDisabledUserinAllEnvironments`). Source: POWERPLAT-CFG-008.
- Copilot / generative-AI tenant settings decided (`intelligence.disableCopilot`, `modelExperimentation.enableModelDataSharing`, ...). Source: POWERPLAT-CFG-009.
- Desktop-flow module data-policy management on (`governance.policy.enableDesktopFlowDataPolicyManagement`), plus the desktop-flow module groups in a policy. Source: POWERPLAT-CFG-014.
- Storage-capacity warning threshold and environment-admin capacity/licensing reports (`licensing.storageCapacityConsumptionWarningThreshold`, `enableTenant*ReportForEnvironmentAdmins`). Source: POWERPLAT-CFG-036.
- Weekly admin digest enabled (`governance.disableAdminDigest`). Source: POWERPLAT-MON-002.

## Needs a different Power type / host

Each line reads a host the `power-platform` type is not allowed to reach; it belongs in a rule file
bound to that type (`power-apps` = api.powerapps.com, `power-automate` = api.flow.microsoft.com,
`power-bi` = api.powerbi.com, `power-platform-api` = api.powerplatform.com).

- Failed cloud-flow runs in 7 d; suspended flows; stale/stopped flows; flow failure-alert subscription (`power-automate`). Source: POWERPLAT-HLT-008, POWERPLAT-HLT-009, POWERPLAT-HYG-002, POWERPLAT-MON-003.
- Apps shared with Everyone or large groups; orphaned apps (disabled owner / unlaunched); critical-app runtime dependencies (`power-apps` apps + permissions). Source: POWERPLAT-IAM-006, POWERPLAT-HYG-001, POWERPLAT-AVL-005.
- Connections owned by leavers or shared widely; broken/unused connections; custom connectors not on OAuth2; deprecated connectors used (`power-apps` connections/apis). Source: POWERPLAT-IAM-008, POWERPLAT-HYG-003, POWERPLAT-AUT-008, POWERPLAT-LCM-004.
- Default-environment sprawl (app/flow/maker counts) - needs both `power-apps` and `power-automate` counts. Source: POWERPLAT-HYG-004.
- Tenant Dataverse Database/File/Log capacity vs entitlement; capacity enforcement state; AI Builder / Copilot credits (`power-platform-api` tenantCapacity, or the BAP listTenantCapacity POST). Source: POWERPLAT-HLT-001, POWERPLAT-HLT-002, POWERPLAT-HLT-005, POWERPLAT-CST-006.
- Power Pages sites not anonymous (`power-platform-api` powerpages/environments/{id}/websites). Source: POWERPLAT-CFG-020.
- Power BI dataset refresh failures; gateway cluster/member online, version, data sources, HA, HTTPS mode; datasets bound to a live gateway; workspace admins and hygiene; activity events; all Power BI / Fabric tenant settings; gateway credentials; block ResourceKey auth (`power-bi`). Source: POWERPLAT-HLT-010, POWERPLAT-HLT-011, POWERPLAT-LCM-001, POWERPLAT-AVL-001, POWERPLAT-AVL-003, POWERPLAT-AVL-004, POWERPLAT-CFG-022..CFG-035, POWERPLAT-IAM-009, POWERPLAT-IAM-010, POWERPLAT-LOG-006, POWERPLAT-HYG-009, POWERPLAT-AUT-005, POWERPLAT-AUT-006, POWERPLAT-LCM-006 (Fabric part).
- Power BI / Power Apps / Power Automate / Dynamics premium-licence usage - `graph` subscribedSkus joined to activity (`graph`, licence pack). Source: POWERPLAT-CST-003, POWERPLAT-CST-004, POWERPLAT-CST-005, POWERPLAT-CST-001.

## Needs a per-environment Dataverse token (`dataverse` integration)

The Dataverse Web API answers only for the one environment its token was issued for, so each is a rule
in a `dataverse` file bound to that environment (one integration instance per environment).

- Failed Dataverse system jobs; mass-record modification; classic workflows still active; top tables by size. Source: POWERPLAT-HLT-007, POWERPLAT-LOG-008, POWERPLAT-LCM-005, POWERPLAT-HLT-013.
- Dataverse auditing on; read/user-access auditing; audit retention finite; audited-table scope; plug-in trace setting. Source: POWERPLAT-LOG-001, POWERPLAT-LOG-002, POWERPLAT-LOG-003, POWERPLAT-LOG-004, POWERPLAT-LOG-005.
- Blocked attachment extensions and max upload size; IP firewall; IP cookie binding. Source: POWERPLAT-CFG-018, POWERPLAT-AUT-003, POWERPLAT-AUT-004.
- System Administrator holders per environment; vendor and application users; disabled/stub users holding roles; the review read-role present (WhoAmI). Source: POWERPLAT-IAM-001, POWERPLAT-IAM-002, POWERPLAT-IAM-003, POWERPLAT-IAM-004, POWERPLAT-IAM-011.
- Copilot Studio agents inventory and Entra authentication (bots/botcomponents). Source: POWERPLAT-CFG-021, POWERPLAT-AUT-007.
- Production holds managed solutions / ALM export freshness; custom log tables bounded; audit-history size. Source: POWERPLAT-BCK-006, POWERPLAT-HYG-007, POWERPLAT-HYG-008.

## Needs a different integration entirely

- Gateway host health, OS/.NET, service recovery, TLS registry, TLS-interception path, service-error logs - `cim`/`registry`/`eventlog` on the gateway EC2 hosts. Source: POWERPLAT-HLT-012, POWERPLAT-LCM-002, POWERPLAT-AVL-002, POWERPLAT-PKI-001, POWERPLAT-PKI-002, POWERPLAT-LOG-007, POWERPLAT-CFG-035 (host part).
- Open Microsoft service incidents and plan-for-change message-center notices - `graph` serviceAnnouncement (held tenant-wide in the m365 pack). Source: POWERPLAT-HLT-014, POWERPLAT-LCM-007.
- Tenant Power Platform / Dynamics / Fabric admin-role holders permanent vs PIM-eligible - `graph` roleManagement (entra.yaml territory). Source: POWERPLAT-IAM-005.
- Unified audit log has Power Platform / Dataverse / Power BI events - `exchange-online` / `purview` Search-UnifiedAuditLog. Source: POWERPLAT-MON-004.
- Keepit coverage, anomalies and cause; gateway monitoring in PRTG/Dynatrace. Source: POWERPLAT-BCK-003, POWERPLAT-BCK-004, POWERPLAT-MON-005.

## Engine / condition gaps - the data is reachable on BAP, the condition cannot be written yet

- Tenant isolation enabled and allow-list limited to documented partners: `GET /providers/PowerPlatform.Governance/v1/tenants/{tenantId}/tenantIsolationPolicy` is on BAP, but the path needs the tenant id and there is no generic tenant-id macro; a `for_each` over a `threshold` tenant id silently passes when the setting is unset (zero objects = no rows = no finding), which breaks "no data is not a pass". Needs a `{TENANT}` request macro, or an isolation endpoint that does not carry the id. Source: POWERPLAT-AUT-001, POWERPLAT-AUT-002.
- Per-environment capacity share of the tenant pool, and sandbox total vs production: `?$expand=properties.capacity` is readable on BAP, but the judgement is a ratio of one environment against the sum of all (and against the tenant entitlement), which needs an aggregate across rows the condition language does not compute. Source: POWERPLAT-HLT-004, POWERPLAT-HYG-006.
- Capacity weekly growth and months-to-cap: needs a trend across run history, not a single read. Source: POWERPLAT-HLT-003.
- Production Dataverse version within one release of PPR / GA, release-wave enabled in PPR first: a cross-row comparison (one environment against another). Source: POWERPLAT-LCM-003.
- Default environment covered by a *restrictive* policy, and new-connector default classification: existence of an all-environments policy is covered by PP-DLP-NO-TENANT-WIDE-POLICY, but "the policy that applies to Default is restrictive" needs the default environment id (a cross-query join to the environment list) and the `defaultConnectorsClassification` semantics confirmed. Source: POWERPLAT-CFG-011.
- DLP blocked group beyond HTTP (consumer storage, custom-connector URL patterns) and the business group limited to a named set: PP-DLP-HTTP-CONNECTOR-NOT-BLOCKED covers the HTTP/web connectors; extending to the full connector allow/deny list needs the tenant's intended business-connector set as a threshold and more schema confidence. Source: POWERPLAT-CFG-012 (remainder).
- DLP change matched to a ticket / connector-group diff vs the previous run: PP-DLP-POLICY-CHANGED-RECENT flags recent changes, but there is no ticket source to match against, and `changed` cannot diff individual array elements of `connectorGroups`. Source: POWERPLAT-CFG-013 (remainder).
- Managed Environment sharing-limit detail (limitSharingMode, maxLimitUserSharing, solutionCheckerMode) and PPR specifically: PP-ENV-PRODUCTION-NOT-MANAGED judges protectionLevel only; the `extendedSettings` detail is readable but the "excludes sharing to security groups or caps users" test needs those fields confirmed. Source: POWERPLAT-CFG-015 (remainder).
- Security-group membership <= intended population: the group id is on the environment, but its member count is a `graph` join. Source: POWERPLAT-CFG-017 (remainder).
- Developer / Teams environment inactivity: the environment list gives `environmentSku` and `createdTime` (PP-ENV-TRIAL-STALE uses them for Trial), but "owned by an enabled maker active within 90 d" needs `lastActivity` (not reliably in the admin list) and a Graph accountEnabled join. Source: POWERPLAT-HYG-005 (remainder).
- Manual backup <= 48 h before each production solution import: `.../environments/{id}/backups` is a BAP GET (a `for_each` over environments), but the judgement joins it to the Dataverse solutions `installedon` and needs date arithmetic. Source: POWERPLAT-BCK-002.
- Managed Environment licence exposure: BAP protectionLevel joined to each user's Graph assignedLicenses. Source: POWERPLAT-CST-007.

## Process / attestation only - no API to read

- Capacity-alert routing to a monitored mailbox, weekly-digest recipients, review-run cadence. Source: POWERPLAT-MON-001, POWERPLAT-MON-006.
- Gateway recovery key held with two custodians; restore drill within 365 d; evacuees app/flows/reports in source control; Log-overage buy-vs-cut decision recorded. Source: POWERPLAT-BCK-005, POWERPLAT-BCK-008, POWERPLAT-BCK-007, POWERPLAT-CST-002.

## Thresholds this rule file defines

- `power-platform.trial-max-age-days` (default 30) - PP-ENV-TRIAL-STALE.
- `power-platform.agreed-region` (required) - PP-ENV-REGION-UNAPPROVED; the region code every environment must be in (e.g. `europe`). Until set, the rule is not configured (n/a, never a pass).
- `power-platform.environment-name-pattern` (required) - PP-ENV-NAME-NONCONFORMING; a .NET regular expression every environment display name must match.
- `power-platform.dlp-change-review-days` (default 7) - PP-DLP-POLICY-CHANGED-RECENT.

## To confirm on the first real run (no live tenant has been read)

- `api-version=2021-04-01` on the admin environments list returns `properties.governanceConfiguration.protectionLevel`, `properties.retentionPeriod`, `properties.states.{management,runtime}.id`, `properties.linkedEnvironmentMetadata.securityGroupId`, `properties.environmentSku`, `properties.isDefault`, `properties.azureRegion` and `properties.createdTime`. If a newer api-version is needed for governanceConfiguration/retentionPeriod, the managed-environment and retention rules read those fields as absent, which is n/a (no finding), never a false positive - so raise the api-version rather than trust a clean result for them.
- `environmentSku` value for production environments is exactly `Production`, and `retentionPeriod` is the ISO string `P28D` / `P7D` (PP-ENV-PRODUCTION-* rules compare text).
- `/providers/PowerPlatform.Governance/v2/policies` answers a GET with `api-version=2021-04-01`, returns rows under the OData `value` array, and each row carries `environmentType` (AllEnvironments / OnlyEnvironments / ExceptEnvironments), `connectorGroups[].classification` (Blocked / General / Confidential), `connectorGroups[].connectors[].id` (e.g. `shared_webcontents`, `shared_http`, `shared_httpwithazuread`) and `lastModifiedTime` at the row root. Confirm the HTTP connector ids and the Blocked classification spelling against a real policy; the connector-id regex is anchored on a word boundary to avoid partial matches.
- A tenant always returns the default environment, so PP-ENV-NONE firing means a missing Power Platform Administrator role, not an empty tenant.
