# Backlog - Azure (Azure Resource Manager)

Legacy checks from `_archive\_health-20261020\Keeper\catalog\checks-AZURE.csv` (201 rows, the
`(Restored1)` duplicates ignored) and CSPM topics that `rules/azure.yaml` cannot express yet, one line
each: the check, what it needs, and the source. `rules/azure.yaml` holds 255 rules (57 before the
22.10.2026 extension). They read through the `azure` integration type: ARM GETs on
`management.azure.com`, plus Resource Graph KQL as a POST to `/providers/Microsoft.ResourceGraph/resources`.

Source labels: `AZURE-*` = the legacy CheckId; `field` = a problem seen in this estate; `request` =
asked for directly; `cspm` = a topic a mature CSPM covers (Defender for Cloud, Prowler, CIS Azure).
The azure integration's token is for ARM only, and the only POST it answers as a read is Resource
Graph; every other data plane needs a different token or a different integration type.

## How the 22.10 extension reads what used to be parked

Two runner behaviours, both in `components/runners/src/Keeper.Runners/PerObject.cs` and
`Keeper.Runners/Rows.cs`, unlocked most of the old "engine gap" items:

- **Several placeholders per path.** `for_each` fills every `{field}` of the path from the parent row,
  not only the named one. A Resource Graph list that projects `subscriptionId`, `resourceGroup` and
  `name` therefore addresses any ARM sub-resource:
  `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/.../{name}/blobServices/default`.
  Only plain ids are filled; a resource group whose name holds brackets or other characters outside
  `[A-Za-z0-9._:-]` is skipped and makes the read partial (never a pass).
- **Must-exist per object.** `map: true` turns the answer object into rows of `key`/`value`, so an
  ARM list answer `{ "value": [] }` becomes one row `{ key: value, value: [] }` per object, judged
  `value empty` (nothing configured) or with `element` / `not element` (nothing of the right kind).
  Per subscription the same works over `for_each: /subscriptions`; where Resource Graph holds the
  data, a KQL `leftouter` join from `ResourceContainers` gives one row per subscription instead.

Moved out of the backlog by this (now rules): activity-log export per subscription
(AZ-ACTIVITY-LOG-NOT-EXPORTED, AZURE-LOG-001), security contact present
(AZ-DEFENDER-SECURITY-CONTACT-MISSING, AZURE-MON-002), a policy assignment and the MCSB initiative
applying (AZ-POLICY-NONE-APPLIES, AZ-POLICY-MCSB-NOT-ASSIGNED, AZURE-CFG-006), a budget per
subscription (AZ-SUBSCRIPTION-NO-BUDGET, AZURE-CST-004), Network Watcher per region and Service Health
alerts (AZ-NETWORK-WATCHER-MISSING, AZ-ACTIVITY-ALERT-SERVICE-HEALTH, AZURE-CFG-016, AZURE-MON-006),
the Owner ceiling (AZ-SUBSCRIPTION-OWNERS-TOO-MANY, AZURE-IAM-002 in part), SQL auditing, firewall,
TDE and Entra-only authentication (AZURE-AUT-011), blob and file soft delete, versioning and SMB
versions (AZURE-BCK-007, AZURE-BCK-008, AZURE-AUT-019 in part), App Service site config (AZURE-AUT-009,
AZURE-CFG-020, AZURE-LCM-007 in part), resource diagnostic settings for Key Vault, Application Gateway,
Azure Firewall, AKS, Front Door/CDN, Cosmos DB and Logic Apps (AZURE-LOG-005, AZURE-LOG-006,
AZURE-LOG-012 in part), Recovery Services and Backup vault soft delete, immutability, redundancy,
alerts and protected-item health (AZURE-BCK-002, AZURE-BCK-004, AZURE-BCK-005, AZURE-BCK-006,
AZURE-BCK-010 in part), Defender for Servers plan components (AZURE-CFG-021 in part).

## Not on the ARM host, or not a POST the azure type answers

- Log Analytics workspace queries (KQL to `api.loganalytics.io`): ingestion stopped / over daily cap, activity-log records actually arriving, legacy-TLS storage clients, ingestion by table. Different host and token. Source: AZURE-HLT-010, AZURE-LOG-002, AZURE-LCM-014, AZURE-CST-011.
- Key Vault certificates (expiry, validity period, issuer, auto-renewal) and key rotation policies: ARM exposes keys and secrets metadata (AZ-KEYVAULT-KEY-*, AZ-KEYVAULT-SECRET-* read `properties.attributes` only) but no certificates, and the rotation policy is not reliably in the ARM key list. Belongs in a `key-vault` pack (one vault's `*.vault.azure.net`). Source: AZURE-PKI-001, AZURE-PKI-003, AZURE-PKI-004, AZURE-PKI-008, cspm.
- Storage data plane: blobs themselves (install media, logs in public containers), static website hosting (a blob-service data-plane property). Per-container public access level is now read through ARM (AZ-STORAGE-CONTAINER-PUBLIC). Source: AZURE-HYG-012, cspm.
- Cost Management query and forecast (`POST .../Microsoft.CostManagement/query`, `/forecast`): a POST the azure type does not allow, so budget burn, cost movers, anomalies, Defender cost, allocation and the approved-services spend check cannot be written. Source: AZURE-CST-003, AZURE-CST-005, AZURE-CST-006, AZURE-CST-012, AZURE-CST-015, AZURE-CST-016.
- App Service application settings and connection strings (`POST .../config/appsettings/list`): a POST, and it returns secret values. So the Functions runtime version (`FUNCTIONS_EXTENSION_VERSION`), secrets stored in plain app settings instead of Key Vault references, and Application Insights wiring per app cannot be read. Source: cspm.
- Billing data plane past-due/overdue invoices and billing-role holders: `Microsoft.Billing/.../invoices` and `.../billingRoleAssignments` need Billing Reader and, for role holders, a Graph principal resolve. AZ-BILLING-ACCOUNT-STATUS already reads account status. Source: AZURE-CST-002, AZURE-IAM-021, AZURE-CST-001.

## Engine gaps - the azure type could read it, the condition language cannot express it yet

### Azure Monitor metric time series (no metric-window condition)

A rule compares a field to a value, not a window of metric data points, so nothing that reads
`Microsoft.Insights/metrics` can be written.

- Regional vCPU / public-IP / NIC quota headroom; storage and file-share capacity and growth; App Service plan CPU/memory saturation; VPN tunnel bandwidth and packet drops; load-balancer and Application Gateway unhealthy-host counts; dormant storage accounts (zero transactions in 90 days). Source: AZURE-HLT-006, AZURE-HLT-007, AZURE-HLT-008, AZURE-HLT-011, AZURE-AVL-009, AZURE-HYG-010.

### Join to Entra ID (the azure token has no Graph audience)

Principal resolution (enabled, guest, deleted, departed) needs a Graph token; it is a cross-system
store join (`row_seen` with the entra system), not an azure rule.

- Owners / privileged holders who are disabled, guests, leavers, deleted, or daily mail-enabled accounts; a floor of at least two Owners counting inherited assignments; eligible assignments on disabled accounts; service principals unused for 90 days; Owner tags and alert/action-group recipients pointing at departed users. Source: AZURE-IAM-002, AZURE-IAM-006, AZURE-IAM-007, AZURE-IAM-008, AZURE-IAM-009, AZURE-IAM-019, AZURE-HYG-007, AZURE-HYG-008, AZURE-MON-008.
- Management-plane MFA and VM-login MFA (Conditional Access policies read through Graph, joined to Azure role holders). Source: AZURE-IAM-027, AZURE-IAM-032.

### Joins across tools and clouds, aggregation, run-to-run diff

- Backup coverage reconciled with Veeam and Rubrik exports (AZ-VM-NO-BACKUP sees Azure Backup only and says so); VNet address overlap with on-prem and AWS ranges; external monitoring (PRTG, Dynatrace) of Azure endpoints; Azure certificates present in the PKI register; services on the approved (Nimbus tier-5) list. Source: AZURE-BCK-012, AZURE-CFG-012, AZURE-MON-013, AZURE-PKI-011, AZURE-CST-016.
- Policy compliance per assignment and its week-over-week trend: Resource Graph `summarize` over `policystates` returns aggregate rows the engine would need percent/by/trend over. Source: AZURE-CFG-007.
- "Since the last run" diffs that need a ticket match: new public IPs and new internet-facing NSG rules, new/removed privileged role assignments, sensitive or failed operations in the activity log. The `changed`/`_new` ops exist, but the attribution to a change record is process. Source: AZURE-IAM-001, AZURE-AUT-003, AZURE-LOG-010, AZURE-LOG-011.
- PIM for Azure resource roles: standing (permanent) privilege, role-management-policy MFA/approval/duration, eligibility without an end date. `roleAssignmentScheduleInstances` / `roleEligibilityScheduleInstances` / `roleManagementPolicies` are ARM GETs, but they need scope iteration over the root MG and every subscription plus element-pinned conditions on nested rule objects; AZ-USER-ACCESS-ADMIN-ASSIGNMENT and AZ-SUBSCRIPTION-OWNERS-TOO-MANY cannot tell a PIM activation from a standing assignment. Source: AZURE-IAM-004, AZURE-IAM-005, AZURE-IAM-006.
- Defender for Cloud recommendations and secure score imported as findings (`securityresources` assessments / secureScores): readable through Resource Graph, left out on purpose - they would duplicate the native rules finding by finding. Revisit as an `emit:` rule if customers want Defender's own verdicts side by side. Source: cspm.

### Authorable now, not yet written

These need nothing new from the engine; they were left out to keep the pack near 250 rules or because
the field shape needs a live answer first.

- Diagnostic settings for storage (blob service), SQL databases, App Service, Recovery Services vaults, Service Bus/Event Hubs, NSGs and public IPs (same `map: true` pattern as AZ-KEYVAULT-NO-DIAGNOSTIC-SETTING). Source: AZURE-LOG-005, AZURE-LOG-013, cspm.
- Diagnostic settings that exist but drop the audit category (`logs[]` with `categoryGroup` audit/allLogs or the resource's own categories) - needs per-type category names. Source: cspm.
- VM guest-agent readiness and health (`{vm}/instanceView`, vmAgent statuses) through for_each over Resource Graph. Source: AZURE-HLT-005.
- Recovery Services backup policies (retention days, instant-restore, schedule) and multi-user authorization (resource guard); Defender for Servers vulnerability-assessment settings. Source: AZURE-BCK-002, AZURE-CFG-021.
- App Service authentication (`config/authsettingsV2`, a GET), client certificates, VNet integration and public network access; Container Apps ingress `allowInsecure`; Event Grid, App Configuration, Machine Learning, Databricks and Automation public network access and local auth; Cosmos DB continuous backup; AKS host encryption, Defender sensor, Free tier SLA and KMS etcd encryption; ACR export policy and ARM-audience tokens; storage local users and CMK; disk CMK and snapshot export. Source: cspm.
- Resource locks on other critical resources (key vaults, production resource groups, hub networking). Source: cspm.
- CIS Microsoft Azure Foundations control numbers on the new rules: the 198 new rules carry Microsoft cloud security benchmark (`MCSB:`) and NIST refs; CIS-Azure numbers moved between v2, v3 and v4 and were not added without the benchmark text at hand. Source: request.

## Retired platform features (no rule on purpose)

- Legacy activity-log profiles (`Microsoft.Insights/logprofiles`) retired on 2026-09-30; the read may already fail, and the export they gave is covered by AZ-ACTIVITY-LOG-NOT-EXPORTED.
- Defender auto-provisioning of the Log Analytics agent (`autoProvisioningSettings`): the agent it installed retired in 2024; AZ-VM-LEGACY-LOG-ANALYTICS-AGENT finds what it left behind.

## Process-only, attestation or documentation

No read proves these; they are an attestation, a decision record or a document review.

- Restore test and DR test failover performed within the window; retained backup data for deleted resources documented. Source: AZURE-BCK-011, AZURE-BCK-013, AZURE-AVL-005.
- Subscription inventory, owners and purpose recorded; Azure documentation current; the infosec lead's read-only scope written by the CISO; periodic access reviews recorded; the Cloud-Risk-Survey run within 183 days; invoices routed to treasury. Source: AZURE-CFG-002, AZURE-CFG-026, AZURE-IAM-022, AZURE-IAM-020, AZURE-MON-014, AZURE-CST-002.

## Thresholds and what to confirm on the first real run

Fixed values (with a tenant threshold where one is named): minimum TLS 1.2 everywhere; key-vault
soft-delete retention 90 days; the management-port list of AZ-NSG-MGMT-PORT-OPEN-FROM-INTERNET and the
wider sensitive-port list of AZ-NSG-SENSITIVE-PORT-RANGE-FROM-INTERNET; the Owner, User Access
Administrator and Contributor built-in role GUIDs; the MCSB initiative id
`1f3afdf9-d0c9-4c3d-847f-89da613e70a8`. Tenant thresholds added: `azure.log-retention-days` (90),
`azure.flow-log-retention-days` (90), `azure.storage-key-rotation-days` (90),
`azure.blob-soft-delete-days` (7), `azure.key-notice-days` / `azure.secret-notice-days` (30),
`azure.sql-audit-retention-days` (90), `azure.postgres-min-version` (14), `azure.aks-min-version`
(1.33 - raise it as AKS minors age out), `azure.max-subscription-owners` (3), `azure.backup-max-age-days` (2).

Nothing here has been run against a subscription. Confirm on the first run:

- The azure integration answers the Resource Graph POST (`items: data`, `$skipToken` body-cursor paging) and the scanning identity has Reader at the tenant root management group; otherwise Resource Graph rules read nothing. ARG KQL used here relies on `join kind=leftouter`/`inner` (including Resources joined to ResourceContainers, SecurityResources and RecoveryServicesResources), `mv-expand`, `summarize make_set/countif/dcount`, `array_concat`, `pack_array` and `matches regex`; a query the service refuses fails the rule (unknown), never passes it.
- `map: true` rows (key `value`) on diagnostic settings, security contacts, policy assignments, budgets, Front Door security policies and locks: first runtime use of `map` in any pack. Confirm one row per object appears and that an empty `value` array is judged empty. Policy assignments are read with `paging: none`; a subscription with more than one page of applicable assignments could make AZ-POLICY-MCSB-NOT-ASSIGNED fire falsely.
- Locks listed at a vault's own scope: confirm the answer includes locks inherited from the resource group and subscription; if it does not, AZ-RECOVERY-VAULT-NO-DELETE-LOCK over-reports.
- Field shapes taken from the ARM schemas but not seen live in Resource Graph: Recovery Services `securitySettings` / `redundancySettings` / `monitoringSettings`; Defender alert properties (`Status`, `Severity`, `AlertDisplayName`, PascalCase); `microsoft.security/pricings` in SecurityResources; protected items' `sourceResourceId` and `lastBackupTime`; VPN `connectionStatus` (a snapshot, may lag); Logic App `definition.triggers`; APIM `customProperties` keys; App Service Environment `kind` for v1; VM `properties.extended.instanceView.osName/osVersion`.
- Key Vault keys and secrets through ARM: confirm a vault with a restrictive firewall still answers the ARM list (management-plane), and that `attributes.exp` comes back as Unix seconds.
- The securityContacts api-version `2020-01-01-preview` and the `properties.emails` shape (string vs array); the classic-administrator, Lighthouse, Defender-settings and subscription-transfer-policy reads each need their own ARM permission; a denied read is recorded unknown, not a pass.
