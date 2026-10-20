# Backlog - infrastructure (VMware, Veeam, PRTG, Dynatrace, Azure, ServiceNow, Wiz, AWS, Keepit)

Checks that `rules/vmware.yaml`, `rules/veeam.yaml`, `rules/prtg.yaml`, `rules/dynatrace.yaml`,
`rules/azure.yaml`, `rules/servicenow.yaml` and `rules/wiz.yaml` cannot express yet, one line each:
the check, what it needs, and where it came from. After the backlog: the thresholds the rule files
define, and the details to confirm on the first real run.

Source labels: `rgcheck` = the legacy health-check plugin (check id), `signals` = the legacy notes on
which product states are the dangerous ones, `field` = a problem seen in a real estate (described
generically), `request` = asked for directly, `proposal` = `docs/proposals/infrastructure.md`.

Closed by the per-object requests (`for_each`) and relative dates (`{DAYS_AGO:n}`): VMware Tools per
VM, ISO connected per VM, SureBackup must-exist, and the Azure subscription-scoped checks for Defender
plans, storage accounts, Key Vault purge protection, unattached disks and public IPs, and stopped but
allocated VMs. The items below are what is still open, with the reason.

## Engine gaps - the data is in the API, the engine cannot use it yet

### Comparing two fields of the same row, or arithmetic

Conditions compare a field with a literal or a threshold, never with another field. Proposed: an
operand `ref: <field path>` and simple arithmetic (`ratio`, `sum`, `difference`).

- Datastore free space as a percentage (free_space / capacity). Source: rgcheck VM06. Partial: VMW-DATASTORE-FREE-SPACE (absolute bytes).
- Thin-provisioning over-commit per datastore (sum of VM provisioned space / capacity) - also needs aggregation across VMs and per-VM storage detail. Source: rgcheck VM07; signals (free space only means something together with over-commit).
- Repository free space as a percentage (freeGB / capacityGB). Source: rgcheck BK05. Partial: VEEAM-REPOSITORY-FREE-SPACE (absolute GB), VEEAM-STORAGE-SPACE-WARNING-OFF (the server's own percentage alarm).
- Used versus licensed instances on the backup licence (instanceLicenseSummary.usedInstancesNumber > licensedInstancesNumber). Source: rgcheck BK11; signals (instance creep has no date). Partial: VEEAM-LICENSE-SOCKETS-EXHAUSTED for socket licences.
- PRTG sensor count against the licensed sensor count - the licence figure is also not in the public API reference (`/api/getstatus.htm` fields are undocumented). Source: rgcheck MO02; signals. Partial: PRTG-SENSOR-PAUSED-BY-LICENSE (the effect, once the limit is hit).
- Dynatrace host-unit or platform-subscription consumption against entitlement - the entitlement is not in the environment API and billing metric names differ by licensing model. Source: rgcheck MO06; signals. Partial: DT-AGENT-UNLICENSED.
- Azure budget consumption percentage (currentSpend.amount / amount). Source: rgcheck AZ12.
- Health-event lead time (start of the maintenance minus the first notice time) - "notices that arrive too late to plan for". Source: field (most cloud maintenance notices in a quarter gave no usable lead time). Applies to AWS Health and Azure Service Health.
- Budget limit lower than actual spend (CalculatedSpend.ActualSpend > BudgetLimit). Source: field (department budgets set before usage tripled, never updated). AWS, see below.

### Conditions on one array element

A leaf over `a[].b` fires when any element matches; two leaves cannot be pinned to the same element.

- NSG rule that allows inbound traffic from Internet / `*` / 0.0.0.0/0 to an admin port (22, 3389, 445, 1433, 5985, 5986): direction, access, source and port must all hold for the same element of `properties.securityRules[]`, and port ranges ("3380-3390", "*") need range containment. Today `all` over `[]` paths could match four different rules. The per-subscription read itself is now possible (for_each). Source: rgcheck AZ07; request. Proposed: `each-element: <path>` with a nested condition, and an `in-range` op.
- Reservation utilisation below N% over 30 days: the 30-day value is one element of `utilization.aggregates[]` (grain 30); the 1- and 7-day elements must be ignored. Same for savings plans. Source: request (cost hygiene).
- VMW-VM-ISO-CONNECTED pairs `cdroms[].value.backing.type` and `cdroms[].value.state` across elements: a VM with two CD-ROMs can match one device's ISO backing with the other's connected state (a rare false positive). Source: proposal.

### Aggregation across rows (newest per entity, per-parent counts)

`count` (with or without `where`) judges the whole row set of an http query, not each parent of a
for_each. Proposed: `count: { group: <field>, ... }`.

- Last successful vCenter file-based backup older than N days (newest SUCCEEDED row of the job details). Source: request. Partial: VMW-VCSA-BACKUP-FAILED, VMW-VCSA-BACKUP-SCHEDULE-*.
- Newest restore point per protected object against its RPO (max creationTime per backupObjectId over `/api/v1/restorePoints`). Source: rgcheck BK04. Partial: VEEAM-OBJECT-FEW-RESTORE-POINTS, VEEAM-JOB-STALE.
- Last successful session per job compared with the job's own schedule (BK03 used last success, not last run). Source: rgcheck BK03. Partial: VEEAM-JOB-STALE (last run of any result), VEEAM-JOB-LAST-FAILED.
- Backup copy / offsite lag: copy jobs whose last success is older than N hours, and objects with no copy on an offsite repository type (3-2-1). Also blocked by the job types of REST 1.2 (see Unverified details). Source: rgcheck BK07; signals.
- Backup job duration longer than the backup window, per job, from session history (end - start). Source: rgcheck BK10. Partial: VEEAM-SESSION-LONG-RUNNING (sessions still working).
- A PRTG or Dynatrace parent object hiding many children (count of sensors paused by dependency per parent). Source: rgcheck MO03.
- Azure per subscription: no budget defined, no policy assignment, more than N Owner-role holders. The reads work through for_each; the "per subscription" count does not (a whole-tenant count would only say "no budget anywhere"). Source: rgcheck AZ12, AZ11; proposal.

### Paging the runner does not follow

- Azure Resource Manager pages with `nextLink`, not `@odata.nextLink`; `paging: auto` stops after page one. Tenant lists are usually one page, but per-subscription resource lists (VMs, disks, storage accounts, public IPs) can be longer and are then judged on the first page without a warning. Source: request; proposal. Proposed: an `arm` paging mode (or a `nextLink` field name option).
- Dynatrace pages with `nextPageKey` (and other parameters must be dropped on later pages). Problems are read as one page of 500 (DT-PROBLEM-LIST-TRUNCATED warns), API tokens as one page of 10,000, settings objects as one page of 500; OneAgent hosts as one page of the API's default size. Source: request. Proposed: a `token` paging mode with a "next request carries only the token" flag.
- Wiz `cloudAccounts` and `connectors` are read without a cursor (first 500), because only the plain shape was confirmed on a live tenant. Source: request.

### Tenant thresholds on query parameters

`threshold:` replaces a condition value only. Windows written into a request are fixed in the rule:
DT-PROBLEM-OPEN-LONG (`to: now-7d`) and VEEAM-SUREBACKUP-NO-RECENT-RUN (`createdAfterFilter:
{DAYS_AGO:90}`). Proposed: `{DAYS_AGO:threshold.name|90}` or a `threshold:` on a parameter. Source: proposal.

### A constant deadline

VMW-VCSA-VERSION-SUPPORT-ENDING has no date field for `deadline:` (the end of general support of
vCenter 8 is a vendor date, 2027-10-11), so it cannot rank like other expiries or raise its severity
as the date nears. Proposed: `deadline: { value: "<date>" }`. Source: proposal.

### Dates the engine does not read

- Epoch milliseconds (Dynatrace problem startTime, host lastSeenTimestamp, ActiveGate offlineSince): problem age, hosts not seen for N days, ActiveGate offline for N hours. Source: rgcheck MO06; request. Partial: DT-PROBLEM-OPEN-LONG (works through the query timeframe instead). Proposed: accept 13-digit epoch-ms as a date.
- OLE automation dates (PRTG `lastcheck_raw`, `lastup_raw`: days since 1899-12-30) and the localized display dates: sensors whose data is stale, how long a sensor has been paused. Source: rgcheck MO03 (paused more than 7 days); signals. Partial: PRTG-SENSOR-PAUSED-BY-USER (all user pauses), PRTG-SENSOR-DOWN-LONG (uses downtimesince_raw seconds).
- vCenter patch release date (`/api/appliance/system/version` releasedate): format undocumented; a "patch older than N days" rule waits for a first real answer. Source: request.

### Responses that are not a list of objects

- The vSphere `/api` base path answers several GETs with a bare string or boolean (health colours, SSH, time-sync mode, last health check) or a map keyed by id (backup schedules, job details, services, a VM's devices). The rules use the deprecated `/rest` base path instead, which wraps them; when `/rest` is removed they need the runner to wrap a scalar as `{value: ...}` and turn a map into `[{key, value}]` rows. Source: request.
- A bare array of strings gives no rows at all - on `/api`, and on `/rest` too, because `{value: [...]}` is unwrapped as an OData list and its strings are dropped. A count over it would look like a pass, so no rule was written. Blocked: an enabled appliance local account other than root (`/api/appliance/local-accounts` lists names only; the per-name detail could then be read with for_each), and exactly one appliance NTP server (`/rest/appliance/ntp`). Proposed: turn a string element into `{value: "<string>"}`. Source: proposal (VMW-VCSA-LOCAL-ACCOUNT-EXTRA, VMW-VCSA-NTP-SINGLE-SERVER).
- XML-only APIs (Keepit, the EC2 query API) - see the Keepit and AWS sections.

### Nested per-object requests

`for_each` cannot be nested (a list per object, then a request per item of that list).

- Recovery Services: VMs with no protected item, and protected items whose last backup is older than N hours (subscriptions -> vaults -> protected items). Source: rgcheck AZ05.
- Diagnostic settings per resource (subscriptions -> resources -> diagnostic settings). Source: proposal.
- VPN gateway connections not Connected: connections are listed per resource group only (subscriptions -> resource groups -> connections). Source: field (the same tunnel-down class of outage as on AWS).

### Joins across systems

- vCenter VMs that are in no backup job (VM inventory minus Veeam backup objects, matched on name or instance UUID). Source: rgcheck BK01; signals (the VM nobody added, found at restore time).
- Every workload in at least one backup product (VMware, Veeam, cloud-native, SaaS backup). Source: rgcheck BK20.
- ESXi hosts known to the network or CMDB but in no vCenter inventory. Source: rgcheck VM13.
- A configuration item monitored by none of the monitoring tools (CMDB minus PRTG devices minus Dynatrace hosts). Source: signals.
- Cloud-security connector or deployment owned or created by a person who has left (connector creator x directory account disabled). Source: field.
- Users disabled in the directory who still hold admin in Dynatrace or a SaaS backup console. Source: field.
- Backup appliance in a public cloud reconciled against the cloud's native backup findings. Source: rgcheck AW02.

## Not expressible with the current integration scope

### VMware - not in the vSphere Automation API

The Automation API has no per-host or per-cluster detail with these fields, so for_each does not help;
they need the Web Services (SOAP) API, which is a different runner.

- ESXi version and build per host, against end of support (the host list has no version, and there is no host GET). Source: rgcheck VM03 (ESXi part).
- Hosts in maintenance mode. Source: rgcheck VM05.
- Host NTP service, servers and clock offset; ESXi lockdown mode. Source: rgcheck VM12.
- VM connection state orphaned / inaccessible / invalid. Source: rgcheck VM10. Partial: VMW-VM-CONFIG-UNAVAILABLE.
- Cluster admission control and DRS automation level (the cluster GET returns name and resource pool only). Source: rgcheck VM11; signals (admission control off is the common one). Partial: VMW-CLUSTER-HA-OFF, VMW-CLUSTER-DRS-OFF.
- Old or large VM snapshots (no snapshot list in the 8.0 Automation API). Source: proposal.

### Azure - subscription-scoped routes still open

Subscription-scoped reads now go through for_each over `/subscriptions` in `rules/azure.yaml`. Still
open (beyond the element-wise, per-parent count, paging and nested items above):

- Storage accounts with a minimum TLS version below 1.2 - not written: the service has been retiring TLS 1.0/1.1 on its side; confirm whether the account setting still has effect before adding a rule. Source: rgcheck AZ09; request.
- Key Vault secret and certificate expiry (data plane, a separate token audience; metadata only, never values). Soft delete is no longer a check: it cannot be switched off on current vaults. Source: rgcheck AZ08.
- Disks without encryption at host or a customer-managed key where policy requires one (which disks need it is a tenant decision). Source: rgcheck AZ06.
- Resource Health availability statuses Unavailable / Degraded / Unknown - expressible now, not written: the per-subscription list covers every resource and pages with `nextLink`, so a large subscription would be judged on a fraction without a warning. Source: rgcheck AZ03.
- Subscription-level service health events (the tenant-level ones are covered by AZ-HEALTH-*) - expressible now, not written in this pass. Source: rgcheck AZ02.
- Policy compliance summary - a POST (`policyStates/latest/summarize`), which the GET-only runner refuses. Source: rgcheck AZ11.
- App Service: state not Running, HTTPS-only off, custom-domain certificate expiry - expressible now (`/subscriptions/{id}/providers/Microsoft.Web/sites`), not written in this pass. Source: rgcheck AZ10.
- ExpressRoute circuit provider state - expressible now, not written in this pass. Source: field.
- Defender for Cloud secure score below a target - expressible, not written: a score is a trend to watch, not a task for today. Source: proposal.

### Dynatrace account management (users and SSO)

User, group and SAML configuration live in the account-management API on a different host
(`api.dynatrace.com`, account UUID in the path, OAuth client with account read scopes), not on the
environment endpoint that `rules/dynatrace.yaml` binds. Needs a second integration (for example a
`dynatrace-account` file, endpoint `https://api.dynatrace.com/iam/v1/accounts/<uuid>`, rule path
`/users`) and the response field names confirmed against that API. Checks waiting for it:

- Users who do not sign in through SSO: their e-mail domain is not one bound to the SAML configuration (domain pattern as a tenant threshold). Source: request; field (SAML bound to only one of two verified domains, so most users kept signing in with the vendor's own login).
- Users in no SCIM-provisioned group (access granted locally, outside the directory) - one call per user, which for_each could now make once the integration exists. Source: field (most users held access through local groups only).
- Admin rights held through local groups next to SCIM groups. Source: field.
- Break-glass / account-admin user outside the organisation's domains (vendor-held). Source: field.
- SCIM token and SAML signing certificate expiry. Source: field.

### Keepit (SaaS backup) - XML API

The Keepit API answers XML, and several of its list calls are PUT requests with a query body, so
neither the `http` runner (GET, JSON) nor `graphql` can read it. Needs XML parsing in the http runner
and an allow-listed read-only PUT, or a `file` import of an exported report. Checks waiting for it
(generic to any SaaS backup console):

- Backup job stuck "in progress" far longer than its normal duration (a job running for days while normal runs take minutes). Source: request; field.
- Failed backup jobs in the last N hours. Source: rgcheck BK19.
- Administrators who sign in with a local password instead of SSO - disabling them in the directory does not cut their access. Source: request; field.
- A departed person still a master admin and the primary contact; emergency, financial and legal contacts empty. Source: field.
- Objects selected for backup but not covered, and items skipped on every run. Source: field.
- Workloads in scope (mail, files, sites, chat) and protected seats against licensed users. Source: rgcheck BK17, BK18; signals.
- Anomaly detections (mass modification) and recurring anomalies on the same dataset. Source: field.
- Admin API tokens unused for months. Source: field.
- Note for coverage reviews: a SaaS backup product may not cover on-premises directories at all; that gap belongs to the cross-product coverage join above. Source: field.

### AWS - no integration type (SigV4)

There is no `aws` integration: requests need SigV4 signing; most AWS read APIs are POST
(JSON 1.0/1.1 with `X-Amz-Target`) or return XML (EC2 query API), and organisation-wide checks need a
role assumed per account. A future `aws` runner would need: SigV4 with the integration's credentials,
an allow-list of read actions (Describe*, List*, Get*, Search*), XML and JSON decoding, per-account
fan-out, and CloudWatch metric statistics. Rules it would enable (all from real problems, described
generically):

- VPN tunnel down, per tunnel, with time since the status changed (EC2 DescribeVpnConnections, vgwTelemetry). Source: field (a tunnel down overnight, found in the morning; its pair down for weeks).
- Both tunnels of a VPN connection down. Source: field.
- VPN tunnel IKE logging disabled (tunnel log options), which leaves no evidence when a tunnel fails. Source: field.
- VPN connection with no CloudWatch alarm on TunnelState - "no alarm fired". Source: field.
- VPN tunnel throughput near the per-tunnel ceiling (TunnelDataIn/Out against about 1.25 Gbps). Source: field.
- Direct Connect connection not available, virtual interface down, BGP peer down (DescribeConnections, DescribeVirtualInterfaces). Source: request; field.
- Transit gateway attachment with no route-table association; route tables with no propagated routes where propagation is expected. Source: field.
- Health scheduled changes (maintenance) starting within N days, with the start as deadline; open Health issues affecting the organisation. Source: request; field (connectivity maintenance announced with little notice).
- Health notices whose lead time is shorter than N days (also needs the arithmetic above). Source: request; field.
- Cost anomalies above a tenant threshold (Cost Explorer GetAnomalies). Source: request.
- Budget exceeded (also arithmetic), budgets not updated while spend grew, accounts covered by no budget, no organisation-wide budget. Source: field.
- Marketplace agreements ending within N days (Marketplace Agreement SearchAgreements, end time as deadline). Source: request; field (many renewal reminders and a pricing change at renewal).
- Account root e-mail on a personal mailbox rather than a role mailbox (Organizations ListAccounts, address pattern as a tenant threshold); alternate contacts missing (Account GetAlternateContact). Source: field.
- Service control policies with no targets; accounts without a region-restriction policy. Source: field.
- Gateway load balancers with cross-zone load balancing on (a large cross-AZ data charge). Source: field.
- Database clusters far oversized for their load (CPU below N% for 14 days). Source: field.
- Cost and usage exports missing or unreadable to the review role. Source: field.
- Security groups attached to nothing, especially temporary groups a backup product creates and never deletes. Source: field.
- Support cases auto-closed without a customer reply while the problem recurs (Support API, needs a paid support plan). Source: field.

### Other systems and other packs

- vCenter SSO identity sources and local-only administrators (vsphere.local accounts in use): not in the Automation API (SSO admin interface only). Source: request (admins without SSO).
- Backup console users without MFA, and four-eyes authorisation: the users-and-roles and MFA settings routes are not confirmed in REST revision 1.2. Source: request.
- PRTG users authenticating locally instead of through the directory: no documented user-list API. Source: request.
- iDRAC / Redfish hardware health and predictive drive failure: a different endpoint per server; needs a Redfish integration. Source: rgcheck VM15.
- Machine SSL certificates on ESXi hosts and other appliance ports: belongs to `rules/certificates.yaml` (tls protocol). Source: rgcheck VM14.
- vCenter STS signing certificate and trusted root chains: the API returns PEM chains without dates; needs certificate parsing in the runner. Source: signals (an expired STS certificate locks everyone out).
- Veeam ONE alarms, unacknowledged and long-acknowledged: separate product and API. Source: rgcheck BK12; signals.
- Veeam Backup for AWS sessions and policy count: separate appliance and API. Source: rgcheck BK13; signals.
- A shared mailbox that receives cloud notices and is not triaged (hundreds unread): mailbox data, belongs to the Microsoft 365 pack (Graph mail folder unread count). Source: field.
- Secrets sent in clear in mail or documents (a tunnel pre-shared key in an attachment): content inspection, not a state check. Source: field.
- On-premises gateway route leaks and missing prefix filters: needs a firewall or router integration. Source: field.
- Traffic asymmetry between two tunnels (flow-log analysis): log analytics, not a state check. Source: field.
- Invoices without a purchase order: billing documents, not an API state. Source: field.

## Unverified details - rule not written

- Veeam repository immutability (hardened repository immutability days, object-storage object lock): the published GET samples of REST 1.2-rev1 show only Windows and Linux repositories and no immutability path; the proposal's `repository.makeRecentBackupsImmutableDays` appears only in an add-repository sample. Partial: VEEAM-REPOSITORY-NO-IMMUTABLE-CAPABLE (no repository of a kind that can be immutable). Source: rgcheck BK06; signals (immutability you believe you have); proposal (VEEAM-REPOSITORY-IMMUTABILITY-SHORT).
- Veeam backup copy job missing: the REST 1.2 job type list has no VM backup-copy type (only FileBackupCopy); 1.3 adds BackupCopy and LegacyBackupCopy but renames Backup to VSphereBackup, so the rule needs the file (or a second file) pinned to 1.3 on version 13 servers. Source: proposal (VEEAM-COPY-JOB-MISSING); rgcheck BK07.
- Veeam failed-session detail per object (`/api/v1/sessions/{id}/taskSessions`, now readable with for_each over failed sessions): the published sample shows only scan fields; the result fields (`result.result`, `result.message`) are not confirmed. Source: rgcheck BK02.
- Veeam session states WaitingRepository / WaitingSlot as filters: listed from revision 1.2-rev1, while the rules pin 1.2-rev0. Source: request.
- vCenter pending-update list (`/api/appliance/update/pending`): undocumented whether an up-to-date appliance answers an empty list or 404. Partial: VMW-VCSA-HEALTH-PACKAGES, VMW-VCSA-UPDATE-*.
- PRTG core status (`/api/getstatus.htm?id=0`): maintenance days left, update available, low memory. The field names are undocumented (MaintExpiryDays appears in no vendor page; a community sample shows PRTGUpdateAvailable as "yes", not true). Source: proposal (PRTG-MAINTENANCE-EXPIRING, PRTG-UPDATE-AVAILABLE, PRTG-LOW-MEMORY).
- Dynatrace host entities' monitoring mode through `/api/v2/entities` (property names community-sourced only); the OneAgent API covers it with documented fields. Source: rgcheck MO06.
- Wiz issues whose related entity is a secret (`relatedEntity: {type: [SECRET]}`) and rejected critical or high issues without a note (`note`, `resolutionReason`): the filter value and field names exist only in the tenant's schema explorer. Source: proposal (WIZ-ISSUE-SECRET-EXPOSED, WIZ-ISSUE-REJECTED-NO-NOTE).
- Wiz cloud-event sources (audit logs, flow logs, DNS, Kubernetes audit) switched off: no public field found. Source: field (every cloud event source off).
- Wiz exposure fields on issues (only confirmed on vulnerability assets). Source: request.

## Thresholds

Set as `threshold.<name>` in the Keeper home; the value in the rule applies when it is not set.

| Threshold | Default | Rule |
|---|---|---|
| vmware.datastore-free-bytes-min | 107374182400 (100 GiB) | VMW-DATASTORE-FREE-SPACE |
| vmware.unsupported-version-pattern | `^(5\|6\|7)\.` | VMW-VCSA-VERSION-UNSUPPORTED |
| vmware.support-ending-version-pattern | `^8\.` | VMW-VCSA-VERSION-SUPPORT-ENDING |
| vmware.update-check-max-age-days | 30 | VMW-VCSA-UPDATE-CHECK-STALE |
| vmware.health-check-max-age-days | 1 | VMW-VCSA-HEALTH-CHECK-STALE |
| vmware.cert-notice-days | 60 | VMW-VC-TLS-CERT-EXPIRY |
| vmware.root-password-notice-days | 30 | VMW-VCSA-ROOT-PASSWORD-EXPIRY |
| vmware.local-password-max-days | 90 | VMW-VCSA-PASSWORD-POLICY-MAX-DAYS |
| vmware.replication-max-lag | 100 | VMW-VC-ELM-REPLICATION-LAG |
| vmware.backup-failure-window-days | 7 | VMW-VCSA-BACKUP-FAILED |
| vmware.backup-max-run-days | 0.5 | VMW-VCSA-BACKUP-STUCK |
| veeam.job-max-age-days | 2 | VEEAM-JOB-STALE |
| veeam.min-retention-quantity | 7 | VEEAM-JOB-SHORT-RETENTION |
| veeam.session-window-days | 1 | VEEAM-SESSION-FAILED |
| veeam.session-max-run-days | 0.5 | VEEAM-SESSION-LONG-RUNNING |
| veeam.repository-free-gb-min | 200 | VEEAM-REPOSITORY-FREE-SPACE |
| veeam.storage-warning-min-percent | 10 | VEEAM-STORAGE-SPACE-WARNING-OFF |
| veeam.license-notice-days | 60 | VEEAM-LICENSE-EXPIRY |
| veeam.support-notice-days | 90 | VEEAM-SUPPORT-EXPIRY |
| veeam.license-min-free-sockets | 0 | VEEAM-LICENSE-SOCKETS-EXHAUSTED |
| veeam.config-backup-max-age-days | 2 | VEEAM-CONFIG-BACKUP-STALE |
| veeam.malware-window-days | 30 | VEEAM-MALWARE-INFECTED, VEEAM-MALWARE-SUSPICIOUS |
| veeam.analyzer-max-age-days | 30 | VEEAM-ANALYZER-STALE |
| veeam.min-restore-points | 2 | VEEAM-OBJECT-FEW-RESTORE-POINTS |
| prtg.down-max-seconds | 604800 (7 days) | PRTG-SENSOR-DOWN-LONG |
| prtg.high-priority-down-max-seconds | 86400 (1 day) | PRTG-SENSOR-DOWN-HIGH-PRIORITY-DAY |
| dynatrace.token-unused-days | 90 | DT-TOKEN-UNUSED |
| dynatrace.token-notice-days | 14 | DT-TOKEN-EXPIRING |
| azure.reservation-notice-days | 60 | AZ-RESERVATION-EXPIRY |
| azure.savings-plan-notice-days | 60 | AZ-SAVINGS-PLAN-EXPIRY |
| azure.enrollment-notice-days | 90 | AZ-BILLING-ENROLLMENT-ENDING |
| azure.maintenance-notice-days | 14 | AZ-HEALTH-PLANNED-MAINTENANCE |
| azure.defender-required-plans | `^(VirtualMachines\|StorageAccounts\|KeyVaults\|Arm\|CloudPosture)$` | AZ-DEFENDER-PLAN-OFF |
| azure.unattached-disk-days | 30 | AZ-DISK-UNATTACHED |
| servicenow.urgent-incident-stale-days | 1 | SNOW-INCIDENT-HIGH-PRIORITY-STALE |
| servicenow.new-incident-max-days | 1 | SNOW-INCIDENT-NEW-UNTOUCHED |
| servicenow.incident-stale-days | 14 | SNOW-INCIDENT-STALE |
| servicenow.on-hold-max-days | 7 | SNOW-INCIDENT-ON-HOLD-LONG |
| servicenow.sla-risk-percent | 75 | SNOW-SLA-AT-RISK |
| servicenow.change-lookahead-days | 7 | SNOW-CHANGE-STARTING-SOON |
| servicenow.change-approval-lead-days | 3 | SNOW-CHANGE-UNAPPROVED-SOON |
| servicenow.change-close-grace-days | 1 | SNOW-CHANGE-NOT-CLOSED |
| servicenow.task-due-notice-days | 0 | SNOW-CATALOG-TASK-OVERDUE |
| servicenow.approval-max-wait-days | 3 | SNOW-APPROVAL-PENDING-LONG |
| servicenow.ci-discovery-max-days | 30 | SNOW-CMDB-SERVER-NOT-DISCOVERED |
| servicenow.max-admins | 10 | SNOW-ADMIN-ROLE-COUNT |
| servicenow.user-dormant-days | 90 | SNOW-USER-DORMANT |
| wiz.issue-max-open-days | 30 | WIZ-ISSUE-OPEN-TOO-LONG (high severity only) |
| wiz.critical-max-open-days | 7 | WIZ-ISSUE-CRITICAL-AGED |
| wiz.triage-max-days | 3 | WIZ-ISSUE-UNTRIAGED |
| wiz.issue-due-notice-days | 0 | WIZ-ISSUE-PAST-DUE |
| wiz.critical-fix-max-age-days | 30 | WIZ-VULN-CRITICAL-FIX-OVERDUE |
| wiz.ignored-health-recent-days | 2 | WIZ-HEALTH-IGNORED-RECURRING |
| wiz.service-account-rotation-days | 365 | WIZ-SERVICE-ACCOUNT-SECRET-OLD |

## To confirm on the first real run

- vCenter: the integration's `/api/session` id is accepted on the `/rest` routes (it is the same vAPI session on 7.x and 8.x); the certificate-management and local-accounts routes need administrator-level privileges.
- vCenter: `/rest/vcenter/services` and `/rest/vcenter/vm/{vm}` render their maps as `[{key, value}]` like the backup routes; `standalone=true` is honoured on the host list (if it is ignored, every host is reported as standalone - visible at once); the `/rest/appliance/health/system/lastcheck` value is a date the engine reads (otherwise VMW-VCSA-HEALTH-CHECK-STALE is n/a); `power_states=POWERED_ON` filters the VM list for the for_each rules; more than 2000 powered-on VMs makes the per-VM rules partial.
- Veeam: x-api-version 1.2-rev0 is accepted by the server (12.2 or later) and the integration does not add its own x-api-version header; the Security & Compliance Analyzer status words (Ok, Violation, UnableToCheck, Suppressed) match the REST enum.
- Veeam: `/api/v1/jobs` carries the encryption, application-aware, schedule, retry and retention paths for the job types present (seen in the 1.2-rev1 sample); `typeFilter=SureBackup` on sessions is accepted by 1.2-rev0 (seen in 1.2-rev1; a refusal makes the rule unknown) and the rows carry `sessionType` SureBackup; licence `type` spellings Evaluation / NFR / Subscription / Rental and `autoUpdateEnabled` (seen in the 1.2-rev1 sample) are returned by 1.2-rev0; `jobId` is absent or empty on imported or orphaned backups (if it keeps the deleted job's id, VEEAM-BACKUP-ORPHANED sees only imported ones); the `generalOptions` paths read on 1.1 are unchanged.
- PRTG: `start` in the table API is zero-based (otherwise each page repeats one row, which only duplicates a result); `content=probes&filter_parentid=0` answers `{"probes": [...]}` with `condition_raw` (a support answer suggests `filter_type=probenode` instead - an empty list shows up as PRTG-PROBE-NONE); `content=devices` answers `{"devices": [...]}` with the `*sens_raw` columns; a paused device reports `status_raw` 7.
- Dynatrace: the OneAgent list fits one page; problems older than the 90-day window are not open; the token has `apiTokens.read` and `settings.read`; API token rows carry `enabled` (or the sample's `disabled`); `scopes` omitted on settings objects returns the host and host-group overrides as well as the environment object.
- Azure: the review identity has root-scope read for AZ-ROOT-SCOPE-ROLE-ASSIGNMENT and the custom-role rules, Reservations Reader for the reservation and savings-plan rules, and Billing Reader for the billing rules; without them those rules are unknown or (billing) report no account. An untagged subscription returns `tags: {}` or no key (both are covered). `statusOnly=true` on the VM list returns `properties.instanceView.statuses[].code`; the Defender plan names in the default pattern match the subscription's pricings list; disks expose `LastOwnershipUpdateTime` on API 2024-03-02.
- ServiceNow: `sysparm_display_value=all` returns `{display_value, value}` per field as assumed by the SLA and approval rules; risk codes 1/2 are very high/high; `sysapproval_approver.state` stores `requested`; `reopen_count` and `hold_reason` exist on incident; `cmdb_ci_server` is the right class (some estates use `cmdb_ci_computer` or `cmdb_ci_win_server` only); the integration account may call the Aggregate API (`/api/now/stats/sys_user_has_role`); `last_login_time` is set by single sign-on logins too.
- Wiz: `issuesV2` and `vulnerabilityFindings` accept `first: 500`; the vulnerability queries can be large (hundreds of pages on a big estate) and stop at `maxPages` as partial; `hasExploit: false` is accepted as a filter; `projects { archived }` and `serviceAccounts { createdAt lastRotatedAt }` exist with those names, and the service account can read them.
