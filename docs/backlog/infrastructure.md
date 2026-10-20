# Backlog - infrastructure (VMware, Veeam, PRTG, Dynatrace, Azure, ServiceNow, Wiz, AWS, Keepit)

Checks that `rules/vmware.yaml`, `rules/veeam.yaml`, `rules/prtg.yaml`, `rules/dynatrace.yaml`,
`rules/azure.yaml`, `rules/servicenow.yaml` and `rules/wiz.yaml` cannot express yet, one line each:
the check, what it needs, and where it came from. After the backlog: the thresholds the rule files
define, and the details to confirm on the first real run.

Source labels: `rgcheck` = the legacy health-check plugin (check id), `signals` = the legacy notes on
which product states are the dangerous ones, `field` = a problem seen in a real estate (described
generically), `request` = asked for directly.

## Engine gaps - the data is in the API, the engine cannot use it yet

### Comparing two fields of the same row, or arithmetic

Conditions compare a field with a literal or a threshold, never with another field. Proposed: an
operand `ref: <field path>` and simple arithmetic (`ratio`, `sum`, `difference`).

- Datastore free space as a percentage (free_space / capacity). Source: rgcheck VM06. Partial: VMW-DATASTORE-FREE-SPACE (absolute bytes).
- Thin-provisioning over-commit per datastore (sum of VM provisioned space / capacity) - also needs aggregation across VMs and per-VM storage detail. Source: rgcheck VM07; signals (free space only means something together with over-commit).
- Repository free space as a percentage (freeGB / capacityGB). Source: rgcheck BK05. Partial: VEEAM-REPOSITORY-FREE-SPACE (absolute GB).
- Used versus licensed instances on the backup licence (instanceLicenseSummary.usedInstancesNumber > licensedInstancesNumber). Source: rgcheck BK11; signals (instance creep has no date). Partial: VEEAM-LICENSE-SOCKETS-EXHAUSTED for socket licences.
- PRTG sensor count against the licensed sensor count - the licence figure is also not in the public API reference (`/api/getstatus.htm` fields are undocumented). Source: rgcheck MO02; signals. Partial: PRTG-SENSOR-PAUSED-BY-LICENSE (the effect, once the limit is hit).
- Dynatrace host-unit or platform-subscription consumption against entitlement - the entitlement is not in the environment API and billing metric names differ by licensing model. Source: rgcheck MO06; signals. Partial: DT-AGENT-UNLICENSED.
- Azure budget consumption percentage (currentSpend.amount / amount) - also subscription-scoped, see below. Source: rgcheck AZ12.
- Health-event lead time (start of the maintenance minus the first notice time) - "notices that arrive too late to plan for". Source: field (most cloud maintenance notices in a quarter gave no usable lead time). Applies to AWS Health and Azure Service Health.
- Budget limit lower than actual spend (CalculatedSpend.ActualSpend > BudgetLimit). Source: field (department budgets set before usage tripled, never updated). AWS, see below.

### Conditions on one array element

A leaf over `a[].b` fires when any element matches; two leaves cannot be pinned to the same element.

- NSG rule that allows inbound traffic from Internet / `*` / 0.0.0.0/0 to an admin port (22, 3389, 445, 1433, 5985, 5986): direction, access, source and port must all hold for the same element of `properties.securityRules[]`, and port ranges ("3380-3390", "*") need range containment. Today `all` over `[]` paths could match four different rules. Also subscription-scoped. Source: rgcheck AZ07; request. Proposed: `each-element: <path>` with a nested condition, and an `in-range` op.
- Reservation utilisation below N% over 30 days: the 30-day value is one element of `utilization.aggregates[]` (grain 30); the 1- and 7-day elements must be ignored. Source: request (cost hygiene).

### Aggregation across rows (newest per entity, "at least one row matches")

- Last successful vCenter file-based backup older than N days (newest SUCCEEDED row of the job details). Source: request. Partial: VMW-VCSA-BACKUP-FAILED, VMW-VCSA-BACKUP-SCHEDULE-*.
- Newest restore point per protected object against its RPO (max creationTime per backupObjectId over `/api/v1/restorePoints`). Source: rgcheck BK04. Partial: VEEAM-OBJECT-FEW-RESTORE-POINTS, VEEAM-JOB-STALE.
- Last successful session per job compared with the job's own schedule (BK03 used last success, not last run). Source: rgcheck BK03. Partial: VEEAM-JOB-STALE (last run of any result), VEEAM-JOB-LAST-FAILED.
- Backup copy / offsite lag: copy jobs whose last success is older than N hours, and objects with no copy on an offsite repository type (3-2-1). Source: rgcheck BK07; signals.
- At least one SureBackup (restore verification) job exists and ran within 90 days ("count where type = SureBackup, fail if none"). Source: rgcheck BK09; signals. Proposed: `count: { where: <condition>, op: lt, value: 1 }`.
- Backup job duration longer than the backup window, per job, from session history (end - start). Source: rgcheck BK10. Partial: VEEAM-SESSION-LONG-RUNNING (sessions still working).
- A PRTG or Dynatrace parent object hiding many children (count of sensors paused by dependency per parent). Source: rgcheck MO03.

### Paging the runner does not follow

- Azure Resource Manager pages with `nextLink`, not `@odata.nextLink`; `paging: auto` stops after page one. Lists are usually one page, but a large tenant would be judged on part of its data without any warning. Source: request. Proposed: an `arm` paging mode (or `nextLink` field name option).
- Dynatrace pages with `nextPageKey` (and other parameters must be dropped on later pages). Problems are read as one page of 500 (DT-PROBLEM-LIST-TRUNCATED warns); OneAgent hosts are read as one page of the API's default size. Source: request. Proposed: a `token` paging mode with a "next request carries only the token" flag.
- Wiz `cloudAccounts` and `connectors` are read without a cursor (first 500), because only the plain shape was confirmed on a live tenant. Source: request.

### Dates the engine does not read

- Epoch milliseconds (Dynatrace problem startTime, host lastSeenTimestamp, ActiveGate offlineSince): problem age, hosts not seen for N days, ActiveGate offline for N hours. Source: rgcheck MO06; request. Proposed: accept 13-digit epoch-ms as a date.
- OLE automation dates (PRTG `lastcheck_raw`, `lastup_raw`: days since 1899-12-30) and the localized display dates: sensors whose data is stale, how long a sensor has been paused. Source: rgcheck MO03 (paused more than 7 days); signals. Partial: PRTG-SENSOR-PAUSED-BY-USER (all user pauses), PRTG-SENSOR-DOWN-LONG (uses downtimesince_raw seconds).
- vCenter patch release date (`/api/appliance/system/version` releasedate): format undocumented; a "patch older than N days" rule waits for a first real answer. Source: request.

### Responses that are not a list of objects

- The vSphere `/api` base path answers several GETs with a bare string or boolean (health colours, SSH, time-sync mode) or a map keyed by id (backup schedules, job details). The rules use the deprecated `/rest` base path instead, which wraps them; when `/rest` is removed they need the runner to wrap a scalar as `{value: ...}` and turn a map into `[{key, value}]` rows. Source: request.
- XML-only APIs (Keepit, the EC2 query API) - see the Keepit and AWS sections.

### One GET per object (fan-out)

- VMware Tools running and current per VM (`/api/vcenter/vm/{vm}/tools`): toolsNotRunning means crash-consistent backups that still report success. Source: rgcheck VM09; signals.
- ESXi version and build per host, against end of support (the host list has no version). Source: rgcheck VM03 (ESXi part).
- Hosts in maintenance mode (not in the host list summary). Source: rgcheck VM05.
- Host NTP service, servers and clock offset (not in the Automation API). Source: rgcheck VM12.
- VM connection state orphaned / inaccessible / invalid (only in the Web Services API). Source: rgcheck VM10. Partial: VMW-VM-CONFIG-UNAVAILABLE.
- Cluster admission control and DRS automation level (not in the cluster summary). Source: rgcheck VM11; signals (admission control off is the common one). Partial: VMW-CLUSTER-HA-OFF, VMW-CLUSTER-DRS-OFF.
- Failed backup session detail: failing objects and log text per session (`/api/v1/sessions/{id}/taskSessions`, `/logs`). Source: rgcheck BK02.
- Dynatrace users and their groups (see the Dynatrace account section).

### Joins across systems

- vCenter VMs that are in no backup job (VM inventory minus Veeam backup objects, matched on name or instance UUID). Source: rgcheck BK01; signals (the VM nobody added, found at restore time).
- Every workload in at least one backup product (VMware, Veeam, cloud-native, SaaS backup). Source: rgcheck BK20.
- ESXi hosts known to the network or CMDB but in no vCenter inventory. Source: rgcheck VM13.
- A configuration item monitored by none of the monitoring tools (CMDB minus PRTG devices minus Dynatrace hosts). Source: signals.
- Cloud-security connector or deployment owned or created by a person who has left (connector creator x directory account disabled). Source: field.
- Users disabled in the directory who still hold admin in Dynatrace or a SaaS backup console. Source: field.
- Backup appliance in a public cloud reconciled against the cloud's native backup findings. Source: rgcheck AW02.

## Not expressible with the current integration scope

### Azure - subscription-scoped routes

ARM list routes for resources need `/subscriptions/{id}` in the path. `rules/azure.yaml` reads only
tenant-wide routes. Two ways in: a subscription-scoped `azure` integration whose endpoint path is the
subscription (`https://management.azure.com/subscriptions/<id>`, one integration per subscription,
like one `ldap` integration per forest) with a second rule file of relative `/providers/...` paths, or
engine fan-out over the `/subscriptions` rows. Checks waiting for it:

- NSG inbound from the internet on admin ports - also needs the element-wise condition above. Source: rgcheck AZ07; request.
- Storage accounts: HTTPS-only off, minimum TLS below 1.2, public blob access allowed, shared-key access allowed. Source: rgcheck AZ09; request.
- Key Vault soft delete and purge protection (management plane). Source: request.
- Key Vault secret and certificate expiry (data plane, a separate token audience; metadata only, never values). Source: rgcheck AZ08.
- VM power state "stopped but not deallocated" (needs `instanceView` per VM - also fan-out). Source: rgcheck AZ04.
- Unattached managed disks older than N days; disks without encryption at host or CMK where required. Source: rgcheck AZ06.
- VMs with no Recovery Services protected item, and protected items whose last backup is older than N hours. Source: rgcheck AZ05.
- Resource Health availability statuses Unavailable / Degraded / Unknown. Source: rgcheck AZ03.
- Subscription-level service health events (the tenant-level ones are covered by AZ-HEALTH-*). Source: rgcheck AZ02.
- Policy compliance summary - also a POST (`policyStates/latest/summarize`), which the GET-only runner refuses; and "zero assignments reads as 100% compliant" needs a count over assignments. Source: rgcheck AZ11.
- Budgets: none defined, consumption above N% (Consumption budgets). Source: rgcheck AZ12; field (no organisation-wide budget).
- App Service: state not Running, HTTPS-only off, custom-domain certificate expiry. Source: rgcheck AZ10.
- VPN gateway connections not Connected; ExpressRoute circuit provider state. Source: field (the same tunnel-down class of outage as on AWS).

### Dynatrace account management (users and SSO)

User, group and SAML configuration live in the account-management API on a different host
(`api.dynatrace.com`, account UUID in the path, OAuth client with account read scopes), not on the
environment endpoint that `rules/dynatrace.yaml` binds. Needs a second integration (for example a
`dynatrace-account` file, endpoint `https://api.dynatrace.com/iam/v1/accounts/<uuid>`, rule path
`/users`) and the response field names confirmed against that API. Checks waiting for it:

- Users who do not sign in through SSO: their e-mail domain is not one bound to the SAML configuration (domain pattern as a tenant threshold). Source: request; field (SAML bound to only one of two verified domains, so most users kept signing in with the vendor's own login).
- Users in no SCIM-provisioned group (access granted locally, outside the directory) - needs one call per user. Source: field (most users held access through local groups only).
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

- Veeam repository immutability (hardened repository immutability days, object-storage immutability flag): the field names are not in the published samples of REST revision 1.2. Source: rgcheck BK06; signals (immutability you believe you have).
- Veeam session states ActionRequired / WaitingRepository / WaitingSlot as filters: listed only for revision 1.3, while the rules pin 1.2-rev0. Source: request.
- vCenter pending-update list (`/api/appliance/update/pending`): undocumented whether an up-to-date appliance answers an empty list or 404. Partial: VMW-VCSA-HEALTH-PACKAGES, VMW-VCSA-UPDATE-*.
- Dynatrace host entities' monitoring mode through `/api/v2/entities` (property names community-sourced only); the OneAgent API covers it with documented fields. Source: rgcheck MO06.
- Wiz cloud-event sources (audit logs, flow logs, DNS, Kubernetes audit) switched off: no public field found. Source: field (every cloud event source off).
- Wiz exposure fields on issues (only confirmed on vulnerability assets). Source: request.

## Thresholds

Set as `threshold.<name>` in the Keeper home; the value in the rule applies when it is not set.

| Threshold | Default | Rule |
|---|---|---|
| vmware.datastore-free-bytes-min | 107374182400 (100 GiB) | VMW-DATASTORE-FREE-SPACE |
| vmware.unsupported-version-pattern | `^(5\|6\|7)\.` | VMW-VCSA-VERSION-UNSUPPORTED |
| vmware.update-check-max-age-days | 30 | VMW-VCSA-UPDATE-CHECK-STALE |
| vmware.cert-notice-days | 60 | VMW-VC-TLS-CERT-EXPIRY |
| vmware.root-password-notice-days | 30 | VMW-VCSA-ROOT-PASSWORD-EXPIRY |
| vmware.backup-failure-window-days | 7 | VMW-VCSA-BACKUP-FAILED |
| vmware.backup-max-run-days | 0.5 | VMW-VCSA-BACKUP-STUCK |
| veeam.job-max-age-days | 2 | VEEAM-JOB-STALE |
| veeam.session-window-days | 1 | VEEAM-SESSION-FAILED |
| veeam.session-max-run-days | 0.5 | VEEAM-SESSION-LONG-RUNNING |
| veeam.repository-free-gb-min | 200 | VEEAM-REPOSITORY-FREE-SPACE |
| veeam.license-notice-days | 60 | VEEAM-LICENSE-EXPIRY |
| veeam.support-notice-days | 90 | VEEAM-SUPPORT-EXPIRY |
| veeam.license-min-free-sockets | 0 | VEEAM-LICENSE-SOCKETS-EXHAUSTED |
| veeam.config-backup-max-age-days | 2 | VEEAM-CONFIG-BACKUP-STALE |
| veeam.malware-window-days | 30 | VEEAM-MALWARE-INFECTED, VEEAM-MALWARE-SUSPICIOUS |
| veeam.analyzer-max-age-days | 30 | VEEAM-ANALYZER-STALE |
| veeam.min-restore-points | 2 | VEEAM-OBJECT-FEW-RESTORE-POINTS |
| prtg.down-max-seconds | 604800 (7 days) | PRTG-SENSOR-DOWN-LONG |
| azure.reservation-notice-days | 60 | AZ-RESERVATION-EXPIRY |
| azure.maintenance-notice-days | 14 | AZ-HEALTH-PLANNED-MAINTENANCE |
| servicenow.urgent-incident-stale-days | 1 | SNOW-INCIDENT-HIGH-PRIORITY-STALE |
| servicenow.sla-risk-percent | 75 | SNOW-SLA-AT-RISK |
| servicenow.change-lookahead-days | 7 | SNOW-CHANGE-STARTING-SOON |
| servicenow.change-approval-lead-days | 3 | SNOW-CHANGE-UNAPPROVED-SOON |
| servicenow.change-close-grace-days | 1 | SNOW-CHANGE-NOT-CLOSED |
| servicenow.task-due-notice-days | 0 | SNOW-CATALOG-TASK-OVERDUE |
| wiz.issue-max-open-days | 30 | WIZ-ISSUE-OPEN-TOO-LONG |
| wiz.issue-due-notice-days | 0 | WIZ-ISSUE-PAST-DUE |
| wiz.critical-fix-max-age-days | 30 | WIZ-VULN-CRITICAL-FIX-OVERDUE |
| wiz.ignored-health-recent-days | 2 | WIZ-HEALTH-IGNORED-RECURRING |

## To confirm on the first real run

- vCenter: the integration's `/api/session` id is accepted on the `/rest` routes (it is the same vAPI session on 7.x and 8.x); the certificate-management and local-accounts routes need administrator-level privileges.
- Veeam: x-api-version 1.2-rev0 is accepted by the server (12.2 or later) and the integration does not add its own x-api-version header; the Security & Compliance Analyzer status words (Ok, Violation, UnableToCheck, Suppressed) match the REST enum.
- PRTG: `start` in the table API is zero-based (otherwise each page repeats one row, which only duplicates a result).
- Dynatrace: the OneAgent list fits one page; problems older than the 90-day window are not open.
- Azure: the review identity has root-scope read for AZ-ROOT-SCOPE-ROLE-ASSIGNMENT and Reservations Reader for the reservation rules; without them those rules are unknown, not passed.
- ServiceNow: `sysparm_display_value=all` returns `{display_value, value}` per field as assumed by the SLA rules.
- Wiz: `issuesV2` and `vulnerabilityFindings` accept `first: 500`; the vulnerability queries can be large (hundreds of pages on a big estate) and stop at `maxPages` as partial.
