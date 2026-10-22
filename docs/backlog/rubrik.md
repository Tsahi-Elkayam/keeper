# Backlog - Rubrik (backup assurance)

Legacy `checks-RUBRIK.csv` rows that `rules/rubrik.yaml` cannot express yet, one line each: the check
(by CheckId), what it needs, and the reason. The pack reads only through the `rubrik` integration's
Rubrik Security Cloud (RSC) GraphQL endpoint, and only the RSC queries whose field, type and enum names
are confident from Rubrik's public SDKs (clusterConnection, slaDomains, activitySeriesConnection). There
is no live cluster to confirm anything against, so the honest cut is a small confident pack plus this
backlog; every item below says "confirm GraphQL schema on first run" where a live tenant would settle it.

Source: `rubrik` = the legacy health-check catalogue
(`_archive\_health-20261020\Keeper\catalog\checks-RUBRIK.csv`). The `(Restored1)` duplicates were ignored.

Covered by `rules/rubrik.yaml` (so not repeated below), some only in part:
RUBRIK-HLT-005 (RBK-CLUSTER-RUNWAY-LOW), RUBRIK-HLT-001/007 (RBK-CLUSTER-DISCONNECTED, RSC connection only),
RUBRIK-CFG-006 (RBK-SLA-NO-RETENTION-LOCK, flags every unlocked SLA - cannot scope to production),
RUBRIK-LOG-001/002/003/004/005/006/007 (the backup/archive/replication/recovery/warning/system activity
rules; warnings are not grouped by signature), RUBRIK-BCK-009 (RBK-NO-RECOVERY-TEST, any successful
recovery in 90 d - not per criticality-1 workload), RUBRIK-BCK-016 (RBK-LOG-BACKUP-FAILED, event only, no
latest-recovery-point age), RUBRIK-MON-002 (RBK-ANOMALY-OPEN).

## CDM REST API - a different host this integration never reaches

The `rubrik` integration binds the RSC SaaS endpoint (`*.my.rubrik.com`). CDM REST (`/api/v1`,
`/api/internal` on the cluster's own FQDN) is a separate host, and a credential only ever goes to its
integration's endpoint. Every check whose only method is CDM REST needs a second integration bound to the
cluster (type `rubrik`, protocol `http`, the cluster FQDN) and the read endpoints confirmed - or an RSC
GraphQL equivalent (below). Pure-CDM checks:

- RUBRIK-HLT-002 - every node OK and node count as expected (`/api/internal/cluster/me/node`).
- RUBRIK-HLT-003 - every disk ACTIVE, none degraded/failed (`/api/internal/cluster/me/disk`).
- RUBRIK-HLT-004 - local storage used percentage (`/api/internal/stats/system_storage`) - also a two-field ratio (engine gap).
- RUBRIK-HLT-006 - daily storage growth and its trend (`/api/internal/stats/average_storage_growth_per_day`) - also run-to-run trend.
- RUBRIK-HLT-008 - appliance hardware health: PSU, fans, temperature, RAID/boot (`/api/internal/node_management/hardware_health` or BMC Redfish).
- RUBRIK-HLT-009 - ingest balanced across nodes (`/api/internal/stats/physical_ingest_per_node`) - also per-node aggregation.
- RUBRIK-HLT-010 - Live Mounts left running (`/api/v1/vmware/vm/snapshot/mount`, `/api/v1/mssql/db/mount`).
- RUBRIK-HLT-011 - activities running past the window or queued > 1 day (`/api/v1/event?status=Running`) - activity duration, see engine gap.
- RUBRIK-HLT-012 - archival target storage/object-count trend (`/api/internal/archive/location` + CloudWatch) - also run-to-run trend.
- RUBRIK-LCM-003 - RBS agent version equals cluster version on every host (`/api/v1/host`, `/api/v1/cluster/me/version`).
- RUBRIK-LCM-004 - registered vCenter versions compatible with the CDM version (`/api/v1/vmware/vcenter`) - also a vendor matrix lookup.
- RUBRIK-LCM-005 - appliance model hardware end-of-support (`/api/internal/cluster/me/node` hardwareModel) - also a vendor lifecycle date (constant deadline).
- RUBRIK-LCM-006 - RBS host OS inside vendor support (`/api/v1/host` operatingSystem) - also a Microsoft lifecycle map.
- RUBRIK-LCM-007 - collectors use documented v1/v2 endpoints only (review of the legacy collector) - tooling review, not a tenant state.
- RUBRIK-AVL-009 - cluster time synced, NTP sources reachable (`/api/internal/cluster/me/ntp_server`) - also a network probe.
- RUBRIK-AVL-010 - DNS resolvers answer and resolve vCenter/RBS/archival (`/api/internal/cluster/me/dns_nameserver`) - also a UDP 53 probe.
- RUBRIK-AVL-011 - node interfaces bonded, all links up (`/api/internal/cluster/me/network_interface`).
- RUBRIK-AVL-012 - floating IPs configured for RBS traffic (`/api/internal/cluster/me/floating_ip`).
- RUBRIK-AVL-013 - outbound path to RSC (proxy/DNS/443) and RSC service status (`/api/internal/cluster/me/proxy_config` + a 443 probe + status page).
- RUBRIK-CFG-013 - SMTP configured and tested (`/api/internal/cluster/me/smtp_instance`).
- RUBRIK-CFG-015 - SNMP v3 or disabled (`/api/internal/cluster/me/snmp`).
- RUBRIK-CFG-016 - at least two internal NTP servers configured (`/api/internal/cluster/me/ntp_server`).
- RUBRIK-CFG-018 - guest OS credentials stored for app-consistent snapshots (`/api/internal/vmware/guest_credential`).
- RUBRIK-CFG-019 - SQL databases have transaction-log backups at the agreed frequency (`/api/v1/mssql/db` recoveryModel, logBackupFrequencyInSeconds).
- RUBRIK-CFG-020 - every RBS host has a fileset; includes cover data, excludes do not (`/api/v1/fileset_template`, `/api/v1/fileset`, `/api/v1/host`) - also a set-difference join.
- RUBRIK-AUT-005 - local password and lockout policy (`/api/internal/cluster/me/security/password_policy`).
- RUBRIK-AUT-006 - web session idle timeout and max length (`/api/internal/cluster/me/security/web_session`).
- RUBRIK-AUT-007 - support tunnel disabled unless a case is open, with an inactivity timeout (`/api/internal/cluster/me/support_tunnel`).
- RUBRIK-IAM-010 - CDM built-in admin: unused, rotated < 365 d, logins alerted (`/api/internal/user?username=admin`, audit).
- RUBRIK-BCK-016 (age half) - SQL latest recovery point within 2x log frequency (`/api/v1/mssql/db` latestRecoveryPoint) - the failure half is covered; the age needs CDM + newest-per-object.
- RUBRIK-BCK-017 - fileset backups succeeded within SLA per host (`/api/v1/fileset`) - also newest-per-object.
- RUBRIK-BCK-019 - SLA/role/user definitions exported off-cluster within 90 d (dated file export) - file-timestamp attestation.
- RUBRIK-MON-006 - email notification recipients are monitored mailboxes (`/api/internal/notification_setting`) - also a join to Entra.
- RUBRIK-MON-008 - scheduled compliance/capacity reports delivered weekly (`/api/internal/report`).
- RUBRIK-MON-011 - capacity threshold notifications configured (notification settings).
- RUBRIK-HYG-005 - RBS hosts disconnected > 30 d or absent from AD (`/api/v1/host`) - also an AD join.
- RUBRIK-HYG-008 - on-demand snapshots with Forever retention accumulating (`/api/v1/vmware/vm/{id}/snapshot`) - also per-object fan-out.
- RUBRIK-HYG-009 - stored guest/host credentials no longer referenced (`/api/internal/vmware/guest_credential` + usage).

## RSC GraphQL per-object inventory - unconfirmed filter field and condition enum (false-pass risk)

These read the snappable (protected-object) inventory. Unlike the activity rules, their verdict depends on
an enum compared INSIDE a condition (complianceStatus, protectionStatus, slaAssignment) or a snapshot-age
field, and on a `snappableConnection` filter whose field and text values exist only in the tenant's schema.
A misspelt condition enum on a real field returns rows that never match - a silent pass, which is worse than
a wrong field (that errors). Written only once the shape is confirmed on the first real run.

- RUBRIK-BCK-001 - every protected object InCompliance (snappableConnection complianceStatus).
- RUBRIK-BCK-002 - objects with compliance NotAvailable counted and explained (same, filtered to NOT_AVAILABLE).
- RUBRIK-BCK-003 - latest snapshot age per object vs SLA frequency (newest-per-object snapshot date) - also newest-per-object aggregation.
- RUBRIK-BCK-004 - missed snapshots per object in 7 days (missedSnapshotConnection).
- RUBRIK-BCK-005 - protected objects with zero snapshots (snapshotConnection count = 0 and protected).
- RUBRIK-BCK-006 - archived copy exists for criticality-1/2 objects (archived snapshot age) - also a criticality classification.
- RUBRIK-BCK-007 - replicated copy exists for criticality-1 objects (replicated snapshot) - also classification.
- RUBRIK-BCK-008 - immutable copy: retention-locked SLA plus target Object Lock per object - also a two-read join.
- RUBRIK-BCK-013 - retention honoured: snapshot count and oldest-snapshot age vs SLA - also per-object aggregation and SLA join.
- RUBRIK-BCK-015 - DC VMs protected once, app-consistent, no snapshot-revert runbook - also a name match and attestation.
- RUBRIK-BCK-018 - NAS/FSx/file servers protected by exactly one product (nasShares) - also a cross-product join.
- RUBRIK-BCK-021 - snapshots under legal hold inventoried, each tied to a request (isOnLegalHold).
- RUBRIK-CFG-002 - snapshot frequency meets the RPO per workload class (SLA schedule vs per-object RPO) - also a classification/join.
- RUBRIK-CFG-003 - local retention meets policy and dwell-time (SLA schedule retention) - the SLA schedule shape is unconfirmed.
- RUBRIK-CFG-004 - archival on every SLA covering criticality-1/2 (SLA archivalSpecs) - also a classification/join.
- RUBRIK-CFG-005 - replication configured or its absence recorded (SLA replicationSpecs) - also an attestation.
- RUBRIK-CFG-008 - Do Not Protect objects each with a recorded reason (slaAssignment DoNotProtect) - also an attestation of reasons.
- RUBRIK-CFG-009 - unprotected objects (no SLA, not DoNotProtect) (protectionStatus / effectiveSlaDomain UNPROTECTED).
- RUBRIK-CFG-010 - direct SLA assignments overriding inheritance (slaAssignment Direct vs parent).
- RUBRIK-CFG-012 - application-consistent snapshots on DB/DC VMs (snapshotConsistencyMandate) - also a name match.
- RUBRIK-AVL-005 - archival lag per object vs SLA threshold (archivalComplianceStatus / latestArchivedSnapshot).
- RUBRIK-AVL-007 - replication lag per object vs SLA (replicationComplianceStatus).
- RUBRIK-HYG-002 - relic objects (deleted VMs still holding snapshots) reviewed (snappableConnection IS_RELIC filter).
- RUBRIK-HYG-003 - SLA domains with zero objects and duplicate SLAs (numProtectedObjects + pairwise compare) - also aggregation.
- RUBRIK-HYG-004 - default Gold/Silver/Bronze SLAs unused or reviewed (SLA object counts + settings compare).
- RUBRIK-HYG-006 - SLA/fileset/target names follow a convention (name vs a tenant regex) - needs the convention as a tenant threshold.

## RSC GraphQL settings and directory - query shape unconfirmed

Users, roles, SSO/MFA, service accounts, quorum, archival and replication targets, vCenter connections,
notification/Radar/Threat/SDD/licence settings. The legacy catalogue marks each of these RSC paths
"schema to confirm"; the top-level query name and fields exist only in the tenant's schema explorer, so a
guess risks either an error (unknown) or, for condition enums, a silent pass. Confirm on the first run.

- RUBRIK-AVL-001 - every registered vCenter Connected (vSphereVCenterConnection connectionStatus).
- RUBRIK-AVL-002 - vCenter inventory last-refresh age (vSphereVCenterConnection lastRefreshTime).
- RUBRIK-AVL-004 - archival location state CONNECTED (targets status).
- RUBRIK-AVL-006 - replication target cluster connected (replicationPairs status).
- RUBRIK-AVL-008 - RBS-registered hosts Connected (physicalHosts connectionStatus).
- RUBRIK-CFG-001 - SLA domain inventory (full schedule/archival/replication shape) recorded and trended.
- RUBRIK-CFG-007 - retention lock in Compliance mode and quorum on change requests (retentionLockMode).
- RUBRIK-CFG-011 - backup windows defined and outside production hours (SLA backupWindows).
- RUBRIK-CFG-017 - cluster name/timezone/location consistent across RSC, CDM and the README - also documentation.
- RUBRIK-IAM-001 - RSC federated to Entra SAML, SSO enforced except break-glass (ssoConfigs) - also an Entra join.
- RUBRIK-IAM-002 - MFA enforced on RSC and TOTP on every local user (userConnection totpStatus).
- RUBRIK-IAM-003 - local (non-SSO) user inventory and count (userConnection authDomain).
- RUBRIK-IAM-004 - Administrator-role holders <= 3 named people (roleConnection / userConnection roles).
- RUBRIK-IAM-005 - custom roles follow least privilege (roleConnection permissions).
- RUBRIK-IAM-006 - users idle > 90 d or whose Entra account is disabled (userConnection lastLogin) - also an Entra join.
- RUBRIK-IAM-007 - RSC service-account inventory, roles, last use (serviceAccountConnection).
- RUBRIK-IAM-008 - service-account secrets/CDM tokens rotated < 365 d and vaulted (serviceAccount rotation + vault).
- RUBRIK-IAM-009 - quorum (two-person) authorization enabled for destructive actions (orgSecurityPolicy).
- RUBRIK-IAM-011 - who can place/release legal hold and the current hold inventory (legalHold queries).
- RUBRIK-IAM-012 - Entra groups mapped to RSC roles hold only intended people (ssoGroups) - also an Entra join.
- RUBRIK-IAM-013 - who can create users or edit roles beyond Administrator (roleConnection permissions).
- RUBRIK-AUT-002 - data-at-rest encryption enabled (clusterConnection encryptionEnabled) - field unconfirmed.
- RUBRIK-AUT-003 - archival target TLS and encryption, S3 Object Lock (targets encryptionType) - also an AWS join.
- RUBRIK-AUT-004 - replication traffic encrypted between clusters (replication target encryption).
- RUBRIK-CFG-014 - syslog export to the SIEM configured (RSC audit-log webhook / SIEM settings).
- RUBRIK-MON-001 - Radar/Anomaly Detection licensed and enabled on production objects (radar settings).
- RUBRIK-MON-003 - Threat Monitoring/Hunting enabled and a hunt within 30 d (threatHunts).
- RUBRIK-MON-004 - Sensitive Data Discovery scanning file servers (SDD policies).
- RUBRIK-MON-007 - open critical notifications unresolved > 48 h (notifications / eventConnection) - status enum unconfirmed.
- RUBRIK-MON-009 - alerts configured for security-relevant audit events (notification/webhook settings) - also a SIEM join.
- RUBRIK-MON-010 - appliance/RSC present in estate monitoring (PRTG/Dynatrace) - a join to the monitoring packs.
- RUBRIK-CST-001 - licensed capacity consumed vs entitlement (licence usage) - also a two-field ratio.
- RUBRIK-CST-006 - licensed add-ons actually in use (product entitlements vs MON-001/003/004 state) - a join.

## RSC GraphQL audit log - ransomware-precursor review

The RSC audit-log query (`auditLogs` / `auditEventConnection`) and its event-type enums
(SLA_MODIFIED, SNAPSHOT_DELETED, USER_ADDED, ...) exist only in the tenant's schema. The review semantics
("matched to a ticket or a named reason") also need a human; the rule could at most surface the events.
Confirm the query and enums on the first run, then write "deletion/retention-reduction event in N days".

- RUBRIK-LOG-010 - failed logins and lockouts on RSC and CDM (auditLogs LOGIN FAILURE).
- RUBRIK-LOG-011 - SLA/retention/snapshot/user/role changes reviewed weekly (auditLogs filtered to those event types).
- RUBRIK-LOG-012 - manual user-initiated snapshot deletions/expirations (auditLogs snapshot-delete events).

## TLS probe / network reachability - belongs to the certificates pack or a network probe

- RUBRIK-AUT-001 - CDM endpoint accepts TLS 1.2+ and strong ciphers only (tls probe of the cluster FQDN).
- RUBRIK-AUT-008 - SSH/BMC closed from user and server networks (TcpClient probe 22/623) - network probe.
- RUBRIK-AUT-009 - management interface unreachable from user VLANs (443 probe or firewall rulebase read).
- RUBRIK-PKI-001 - CDM web/API certificate validity and expiry (tls probe) - `rules/certificates.yaml`.
- RUBRIK-PKI-002 - CDM certificate CA-issued, not factory self-signed (tls probe chain) - certificates pack.
- RUBRIK-PKI-003 - RSC tenant endpoint certificate valid (tls probe of the RSC FQDN) - certificates pack.
- RUBRIK-PKI-004 - vCenter certificates trusted by Rubrik (pinned chain vs live) (CDM vcenter caCerts + tls probe).
- RUBRIK-PKI-005 - archival/replication target certificates valid (tls probe of each target).
- RUBRIK-PKI-006 - uploaded cluster certificates inventoried with expiry/purpose (CDM certificate list or RSC certificates).

## Attestation, documentation and cross-system joins - no single query

- RUBRIK-AVL-003 - all five estate vCenters registered or recorded as not Rubrik-protected - a Rubrik/Veeam/CMDB join.
- RUBRIK-AVL-014 - single cluster/single site: a replication target or a proven archival-restore RTO - attestation + topology.
- RUBRIK-BCK-014 - every VM/server protected by exactly one product, zero in none - a Rubrik/Veeam/vCenter/AD join.
- RUBRIK-BCK-020 - RTO documented and demonstrated per criticality-1 workload - attestation (SYS-DR).
- RUBRIK-CST-002 - subscription/support renewal date known and > 90 d away - attestation/procurement record.
- RUBRIK-CST-003 - hardware support contract active with a known end date - attestation.
- RUBRIK-CST-004 - archival storage/egress cost per month known and attributed - AWS/Azure cost join.
- RUBRIK-CST-005 - objects protected by both Rubrik and Veeam (paid twice) - the BCK-014 overlap join.
- RUBRIK-IAM-014 - RSC break-glass procedure documented and tested within 365 d - attestation.
- RUBRIK-HYG-001 - backup ownership per workload class documented - attestation, feeds BCK-014.
- RUBRIK-HYG-007 - README names the appliance by FQDN, tenant, nodes, owner, support path - documentation (SYS-DOC).

## Engine features these also wait on

- Comparing two fields of one row / arithmetic: capacity used percentage (HLT-004), licensed-capacity usage (CST-001).
- Run-to-run trend of an absolute value: storage growth (HLT-006), archival consumption (HLT-012).
- Newest / oldest per entity, and per-parent aggregation: snapshot age per object (BCK-003), missed snapshots (BCK-004), retention honoured (BCK-013), activity duration per object (LOG-008), warning grouping by signature (LOG-006), ingest per node (HLT-009).
- A tenant threshold on a query argument: the activity-window rules fix 7/30/90 days in the document (same gap as the Veeam/Dynatrace window rules).

## Thresholds

Set as `threshold.<name>` in the Keeper home; the value in the rule applies when it is not set.

| Threshold | Default | Rule |
|---|---|---|
| rubrik.runway-min-days | 90 | RBK-CLUSTER-RUNWAY-LOW |

## To confirm on the first real run

No live cluster was available, so these are assumptions the pack makes about the RSC GraphQL schema; a
wrong name fails the query and the rule reads unknown, never a pass.

- `clusterConnection` is the top-level cluster query, takes `first`/`after`, and exposes `id name status version defaultAddress estimatedRunway` on its nodes; `status` uses the enum value `CONNECTED`; `estimatedRunway` is an integer number of days (and whether it has a sentinel such as -1 for "no growth / infinite" - the rule already ignores negatives).
- `slaDomains` is the top-level SLA query, takes `first`/`after`, and its nodes expose `id name`; `GlobalSlaReply.isRetentionLockedSla` is the retention-lock boolean (cluster-local SLA nodes that are not `GlobalSlaReply` return n/a and are not flagged).
- `activitySeriesConnection` takes `filters` (plural) of `lastActivityType`, `lastActivityStatus` and `startTimeGt` (a DateTime that accepts the `{DAYS_AGO:n}` ISO value), and its nodes expose `activitySeriesId objectName objectType lastActivityType lastActivityStatus severity startTime lastUpdated cluster { id name }`.
- The `EventType` enum spells the values `BACKUP`, `ARCHIVE`, `REPLICATION`, `RECOVERY`, `LOG_BACKUP`, `SYSTEM`, `ANOMALY`; the activity-status enum spells `FAILURE`, `CANCELED`, `WARNING`, `SUCCESS`. A different spelling fails the query (unknown) rather than passing quietly, because every value sits in a filter argument.
- The review service account's read-only role grants read access to cluster, SLA and activity-series data; too few rows from any of them reads as partial, not a pass.
