# Proposals - applications, ITSM and business systems (catalogue port)

Source: the old check catalogue for the ITSM tools, work trackers, developer platform, document
management, payroll and attendance services, published desktops, telephony, call recording, video
surveillance, facilities power devices, the public web portal, the integration platform and the
managed-service partners (790 rows, 18 catalogue files plus 15 known-issue rows). Every row was mapped
to one Keeper status; the per-row map stays outside the repo because it names tenant systems. This
file holds only what is new and tenant-free.

Conventions used here:

- **Status words** in the map: `covered` (a rule exists), `proposed` (already in another proposals
  file), `new-http` (a new scan rule through an existing protocol - http, graphql, sql, cim,
  registry, eventlog, ldap, graph or store; the protocol is named per entry), `new-register` (a
  register row or field judged by an existing or new REG rule), `new-obligation`, `new-tls` (bind the
  endpoint as a tls target), `needs-integration`, `not-automatable`, `duplicate`.
- **Confidence**: *verified* - fields match an existing rule or the product's documented base table;
  *likely* - documented table, field names to confirm on the first run; *guess* - the read exists but
  its shape is uncertain.
- Thresholds are `threshold.<system>.<name>` settings; defaults are given in the condition.
- Refs are canonical ids: `NIST-800-53:XX-n`, `CIS-Controls-v8:n.n`, `ISO-27001:A.n.n`.

Rows mapped: 790. Of these 211 covered, 29 proposed elsewhere, 27 duplicates, 174 new scan rules,
153 new obligations, 54 register rows, 12 tls targets, 101 need an integration type Keeper does not
have, 29 are not automatable.

## Generic patterns

Business applications rarely have an API Keeper can read. What they have in common is a set of duties
that any system owner can attest to, and a set of dates and counts that belong in the registers. The
rules below are written once and targeted per system; together they absorb 174 catalogue rows, and
the already-shipped obligations (OBL-IAM-USER-ACCESS-REVIEW, OBL-IAM-VENDOR-ACCESS-REVIEW,
OBL-IAM-SERVICE-ACCOUNT-REVIEW, OBL-LOG-REVIEW, OBL-BCP-REVIEW, OBL-BACKUP-RESTORE-TEST, OBL-DR-DRILL,
OBL-GOV-POLICY-REVIEW, OBL-PATCH-COMPLIANCE-REVIEW, OBL-ASSET-INVENTORY-REVIEW,
OBL-VULN-SCAN-EXTERNAL, OBL-NET-FIREWALL-RULE-REVIEW, OBL-CHANGE-CODE-REVIEW,
OBL-SECURITY-PENETRATION-TEST, OBL-PKI-CERTIFICATE-INVENTORY-REVIEW, OBL-BACKUP-OFFLINE-COPY-VERIFIED,
OBL-IAM-BREAK-GLASS-TEST) absorb another 95 as `covered`.

All obligations below use the obligations.yaml template exactly (one row per attested target plus a
`-` row; fails when the latest attestation is not `na` and no `yes` with `done_on` lies inside the
interval; `deadline: due_on`). Add each id to the severity maps of OBL-ATTESTATION-EXPIRED and
OBL-ATTESTED-NO where the severity is not medium, and to the id list of OBL-ATTESTATION-UNKNOWN-ID.
Mechanics confidence is *verified* (shipped template); interval defaults are *likely*.

### OBL-SYS-RUNBOOK (`obligations.yaml`, `sys.runbook`, 365 d, target = a system) - absorbs 20 rows
- What: the system has a current operations record - architecture (hosts and roles, without
  addresses), dependencies and co-tenants, service accounts by name, backup and recovery steps,
  vendor and escalation path, documented design decisions (fallback paths, hosting choice).
- Why: in every catalogue the first finding was "the only documentation is two bookmarks"; the
  knowledge sits with a partner or with someone who left.
- Severity: medium. Refs: `ISO-27001:A.5.37`, `NIST-800-53:CM-8`, `NIST-800-53:CP-2`, `CIS-Controls-v8:1.1`.
- Fix: write or refresh the runbook, record co-tenancy as `system_dependency` rows, attest with the
  system as target and the document location as evidence.

### OBL-APP-BACKUP-VERIFIED (`obligations.yaml`, `app.backup-verified`, 30 d, target = a system or a
store) - absorbs 16 rows
- What: an application-level copy exists off the host - database export, configuration, keys,
  licence file, project sources, SaaS export - newer than the last change, readable without the
  product where the product may be gone (SaaS exit, retired vendor).
- Why: VM images and vendor backups do not cover SaaS data, bundled databases, keystores or the
  licence that a rebuild needs; restore tests (OBL-BACKUP-RESTORE-TEST) prove the copy works, this
  proves it exists and is recent.
- Severity: high. Refs: `NIST-800-53:CP-9`, `CIS-Controls-v8:11.2`, `ISO-27001:A.8.13`.
- Fix: schedule the export to municipal storage outside the host, record the escrow of any
  passphrase, attest with the copy's location and date as evidence.

### OBL-APP-SSO-ENFORCED (`obligations.yaml`, `app.sso-enforced`, 365 d, target = a system) - absorbs 12 rows
- What: interactive sign-in goes through the identity provider (SAML/OIDC or integrated Windows
  authentication) with MFA; local or vendor-side passwords remain only for documented break-glass
  and integration accounts; self-service portals do not authenticate by a public identifier alone.
- Why: offboarding and MFA only reach an application through SSO; a local password outlives every
  leaver process. The directory side is already judged (ENTRA-SP-SSO-NO-ASSIGNMENT, ENTRA-CA-*);
  this covers the application side and the products that cannot federate.
- Severity: high. Refs: `NIST-800-53:IA-2(1)`, `NIST-800-53:IA-8`, `CIS-Controls-v8:6.3`,
  `CIS-Controls-v8:6.7`, `ISO-27001:A.8.5`.
- Fix: enable the federation the vendor supports, or enforce vendor MFA and lockout; list the
  remaining local accounts as evidence; attest per system.

### OBL-APP-AUDIT-TRAIL (`obligations.yaml`, `app.audit-trail`, 365 d, target = a system) - absorbs 12 rows
- What: the application records who did what (logins, reads of personal data where the law requires
  it, changes, exports), keeps it for the policy period, and the record leaves the host (export to
  the central log store or a periodic pull from the vendor).
- Why: for SaaS and appliance products the only audit is the vendor's; for self-hosted ones the
  default retention is days. Regulation on personal-data access records needs years.
- Severity: high. Refs: `NIST-800-53:AU-2`, `NIST-800-53:AU-11`, `NIST-800-53:AU-6(3)`,
  `CIS-Controls-v8:8.2`, `CIS-Controls-v8:8.9`, `ISO-27001:A.8.15`.
- Fix: enable the audit features, set retention, configure the export or schedule the vendor pull;
  attest with a sample export as evidence.

### OBL-APP-INTERFACE-INVENTORY (`obligations.yaml`, `app.interface-inventory`, 365 d, target = a
system) - absorbs 10 rows
- What: every data exchange of the system is listed - source, target, channel and protocol,
  authentication method, owner, failure behaviour and the reconciliation step for batch files - and
  none carries personal data in clear (mail attachments, plain FTP/HTTP, unencrypted database links).
- Why: integrations are where personal data leaves access control; they are set up once and
  forgotten, and when they break the help desk hears about the wrong system.
- Severity: high. Refs: `NIST-800-53:CA-3`, `NIST-800-53:SC-8`, `NIST-800-53:AC-4`,
  `CIS-Controls-v8:3.10`, `ISO-27001:A.5.14`, `ISO-27001:A.8.24`.
- Fix: build the table from the product's connector list and the partner's documentation, move
  clear-text flows to their TLS variants, attest per system.

### OBL-APP-SOD-REVIEW (`obligations.yaml`, `app.sod-review`, 365 d, target = a system) - absorbs 5 rows
- What: for systems that move money or change pay, no single person can both enter and approve (or
  release), out-of-band verification exists for bank-detail changes, and administrators of the
  platform cannot edit business data.
- Why: maker-checker is the control auditors ask for first and the one a small team quietly loses.
- Severity: high. Refs: `NIST-800-53:AC-5`, `NIST-800-53:AC-6`, `ISO-27001:A.5.3`.
- Fix: export the role matrix, separate the roles or record a compensating review, attest.

### OBL-SYS-ALERT-ROUTING (`obligations.yaml`, `sys.alert-routing`, 365 d, target = a system) - absorbs 21 rows
- What: the product's own alerts, scheduled reports, vendor notices (maintenance, security, renewal)
  and device e-mails go to a monitored group address, not a person; the routing was tested within
  the interval.
- Why: notices addressed to whoever installed the product stop when that person leaves; a yearly
  test is the only proof that a night-time alert reaches anyone.
- Severity: medium. Refs: `NIST-800-53:IR-6`, `NIST-800-53:SI-4(5)`, `ISO-27001:A.5.24`, `ISO-27001:A.8.16`.
- Fix: point every recipient field at a shared mailbox, subscribe the group to the vendor's
  notices, send a test, attest with the test date as evidence.

### OBL-SYS-HARDENING-REVIEW (`obligations.yaml`, `sys.hardening-review`, 365 d, target = a system) - absorbs 20 rows
- What: the vendor's hardening guide (or the relevant benchmark) was applied and each deviation
  recorded: default credentials changed, management on HTTPS/SSH only, sample and manager
  applications removed, session limits, upload and sharing restrictions, SNMP v3, installed
  third-party apps approved.
- Why: appliances, SaaS admin panels and bundled runtimes keep installer defaults for years; nothing
  scans them and the settings live only in admin pages.
- Severity: high. Refs: `NIST-800-53:CM-6`, `NIST-800-53:CM-7`, `CIS-Controls-v8:4.1`,
  `CIS-Controls-v8:4.7`, `ISO-27001:A.8.9`.
- Fix: walk the guide, export the settings, fix or record the exception, attest with the export as evidence.

### OBL-SYS-NETWORK-EXPOSURE-REVIEW (`obligations.yaml`, `sys.network-exposure-review`, 365 d,
target = a system) - absorbs 5 rows
- What: the administrative interfaces of the system are reachable only from the management segment
  (not from user networks, not from the internet), and the network team confirmed the rules.
- Why: Keeper scans from one host and cannot probe from a user segment; a console that resets
  passwords or stops integrations should be one hop away from administrators only.
- Severity: high. Refs: `NIST-800-53:SC-7`, `NIST-800-53:AC-17`, `CIS-Controls-v8:12.8`, `ISO-27001:A.8.20`.
- Fix: move the console to a management VLAN or restrict with firewall/security-group rules;
  attest with the rule identifiers. External exposure is OBL-VULN-SCAN-EXTERNAL's job.

### OBL-SYS-DECOMMISSION (`obligations.yaml`, `sys.decommission`, 90 d while open, target = a retired
system or vendor) - absorbs 15 rows
- What: a retired system has a dated checklist and every item is closed: data exported or disposed
  with a record, application accounts and API keys revoked, directory and service accounts
  disabled, DNS names and firewall rules removed, monitoring and backup jobs deleted, licences and
  contracts ended, documentation and the system register marked closed, disks wiped.
- Why: decommissions stall at "switched off": the disk with the helpdesk database, the DNS name, the
  vendor's copy of the payroll and the contract all outlive the service.
- Severity: medium. Refs: `NIST-800-53:CM-8`, `NIST-800-53:MP-6`, `NIST-800-53:SA-9`,
  `CIS-Controls-v8:1.1`, `ISO-27001:A.8.10`, `ISO-27001:A.5.20`.
- Fix: run the checklist, attest `yes` only when the last item is closed; until then the finding
  stays open. Pair with the system register's `active` flag so REG-LIC-SYSTEM-INACTIVE and
  REG-CON-SYSTEM-INACTIVE catch what still costs money.

### OBL-PRIVACY-DATABASE-RECORD (`obligations.yaml`, `privacy.database-record`, 365 d, target = a
system holding personal data) - absorbs 16 rows
- What: each database of personal data has its definitions document and security level, a recorded
  purpose, a retention schedule per data type with its legal basis and a disposition run, the access
  model, and the special cases (biometrics, health documents, minors, footage, recordings, notices to
  data subjects) approved by the data-protection officer.
- Why: the catalogue asked the same privacy questions of eight products; the answers are documents,
  not settings, and they expire with the law and the system.
- Severity: high. Refs: `NIST-800-53:PT-3`, `NIST-800-53:PM-5(1)`, `NIST-800-53:SI-12`,
  `ISO-27001:A.5.34`, `ISO-27001:A.5.33`, `ISO-27001:A.8.10`.
- Fix: prepare or refresh the record with the DPO, align the product's retention settings to it,
  attest per system.

### OBL-TEL-EMERGENCY-CALL-TEST (`obligations.yaml`, `tel.emergency-call-test`, 365 d, target = a
telephony cluster) - absorbs 1 row
- What: emergency numbers were test-called from the main sites within the interval and the routing
  uses a path with a fallback. Severity: critical. Refs: `NIST-800-53:CP-8`, `ISO-27001:A.5.29`.
- Fix: test with the carrier, fix the route list, attest.

### REG-KEY-SUPPORT-END-DUE (`registers.yaml`, new key_date kind `support-end`) - absorbs 5 rows
- What: a key date of kind `support-end` records when a product version, device model or hosted
  runtime leaves vendor support (end of software maintenance, end of life, compatibility-matrix
  limit). The rule fires inside the notice period like REG-KEY-RENEWAL-DUE.
- Why: lifecycle for CMS releases, PBX software, camera and clock-terminal models, UPS cards and the
  ECM patch train cannot be scanned; the dates are published and change rarely.
- Severity: by days left: 0 -> high, 90 -> medium, default low. Refs: `NIST-800-53:SA-22`,
  `CIS-Controls-v8:2.2`, `ISO-27001:A.8.8`.
- Source: `store`, the existing key_date query with `kind = 'support-end'`. Condition: as
  REG-KEY-OTHER-DUE. Fix: plan the upgrade or replacement before the date; move the date on when done.
- Confidence: verified (same mechanics as the other REG-KEY rules).

### REG-KEY-SYSTEM-INACTIVE (`registers.yaml`) - absorbs 1 row
- What: an upcoming key date (certificate, renewal, support) belongs to a system marked inactive -
  someone will renew a certificate or a contract for a retired service.
- Severity: low. Refs: `NIST-800-53:CM-8`. Source: key_date joined to system on `system_id`;
  condition `system_active eq 0 and days_left ge 0`. Fix: delete the date or move it to the live
  system. Confidence: verified (mirror of REG-LIC-SYSTEM-INACTIVE).

### Register rows (existing rules) - 48 rows
No new rule: the check becomes a register row judged by an existing REG rule. Licence rows with
`seats`/`seats_used` for every per-seat product (REG-LIC-SEATS-AT-CAP, -NEARLY-FULL, -UNUSED-SEATS);
contract rows with `end_on`, `notice_days`, `decision`, `value`, `owner` for every marketplace
agreement, support contract, maintenance contract and procurement basis (REG-CON-*); vendor rows
with `sla`, `sensitive`, data record, review date, exit plan (REG-VEN-*); key dates of kind
`certificate` for certificates not on a TLS listener (keystores, signing keys, archive
certificates); initiative rows for hosting and capacity decisions (REG-INI-*).

### TLS targets - 12 rows
No new rule: bind each web console, custom URL, voice node (8443, 5061), recorder console, management
console on its odd port, and gateway as a tls target. TLS-CERT-EXPIRING, TLS-SELF-SIGNED,
TLS-NAME-MISMATCH, TLS-LEGACY-PROTOCOL and TLS-CHAIN-* then judge it, and a failed handshake is the
liveness signal (unknown, never a pass). An unknown console's subject and issuer identify its product.

### Reusable scan rules for any Windows-hosted product
- **WINSRV-SW-VERSION-BELOW-MIN** (`windows-server.yaml`, registry) - absorbs 9 rows. What: an
  installed product (Uninstall key DisplayName/DisplayVersion, 64- and 32-bit views) is below the
  minimum version the tenant recorded for it. Why: products patched by files dropped in a folder
  (ECM, delegation tools, integration platform, VMS, broker) never appear in the patch tool; the
  version floor is the only generic check, and KEV-listed builds become floor entries. Severity:
  high. Source: `registry` `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` with `subkeys: true`
  then the values DisplayName, DisplayVersion, Publisher; condition `DisplayName match <product>` and
  `DisplayVersion` below the floor - the engine has no version comparison, so the proposal is a
  `notmatch` on a tenant regular expression of acceptable versions (threshold
  `windows.software-version-floors`, a map). Refs: `NIST-800-53:SI-2`, `CIS-Controls-v8:7.4`,
  `ISO-27001:A.8.8`. Fix: upgrade in a window. Confidence: likely (registry protocol is shipped;
  enumerating the Uninstall key per host is a large read).
- **WSF-SW-VERSION-BELOW-MIN** (`workstations-sccm.yaml`, http AdminService) - absorbs 2 rows. Same
  idea from inventory (`SMS_G_System_INSTALLED_SOFTWARE` ProductName/ProductVersion). Confidence:
  verified (table used by WSF-SW-EOL-*).
- **WINSRV-PROCESS-MISSING** (`windows-server.yaml`, cim) - What: a process the tenant lists for a host
  class is absent (grid containers, Java engines that are not services). Source: `Win32_Process` Name
  in list, `count: none` per host. Severity: high. Refs: `NIST-800-53:SI-4`. Confidence: verified (cim).
- **WINSRV-DB-LISTENING-NONLOCAL** (`windows-server.yaml`, cim root/standardcimv2) - What: a bundled
  database or management port listens on a non-loopback address. Source: `MSFT_NetTCPConnection`
  State=2, LocalPort in threshold list, `LocalAddress ne 127.0.0.1 and ne ::1`. Severity: high.
  Refs: `NIST-800-53:CM-7`, `CIS-Controls-v8:4.8`. Confidence: likely (class and namespace exist on
  Server 2012 R2 and later).
- **WINSRV-SECURITY-LOG-SMALL** (`windows-server.yaml`, cim) - What: the Security log maximum size is
  below the floor (existing WINSRV-EVENTLOG-SMALL covers Application/System only). Source:
  `Win32_NTEventlogFile` LogfileName=Security, MaxFileSize lt threshold (default 1 GB on DCs and
  multi-user hosts). Severity: medium. Refs: `NIST-800-53:AU-4`, `CIS-Controls-v8:8.3`. Confidence: verified.
- **WINSRV-EVT-PROVIDER-ERRORS** (`windows-server.yaml`, eventlog) - absorbs 2 rows. What: more than N
  level 1-2 events from a tenant list of product providers in 7 days. Source: `log: Application`,
  providers list, `count gt threshold`. Severity: medium. Refs: `NIST-800-53:SI-4`. Confidence: verified.
- **WINSRV-EVT-GPO-SOFTWARE-INSTALL-ERRORS** (eventlog) - Application, provider
  `Application Management Group Policy`, ids 101-108, count gt 0 in 30 d. Severity: low. Confidence: verified.
- **WINSRV-EVT-TEMP-PROFILE** (eventlog) - Application, provider User Profile Service, ids 1511,
  1515, 1530, 7 d. Severity: medium. Refs: `NIST-800-53:SI-4`. Confidence: verified.
- **WINSRV-EVT-RDS-LICENSING** (eventlog) - System, provider TerminalServices-Licensing (and
  TermService), ids 1128, 1130, 1069, 7 d, `count gt 0`. Severity: high. Refs: `NIST-800-53:CM-10`.
  Confidence: verified.
- **WINSRV-EVT-RDGATEWAY-CONNECTIONS** (eventlog) - channel
  `Microsoft-Windows-TerminalServices-Gateway/Operational`, ids 302, 303, 312, 30 d, info list per
  host (who came through the gateway). Severity: info. Refs: `NIST-800-53:AU-12`. Confidence: verified.
- **WINSRV-EVT-RDP-LOGON-PATTERN** (eventlog) - Security 4624 with LogonType 10 and TargetUserName
  matching a tenant pattern (vendor accounts), 30 d, info. Severity: info. Refs: `NIST-800-53:AU-6`,
  `NIST-800-53:MA-4`. Confidence: verified (event data fields are exposed by the runner).
- **WINSRV-RDS-DRAIN-MODE / WINSRV-RDS-SESSIONS-HIGH / WINSRV-RDGATEWAY-RAP-BROAD** (cim namespace
  root/cimv2/TerminalServices) - `Win32_TerminalServiceSetting` SessionBrokerDrainMode ne 0 or
  AllowTSConnections eq 0 (high); `Win32_LogonSession` LogonType=10 count gt threshold (medium);
  `Win32_TSGatewayResourceAuthorizationPolicy` with an all-computers group (high). Refs:
  `NIST-800-53:AC-17`, `CIS-Controls-v8:12.7`. Confidence: likely (classes documented; namespace must
  be set per rule).
- **WINSRV-RDS-REDIRECTION-OPEN** (registry) - `SOFTWARE\Policies\Microsoft\Windows NT\Terminal
  Services` values fDisableCdm, fDisableClip, fDisableCpm, MaxIdleTime, MaxDisconnectionTime; fails
  when drive/clipboard redirection is allowed on multi-user hosts or no idle limit is set. Severity:
  medium. Refs: `CIS-Controls-v8:4.1`. Confidence: verified (registry protocol).
- **WINSRV-SCHANNEL-LEGACY-ON** (registry) - `SYSTEM\CurrentControlSet\Control\SecurityProviders\
  SCHANNEL\Protocols\TLS 1.0\Server` (and TLS 1.1, SSL 3.0) value Enabled ne 0 or key absent on hosts
  that serve clients. Severity: medium. Refs: `NIST-800-53:SC-8`, `NIST-800-53:SC-13`. Confidence: verified.
- **WINSRV-VOLUME-NOT-ENCRYPTED** (cim namespace root/cimv2/Security/MicrosoftVolumeEncryption) -
  `Win32_EncryptableVolume` ProtectionStatus ne 1 for fixed data volumes on hosts that store
  recordings, footage or personal data. Severity: high. Refs: `NIST-800-53:SC-28`,
  `CIS-Controls-v8:3.11`. Confidence: likely.
- **WINSRV-TCP-RETRANSMIT-HIGH** (cim) - `Win32_PerfFormattedData_Tcpip_TCPv4`
  SegmentsRetransmittedPersec gt threshold on hosts that ingest streams. Severity: medium. Refs:
  `NIST-800-53:SI-4`. Confidence: verified.
- **WS-CREDPROV-UNKNOWN** (`workstations.yaml`, registry, also servers) - subkeys of
  `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers` not in the
  tenant allow-list (the built-in GUIDs plus approved products). Why: a third-party credential
  provider is code in the logon path; an orphaned one from a retired product is unpatched code loaded
  by the logon UI. Severity: high. Refs: `NIST-800-53:CM-7`, `CIS-Controls-v8:2.3`. Confidence:
  verified (registry `subkeys: true`).
- **WSF-SVC-RETIRED-PRODUCT** (`workstations-sccm.yaml`, http AdminService) - `SMS_G_System_SERVICE`
  Name in a tenant list of retired products and StartMode ne Disabled. Severity: low. Refs:
  `CIS-Controls-v8:2.3`. Confidence: likely (service inventory class must be enabled in hardware inventory).
- **SQL-EXPRESS-DB-NEAR-CAP** (`sql-server.yaml`) - `SERVERPROPERTY('Edition') LIKE 'Express%'` and
  a user database's data-file size above 8 GB (cap is 10 GB). Severity: high. Refs:
  `NIST-800-53:CP-2`, `ISO-27001:A.8.6`. Confidence: verified (sys.master_files).
- **AD-USER-GENERIC-NAME / ENTRA-USER-GENERIC-NAME** (ldap / graph) - enabled accounts whose name
  matches a tenant pattern of shared or generic names (class, lab, student, partner-ops). Severity:
  medium. Refs: `NIST-800-53:IA-2`, `ISO-27001:A.5.16`. Confidence: verified.
- **AD-COMP-SERVER-IN-WORKSTATION-OU** (ldap) - operatingSystem match Server and distinguishedName
  under a tenant workstation-OU pattern. Severity: low. Refs: `ISO-27001:A.8.9`. Confidence: verified.
- **AD-EVT-UNSIGNED-LDAP-BIND** (eventlog on DCs) - channel Directory Service, id 2889, 7 d, info list
  with the client address field. Why: shows which hosts will break when LDAP signing is enforced.
  Severity: info. Refs: `NIST-800-53:SC-8`. Confidence: verified.
- **AD-GPO-VENDOR-AUDIT-POLICY** (ldap, configuration of groupPolicyContainer) - displayName match a
  vendor pattern (audit products create their own audit GPOs). Severity: info. Confidence: verified.
- **SCCM-DEPLOYMENT-RETIRED-PACKAGE / SCCM-PACKAGE-RETIRED-ON-DP** (`sccm.yaml`, http AdminService) -
  `SMS_DeploymentInfo` and `SMS_PackageStatusDistPointsSummarizer` rows whose PackageID is in the
  tenant's retired list, `count: some`. Severity: medium. Refs: `NIST-800-53:CM-7`. Confidence: verified.

## ServiceNow (`servicenow.yaml`, integration `servicenow`) - 67 rows

Common read shape: http GET `/api/now/table/<table>` (or `/api/now/stats/<table>` for counts),
`sysparm_display_value: "false"`, `sysparm_exclude_reference_link: "true"`, `paging: offset`,
`pageSize: 1000`, `items: result`. Dot-walked fields in `sysparm_query` (`user.active=true`) are
standard. The Table API ignores unknown fields, so every new rule needs a first-run confirmation.
Reference: ServiceNow Table API and the base tables named
(<https://www.servicenow.com/docs/>, Table API and the platform tables). Unless stated, confidence is
*likely* (documented base table, field names to confirm); *verified* where the same fields already
serve a shipped rule.

### Platform health
- **SNOW-NODE-OFFLINE** - sys_cluster_state, fields system_id,status,node_type,schedulers,most_recent_message;
  `status ne online`. Severity high. Refs `NIST-800-53:SI-4`. Fix: open a vendor case with the node id.
- **SNOW-EVENT-QUEUE-BACKLOG** - sysevent with `sysparm_query: state=ready^sys_created_on<{DAYS_AGO:0}`
  is not expressible by minutes; use `/api/now/stats/sysevent?sysparm_query=state=ready&sysparm_count=true`,
  `items: result.stats`, `count gt 1000` (threshold `servicenow.event-backlog-max`). Severity medium.
  Refs `NIST-800-53:SI-4`. Fix: find the flooding event source. Confidence: guess for the stats shape.
- **SNOW-SCHEDULED-JOB-OVERDUE** - sys_trigger, fields name,next_action,state,claimed_by;
  `next_action age-gt 0.05 and state ne 2`. Severity medium. Fix: release the claimed job.
- **SNOW-EMAIL-SEND-STUCK** - sys_email `type=send-ready`, `sys_created_on age-gt 0.02`; sibling
  **SNOW-EMAIL-SEND-FAILED** `type=send-failed^sys_created_on>{DAYS_AGO:7}`, `count gt threshold`.
  Severity high. Refs `NIST-800-53:SI-4`. Fix: repair the SMTP path; requeue.
- **SNOW-EMAIL-ACCOUNT-ERROR** - sys_email_account `type=imap^ORtype=pop3`, fields
  name,active,error_message,last_sync; `error_message notempty or last_sync age-gt 1`. Severity high.
  Fix: renew the mailbox credential or token.
- **SNOW-TRANSACTION-SLOW** - syslog_transaction `response_time>10000^sys_created_on>{DAYS_AGO:7}`,
  `count gt threshold`. Severity low. Fix: find the slow rule or report.
- **SNOW-TABLE-NO-CLEANUP** - sys_auto_flush plus sys_table_rotation, one rule per high-volume table
  (`count: { op: lt, value: 1, where: tablename eq <table> }`). Severity medium. Refs `ISO-27001:A.8.6`.
- **SNOW-MID-SERVER-STALE** - ecc_agent, `last_refreshed age-gt 0.01` (15 min) on `status eq Up`;
  addition to the shipped MID rules. Severity medium. Confidence: verified fields.
- **SNOW-ECC-OUTPUT-BACKLOG** - ecc_queue `queue=output^state=ready`, `sys_created_on age-gt 0.02`;
  sibling `state=error` in 24 h count. Severity medium. Fix: fix the MID or probe.
- **SNOW-MID-NO-CLUSTER** - ecc_agent_cluster, `count: none`; sibling **SNOW-DISCOVERY-SCHEDULE-PINNED-MID**:
  discovery_schedule active with `mid_select_method eq specific_mid`. Severity high. Refs
  `NIST-800-53:CP-10`. Fix: create the cluster, repoint schedules.
- **SNOW-MID-ISSUE-OPEN** - ecc_agent_issue `state!=resolved`, `sys_created_on age-gt 1`; sibling
  **SNOW-MID-NOTIFICATION-INACTIVE**: sysevent_email_action `collection=ecc_agent_issue`, `active ne true`.
  Severity medium. Fix: enable and route.
- **SNOW-MID-TLS-CHECK-DISABLED** - ecc_agent_property name match `check_cert`, value eq false.
  Severity medium. Refs `NIST-800-53:SC-23`. Fix: import the CA into the MID keystore, re-enable.
- **SNOW-MONITORING-EVENTS-NONE** - em_event (or incident `contact_type=monitoring`) created in 7 d,
  `count: none`. Severity medium. Fix: integrate the monitoring tools or record the decision.

### Lifecycle
- **SNOW-RELEASE-OLD** - sys_properties `name=glide.buildtag`, `value notmatch` threshold
  `servicenow.supported-families` (a regular expression maintained by the tenant). Severity high.
  Refs `NIST-800-53:SI-2`, `ISO-27001:A.8.8`. Fix: plan the family upgrade.
- **SNOW-STORE-APP-UPDATE-PENDING** - sys_store_app `active=true^update_available=true`,
  `sys_updated_on age-gt 180`. Severity medium. Fix: update in a window.
- **SNOW-UPGRADE-SKIPS-UNREVIEWED** - sys_upgrade_history_log `disposition=4^resolution_status!=reviewed`,
  `each: any`. Severity medium. Refs `NIST-800-53:CM-3`. Fix: review with the partner.
- **SNOW-UPDATE-SET-IN-PROGRESS-OLD** - sys_update_set `state=in progress`, `sys_created_on age-gt 30`.
  Severity medium. Refs `NIST-800-53:CM-5`. Fix: close stray sets; develop in test.
- **SNOW-LEGACY-WORKFLOW-ACTIVE** - wf_workflow `active=true^published=true`, `each: any`, info.
- **SNOW-CLONE-TO-TEST-STALE** - clone_instance `state=completed`, `count: { op: lt, value: 1,
  where: completed age-lt 90 }`. Severity medium. Refs `NIST-800-53:CM-4`. Fix: schedule a clone.
- **SNOW-TEST-INSTANCE-SENDS-MAIL** - bound to the test integration: sys_properties
  `glide.email.smtp.active` eq true with `glide.email.test.user` empty, or `glide.email.read.active` eq true.
  Severity medium. Refs `ISO-27001:A.8.31`. Fix: set the properties on test.
- **SNOW-CLONE-NO-DATA-EXCLUSION** - clone_data_exclude, `count: none`. Severity medium. Refs
  `NIST-800-53:SA-3(2)`. Fix: add exclusion rules for mail, attachments and credentials.

### Logs and audit
- **SNOW-SYSLOG-ERROR-STORM** - syslog `level=2^sys_created_on>{DAYS_AGO:1}`, `count gt 500`
  (threshold `servicenow.syslog-errors-max`). Severity medium. Refs `NIST-800-53:SI-4`.
- **SNOW-IMPORT-SET-ERRORS** - sys_import_set_run `sys_created_on>{DAYS_AGO:7}`, `errors gt 0`;
  sibling **SNOW-SCHEDULED-IMPORT-STALE**: scheduled_import_set active, last run older than its
  period (field `run_start` age-gt threshold). Severity medium. Fix: fix the source or transform map.
- **SNOW-FLOW-ERRORS** - sys_flow_context `state=ERROR^sys_created_on>{DAYS_AGO:7}`, `count gt 5`
  per instance; wf_context `state=faulted` sibling. Severity medium. Fix: fix the flow, restart requests.
- **SNOW-OUTBOUND-HTTP-FAILING** - sys_outbound_http_log `response_status>=400^sys_created_on>{DAYS_AGO:7}`,
  `count gt threshold`. Severity medium. Refs `ISO-27001:A.5.14`. Fix: fix the endpoint credential.
- **SNOW-AUDIT-SECURITY-TABLES-OFF** - sys_dictionary `internal_type=collection^nameINsys_user_has_role,
  sys_user_grmember,sys_security_acl,sys_properties`, `attributes contains no_audit`; sibling on
  sys_properties `glide.sys.audit` ne true. Severity high. Refs `NIST-800-53:AU-2`, `NIST-800-53:AU-12`,
  `CIS-Controls-v8:8.5`. Fix: enable auditing on the four tables.
- **SNOW-LOGIN-FAILED-BURST** - sysevent `name=login.failed^sys_created_on>{DAYS_AGO:7}`, `count gt
  threshold`; sibling **SNOW-LOCAL-LOGIN-EVENT** (sysevent `name=login`, parm2 not the SSO source,
  info). Severity medium. Refs `NIST-800-53:AC-7`, `NIST-800-53:AU-6`.
- **SNOW-AUDIT-FLUSH-RULE-SHORT** - sys_auto_flush `tablename=sys_audit^ORtablename=syslog^ORtablename=sysevent`,
  `age lt 730 days` (field unit to confirm). Severity medium. Refs `NIST-800-53:AU-11`.

### Configuration and exposure
- **SNOW-CMDB-APP-NO-OWNER** - cmdb_ci_business_app and cmdb_ci_service `operational_status=1`,
  `owned_by empty or support_group empty` (the server rules exist; application classes do not).
  Severity medium. Refs `NIST-800-53:CM-8(2)`, `CIS-Controls-v8:1.1`.
- **SNOW-CMDB-DEDUP-TASK-OLD** - reconcile_duplicate_task `state!=closed`, `sys_created_on age-gt 30`.
  Severity medium. Fix: merge through the tasks.
- **SNOW-CI-OWNER-INACTIVE** - cmdb_ci `install_status=1^owned_by.active=false^ORmanaged_by.active=false`.
  Severity medium. Fix: reassign.
- **SNOW-DISCOVERY-SCHEDULE-STALE** - for_each discovery_schedule (active) -> discovery_status
  `dscheduler={id}^ORDERBYDESCsys_created_on` with `top` 1; `started age-gt` the schedule period
  (threshold `servicenow.discovery-max-age-days`, default 7) or `state ne Completed`. Severity high.
  Refs `NIST-800-53:CM-8(3)`. Fix: fix the schedule, MID or credentials. Confidence: likely (for_each
  with a per-object query; `top` support in http to confirm).
- **SNOW-DISCOVERY-AUTH-FAILURES** - discovery_log `message LIKE authentication failure` in the last
  run window, `count gt threshold`. Severity medium. Fix: fix credentials per range.
- **SNOW-DISCOVERY-UNCLASSIFIED-MANY** - discovery_device_history `issues LIKE Unclassified` 7 d,
  `count gt threshold`. Severity medium. Fix: add patterns; investigate unknown devices.
- **SNOW-INBOUND-EMAIL-ACTION-OPEN** - sysevent_in_email_action `active=true^type=new^fromISEMPTY^
  required_rolesISEMPTY`; sibling **SNOW-EMAIL-FILTER-NONE** (sys_email_filter active, `count: none`).
  Severity high. Refs `ISO-27001:A.8.7`, `NIST-800-53:SI-3`. Fix: restrict record-creating actions to
  known senders.
- **SNOW-NOTIFICATION-INACTIVE-RECIPIENT** - sysevent_email_action `active=true^recipient_users.active=false`;
  literal external addresses: `recipient_fields match` tenant pattern. Severity low.
- **SNOW-PUBLIC-PAGE-ACTIVE** - sys_public `active=true` (info list); **SNOW-SP-PAGE-PUBLIC** sp_page
  `public=true`; **SNOW-KB-ARTICLE-PUBLIC** kb_knowledge with a public user criteria; **SNOW-GUEST-USER-UNLOCKED**
  sys_user `user_name=guest^locked_out=false`. Severity high. Refs `NIST-800-53:AC-3`,
  `ISO-27001:A.5.15`. Fix: remove public flags; lock guest.
- **SNOW-HARDENING-PROPERTY-OFF** - sys_properties `nameIN` the hardening list (script sandbox, CSRF
  token, HTML sanitising, escaping, strict updates, no blank password, strict elevate), `value ne`
  expected; one rule per property or a `where` list. Severity high. Refs `NIST-800-53:CM-6`,
  `CIS-Controls-v8:4.1`. Fix: set after testing on the test instance.
- **SNOW-ATTACHMENT-POLICY-WEAK** - sys_properties `glide.attachment.extensions` empty or
  `glide.security.file.mime_type.validation` ne true. Severity medium. Refs `ISO-27001:A.8.7`.
- **SNOW-IP-ACCESS-CONTROL-NONE** - ip_access `active=true`, `count: none`. Severity medium. Refs
  `NIST-800-53:AC-17`, `NIST-800-53:SC-7`.
- **SNOW-SESSION-TIMEOUT-LONG** - sys_properties `glide.ui.session_timeout` gt 30 or `glide.ui.forgetme`
  ne true. Severity low. Refs `NIST-800-53:AC-11`, `NIST-800-53:AC-12`.
- **SNOW-REST-OPERATION-NO-AUTH** - sys_ws_operation `active=true^requires_authentication=false^OR
  requires_acl_authorization=false`. Severity high. Refs `NIST-800-53:IA-2`, `NIST-800-53:AC-3`.
- **SNOW-REST-MESSAGE-INSECURE** - sys_rest_message `rest_endpoint match ^http://` or
  `authentication_type eq basic`; sys_soap_message sibling. Severity medium. Refs `NIST-800-53:SC-8`.
- **SNOW-ARCHIVE-RULE-NONE** - sys_archive `active=true`, `count: none`. Severity medium. Refs
  `NIST-800-53:SI-12`, `ISO-27001:A.8.10`.
- **SNOW-CMDB-NO-RECONCILIATION-RULES** - cmdb_reconciliation_definition, `count: none`. Severity medium.
- **SNOW-CATALOG-ITEM-OWNER-INACTIVE** - sc_cat_item `active=true^owner.active=false^ORgroupISEMPTY`.
  Severity low.
- **SNOW-CONTENT-LEGACY-REFERENCE** - kb_knowledge, sc_cat_item and sysevent_email_template with
  `textLIKE{pattern}` from threshold `servicenow.legacy-system-pattern`, `count gt 0`. Severity low.
- **SNOW-KB-ARTICLE-EXPIRED** - kb_knowledge `workflow_state=published^valid_to<{TODAY}`; sibling
  **SNOW-KB-OWNER-INACTIVE** (`kb_knowledge_base.owner.active=false` or article author inactive).
  Severity low.
- **SNOW-SCOPED-APP-NO-REPO** - for_each sys_app -> sys_repo_config `app={id}`, `count: none`.
  Severity medium. Refs `NIST-800-53:CM-2(3)`, `CIS-Controls-v8:16.1`. Fix: link to a repository.

### Identity and access
- **SNOW-ELEVATED-ROLE-HOLDER** - sys_user_has_role `role.elevated_privilege=true^user.active=true`,
  `each: any` with a count sibling; **SNOW-ELEVATION-EVENT** sysevent `name=security.elevated_role.enabled`
  90 d (info). Severity high. Refs `NIST-800-53:AC-6(9)`.
- **SNOW-IMPERSONATOR-ROLE-HOLDER** - role.name=impersonator; **SNOW-IMPERSONATION-EVENT** sysevent
  `name=impersonation.start` 90 d (info). Severity high. Refs `NIST-800-53:AC-6(9)`, `ISO-27001:A.8.15`.
- **SNOW-USER-LOCAL-LOGIN** - sys_user `active=true^sourceISEMPTY^web_service_access_only=false`,
  `each: any`. Severity high. Refs `CIS-Controls-v8:6.7`, `ISO-27001:A.8.5`. Fix: remove local passwords.
- **SNOW-SSO-NOT-ENFORCED** - sys_properties `glide.authenticate.multisso.enabled` ne true, or
  saml2_update1_properties with `active=true^default=true` `count: none`. Severity high. Refs
  `NIST-800-53:IA-8`, `CIS-Controls-v8:6.7`.
- **SNOW-VENDOR-USER-PRIVILEGED** - sys_user_has_role for users from the vendor source (tenant
  marker on `company` or `source`) with `role.nameINadmin,security_admin,itil_admin`. Severity high.
  Refs `NIST-800-53:AC-6`, `ISO-27001:A.5.19`.
- **SNOW-INTEGRATION-USER-INTERACTIVE** - sys_user `internal_integration_user=true^web_service_access_only=false`;
  **SNOW-INTEGRATION-USER-ADMIN** same users with admin roles; idle ones already SNOW-USER-DORMANT.
  Severity high. Refs `NIST-800-53:IA-9`, `CIS-Controls-v8:5.5`.
- **SNOW-ITIL-DIRECT-GRANT** - sys_user_has_role `role.name=itil^inherited=false^user.active=true`.
  Severity medium. Refs `NIST-800-53:AC-2`.
- **SNOW-GROUP-MANAGER-INACTIVE** - sys_user_group `active=true^manager.active=false^ORmanagerISEMPTY`
  for groups with an itil type. Severity medium.
- **SNOW-APPROVAL-APPROVER-INACTIVE** - sysapproval_approver `state=requested^approver.active=false`.
  Severity medium. Fix: reassign; set delegation rules.
- **SNOW-ACL-RECENTLY-CHANGED** - sys_security_acl `active=true^sys_updated_on>{DAYS_AGO:90}`, info list
  with sys_updated_by. Severity info. Refs `NIST-800-53:AC-3`, `NIST-800-53:CM-3`.
- **SNOW-PII-FIELD-NO-ACL** - sys_security_acl `name=sys_user.<field>^operation=read` per sensitive
  field from a threshold list, `count: none`. Severity high. Refs `NIST-800-53:AC-3`, `ISO-27001:A.8.3`.
- **SNOW-DELEGATED-DEVELOPER-PROD** - sys_user_has_role `role.name LIKE delegated_developer^user.active=true`.
  Severity low. Refs `NIST-800-53:CM-5`.
- **SNOW-LOCAL-MFA-OFF** - v_plugin for the multi-factor plugin not active, or sys_properties
  `glide.authenticate.multifactor` ne true. Severity high. Refs `NIST-800-53:IA-2(1)`.
- **SNOW-BASIC-AUTH-ALLOWED** - sys_properties `glide.basicauth.required.*` ne true. Severity medium.
  Refs `NIST-800-53:IA-5`. Confidence: guess (property set varies by release).
- **SNOW-REQUEST-ITEM-OLD** - sc_req_item `active=true^opened_at<{DAYS_AGO:30}`. Severity medium.
- **SNOW-INCIDENT-P1-NO-PROBLEM** - incident `priorityIN1,2^opened_at>{DAYS_AGO:90}^problem_idISEMPTY^
  state>=6` (resolved/closed); **SNOW-PROBLEM-OLD-NO-CAUSE** problem `active=true^opened_at<{DAYS_AGO:180}^
  cause_notesISEMPTY`. Severity medium. Refs `NIST-800-53:IR-4`.
- **SNOW-P1-NO-MAJOR-INCIDENT-RECORD** - incident `priority=1^opened_at>{DAYS_AGO:180}^major_incident_stateISEMPTY`.
  Severity medium. Refs `NIST-800-53:IR-4`, `NIST-800-53:IR-8`.
- **SNOW-CHANGE-NO-CI** - change_request `active=true^cmdb_ciISEMPTY^type!=standard`. Severity medium.
  Refs `NIST-800-53:CM-3`.

### Store joins for the CMDB (`cross-system.yaml`, protocol store)
- **XS-SERVER-AD-NOT-IN-CMDB** - a server computer account active in the directory (row_seen of the
  AD scan) whose normalised name is not in the newest ServiceNow cmdb_ci_server rows (needs a
  SNOW-CMDB-SERVER read that returns every operational server; the shipped CMDB rules provide it).
  **XS-CMDB-SERVER-GONE** - the reverse. **XS-SYSTEM-NOT-IN-CMDB** - a system register row with no
  cmdb_ci_business_app row of the same name. **XS-AD-SUBNET-NOT-DISCOVERED** - an AD subnet object with
  no covering discovery_range_item row (needs a SNOW-DISCOVERY-RANGE read; CIDR containment is not in
  SQLite, so match exact prefixes first). Severity medium. Refs `NIST-800-53:CM-8`,
  `CIS-Controls-v8:1.1`. Confidence: likely (follows the cross-system.md conventions).

## Work-management board service (`monday.yaml`, integration `monday`, graphql) - 8 rows

Documents use the GraphQL API v2 (<https://developer.monday.com/api-reference/>); all reads are
queries. Confidence *likely* for `users`, `boards`, `webhooks` (documented); *guess* for activity logs.

- **MON-ACCOUNT-UNEXPECTED** - `{ account { id slug tier } }`, `slug ne` threshold `monday.account-slug`.
  Severity medium. Why: a token on the wrong account reads the wrong boards. Fix: fix the token.
- **MON-ADMIN-COUNT / MON-ADMIN-HOLDER** - `{ users(limit: 500) { id email is_admin is_guest
  is_view_only is_pending enabled last_activity created_at } }`, `items: data.users`; count of
  `is_admin eq true and enabled eq true` gt 3 (threshold `monday.max-admins`); holder list at info.
  Refs `NIST-800-53:AC-6(5)`, `CIS-Controls-v8:5.4`.
- **MON-GUEST-INACTIVE** - same read; `is_guest eq true and enabled eq true and last_activity age-gt 90`.
  Severity medium. Refs `ISO-27001:A.5.19`. Fix: remove the guest.
- **MON-INVITE-PENDING** - `is_pending eq true and created_at age-gt 30`. Severity low.
- **MON-MEMBER-IDLE** - `is_guest eq false and is_view_only eq false and last_activity age-gt 90`.
  Severity low; feeds `seats_used` on the licence row.
- **MON-BOARD-PUBLIC-IN-OPEN-WORKSPACE** - `{ boards(limit: 500) { id name board_kind workspace { kind }
  owners { email } } }`; `board_kind eq public and workspace.kind eq open and name match` threshold
  `monday.sensitive-board-pattern`. Severity medium. Refs `ISO-27001:A.5.15`, `NIST-800-53:AC-3`.
- **MON-BOARD-SHAREABLE** - `board_kind eq share`, info list. Refs `ISO-27001:A.5.14`.
- **MON-WEBHOOK-UNAPPROVED-HOST** - for_each boards -> `{ webhooks(board_id: {id}) { id event config } }`;
  `config notmatch` threshold `monday.approved-webhook-hosts`. Severity medium. Refs `NIST-800-53:CA-3`.
  Confidence: likely (GraphQL for_each needs variables; see engine gaps).
- **MON-AUTOMATION-FAILURE-EVENTS** - `boards { activity_logs(limit: 200) { event data created_at } }`,
  `event match failure`. Severity low. Confidence: guess.

## Issue tracker (`jira.yaml`, integration `http` with Basic token) - 11 rows

Cloud REST API v3 (<https://developer.atlassian.com/cloud/jira/platform/rest/v3/>); pagination is
`startAt`/`maxResults` (offset paging with those names). Confidence *likely*.

- **JIRA-PROJECT-INACTIVE** - `/rest/api/3/project/search?expand=insight`, `items: values`,
  `insight.lastIssueUpdateTime age-gt 365`. Severity low. Fix: archive the project.
- **JIRA-APP-INSTALLED** - `/rest/plugins/1.0/?os_authType=basic`, `items: plugins`, `userInstalled eq true`
  (info). Refs `ISO-27001:A.5.21`.
- **JIRA-PERMISSION-CHANGE-RECENT** - `/rest/api/3/auditing/record?filter=permission&from={DAYS_AGO:90}`,
  `items: records`, info list. Refs `NIST-800-53:AU-6`.
- **JIRA-PERMISSION-ANYONE** - `/rest/api/3/permissionscheme?expand=permissions`, `items: permissionSchemes`,
  `permissions[].holder.type eq anyone`. Severity high. Refs `NIST-800-53:AC-3`, `ISO-27001:A.5.15`.
- **JIRA-PERMISSION-ADMIN-DEFAULT-GROUP** - same read; `permissions[].permission eq ADMINISTER_PROJECTS`
  and `holder.parameter in` threshold default-group list. Severity medium. Refs `NIST-800-53:AC-6`.
- **JIRA-FILTER-PUBLIC** - `/rest/api/3/filter/search?expand=sharePermissions`,
  `sharePermissions[].type in [global, authenticated]`; dashboard sibling. Severity medium.
- **JIRA-WEBHOOK-UNAPPROVED-HOST** - `/rest/webhooks/1.0/webhook`, `url notmatch` approved hosts.
  Severity low.
- **JIRA-ISSUES-SECRET-TEXT** - `/rest/api/3/search?jql=text ~ "{term}"&maxResults=0` per term,
  `total gt 0`. Severity low (noisy). Refs `ISO-27001:A.5.17`.
- **JIRA-ADMIN-GROUP-MEMBERS** - `/rest/api/3/group/member?groupname=site-admins`, `items: values`,
  `count gt 3`; jira-administrators sibling. Refs `CIS-Controls-v8:5.4`.
- **JIRA-USER-EXTERNAL-DOMAIN** - `/rest/api/3/users/search?maxResults=1000`, `accountType eq atlassian
  and active eq true and emailAddress notmatch` tenant domains; the same read feeds
  XS-SCIM-LEAVER-STILL-IN-APP. Severity medium. Refs `ISO-27001:A.5.19`.
- **JIRA-PROJECT-ADMINS-MANY** - for_each project -> `/rest/api/3/project/{id}/role/{adminRoleId}`,
  `actors size-gt 3`. Severity low.

## Developer platform (`azure-devops.yaml`, integration `http` with PAT) - 22 rows

REST 7.1 (<https://learn.microsoft.com/rest/api/azure/devops/>); each API host is its own
integration because a credential only goes to its endpoint: the organisation host, the identity
host (`vssps`), the entitlement host (`vsaex`), the feeds host, the audit host. Responses are
`{count, value}` -> `items: value`. Confidence *likely* unless noted.

- **ADO-AGENT-OFFLINE** - for_each `/_apis/distributedtask/pools?poolType=automation` ->
  `/_apis/distributedtask/pools/{id}/agents`; `status ne online or enabled eq false`. Severity medium.
  Refs `NIST-800-53:CP-10`. **ADO-POOL-SINGLE-AGENT** - same read, `size-lt 2` per pool. 
- **ADO-PIPELINE-CLASSIC** - `/{project}/_apis/release/definitions`, `count: some` (info);
  `/_apis/build/definitions?includeAllProperties=true`, `process.type eq 1` (designer). Refs `ISO-27001:A.8.8`.
- **ADO-AUDIT-STREAM-NONE** - audit host `/_apis/audit/streams`, `count: none`. Severity medium. Refs
  `NIST-800-53:AU-6(3)`, `CIS-Controls-v8:8.9`.
- **ADO-RETENTION-SHORT** - `/{project}/_apis/build/retention`, `maximumRetentionPolicy.daysToKeep lt 365`
  for production projects. Severity low. Refs `NIST-800-53:AU-11`.
- **ADO-PROJECT-PUBLIC** - `/_apis/projects`, `visibility eq public`. Severity high. Refs `NIST-800-53:AC-3`.
- **ADO-REPO-MAIN-UNPROTECTED** - `/{project}/_apis/policy/configurations`, `count: { op: lt, value: 1,
  where: type.displayName eq "Minimum number of reviewers" and isEnabled and isBlocking and
  settings.scope[].refName eq refs/heads/main }` - per project; per repository needs a for_each over
  repositories and a filter on `settings.scope[].repositoryId` (engine gap: the must-exist is per
  parent). Severity high. Refs `NIST-800-53:CM-5`, `NIST-800-53:SA-10`, `CIS-Controls-v8:16.1`.
- **ADO-SERVICE-CONNECTION-SECRET-AUTH** - `/{project}/_apis/serviceendpoint/endpoints?includeDetails=true`,
  `authorization.scheme in [ServicePrincipal, UsernamePassword, Token, InstallationToken]`; sibling
  **ADO-SERVICE-CONNECTION-ALL-PIPELINES**: for_each endpoint -> `/_apis/pipelines/pipelinePermissions/endpoint/{id}`,
  `allPipelines.authorized eq true`. Severity high. Refs `NIST-800-53:IA-5`, `NIST-800-53:AC-6`,
  `ISO-27001:A.5.17`. Fix: convert to workload identity federation; restrict to named pipelines.
- **ADO-VARIABLE-GROUP-PLAIN-SECRET** - `/{project}/_apis/distributedtask/variablegroups`, `type eq Vsts`
  and a variable whose name matches `(password|secret|key|token)` with `isSecret ne true` (variables
  are a map, so the condition needs the map-to-rows gap noted below). Severity high. Refs
  `NIST-800-53:IA-5(7)`, `CIS-Controls-v8:16.12`. **ADO-SECRET-SCAN-ALERT-OPEN** -
  `/{project}/_apis/alert/repositories/{repo}/alerts?criteria.alertType=secret` where licensed.
- **ADO-ENVIRONMENT-NO-APPROVAL** - for_each `/{project}/_apis/distributedtask/environments` ->
  `/_apis/pipelines/checks/configurations?resourceType=environment&resourceId={id}`, `count: { op: lt,
  value: 1, where: type.name eq Approval }` for environments named production. Severity high. Refs
  `NIST-800-53:CM-3`, `ISO-27001:A.8.32`.
- **ADO-FEED-PUBLIC-UPSTREAM** - feeds host `/_apis/packaging/feeds`, `upstreamSources notempty` (info).
  Refs `NIST-800-53:SR-3`.
- **ADO-PIPELINE-SETTINGS-WEAK** - `/{project}/_apis/build/generalsettings`, any of
  `enforceJobAuthScope`, `enforceJobAuthScopeForReleases`, `enforceReferencedRepoScopedToken`,
  `enforceSettableVar` eq false. Severity medium. Refs `NIST-800-53:AC-6`.
- **ADO-ADVSEC-DISABLED** - `/{project}/_apis/management/repositories/{repoId}/enablement`,
  `advSecEnabled ne true` for production repositories (licensed feature). Severity medium. Refs
  `NIST-800-53:RA-5`, `NIST-800-53:SA-11`.
- **ADO-COLLECTION-ADMINS-MANY** - identity host `/_apis/graph/groups` to find the Project Collection
  Administrators descriptor, then `/_apis/graph/memberships/{descriptor}?direction=down`, `count gt 3`;
  nested groups need a second level (engine gap). Severity high. Refs `CIS-Controls-v8:5.4`.
  **ADO-PROJECT-ADMINS-MANY** - the same per project's Project Administrators group.
- **ADO-USER-IDLE** - entitlement host `/_apis/userentitlements?top=1000`, `items: members`,
  `lastAccessedDate age-gt 90`; **ADO-BASIC-LICENCE-IDLE** adds `accessLevel.accountLicenseType eq express`;
  **ADO-USER-EXTERNAL-DOMAIN** `user.principalName notmatch` tenant domains; **ADO-SERVICE-PRINCIPAL-ENTITLEMENT**
  `user.subjectKind eq servicePrincipal` (info). Refs `CIS-Controls-v8:5.3`, `ISO-27001:A.5.18`.
- **ADO-PAT-FULL-SCOPE** - identity host `/_apis/tokenadmin/personaltokens/{subjectDescriptor}` with
  for_each over users (needs the descriptor, so two-level for_each: engine gap); `scope eq app_token`
  or `validTo until-lt` beyond 90 days. Severity high. Refs `NIST-800-53:IA-5`, `ISO-27001:A.5.17`.
  Confidence: guess (admin API, descriptor plumbing).
- **ADO-BUILD-FAILED-RECENT** - `/{project}/_apis/build/builds?resultFilter=failed&minTime={DAYS_AGO:30}`,
  info list. **ADO-PROJECT-STALE** - `/_apis/projects`, `lastUpdateTime age-gt 365`. Severity low.

## GitOps, Kubernetes and dashboards (generic `http` integrations) - 8 rows
- **ARGO-APP-OUT-OF-SYNC / ARGO-APP-UNHEALTHY** (`argocd.yaml`, bearer token) - `/api/v1/applications`,
  `items: items`, `status.sync.status ne Synced` / `status.health.status ne Healthy`; `status.reconciledAt
  age-gt 0.01`. Severity medium. Refs `NIST-800-53:CM-2`, `NIST-800-53:CM-3`. Confidence: verified
  (Argo CD REST is documented and JSON).
- **ARGO-SETTINGS-NO-OIDC** - `/api/v1/settings`, `oidcConfig absent and dexConfig empty`. Severity
  high. Refs `NIST-800-53:IA-2`, `CIS-Controls-v8:6.7`. **ARGO-LOCAL-ADMIN-ENABLED** - through the
  Kubernetes integration: `/api/v1/namespaces/argocd/configmaps/argocd-cm`, `data.admin.enabled ne "false"`.
- **K8S-NODE-NOT-READY** (`kubernetes.yaml`, bearer token of a view-only service account) -
  `/api/v1/nodes`, `items: items`, `status.conditions[]` with `type eq Ready and status ne True` (array
  element matching on two fields is an engine gap; interim: `status.conditions[].status contains False`).
  **K8S-POD-CRASHLOOP** - `/api/v1/pods`, `status.containerStatuses[].state.waiting.reason in
  [CrashLoopBackOff, ImagePullBackOff]` or `restartCount gt 5`. Severity high. Refs `NIST-800-53:SI-4`.
- **K8S-POD-PRIVILEGED** - `/api/v1/pods`, `spec.containers[].securityContext.privileged eq true or
  spec.hostNetwork eq true` outside kube-system. Severity high. Refs `NIST-800-53:CM-7`,
  `CIS-Controls-v8:4.1`. **K8S-CLUSTER-ADMIN-BINDING** - `/apis/rbac.authorization.k8s.io/v1/clusterrolebindings`,
  `roleRef.name eq cluster-admin` (info list of subjects). Refs `NIST-800-53:AC-6`.
  **K8S-VERSION-OLD** - `/version`, `gitVersion notmatch` threshold of supported minors. Severity high.
  Refs `NIST-800-53:SA-22`. Confidence: verified (Kubernetes API shapes).
- **GRAFANA-ALERT-RULE-NONE** (`grafana.yaml`, service-account token) - `/api/v1/provisioning/alert-rules`,
  `count: none`; sibling on `/api/v1/provisioning/contact-points` for a non-default contact point.
  Severity medium. Refs `NIST-800-53:SI-4(5)`. Confidence: verified. The monitoring area may own this file.
- **UMB-AUDIT-STALE** (`umbraco.yaml`, integration `sql`, the CMS database) - `SELECT MAX(datetime) AS
  newest FROM umbracoLog` and `umbracoAudit`, `newest age-gt 7`. Severity medium. Refs
  `NIST-800-53:AU-12`. Confidence: guess (database engine and table names per deployment).

## Document management (`opentext.yaml`, integration `sql`, the content-server database) - 7 rows
All rows are read-only SELECTs; table names are the product's documented schema. Confidence *likely*.
- **OT-AUDIT-RETENTION-SHORT** - `SELECT MIN(AuditDate) AS oldest, COUNT_BIG(*) AS rows FROM DAuditNew`,
  `oldest age-lt 730` once the system is older than two years (pair with a system start date in the
  register). Severity high. Refs `NIST-800-53:AU-11`, `ISO-27001:A.8.15`. Fix: raise the purge setting.
- **OT-ACL-PUBLIC-ACCESS** - `SELECT DataID, Name FROM DTree WHERE ParentID = 2000 AND DataID IN
  (SELECT DataID FROM DTreeACL WHERE RightID = -1 AND Permissions > 0)` (public-access right on
  top-level folders), `each: any`. Severity high. Refs `NIST-800-53:AC-3`, `ISO-27001:A.8.3`.
- **OT-ADMIN-USE-RECENT** - `SELECT COUNT(*) AS uses FROM DAuditNew WHERE PerformerID = 1000 AND AuditDate
  > :since`, `uses gt 0` (built-in admin should be break-glass). Severity medium. Refs `NIST-800-53:AC-2(7)`.
- **OT-REPORTS-BY-NON-ADMIN** - `SELECT DataID, Name, UserID FROM DTree WHERE SubType IN (299, 30303)`
  with `UserID notin` the admin list threshold. Severity high. Refs `NIST-800-53:AC-6`.
- **OT-VERSIONS-PER-PROVIDER** - `SELECT ProviderID, COUNT(*) AS versions FROM DVersData GROUP BY ProviderID`,
  info. **OT-DOC-VERSIONS-MANY** - `SELECT DocID, COUNT(*) AS versions FROM DVersData GROUP BY DocID
  HAVING COUNT(*) > 20`, `count gt threshold`. Severity low. Refs `ISO-27001:A.8.10`.
- **OT-ITEMS-OWNED-BY-DELETED-USER** - `SELECT COUNT(*) AS orphans FROM DTree t JOIN KUAF u ON u.ID =
  t.UserID WHERE u.Deleted = 1`, `orphans gt 0`. Severity low. Refs `ISO-27001:A.5.18`.

## Integration platform (`xpi.yaml`, integration `sql`, the platform database) - 5 rows
- **XPI-FLOW-ERRORS** - `SELECT COUNT(*) AS errors FROM IFS_ACTLOG WHERE MessageType IN (error types)
  AND StartTime > :since`, `errors gt 50` (threshold). Severity high. Refs `NIST-800-53:SI-4`.
- **XPI-TRIGGER-NOT-FIRED** - `SELECT ProjectName, FlowName, MAX(StartTime) AS last FROM IFS_ACTLOG
  GROUP BY ProjectName, FlowName`, `last age-gt` threshold per flow class. Severity medium.
- **XPI-MESSAGE-BACKLOG** - oldest pending row in the ODS tables `age-gt 0.05`. Severity medium.
- **XPI-ACTLOG-RETENTION-LONG** - `SELECT MIN(StartTime) AS oldest FROM IFS_ACTLOG`, `oldest age-gt 90`;
  sibling on `sys.database_permissions` for SELECT grants beyond the service and admin logins.
  Severity high. Refs `NIST-800-53:SI-12`, `ISO-27001:A.8.10`.
- **XPI-FLOW-DORMANT** - same MAX(StartTime) read, `last age-gt 90`, info. Refs `NIST-800-53:CM-7`.
Confidence: likely (activity-log table documented; column names to confirm).

## Call recording (`callrec.yaml`, integration `sql`) - 1 row
- **CR-RECORDINGS-LOW** - count of recordings in the last 24 h on working days below the baseline
  threshold. Confidence: guess (vendor schema unknown until read). Severity high. Refs `NIST-800-53:SI-4`.

## Microsoft cloud additions (`m365.yaml`, `entra.yaml`, graph) - 5 rows
- **M365-TEAMS-ROOM-DEVICE-UNHEALTHY** - `/teamwork/devices` (beta), `healthStatus ne healthy or
  activityState ne active`. **M365-RESOURCE-ACCOUNT-PASSWORD-EXPIRES** - `/users?$filter=...` room and
  resource accounts (tenant pattern on userPrincipalName or `mailboxSettings`), `passwordPolicies
  notcontains DisablePasswordExpiration`. Severity medium. Refs `NIST-800-53:IA-5`. Confidence: likely
  (TeamworkDevice.Read.All).
- **ENTRA-GDAP-RELATIONSHIP-ACTIVE** - `/tenantRelationships/delegatedAdminRelationships`, `status eq
  active` (info with endDateTime and roles). Refs `NIST-800-53:AC-6`, `ISO-27001:A.5.20`.
- **ENTRA-SIGNIN-GUEST-UNEXPECTED-COUNTRY** - `/auditLogs/signIns?$filter=userType eq 'guest' and
  createdDateTime ge {DAYS_AGO:30} and status/errorCode eq 0`, `location.countryOrRegion notin`
  threshold list. Severity medium. Refs `NIST-800-53:AC-17`.
- **ENTRA-AUDIT-GUEST-INITIATED** - `/auditLogs/directoryAudits?$filter=activityDateTime ge {DAYS_AGO:30}`,
  `initiatedBy.user.userPrincipalName match #EXT#`, info. Refs `NIST-800-53:AU-6`.

## Virtualisation addition (`vmware.yaml`) - 1 row
- **VMW-CLUSTER-NO-AFFINITY-RULES** - cluster DRS rules with no anti-affinity rule for a VM group the
  tenant names. Confidence: guess - the automation REST surface for DRS rules is version-dependent;
  may need the infrastructure area's judgement.

## Rows that need an integration type Keeper does not have (101 rows)

Listed so the gap is a decision, not a loss. Each line: what is missing, what it would unlock.

- **Cloud provider API with request signing** (SigV4): 45 rows - compute and volume state,
  CloudWatch metrics and alarms, auto scaling, load balancer and CDN health, WAF rules, SES, Organizations
  and SCP content, Identity Center permission sets, CloudTrail event lookup, Cost Explorer, backup
  vaults, transit-gateway routes, certificate manager renewal state, registry lifecycle. Interim:
  the Prowler import covers the configuration posture (public buckets, endpoint exposure, key age,
  trail validation, logging), and the registers carry the costs and decisions.
- **SOAP / XML over POST** (unified communications): 22 rows - services, registrations, trunks,
  replication, performance counters, dial-plan and trunk security, credential policies, call-detail
  records. The http runner is GET-only and JSON.
- **SNMP** (power devices): 7 rows - UPS state, battery, load, runtime, input events, environment,
  clocks. A read-only SNMP v3 protocol would also serve network and printer rows in other areas.
- **Token-exchange REST** (video management, directory service of the document platform, vendor
  cloud tenants, advisory feeds): 17 rows - the product issues a bearer token from a POST sign-in;
  the http integration carries a static credential only. A per-integration "token endpoint" option
  would unlock them without a new protocol.
- **Vendor admin APIs on separate hosts with their own keys** (organisation audit, managed accounts,
  API-token visibility, audit-log service): 6 rows.
- **Firewall management API** (drops and flows): 1 row. **Log-query API that is a POST** (central
  log store): 1 row. **Vendor databases whose schema is unknown until read** (attendance terminals,
  cards, employee feed): 4 rows - become `sql` rules once the tables are named.

## Not automatable (29 rows)
Content judgement (secrets in channels, personal documents in a media library, near-duplicate
category names), files on hosts (ini files, log folders, patch folders, bundled runtime version
files, keystores in JKS form), ACL reads (no protocol returns security descriptors), HTML pages
(front-end libraries, robots directives, publish pages), one-off request states, procurement
reconciliation, and time-of-day conditions. Several of these fold into the generic obligations
above (hardening review, runbook, interface inventory) so the duty is still tracked.

## Engine gaps met while writing these
- **Version comparison**: no `version-lt` operator; WINSRV-SW-VERSION-BELOW-MIN and the K8S/CMS
  version rules fall back to regular expressions of acceptable versions.
- **Aggregates and grouping**: counts per group (events per source, duplicates by serial, members per
  group, use per catalog item) are not expressible; the ServiceNow stats endpoint's `result.stats`
  shape needs confirming as an `items` path.
- **Per-parent must-exist**: "every repository has a blocking policy", "every production
  environment has an approval check" need a `count: none` judged per for_each parent, not per system.
- **Two-level for_each** (users -> descriptors -> tokens; boards -> webhooks with GraphQL variables)
  and GraphQL `for_each` with the parent id as a variable.
- **Array element matching on two fields** (Kubernetes conditions `type eq Ready and status ne True`).
- **Map-valued fields** (pipeline variable groups: variables are a map keyed by name).
- **Cross-row date correlation** (clone before upgrade, MID version vs instance build).
- **Second instance of the same product** in one rule (test vs production comparison) - today each
  instance is a separate integration and rules see one at a time.
- **CIDR containment in SQLite** for subnet-vs-range joins.
- **A token-endpoint option on the http integration** (see the integration list above) would turn
  17 `needs-integration` rows into ordinary http rules.

## Counts
- Rows: 790 (775 catalogue + 15 known-issue).
- covered 211; proposed elsewhere 29 (XS-*, ENTRA-* and WINSRV/WS-* proposals in cross-system.md,
  microsoft-cloud.md, windows-estate.md); duplicate 27; new scan rules 174 (of which 67 ServiceNow,
  22 developer platform, 11 issue tracker, 8 board service, 8 GitOps/Kubernetes/dashboards, 7
  document management, 5 integration platform, 46 generic Windows/AD/Entra/SCCM/SQL/store); new
  obligations 153 (11 generic ids plus one telephony test); register rows 54 (two new REG rules, the
  rest existing); tls targets 12; needs-integration 101; not-automatable 29.
- Generic patterns and the rows each absorbs: OBL-SYS-ALERT-ROUTING 21, OBL-SYS-HARDENING-REVIEW 20,
  OBL-SYS-RUNBOOK 20, OBL-APP-BACKUP-VERIFIED 16, OBL-PRIVACY-DATABASE-RECORD 16, OBL-SYS-DECOMMISSION
  15, OBL-APP-AUDIT-TRAIL 12, OBL-APP-SSO-ENFORCED 12, OBL-APP-INTERFACE-INVENTORY 10, OBL-APP-SOD-REVIEW
  5, OBL-SYS-NETWORK-EXPOSURE-REVIEW 5, REG-KEY-SUPPORT-END-DUE 5, REG-KEY-SYSTEM-INACTIVE 1,
  OBL-TEL-EMERGENCY-CALL-TEST 1, WINSRV-SW-VERSION-BELOW-MIN 9, register rows on existing REG rules
  48, tls targets 12.
