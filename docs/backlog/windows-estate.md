# Backlog - Windows estate (SCCM, workstations, servers, SQL Server)

Checks that `rules/sccm.yaml`, `rules/workstations-sccm.yaml`, `rules/workstations.yaml`,
`rules/windows-server.yaml` and `rules/sql-server.yaml` cannot express yet. One line each: the
check, what it needs, and where it came from.

Source labels: `cm-health` = the legacy Configuration Manager health check (check id WS01-WS14),
`win11` = the legacy Windows 11 readiness report, `fleet` = the legacy fleet-slowness scan (health
checks and event signals), `weekly` = the legacy weekly report plugins (WS11-WS18, DB01-DB07),
`inventory` = the legacy inventory-portal report rules, `controls` = the legacy control catalogue
(SRV-*, DC-*), `facts` = the legacy server fact types, `review` = the legacy server expert check list
(item id), `field` = a problem seen in a real estate, described generically, `proposal` =
docs/proposals/windows-estate.md (2026-10-20), an entry that was not implemented and why.

## First-run checklist - implemented, but confirm on the first real scan

Names and values below are written from documentation or field use and have not been read from a
live host by Keeper yet. A wrong name makes a query fail (unknown, visible in coverage) or a rule
silent; check each one on a sample before trusting a pass.

- Registry: SecureBoot\Servicing UEFICA2023Status / WindowsUEFICA2023Capable and the value "Updated"
  (WS-/WINSRV-REG-SECUREBOOT-CA2023); `Windows Advanced Threat Protection\Status` OnboardingState
  (REG-MDE-NOT-ONBOARDED); SrpV2\Exe EnforcementMode 0 = audit (REG-APPLOCKER-AUDIT-ONLY);
  `SMS\Mobile Client\Reboot Management\RebootData` as the client's restart flag
  (WS-REG-REBOOT-PENDING-CCM); CcmEval LastEvalTime as a CIM datetime string - the engine reads the
  first 14 digits as UTC (WS-/WINSRV-CCM-EVAL-*); HardenedPaths value names containing backslashes
  read back as fields named `\\*\SYSVOL`.
- CIM: Win32_DeviceGuard UsermodeCodeIntegrityPolicyEnforcementStatus (WS-WDAC-AUDIT-ONLY);
  Win32_TerminalServiceSetting PolicySourceAllowTSConnections meaning (evidence only);
  Win32_ComputerSystem DNSHostName against {HOST} - WS-/WINSRV-HOST-NAME-MISMATCH must stay silent
  on a sample of correctly named hosts; root/ccm/SoftMgmtAgent CacheConfig Size (CCM-CACHE-SMALL);
  InventoryActionStatus ids written with braces `{00000000-0000-0000-0000-000000000001}` (hardware)
  and `...003` (heartbeat); SMS_Authority Name as `SMS:<code>`; MSFT_NetAdapter filtered on
  HardwareInterface in WQL and NdisPhysicalMedium 14 for wired links; Defender exclusions answered as
  an "N/A..." placeholder to non-administrators (WS-/WINSRV-DEFENDER-EXCLUSIONS-UNREADABLE); the
  Defender platform version format 4.18.YYMM(x).N behind WS-DEFENDER-PLATFORM-OLD.
- Event data names: QueryName (DNS 1014), ServerName (SMB client), SSID (WLAN), DCName (GP 5308),
  PolicyElaspedTimeInSeconds (GP 8000/8001, Microsoft's spelling), CSEElaspedTimeInMilliSeconds and
  CSEExtensionName (GP 5016), BootTime / BootPostBootTime / ShutdownTime / DegradationTime /
  FriendlyName (Diagnostics-Performance), BugcheckCode (Kernel-Power 41), updateTitle (WU 20),
  ResultCode (WMI 5858), SubjectUserName (Security 1102), param1/param2 (SCM). AppName on Application
  Error 1000 / Application Hang 1002 may be positional on some builds: the runner returns named data
  only, so the sample would be empty and WS-EVT-AGENT-CRASH silent.
- Event providers: the `where` patterns (DNS-Client, NETLOGON, LsaSrv, GroupPolicy, Dhcp, Tcpip,
  NDIS, Schannel, Kernel-Processor-Power, WindowsUpdateClient, User Profile, Winlogon,
  `^EventLog$` for 6008) and the NIC-driver pattern of WS-EVT-NIC-LINK-DOWN against the fleet's
  actual drivers.
- Event caps: WS-EVT-APP-LOG-FLOOD reads up to 5000 events per PC per day; the SCM and DNS queries up
  to 2000. Check run time and the partial notes on noisy PCs.
- Thresholds to calibrate on the first fleet run: WMI errors (50 per 7 days fired on every PC in the
  field scan), SMB authentication failures, Schannel failures, CPU throttling (any), unexpected
  shutdowns (any), patch window (45 days; 78% of PCs had no update newer than 60 days in the field
  scan, partly the hotfix date-format gap below), hotspot SSID pattern, services.exe share (5% per
  component, fixed in the rule).
- AdminService: SMS_Scripts Author / Approver / ApprovalState (3 = approved, 0 = waiting) and the
  field comparison in SCCM-SCRIPT-SELF-APPROVED; SMS_DeploymentSummary CollectionID and the built-in
  ids SMS00001, SMS00002, SMS00004, SMSDM003; SMS_CombinedDeviceResources SiteCode really carries the
  client's assigned site (the class page describes it differently) - WSF-NO-ASSIGNED-SITE and
  SCCM-SERVER-NO-ASSIGNED-SITE are silent otherwise; SMS_G_System_SERVICE filter
  `startswith(StartName,'NT ') eq false` and the Services class enabled in hardware inventory;
  RefreshType filtered although lazy; SourceDate on SMS_DriverPackage and SMS_ImagePackage.
- SQL: LOGINPROPERTY values (sql_variant) for PasswordLastSetTime and IsLocked; VIEW SERVER STATE for
  sys.dm_tcp_listener_states and sys.dm_exec_connections; msdb read access for sysoperators,
  sysalerts and sysjobactivity; the default startup-procedure allow list (SSIS catalog, replication).

## Engine gaps - the data is readable, the engine cannot use it yet

- Hotfix dates written as d/M/yyyy or as hex FILETIME - Win32_QuickFixEngineering InstalledOn is text; WS-PATCH-NONE-RECENT and WINSRV-PATCH-NONE-RECENT parse it with invariant culture, so other formats are not judged (the finding says how many rows were not judged) and day/month swaps can misdate a row. Needs a date-format option on the condition. Source: fleet (newest update parsed with several formats).
- Fleet-wide total of unexpected local-admin memberships - count rules over a per-host protocol run per host, so there is no single number across all PCs. Per host: WS-LOCALADMIN-COUNT, WINSRV-LOCALADMIN-COUNT. Source: field (a nested group made a large number of accounts local admin on every workstation).
- Piled-up copies of any program, not only listed ones - WS-PROC-PILED-UP counts per host over a name pattern; flagging whichever program has many copies needs group-by Name. Source: fleet (piled-up programs); field.
- Program hangs and crashes per program or faulting module, and the share of PCs where one server name no longer resolves - need group-by (per host today: WS-EVT-APP-HANG, WS-EVT-APP-CRASH, WS-EVT-SMB-NAME-UNRESOLVED with the names in the sample). A `store` rule over row_seen could do it, but store rules live in a `keeper`-integration file, not in these packs. Source: fleet; review WS-LOG-013.
- Single-channel memory only where the board has a free slot - WS-MEMORY-SINGLE-MODULE counts modules per host; comparing with Win32_PhysicalMemoryArray MemoryDevices needs a cross-class join. Source: field.
- CPU share of a process since boot as one number with the share as a setting - WS-SERVICES-EXE-BUSY compares kernel and user time each against 5% of the process age through a field reference; summing the two and taking the multiplier from a setting need arithmetic. Listing the agents that run on the same PC in that finding's evidence needs a cross-query join; WS-WATCHED-AGENT-RUNNING lists them as a separate finding. Source: fleet (services.exe busy, agents vs services.exe).
- Percentages across rows (active clients %, client-check pass %, deployment success %, update compliance per collection) - needs ratios of counts or arithmetic between two fields. Interim: absolute count rules SCCM-CLIENTS-INACTIVE-MANY, SCCM-CLIENT-CHECK-FAILED-MANY. Source: cm-health WS03, WS04.
- Fixed volume free space as a percent from Win32_LogicalDisk or Win32_Volume (mount points, volumes without letters) - a field reference (FreeSpace below Size times 0.15) can express it now, but the share would be fixed in the rule, not a setting; the percent rule reads the perf class, which has drive letters only. Source: weekly WS11, review WS-DSK-002.
- Windows 11 readiness limited to Windows 10 workstations, and Windows 11 installed on unsupported hardware (bypassed check) - SMS_G_System_* rows carry only ResourceID; needs a join with the OS or device row. Today WSF-W11-* cover every inventoried device. Source: win11.
- Devices with no TPM or firmware inventory row at all - needs an anti-join of devices against SMS_G_System_TPM / SMS_G_System_FIRMWARE. Source: win11 (no inventory verdict).
- Client subnets covered by no boundary (IP subnet, range, AD site) - needs CIDR math and a join of SMS_R_System IPSubnets/IPAddresses with SMS_Boundary values. Interim: WSF-NO-AD-SITE, SCCM-BOUNDARY-NO-GROUP, SCCM-BOUNDARY-GROUP-NO-SITE-SYSTEM. Source: cm-health WS06; field (a wired subnet in no boundary and no AD site left its PCs without any content).
- Same application deployed to overlapping collections several times - needs group-by over SMS_DeploymentSummary. Source: field.
- A device that fails every application (script timeouts, process start failures) - needs a per-device error count over SMS_AppDeploymentAssetDetails. Source: field.
- Duplicate computer names or SMBIOS GUIDs in the site, software found on only one or two computers - needs group-by (SMBIOSGUID is not a documented SMS_CombinedDeviceResources property). Interim: WSF-RECORD-OBSOLETE-MANY. Source: inventory (duplicates, rare software); proposal WSF-RECORD-DUPLICATE-NAME/-SMBIOS.
- Disabled AD users still listed as the primary or last user of a computer - needs a join of SCCM user data with the directory pack. Source: inventory (disabled owners).
- Servers in no patch-ring collection - needs the tenant's ring collection IDs and a membership join (SMS_FullCollectionMembership). Source: cm-health WS08, review WS-PAT-010.
- Last software-update scan per device too old - no documented AdminService class carries it; SMS_UpdateComplianceStatus has LastStatusCheckTime per device and update, so it needs a per-device max. Source: review WS-PAT-003; field.
- Time-windowed status messages (client push failures in the last N days, DP content validation runs, task sequence runs) - SMS_StatusMessage needs a `$filter` on Time relative to now; HTTP params take no date macros. Source: cm-health WS10, WS13; field (content validation that had not run for years; no imaging through PXE for a month).
- Tenant additions to the unapproved-software and end-of-support lists in Add/Remove Programs - the server-side `$filter` cannot take a threshold, so the threshold regex can only narrow the generic list. Needs threshold-able params or a full ARP read. Source: field.
- Client version behind the site's own build, and distribution points that did not upgrade with the site - need a comparison with SMS_Site.Version (cross-query); a pattern setting edited at every upgrade drifts. Interim: SCCM-CLIENT-VERSION-UNSUPPORTED and the PC-side WS-/WINSRV-CCM-VERSION-UNSUPPORTED. Source: proposal WSF-CLIENT-VERSION-BEHIND-SITE, WS-CCM-VERSION-BEHIND, SCCM-DP-VERSION-BEHIND.
- Management point a client last used no longer exists - needs a cross-query with SMS_SystemResourceList. Source: proposal WSF-MP-STALE.
- "Client installed but service missing" as one finding - needs the registry key and the service read joined per host; alone, the key exists on every healthy client. WS-CCM-SERVICE-MISSING covers the service side. Source: proposal WS-CCM-INSTALLED-NO-SERVICE.
- Effective Windows Firewall state (policy plus local) - MSFT_NetFirewallProfile returns the local store unless a CIM operation option selects ActiveStore. Interim: WS-FW-PROFILE-OFF (local) plus WS-GPO-FIREWALL-OFF / WINSRV-GPO-FIREWALL-OFF (policy). Source: review WS-FW-001; field (a firewall-off GPO linked at the top of the domain).
- Local Administrators on localised Windows and on domain controllers - the WQL names the group "Administrators"; reading it there needs a two-step lookup by SID S-1-5-32-544. Today WS-LOCALADMIN-UNREADABLE / WINSRV-LOCALADMIN-UNREADABLE turn the empty read into a finding instead of a silent pass. Renamed built-in administrator (RID 500) needs a cross-row SID check. Source: review WS-ADM-001.
- Domain accounts nested in local Administrators through groups, and stale or never-used accounts among them - needs expansion of group members through the directory pack. Source: field.
- Domain Controllers Policy applied on member servers, Print Spooler on domain controllers - the server file targets every server OS including DCs; needs a DC / member split in targets (for example by userAccountControl). WS-GPO-DC-POLICY-APPLIED covers workstations. Source: controls DC-SPOOLER-OFF; field.
- Server not in an AD site - Win32_NTDomain also returns rows for trusted domains whose client site is empty by design; needs a filter on the computer's own domain. WSF-NO-AD-SITE covers workstations from SCCM. Source: controls DC-SUBNET, review WINSRV-AVL-007.
- Disk latency, queue length and sustained CPU load - needs several samples over time; the runner takes one snapshot. Source: review WS-DSK-005, WS-RES-002.
- Volume growth and days until full; SQL TDE "stuck for two scans" - need run-to-run history. Source: review WS-DSK-003; proposal SQL-TDE-IN-PROGRESS.
- Clock offset of a host - LocalDateTime is read during the scan but `age` is judged when the scan ends, minutes later on a large fleet, so a five-minute tolerance fires on the first hosts read. Needs the runner to stamp the read time on each row. Interim: WS-EVT-TIME-SYNC-FAIL, WINSRV-EVT-TIME-SYNC-FAIL, WINSRV-SVC-CORE-DOWN. Source: controls DC-TIME, review WS-TIM-001; proposal WS-/WINSRV-CLOCK-SKEW.
- Per-name thresholds inside one pattern, and conditions that need the chassis or the "on site" fact - laptops keep Wi-Fi up next to a dock and are on the Public network profile at home by design; telling a desktop on a hotspot or an on-site PC on VPN needs Win32_ComputerSystem.PCSystemType or the subnet's site in the same row. Source: proposal WS-NIC-WIFI-AND-WIRED, WS-NIC-VIRTUAL-UP, WS-NET-PROFILE-PUBLIC.
- A host's DNS name resolving to another address, and the hosts file - need runner-side facts (the scanner's resolution of the target) or a file read over admin$. WS-HOST-NAME-MISMATCH covers the wrong-PC case. Source: fleet (stale DNS, hosts entries).
- Unknown-reason taxonomy - per-host failures should say DNS / port / access denied / namespace missing, so "root/ccm broken" (client WMI namespace damaged) can be told from "PC off" and a store rule can count unreachable hosts as one finding. Source: proposal WS-CCM-NAMESPACE-BROKEN, WS-STORE-UNREACHABLE-MANY.

## Event logs - what the eventlog rules do not cover yet

- Shutdown initiator (User32 1074), disk 11/157 and VSS errors. Source: weekly WS15, review WS-LOG-001/003.
- KDC certificate without the KDC EKU on domain controllers. Source: field.
- DCOM floods (10016, 10010), low-privilege app container denials, diagnostic host privilege errors. Source: field (a printer driver and a sensor component flooding logs).
- Code Integrity blocks of security-product DLLs (CodeIntegrity 3033), endpoint sensor cloud failures (SENSE), auto-enrolment errors. Source: review WS-LOG-007, WS-PER-001; field.
- Security log full (1104) and the days of Security log actually held; the time span any log holds - the protocol returns events, not per-log metadata such as the oldest record. Interim: WS-EVT-APP-LOG-FLOOD (events per day). Source: review WS-LOG-010, WS-LOG-011; fleet (Application log holds less than 24 h).
- Errors per source across System and Application - the eventlog XPath takes ids and providers, not levels, so counting errors means reading every event. Source: proposal WS-EVT-ERROR-SOURCE-FLOOD.
- Defender scans during working hours - needs an hour-of-day operator. Background downloads (BITS 60) are activity, not a problem. Source: fleet (AvScan, Downloads).
- Group Policy slow-link estimates (5314/5327) and DC discovery time (5326) - event data field names are not confirmed. Source: fleet (GpBandwidthKbps, GpDcFindMs).
- Recurring and new error signatures between runs. Source: weekly WS17, WS18, review WS-LOG-009.

## Registry and settings

Read through the registry protocol (StdRegProv read methods only). Not covered yet:

- Update build revision (UBR) against the latest cumulative update per build - the read is simple; the per-build table of minimum UBRs must be a maintained setting or register before a rule can ship. Source: review WS-PAT-002; proposal WS-REG-UBR.
- WPAD - the auto-proxy service start type and the AutoDetect policy are two keys (two queries) and must both be judged; disabling the service alone breaks proxy discovery. Source: review WS-CRED-003; proposal WS-REG-WPAD.
- Schannel on workstations, client-side protocol keys and RC4 ciphers - the cipher keys are named like `RC4 128/128` and the registry runner refuses `/` in a path; protocol defaults differ by OS build (cross-class). Servers: WINSRV-REG-TLS10/TLS11/SSL3-SERVER-ON, WINSRV-REG-DOTNET-WEAK-CRYPTO. Source: facts win.hard.tls, review WS-TLS-001/002.
- Windows Update dual scan (deferral policies next to an update server without DisableDualScan) - several keys. Source: review WS-PAT-006.
- Unattend files with passwords - file reads. Source: review WS-SEC-001.
- Defender for Endpoint cloud connectivity, including TLS interception that breaks pinned security agents. Source: review WS-EDR-002; field.
- No application control at all (neither App Control nor AppLocker enforced) - needs the Device Guard state and the AppLocker rule subkeys of one host together; audit-only of each is covered. Source: review WS-APC-001; field.
- Browser policies - a PAC URL check needs the tenant's URL; forced extensions are values named 1..n, which a condition cannot address without a wildcard over value names; per-user settings need the console user's SID (HKU) from another query. Source: fleet (browser and proxy facts); proposal WS-REG-BROWSER-*.

## Group Policy content and user rights

- GPOs that add groups to local Administrators (preference items, restricted groups), competing local-admin policies, and disabled-but-linked GPOs that would add every domain user if re-enabled - needs SYSVOL parsing (belongs with the directory pack). Source: field.
- Logon scripts that add accounts to local Administrators - needs NETLOGON file parsing. Source: field.
- User policy that blocks command prompt or PowerShell for everyone - lives in root/rsop/user per user SID. Source: field.
- Effective user rights (who holds 'Log on as a batch job', 'Log on as a service', 'Load and unload device drivers', 'Profile system performance') - RSOP_UserPrivilegeRight lists SIDs or names; needs well-known SID macros. Service logon failures after a right was removed show in WS-/WINSRV-EVT-SERVICE-FAIL (7038/7041). Source: field.
- Full security-baseline comparison (hundreds of settings, most not configured) - needs a baseline import and per-setting compare. Source: field.
- Corrupt registry.pol files in GPOs - needs SYSVOL file parsing. Source: field.

## Scheduled tasks

- Tasks that store a user password, run from user-writable paths, run elevated as privileged accounts, or fail on their last run (including logon-type failures after a logon right was removed) - MSFT_ScheduledTask returns the principal as an embedded instance and last-run data only through a method. The health-evaluation task is judged indirectly through CcmEval's last run (WS-/WINSRV-CCM-EVAL-*). Source: weekly WS13, controls SRV-TASKS, review WS-TSK-001..004; field.
- Tasks piling up right after boot - needs task run history. Source: field.

## Configuration Manager - lazy or site-control data, logs and client side

- Network Access Account configured, HTTPS / Enhanced HTTP state, DP content-validation schedule, distribution manager thread limits, automatic client upgrade settings - stored in site control Props / PropLists or lazy properties that a list read does not return. Source: cm-health WS09, WS12, WS13; field (upgrade prerequisite warnings about the access account ignored; default distribution threads during monthly content).
- Windows 11 OS image or upgrade package present on the site - the image's OS version is in a lazy XML property (ImageProperty). Source: field.
- Task sequence references to applications that are no longer deployed, and the policy failures they cause every cycle - needs the task sequence reference list joined with application deployments. Source: field.
- Automatic deployment rules scheduled before the monthly sync - needs the rule's schedule token (lazy) and the sync schedule. Source: field.
- Site database tables that grew to most of the database - needs the site database name in a rule or per-database iteration in the SQL runner. Source: field.
- Client-side problems visible only in logs or CMPivot: policy lookups failing with "not found", inventory larger than the size limit resent in a loop, client certificate mismatch, content download timeouts, components hung in a child process, state-message and inbox files parked or corrupt. Source: field.
- Client check details per test - the site keeps ccmeval's per-test results, but the AdminService class name (SMS_CH_EvalResults) and its result codes are not confirmed. Source: proposal WSF-CLIENT-CHECK details.
- Boundary groups per client - a BoundaryGroups property is not in the documented SMS_CombinedDeviceResources class. Source: proposal WSF-NO-BOUNDARY-GROUP.
- Client PKI certificate state - machine certificates are not readable over CIM and the client logs certificate failures only to its own log files. Source: proposal WS-CCM-PKI-CERT.
- Whether local administrators may override the client's site assignment (SMS_Client.AllowLocalAdminOverride) - the default value is not confirmed; if it is true by default the rule would fire on every client. Source: proposal WS-CCM-LOCAL-OVERRIDE.
- Cache crowding - the space used needs a sum of CacheInfoEx ContentSize; a row count is not a fault. Source: proposal WS-CCM-CACHE-CROWDED.
- Unquoted service paths from hardware inventory - without a server-side filter that drops Windows-folder paths (backslash escaping and OData functions untested on AdminService) the read returns most services of every device. The live WS-/WINSRV-SVC-UNQUOTED-PATH cover reachable hosts. Source: proposal WSF-SVC-UNQUOTED-PATH.
- Distribution points that stopped reporting - LastStatusTime only moves when content changes, so an idle DP looks stale. Source: proposal SCCM-DP-STATUS-STALE.
- WSUS database maintenance and application pool settings - needs the WSUS API or IIS configuration. Source: field.
- Local group membership from hardware inventory - no default inventory class holds it; needs a custom class. Source: field.
- Store apps, per-user installs (AppData) and installers left in user folders - Add/Remove Programs inventory covers machine-wide installs only. Interim: WS-PROC-UNAPPROVED. Source: field (messaging apps installed per user or from the Store).
- Antivirus removal blocked by product passwords - vendor console only. Source: field.

## SQL Server - per database, registry or build table

- Guest CONNECT in user databases, orphaned users, SQL authentication in contained databases, CLR assemblies not SAFE, weak symmetric or asymmetric key algorithms, log space use per database - need the SQL runner to iterate databases. Source: CIS-MSSQL 3.2, 3.3, 3.4, 6.2, 7.1, 7.2.
- Number of error log files, login auditing level, Force Encryption, hidden instance and the SQL Browser service - stored in the registry of the SQL host or outside sys.dm_server_services (which lists the engine, Agent, Full-Text and Launchpad only). Interim for Force Encryption: SQL-CONNECTIONS-UNENCRYPTED. Source: CIS-MSSQL 2.12, 5.1, 5.3; proposal SQL-BROWSER-RUNNING.
- Latest cumulative update per version as a maintained table - SQL-BUILD-OLD ships floors (2016 SP3, 2017 final CU, 2019 CU32, 2022 CU25) that must be raised by hand as CUs ship. Source: field (an instance many updates behind).

## Other integrations

- Server protected by a backup job, monitored by the monitoring platform, onboarded to EDR - backup, monitoring and EDR integrations. Source: controls SRV-BACKUP, SRV-MONITOR, SRV-EDR.
- Host unreachable over WinRM - reported as unknown per target in coverage, not as a finding. Source: controls SRV-REACH; field (WinRM refused on many workstations).
- Certificates in the LocalMachine stores (expiring, weak, self-signed RDP) - not exposed by WMI; listeners are covered by the tls pack. Source: review WS-CRT-001..004.
- Share and NTFS permissions - needs security-descriptor methods. Source: review WS-SHR-001, WS-SHR-002.
- Failover cluster node and resource state (root/MSCluster) - needs testing for rights and authentication level before a rule ships. Source: review WS-SVC-005.
- Fleet-wide groupings - DNS server sets, gateways per subnet, newest update per OS build, unreachable hosts as one finding - are `store` rules over row_seen and belong in a `keeper`-integration file, not these packs; the per-OS-build patch table also waits for the hotfix date gap. Source: fleet; proposal WS-STORE-DNS-SERVER-SETS, WS-STORE-PATCH-BY-BUILD.

## Proposals not taken, with the reason

- WS-REG-SMB1-CLIENT - duplicate of WS-SMB1-CLIENT-DRIVER (same driver, registry view).
- WS-CCM-CACHE-MOVED - informational, no action follows.
- WS-NIC-POWER-SAVING - keywords and values are vendor-specific and Energy Efficient Ethernet is on by default on many NICs; only the standard *SpeedDuplex keyword is judged (WS-NIC-SPEED-FORCED).
- WS-DNS-SUFFIX-MISSING - needs the tenant's suffix and has no generic failing condition.
- WS-REG-PROXY-PER-MACHINE - per-user proxy settings are the Windows default, not a fault.
- WS-AGENT-VERSION-OLD, WS-BROWSER-VERSION-OLD - the CIM_DataFile path cannot come from a setting, and version floors need a maintained table.
- WS-PROFILE-STALE by LastUseTime - the date is refreshed by background activity on current Windows; the profile count (WS-PROFILES-MANY) is used instead.
- WSF-CLIENT-REMEDIATION-FAILED - duplicate of WSF-CLIENT-CHECK-FAILED; the remediation result is in SCCM-SERVER-CLIENT-CHECK-FAILED's evidence.
- SCCM-RBAC-SCOPE-ALL - covered by SCCM-RBAC-FULLADMIN-USER.
- WS-SERVICES-EXE-BUSY on formatted performance counters - rate counters read as zero on a single remote query; the rule uses process CPU times instead.

## Windows servers - legacy checks still not expressible (added 2026-10-21 alongside the windows-server.yaml expansion)

- Scheduled-task risk (password-stored tasks, tasks run from user-writable paths, tasks run elevated as privileged accounts) - MSFT_ScheduledTask returns the Principal and Actions as embedded instances that WQL cannot flatten into row fields, and last-run data comes only through a method. The health-evaluation task is judged indirectly through CcmEval (WINSRV-CCM-EVAL-*). Source: controls SRV-TASKS, review WS-TSK-001..004; legacy WINSRV-LOG-007/008.
- Service recovery/restart actions and triggered-start configuration - Win32_Service exposes neither the failure-action list nor service triggers, so a critical service left with no restart action cannot be read. Source: review; field.
- Effective (merged policy + local) firewall state and per-profile allow rules - MSFT_NetFirewallProfile returns the local store unless a CIM operation option selects the ActiveStore; WINSRV-FW-PROFILE-OFF/-INBOUND-ALLOW/-LOGGING-OFF read local, WINSRV-GPO-FIREWALL-OFF reads policy, but there is no one effective view. Source: review WS-FW-001.
- Pending computer rename / pending domain join - ComputerName vs ActiveComputerName live under two sibling registry keys, and the registry protocol reads one key per query, so the two cannot be compared in one rule. Source: field.
- Event-log retention mode (OverwritePolicy = Never on a sized-but-full log, AutoBackupLogFiles) and the actual time span a log holds - the size floor is covered (WINSRV-EVENTLOG-SMALL, WINSRV-REG-SECURITY-LOG-SIZE); retention behaviour and oldest-record age are not exposed as flat per-log metadata. Source: review WS-LOG-010/011.
- Share and NTFS permissions on servers - owned by file-shares.yaml (smb protocol, security-descriptor methods); the windows-server pack deliberately adds no share-ACL rules to avoid duplication. Source: coordination note.
- Unexpected / non-Microsoft root CA certificates in the LocalMachine Root store - readable through the registry certificates view, but "unexpected" has no generic failing condition; it needs a tenant allow-list of approved thumbprints or issuers (a required threshold) before a rule can ship without flagging every built-in Microsoft root. The machine personal (MY) store is now covered for expiry, weak keys and SHA-1 (WINSRV-CERT-MACHINE-*). Source: review WS-CRT-001..004.
- mDNS enabled (DNSClient EnableMDNS) and SMB server-side encryption not required (MSFT_SmbServerConfiguration EncryptData / RejectUnencryptedAccess) - both readable, left out because the secure value is tenant-dependent (requiring SMB encryption breaks legacy clients) and would be noisy as a generic default. Candidates for a tenant-gated rule. Source: field.
- WinRM listener bound to HTTP without HTTPS, and 'Allow remote server management through WinRM' scope (TrustedHosts, IPv4/IPv6 filters) - the listener and filter config is not reliably exposed through StdRegProv value reads; WINSRV-REG-WINRM-SERVICE-INSECURE / -CLIENT-INSECURE cover Basic/Digest/unencrypted. Source: field.
- BitLocker protection state on server OS volumes (Win32_EncryptableVolume ProtectionStatus) - readable via root/CIMV2/Security/MicrosoftVolumeEncryption, left out of the generic pack because many datacentre servers rely on physical security and would flag as a blanket false positive; a tenant that mandates server BitLocker should enable it as a tenant rule. Source: field.

## SCCM legacy catalogue - checks still not expressible (added 2026-10-21 alongside the sccm.yaml +19 AdminService expansion)

The sccm.yaml pack was expanded with 19 generic AdminService rules (in-console update available, no-client / obsolete / unsupported-client-OS counts, update deployment past deadline / unknown-high / ancient / no-targets, expired update still deployed, empty boundary group, collection limited to All Systems, unsupported console, site error-status burst, client-push error burst, excessive maintenance retention, stale client-check / policy / no-assigned-site counts, Full Admin to a privileged directory group). The rest of the legacy catalogue (checks-SCCM.csv, ~270 rows) stays out for these reasons:

### Needs server-side access the sccm integration does not have (WINRM / SMB / Get-WinEvent / IIS / perf counters / registry on the site server or a client)
- Core site services running and Automatic, site-server CPU/memory/disk-latency, uptime and pending reboot, inbox and corrupt/bad-file backlog, NO_SMS_ON_DRIVE markers, content-library size and orphaned content, IIS 5xx rates, SUP/MP in-process HTTP probes, site-server event-log availability and crashes. The sccm type offers only AdminService (http) and the site DB (sql); none of this is a provider class or a site-DB table. The site server itself is reachable as a `cim`/`eventlog`/`registry` target through windows-server.yaml. Source: cm-health SCCM-HLT-002/006/007/008/009/010/017, SCCM-LOG-002/003/010/023, SCCM-AVL-004.
- WCM/distmgr/colleval/dataldr/adsysdis/SMSPXE/smsbkup log parsing - the error counts live in logs on the server, not in a class; the AdminService half (SMS_StatusMessage) is covered generically by SCCM-STATUS-ERRORS-MANY and SCCM-CLIENT-PUSH-ERRORS-MANY. Source: SCCM-LOG-005/006/007/009/015/016/017/018/021, SCCM-BCK-002.

### Needs the site database by name (CM_<sitecode>) or duplicates sql-server.yaml
- The site's SQL instance (max/min memory headroom, tempdb file layout, build/CU and major-version support, SQL error log, Agent job and operator health, backup history in msdb, CHECKDB, recovery model, server-role membership, logins and auth mode, MAXDOP) is read generically by rules/sql-server.yaml as a `sql` integration target (SQL-OS-MEMORY-LOW, SQL-TEMPDB-FILES, SQL-BUILD-OLD, SQL-VERSION-EOS, SQL-AGENT-JOB-*, SQL-BACKUP-*, SQL-DB-CHECKDB-OLD, SQL-SYSADMIN-MANY, SQL-CFG-MAXDOP-UNSET, ...). Adding them to the sccm pack would double-count. Source: SCCM-HLT-011..014, SCCM-LCM-012/013, SCCM-LOG-012/013, SCCM-IAM-014/015/016, SCCM-BCK-005/006/008/009, SCCM-MON-009, SCCM-CFG-047/048/049, SCCM-CST-003/006.
- Site-database bloat (largest tables, the MPE_RequestMessagesHistory purge, SUSDB/ReportServer sizes, storage reclaim) needs the CM_<sitecode> and SUSDB/ReportServer database names, which are tenant-specific; a generic rule cannot name them, and `databases: all` would run CM-only views in every database and fail. Needs a tenant threshold for the site-DB name. Source: SCCM-HLT-013/015, SCCM-LCM-003 (per-collection), SCCM-CST-006.

### Needs site-control or client-setting properties the AdminService list read does not return (lazy Props/PropLists, Get-CMClientSetting, Get-CMAccount, SDMPackageXML)
- Network Access Account, HTTPS/Enhanced HTTP state, message signing/SHA-256, client approval method, NTLM-fallback and site-wide-push scope, PXE/boot-image command support, automatic client upgrade and pre-production promotion, discovery method scope and schedules, all client-settings bodies (policy polling, hardware/software inventory classes and Max MIF, software-updates, restart/notification, remote tools, PowerShell execution policy), maintenance windows (SMS_CollectionSettings ServiceWindows), SUP sync schedule/languages/supersedence, DP PXE/validation/rate-limit settings, co-management workloads and enrolment, antimalware policy ownership, detection/requirement rules in SDMPackageXML. These are lazy properties or console-cmdlet reads, not flat list fields. Source: SCCM-LCM-006, SCCM-AUT-001..011/020..022, SCCM-CFG-004..007/010..018/020/023/025/026/033/037/039/040/041/043/044/052, SCCM-IAM-006/008/009/018/019/021, SCCM-AVL-016/018, SCCM-MON-011.

### Needs a join or group-by the engine does not do in one http protocol
- Subnets/clients in no qualifying boundary (CIDR math + join of SMS_R_System IP data with SMS_Boundary/BoundaryGroup/Members), content present for every active Required deployment (deployment x content-status join), duplicate device records / SMBIOS GUIDs / duplicate hardware IDs, same software deployed to overlapping collections, a device that fails every application, driver/OS-image coverage per fleet model, task-sequence reference validity, unused applications/packages, servers in no patch ring, update compliance per collection, patch-ring pilot-first design. All need a second query joined or a group-by. Interim coverage: SCCM-BOUNDARY-NO-GROUP, SCCM-BOUNDARY-GROUP-NO-SITE-SYSTEM, SCCM-BOUNDARY-GROUP-EMPTY, SCCM-DEPLOYMENT-TO-ALL-SYSTEMS, SCCM-COLLECTION-LIMITED-TO-ALL-SYSTEMS. Source: SCCM-AVL-006/007/010, SCCM-CFG-001/002/003/022/030/036/038, SCCM-HYG-006/008, SCCM-LCM-019, SCCM-CST-001.

### Classes not yet confirmed on a live AdminService, or no generic failing condition
- Co-management / tenant-attach cloud service state (SMS_AzureService, SMS_CoMgmt* - class names and enabled-by-default values unconfirmed; "should have a CMG" is tenant policy, not a generic fault), Management Insights results (SMS_ManagementInsightResult), configuration baselines non-compliant (SMS_ConfigurationBaselineInfo), programs that run as admin and allow user interaction (SMS_Program ProgramFlags bit values unverified), Run Scripts / CMPivot execution audit, alert subscriptions by a monitored mailbox, DP that stopped reporting (SMS_DPStatusInfo LastStatusTime only moves on content change, so an idle DP looks stale - false positives). Confirm the class, fields and a non-noisy threshold on a live site first. Source: SCCM-AVL-017, SCCM-AUT-013, SCCM-CFG-045, SCCM-MON-001/007/008, proposal SCCM-DP-STATUS-STALE.

### Attestation or another integration, not SCCM data
- Passive site server / measured rebuild time, site recovery runbook and last restore test, SSRS encryption-key backup, CD.Latest present, VM-level and off-box backup of the site server, estate monitoring/EDR coverage of the site server, client/server/ESU/SQL licence coverage, open SCCM requests and TODO/toolkit-run tracking. These are attestations, backup/monitoring-integration reads, or workspace file reads. Source: SCCM-AVL-003, SCCM-BCK-003/004/007/011/012/013/014, SCCM-MON-004/010/012/013, SCCM-CST-001/002/004/005, SCCM-HYG-014/015/016/019.

### First-run checklist for the new rules
- SMS_CM_UpdatePackages State values (262146 available, 327682 ready to install, 196612 installed) and DateReleased - SCCM-INCONSOLE-UPDATE-AVAILABLE.
- SMS_StatusMessage Time with the {DAYS_AGO:n} macro in a server-side $filter, Severity -1073741824 for Error, and Component eq 'SMS_CLIENT_CONFIG_MANAGER' - SCCM-STATUS-ERRORS-MANY, SCCM-CLIENT-PUSH-ERRORS-MANY (the earlier "HTTP params take no date macros" note is now out of date; the engine expands {DAYS_AGO:n}).
- SMS_SCI_SQLTask DeleteOlderThan (days) and TaskName spelling of the delete-aged tasks - SCCM-MAINT-RETENTION-EXCESSIVE.
- SMS_Collection LimitToCollectionID carries the built-in All Systems id SMS00001 - SCCM-COLLECTION-LIMITED-TO-ALL-SYSTEMS.
- SMS_DeploymentSummary FeatureType 5 = software update, NumberUnknown present, EnforcementDeadline/CreationTime are dates - SCCM-UPDATE-DEPLOYMENT-PAST-DEADLINE, SCCM-DEPLOYMENT-UNKNOWN-HIGH, SCCM-DEPLOYMENT-NO-TARGETS, SCCM-UPDATE-DEPLOYMENT-ANCIENT.
- SMS_ConsoleAdminsData ConsoleVersion / LastConnectedConsoleTime - SCCM-CONSOLE-VERSION-UNSUPPORTED (pattern required:true until the tenant sets the unsupported-console-build regex).
- SMS_CombinedDeviceResources DeviceOS pattern (required:true) for the unsupported-client-OS list - SCCM-CLIENT-OS-CLIENT-UNSUPPORTED.
- SMS_Admin RoleNames contains 'Full Administrator' and the privileged-group name pattern (Domain Admins / Enterprise Admins / \Administrators) - SCCM-RBAC-FULLADMIN-PRIVILEGED-GROUP.

## Windows workstations - client checks still not expressible (added 2026-10-21 alongside the workstations.yaml +24 expansion)

The pack gained 24 generic client rules: TPM readiness and BitLocker AD escrow policy (WS-TPM-NOT-READY, WS-REG-BITLOCKER-NO-ESCROW); Defender ASR / controlled folder access / sample submission (WS-DEFENDER-ASR-OFF, WS-DEFENDER-CFA-OFF, WS-DEFENDER-SAMPLE-SUBMISSION-OFF); default-allow firewall inbound (WS-FW-INBOUND-ALLOW); Windows Update AU-disabled and over-long quality-update deferral/pause (WS-REG-WU-AU-DISABLED, WS-REG-WU-DEFERRAL-LONG); screen-lock inactivity, AutoRun, SmartScreen, removable-storage policy (WS-REG-INACTIVITY-TIMEOUT, WS-REG-AUTORUN-ON, WS-REG-SMARTSCREEN-OFF, WS-REG-REMOVABLE-STORAGE-UNRESTRICTED); LAPS and built-in administrator (WS-REG-LAPS-NOT-CONFIGURED, WS-BUILTIN-ADMIN-ENABLED, WS-BUILTIN-ADMIN-NOT-RENAMED); PowerShell logging (WS-REG-PS-SCRIPTBLOCK-OFF, WS-REG-PS-MODULE-LOGGING-OFF, WS-REG-PS-TRANSCRIPTION-OFF); anonymous enumeration, Point and Print, time sync (WS-REG-ANON-ENUM, WS-REG-POINTANDPRINT-WEAK, WS-REG-W32TIME-NOSYNC); and the machine personal certificate store (WS-CERT-MACHINE-EXPIRING, WS-CERT-MACHINE-WEAK-KEY, WS-CERT-MACHINE-SHA1). The rest stays out for these reasons:

- Office macro hardening (VBAWarnings, BlockContentExecutionFromInternet, block of macros from the internet) lives per-user under HKCU\Software\Policies\Microsoft\office\<ver>\<app>\Security and per Office version, so it needs the console user's SID (HKU) and a version-specific path, the same limit as the per-user browser policies above. Source: review WS-OFF-001; field.
- BitLocker key protector type (TPM, TPM+PIN, recovery-password-only, external key) comes only from the GetKeyProtectors / GetKeyProtectorType methods on Win32_EncryptableVolume; WQL reads properties only, so a drive "encrypted but protected by a bare password" cannot be told from a TPM-bound one. WS-BITLOCKER-OS-OFF / -DATA-OFF cover protection status and WS-REG-BITLOCKER-NO-ESCROW covers the AD escrow policy. Source: field; proposal WS-BITLOCKER-PROTECTOR-TYPE.
- Legacy Microsoft LAPS (SOFTWARE\Policies\Microsoft Services\AdmPwd AdmPwdEnabled) is a second registry key that cannot be OR-ed with modern Windows LAPS (SOFTWARE\Microsoft\Policies\LAPS BackupDirectory) in one query; WS-REG-LAPS-NOT-CONFIGURED reads the modern key only, so an estate still on legacy LAPS would show a false positive until it migrates. Source: field (local admin managed by GPO VBS, LAPS state unknown).
- Removable-storage read/write deny under the per-class GUID subkey ({53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\Deny_Write and siblings) is a separate key from the top-level Deny_All that WS-REG-REMOVABLE-STORAGE-UNRESTRICTED reads; a per-class write-only deny would be missed, and the whole rule is a candidate for tenant gating where USB storage is permitted. Source: field.
- Scheduled-task risk and client-side Schannel/TLS protocol and cipher keys are the same limits already recorded in the server section and the Registry and settings section above (embedded MSFT_ScheduledTask instances; the registry runner refuses `/` in cipher key names; protocol defaults differ by build).

### First-run checklist for the new workstation rules
Names and values below are from documentation or field use, not yet read from a live host; confirm each on a sample (a wrong name makes the query fail - visible in coverage - or the rule silent):
- CIM: Win32_Tpm (root/cimv2/Security/MicrosoftTpm) IsEnabled_InitialValue / IsActivated_InitialValue / SpecVersion, and that a PC with no TPM returns no row (WS-TPM-NOT-READY); MSFT_MpPreference AttackSurfaceReductionRules_Ids and _Actions as arrays, EnableControlledFolderAccess (1 block/2 audit/0 off), SubmitSamplesConsent (2 = never send) (WS-DEFENDER-ASR-OFF/-CFA-OFF/-SAMPLE-SUBMISSION-OFF); MSFT_NetFirewallProfile DefaultInboundAction value 2 = Allow (WS-FW-INBOUND-ALLOW); built-in Administrator read by RID-500 SID over the LocalAccount=TRUE query without a Domain filter (WS-BUILTIN-ADMIN-ENABLED/-NOT-RENAMED).
- Registry: FVE OSActiveDirectoryBackup (1 = escrow to AD; Intune/Entra escrow is not in this value) (WS-REG-BITLOCKER-NO-ESCROW); WindowsUpdate DeferQualityUpdatesPeriodInDays and PauseQualityUpdatesStartTime (WS-REG-WU-DEFERRAL-LONG); Policies\System InactivityTimeoutSecs (seconds) and EnableSmartScreen; Policies\Explorer NoDriveTypeAutoRun 255; RemovableStorageDevices Deny_All; Microsoft\Policies\LAPS BackupDirectory (0 none/1 Entra/2 AD); PowerShell\{ScriptBlockLogging,ModuleLogging,Transcription} enable values; SystemCertificates\MY through the certificates view, self-signed excluded from expiry (WS-CERT-MACHINE-*).
