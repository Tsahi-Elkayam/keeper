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

- Validator: `artifacts\validator\keeper-rules.exe` (built 2026-10-20 16:14) predates the registry
  protocol's `path:` field and field-reference values. It refuses every registry rule ("key is
  required") and WS-SERVICES-EXE-BUSY ("needs a number"); the newer debug build accepts the registry
  rules. Rebuild the validator, then validate the whole folder again.
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
