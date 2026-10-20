# Backlog - Windows estate (SCCM, workstations, servers, SQL Server)

Checks that `rules/sccm.yaml`, `rules/workstations-sccm.yaml`, `rules/workstations.yaml`,
`rules/windows-server.yaml` and `rules/sql-server.yaml` cannot express yet. One line each: the
check, what it needs, and where it came from.

Source labels: `cm-health` = the legacy Configuration Manager health check (check id WS01-WS14),
`win11` = the legacy Windows 11 readiness report, `fleet` = the legacy fleet-slowness scan (health
checks and event signals), `weekly` = the legacy weekly report plugins (WS11-WS18, DB01-DB07),
`inventory` = the legacy inventory-portal report rules, `controls` = the legacy control catalogue
(SRV-*, DC-*), `facts` = the legacy server fact types, `review` = the legacy server expert check list
(item id), `field` = a problem seen in a real estate, described generically.

## Engine gaps - the data is readable, the engine cannot use it yet

- Hotfix dates written as d/M/yyyy or as hex FILETIME - Win32_QuickFixEngineering InstalledOn is text; WS-PATCH-NONE-RECENT and WINSRV-PATCH-NONE-RECENT parse it with invariant culture, so other formats are not judged (the finding says how many rows were not judged) and day/month swaps can misdate a row. Needs a date-format option on the condition. Source: fleet (newest update parsed with several formats).
- Fleet-wide total of unexpected local-admin memberships - count rules over a per-host protocol run per host, so there is no single number across all PCs. Per host: WS-LOCALADMIN-COUNT, WINSRV-LOCALADMIN-COUNT. Source: field (a nested group made a large number of accounts local admin on every workstation).
- Piled-up copies of any program, not only listed ones - WS-PROC-PILED-UP counts per host over a name pattern; flagging whichever program has many copies needs group-by Name. Source: fleet (piled-up programs); field.
- Single-channel memory only where the board has a free slot - WS-MEMORY-SINGLE-MODULE counts modules per host; comparing with Win32_PhysicalMemoryArray MemoryDevices needs a cross-class join. Source: field.
- CPU share of a process since boot (services.exe pinned by an agent) - needs arithmetic (KernelModeTime + UserModeTime over uptime); formatted perf counters are instantaneous and often empty remotely. Source: fleet (services.exe busy), field.
- Percentages across rows (active clients %, client-check pass %, deployment success %, update compliance per collection) - needs ratios of counts or arithmetic between two fields. Interim: absolute count rules SCCM-CLIENTS-INACTIVE-MANY, SCCM-CLIENT-CHECK-FAILED-MANY. Source: cm-health WS03, WS04.
- Fixed volume free space as a percent from Win32_LogicalDisk or Win32_Volume (mount points, volumes without letters) - needs field arithmetic (FreeSpace / Size); the percent rule reads the perf class, which has drive letters only. Source: weekly WS11, review WS-DSK-002.
- Windows 11 readiness limited to Windows 10 workstations, and Windows 11 installed on unsupported hardware (bypassed check) - SMS_G_System_* rows carry only ResourceID; needs a join with the OS or device row. Today WSF-W11-* cover every inventoried device. Source: win11.
- Devices with no TPM or firmware inventory row at all - needs an anti-join of devices against SMS_G_System_TPM / SMS_G_System_FIRMWARE. Source: win11 (no inventory verdict).
- Client subnets covered by no boundary (IP subnet, range, AD site) - needs CIDR math and a join of SMS_R_System IPSubnets/IPAddresses with SMS_Boundary values. Interim: WSF-NO-AD-SITE, SCCM-BOUNDARY-NO-GROUP, SCCM-BOUNDARY-GROUP-NO-SITE-SYSTEM. Source: cm-health WS06; field (a wired subnet in no boundary and no AD site left its PCs without any content).
- Same application deployed to overlapping collections several times - needs group-by over SMS_DeploymentSummary. Source: field.
- A device that fails every application (script timeouts, process start failures) - needs a per-device error count over SMS_AppDeploymentAssetDetails. Source: field.
- Duplicate computer names in the site, software found on only one or two computers - needs group-by. Source: inventory (duplicates, rare software).
- Disabled AD users still listed as the primary or last user of a computer - needs a join of SCCM user data with the directory pack. Source: inventory (disabled owners).
- Servers in no patch-ring collection - needs the tenant's ring collection IDs and a membership join (SMS_FullCollectionMembership). Source: cm-health WS08, review WS-PAT-010.
- Last software-update scan per device too old - no documented AdminService class carries it; SMS_UpdateComplianceStatus has LastStatusCheckTime per device and update, so it needs a per-device max. Source: review WS-PAT-003; field.
- Time-windowed status messages (client push failures in the last N days, DP content validation runs, task sequence runs) - SMS_StatusMessage needs a `$filter` on Time relative to now; HTTP params take no date macros. Source: cm-health WS10, WS13; field (content validation that had not run for years; no imaging through PXE for a month).
- Tenant additions to the unapproved-software and end-of-support lists in Add/Remove Programs - the server-side `$filter` cannot take a threshold, so the threshold regex can only narrow the generic list. Needs threshold-able params or a full ARP read. Source: field.
- Effective Windows Firewall state (policy plus local) - MSFT_NetFirewallProfile returns the local store unless a CIM operation option selects ActiveStore. Interim: WS-FW-PROFILE-OFF (local) plus WS-GPO-FIREWALL-OFF / WINSRV-GPO-FIREWALL-OFF (policy). Source: review WS-FW-001; field (a firewall-off GPO linked at the top of the domain).
- Local Administrators on localised Windows and on domain controllers - the WQL names the group "Administrators"; reading it there needs a two-step lookup by SID S-1-5-32-544. Today WS-LOCALADMIN-UNREADABLE / WINSRV-LOCALADMIN-UNREADABLE turn the empty read into a finding instead of a silent pass. Renamed built-in administrator (RID 500) needs a cross-row SID check. Source: review WS-ADM-001.
- Domain accounts nested in local Administrators through groups, and stale or never-used accounts among them - needs expansion of group members through the directory pack. Source: field.
- Domain Controllers Policy applied on member servers, Print Spooler on domain controllers - the server file targets every server OS including DCs; needs a DC / member split in targets (for example by userAccountControl). WS-GPO-DC-POLICY-APPLIED covers workstations. Source: controls DC-SPOOLER-OFF; field.
- Server not in an AD site - Win32_NTDomain also returns rows for trusted domains whose client site is empty by design; needs a filter on the computer's own domain. WSF-NO-AD-SITE covers workstations from SCCM. Source: controls DC-SUBNET, review WINSRV-AVL-007.
- Disk latency, queue length and sustained CPU load - needs several samples over time; the runner takes one snapshot. Source: review WS-DSK-005, WS-RES-002.
- Volume growth and days until full - needs run-to-run history. Source: review WS-DSK-003.
- Clock offset against the domain hierarchy - needs a time comparison between hosts. Interim: WINSRV-SVC-CORE-DOWN covers a stopped time service. Source: controls DC-TIME, review WS-TIM-001.

## Event logs - no event-log protocol in these packs yet

- Unexpected shutdowns, bugchecks and their initiator (Kernel-Power 41, EventLog 6008, BugCheck 1001, User32 1074). Source: weekly WS15, review WS-LOG-001.
- Disk, controller, NTFS and VSS errors (disk 7/11/51/153/157, storport 129, Ntfs 55/98). Source: weekly WS15, review WS-LOG-003.
- Service crashes and start failures, service logon failures after logon-right changes (SCM 7000-7043, 7038/7041), service shutdown timeouts. Source: review WS-LOG-002; field (logon rights removed estate-wide by a hardening project; agent services timing out at shutdown).
- Domain controller discovery and secure-channel errors (NETLOGON 5719 and similar), Kerberos errors (Kerberos 4 duplicate SPN, KDC certificate without the KDC EKU). Source: review WS-LOG-004; field.
- Group Policy processing errors and policy silence, including GPOs that reference servers that no longer exist (scripts, wallpaper, registry paths). Source: fleet (GP silence), review WS-LOG-006; field.
- WMI throttling and provider errors (WMI-Activity 5858) and the callers behind them. Source: field.
- Log floods (one source filling the Application log within hours), DCOM floods, low-privilege app container denials, diagnostic host privilege errors. Source: fleet (App-log span); field (a printer driver and a sensor component flooding logs).
- Firmware CPU throttling (Kernel-Processor-Power 37). Source: field.
- Windows Installer reconfigure loops at every boot (MsiInstaller 1035/1040/11722). Source: field.
- SMB client errors to dead or misspelled server names (SMBClient 31001). Source: field.
- Code Integrity blocks of security-product DLLs (CodeIntegrity 3033), endpoint sensor cloud failures (SENSE), Schannel and auto-enrolment errors. Source: review WS-LOG-007, WS-PER-001; field.
- Security log full or cleared (1102, 1104) and days of Security log actually held. Source: review WS-LOG-010, WS-LOG-011.
- Recurring and new error signatures between runs. Source: weekly WS17, WS18, review WS-LOG-009.
- Application crashes and hangs grouped by faulting module. Source: review WS-LOG-013; field.

## Registry and settings that are not delivered by Group Policy

Registry reads over CIM need StdRegProv methods, which the CIM runner never calls. Values set by GPO
are covered through RSoP (RSOP_RegistryPolicySetting, RSOP_RegistryValue) where a rule exists.

- Pending reboot (CBS RebootPending, Windows Update RebootRequired, PendingFileRenameOperations). Interim: SCCM-CLIENT-RESTART-PENDING, WINSRV-CCM-UPDATE-RESTART-WAIT. Source: weekly WS14, fleet; field (hundreds of queued file renames on a PC every tool called clean; a site server whose upgrade prerequisite failed on a pending reboot).
- Update build revision (UBR) against the latest cumulative update per build - needs the registry and a monthly table. Source: review WS-PAT-002.
- UAC and elevation values set locally or by an image (EnableLUA, ConsentPromptBehaviorAdmin) - only GPO-set values are visible (WS-GPO-UAC-WEAK). Source: field.
- LLMNR, NetBIOS node type, WPAD, WDigest caching, LSA protection, cached logon count, hardened UNC paths. Source: review WS-SMB-004, WS-CRED-001..003.
- TLS and Schannel protocols and ciphers, .NET strong crypto. Source: facts win.hard.tls, review WS-TLS-001/002.
- SMB1 client driver start type, WinRM Basic and unencrypted settings, CredSSP. Source: review WS-SMB-001, WS-WRM-001.
- Kerberos encryption types allowing RC4 when set locally (RC4 removal tried on a test OU only). Source: facts win.hard.kerberosRc4; field.
- Windows Update source (WSUS URL scheme, dual scan). Source: review WS-PAT-006.
- Automatic logon with a stored password (DefaultPassword present), unattend files with passwords. Source: review WS-SEC-001.
- Secure Boot certificate update status (UEFI CA 2023). Source: review WS-PAT-011; field (a Secure Boot update task delaying every boot).
- Defender for Endpoint onboarding state and cloud connectivity, including TLS interception that breaks pinned security agents. Source: review WS-EDR-002; field.
- Application control enforcement (AppLocker or WDAC policy present and enforced) - the AppIdentity service state alone is no proof. Source: review WS-APC-001; field.
- Security event log maximum size - Win32_NTEventlogFile needs SeSecurityPrivilege for the Security log. Source: review WS-LOG-010.

## Group Policy content and user rights

- GPOs that add groups to local Administrators (preference items, restricted groups), competing local-admin policies, and disabled-but-linked GPOs that would add every domain user if re-enabled - needs SYSVOL parsing (belongs with the directory pack). Source: field.
- Logon scripts that add accounts to local Administrators - needs NETLOGON file parsing. Source: field.
- User policy that blocks command prompt or PowerShell for everyone - lives in root/rsop/user per user SID. Source: field.
- Effective user rights (who holds 'Log on as a batch job', 'Log on as a service', 'Load and unload device drivers', 'Profile system performance') - RSOP_UserPrivilegeRight lists SIDs or names; needs well-known SID macros. Source: field (a hardening policy restricting driver loading broke a tool installation; a missing right broke a diagnostic service).
- Full security-baseline comparison (hundreds of settings, most not configured) - needs a baseline import and per-setting compare. Source: field.
- Corrupt registry.pol files in GPOs - needs SYSVOL file parsing. Source: field.

## Scheduled tasks

- Tasks that store a user password, run from user-writable paths, run elevated as privileged accounts, or fail on their last run (including logon-type failures after a logon right was removed) - MSFT_ScheduledTask returns the principal as an embedded instance and last-run data only through a method. Source: weekly WS13, controls SRV-TASKS, review WS-TSK-001..004; field.
- Tasks piling up right after boot - needs task run history. Source: field.

## Configuration Manager - lazy or site-control data, logs and client side

- Network Access Account configured, HTTPS / Enhanced HTTP state, DP content-validation schedule, distribution manager thread limits, automatic client upgrade settings - stored in site control Props / PropLists or lazy properties that a list read does not return. Source: cm-health WS09, WS12, WS13; field (upgrade prerequisite warnings about the access account ignored; default distribution threads during monthly content).
- Windows 11 OS image or upgrade package present on the site - the image's OS version is in a lazy XML property (ImageProperty). Source: field.
- Task sequence references to applications that are no longer deployed, and the policy failures they cause every cycle - needs the task sequence reference list joined with application deployments. Source: field.
- Automatic deployment rules scheduled before the monthly sync - needs the rule's schedule token (lazy) and the sync schedule. Source: field.
- Site database tables that grew to most of the database - needs the site database name in a rule or per-database iteration in the SQL runner. Source: field.
- Client-side problems visible only in logs or CMPivot: policy lookups failing with "not found", inventory larger than the size limit resent in a loop, client certificate mismatch, content download timeouts, components hung in a child process, state-message and inbox files parked or corrupt. Source: field.
- WSUS database maintenance and application pool settings - needs the WSUS API or IIS configuration. Source: field.
- Local group membership from hardware inventory - no default inventory class holds it; needs a custom class. Source: field.
- Store apps, per-user installs (AppData) and installers left in user folders - Add/Remove Programs inventory covers machine-wide installs only. Interim: WS-PROC-UNAPPROVED. Source: field (messaging apps installed per user or from the Store).
- Antivirus removal blocked by product passwords - vendor console only. Source: field.

## SQL Server - per database, registry or build table

- Guest CONNECT in user databases, orphaned users, SQL authentication in contained databases, CLR assemblies not SAFE, weak symmetric or asymmetric key algorithms, log space use per database - need the SQL runner to iterate databases. Source: CIS-MSSQL 3.2, 3.3, 3.4, 6.2, 7.1, 7.2.
- Number of error log files, login auditing level, Force Encryption, SQL Browser, non-default port and hidden instance - stored in the registry (xp_ procedures are refused). Source: CIS-MSSQL 2.11, 2.12, 5.1, 5.3.
- Latest cumulative update for SQL Server 2019, 2022 and newer - needs a maintained build table; SQL-BUILD-OLD ships floors for 2016 and 2017 only. Source: field (an instance many updates behind).

## Other integrations

- Server protected by a backup job, monitored by the monitoring platform, onboarded to EDR - backup, monitoring and EDR integrations. Source: controls SRV-BACKUP, SRV-MONITOR, SRV-EDR.
- Host unreachable over WinRM - reported as unknown per target in coverage, not as a finding. Source: controls SRV-REACH; field (WinRM refused on many workstations).
- Certificates in the LocalMachine stores (expiring, weak, self-signed RDP) - not exposed by WMI; listeners are covered by the tls pack. Source: review WS-CRT-001..004.
- Share and NTFS permissions - needs security-descriptor methods. Source: review WS-SHR-001, WS-SHR-002.
- Failover cluster node and resource state (root/MSCluster) - needs testing for rights and authentication level before a rule ships. Source: review WS-SVC-005.

## Expressible, not written yet

- Defender tamper protection, cloud protection (MAPS), PUA blocking and network protection (MSFT_MpComputerStatus, MSFT_MpPreference). Source: facts win.defender.*.
- Stale user profiles on workstations (Win32_UserProfile LastUseTime) - service-account profiles need a SID-to-account join. Source: field.
- SMB server signing on workstations, NetBIOS over TCP/IP on workstations, Windows activation on workstations. Source: review WS-SMB-002.
- Driver packages not updated for years (SMS_DriverPackage SourceDate). Source: field.
