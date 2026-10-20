# Proposals - Windows estate (SCCM, workstations, Windows servers, SQL Server)

Checks proposed for `rules\workstations.yaml` (WS-), `rules\windows-server.yaml` (WINSRV-),
`rules\workstations-sccm.yaml` (WSF-), `rules\sccm.yaml` (SCCM-) and `rules\sql-server.yaml` (SQL-).
Written 2026-10-20 as specs only; no rule file was changed. Ids were checked against the 750 rules
the validator loads today and do not collide. Nothing here names a tenant: anything that varies per
estate is a `threshold.<name>` setting.

Reading an entry:

- **Catches / why** - what the check finds and why it matters.
- **Source** - file, protocol, class and namespace (cim) / SQL text (sql) / AdminService path (http),
  the fields the condition needs, and whether a query already in that file returns them ("existing
  query: X" = reuse X's query verbatim; "new query" = a new query text is needed).
- **Scope** - per host (cim/sql, judged per target) or estate-wide (one list from the site).
- **Condition** - in words; "empty result" says what an empty read means.
- **Confidence** - field names: verified (read in Microsoft docs today, link given), likely (used
  by an existing rule in this repo, or confirmed in community material), guess (from memory only).

Lifecycle dates verified today on Microsoft Learn (links in the entries that use them):
Windows 11 24H2 Home/Pro ended updates (release-information page, 2026-10-13); 23H2 Enterprise
ends 2026-11-10; 24H2 Enterprise 2027-10-12; 25H2 Home/Pro 2027-10-12, Enterprise 2028-10-10.
Windows Server 2022 mainstream ended 2026-10-13 (extended 2031-10-14); 2019 mainstream ended
2024-01-09 (extended 2029-01-09); 2025 mainstream to 2029-11-13. SQL Server 2019 mainstream ended
2025-02-28 (extended 2030-01-08), last CU = CU32 15.0.4430.1, CU32+GDR 15.0.4500.2 (2026-10-13);
SQL Server 2022 latest CU27 = 16.0.4295.3 (2026-09-15), CU27+GDR 16.0.4305.5. Defender platform
support is N-2 of the monthly platform release (version format 4.18.YYMM.N).

---

## Priority 1 - security

### Workstations (cim, `rules\workstations.yaml`)

#### WS-SVC-DOMAIN-ACCOUNT - Service on a workstation runs as a domain user account
- Catches / why: a service whose logon is a domain account. The password sits in LSA secrets on every PC that runs it; one local admin recovers it, and if the account is privileged the whole domain is exposed. On workstations this is almost always a vendor agent installed with a shared account.
- Severity: high. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_Service` - Name, StartName, State, StartMode. Existing query: none in this file; copy the WINSRV-SVC-DOMAIN-ACCOUNT query (`WHERE StartName <> 'LocalSystem' AND NOT StartName LIKE 'NT AUTHORITY%' AND NOT StartName LIKE 'NT SERVICE%'`), key `{host}|{Name}`.
- Condition: StartName contains `\` or `@`, does not start with `.\`, does not end with `$` (gMSA). Empty result = no such service = pass (correct).
- Refs: NIST-800-53:IA-5, CIS-Controls-v8:5.4, MITRE-ATTACK:T1078.002
- Fix: move the service to a gMSA, virtual account or LocalService; keep the account out of privileged groups; expected accounts go in `threshold.workstations.service-account-allow-pattern`.
- Confidence: verified (same WQL already runs in windows-server.yaml; https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service).

#### WS-SVC-USER-WRITABLE-PATH - Service binary lives in a user-writable folder
- Catches / why: a service whose image path is under `\Users\`, `\AppData\`, `\Temp\` or `\ProgramData\<vendor>` with no quoting protection. Anyone who can write there replaces the binary and runs as the service account at next start - a privilege escalation that needs no exploit.
- Severity: high. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_Service` - Name, PathName, StartName, StartMode. New query: `SELECT Name, PathName, StartName, StartMode FROM Win32_Service WHERE PathName LIKE '%\Users\%' OR PathName LIKE '%\Temp\%' OR PathName LIKE '%\AppData\%'` (WQL LIKE treats `\` literally; write it in a block scalar), key `{host}|{Name}`.
- Condition: every row fails unless Name matches `threshold.workstations.userpath-service-ignore-pattern` (empty by default). Empty result = pass.
- Refs: NIST-800-53:CM-6, NIST-800-53:AC-6, MITRE-ATTACK:T1543.003, MITRE-ATTACK:T1574.010
- Fix: reinstall the product under Program Files; if the vendor insists on a profile path, make the folder admin-writable only and record the exception.
- Confidence: verified (Win32_Service.PathName; the WQL escaping is the only thing to test).

#### WS-SMB1-CLIENT-DRIVER - SMB1 client driver still enabled
- Catches / why: the `mrxsmb10` kernel driver present and not Disabled. The optional-feature rule (WS-FEATURE-UNWANTED) sees the feature; this sees the driver, which policy can leave enabled when the feature says removed and the other way round. An SMB1 client is the half that falls for NTLM relay and downgrade.
- Severity: high. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_SystemDriver` - Name, State, StartMode, Started. New query: `SELECT Name, State, StartMode, Started FROM Win32_SystemDriver WHERE Name = 'mrxsmb10'`, key host.
- Condition: StartMode ne Disabled. Empty result (driver not installed, normal on Windows 11) = pass; that is the one place an empty read is the good answer.
- Refs: NIST-800-53:CM-7, CIS-Controls-v8:4.8, MITRE-ATTACK:T1557.001
- Fix: remove the SMB1 feature; where it must stay, set the driver start type to Disabled by policy. Closes backlog "SMB1 client driver start type" (the registry item) - the driver class carries it.
- Confidence: verified (https://learn.microsoft.com/windows/win32/cimwin32prov/win32-systemdriver); same spec for servers, see WINSRV-SMB1-CLIENT-DRIVER.

#### WS-RDP-ENABLED - Remote Desktop connections allowed on a workstation
- Catches / why: `AllowTSConnections = 1`. A user PC that accepts RDP is a lateral-movement hop and a target for stolen-credential logons; most estates allow it on a handful of admin PCs only.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, namespace root/cimv2/TerminalServices, `Win32_TerminalServiceSetting` - ServerName, AllowTSConnections, PolicySourceAllowTSConnections. New query: `SELECT ServerName, AllowTSConnections, PolicySourceAllowTSConnections FROM Win32_TerminalServiceSetting`, key host. Note the namespace needs packet-privacy authentication (the doc says so; WS-RDP-NO-NLA already reads it, so the runner copes).
- Condition: AllowTSConnections eq 1. Evidence says whether policy (PolicySourceAllowTSConnections = 1) or the PC set it. Empty result = n/a (class missing) -> unknown, not a pass.
- Refs: NIST-800-53:AC-17, CIS-Controls-v8:4.8, MITRE-ATTACK:T1021.001
- Fix: turn Remote Desktop off by policy on user PCs; allow it on an admin-PC collection only; keep NLA and a restricted Remote Desktop Users group where it stays.
- Confidence: verified (https://learn.microsoft.com/windows/win32/termserv/win32-terminalservicesetting).

#### WS-RDP-WEAK-SECURITY - RDP security layer or encryption below TLS/High on a workstation
- Catches / why: same as WINSRV-RDP-WEAK-SECURITY, which has no workstation twin: SecurityLayer < 2 or MinEncryptionLevel < 3 lets a session be downgraded or read on the wire.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2/TerminalServices, `Win32_TSGeneralSetting` - TerminalName, UserAuthenticationRequired, SecurityLayer, MinEncryptionLevel. Existing query: WS-RDP-NO-NLA.
- Condition: SecurityLayer lt 2 or MinEncryptionLevel lt 3.
- Refs: NIST-800-53:SC-8, NIST-800-53:AC-17
- Fix: require the SSL (TLS) security layer and High encryption by policy.
- Confidence: verified (field names already in use in both files).

#### WS-RDPUSERS-BROAD - Broad group can log on through Remote Desktop
- Catches / why: Domain Users, Authenticated Users, Everyone, Users or INTERACTIVE as a member of the local Remote Desktop Users group. With RDP enabled, every user in the organisation can open a session on this PC.
- Severity: high. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_GroupUser` - GroupComponent, PartComponent. New query: `SELECT GroupComponent, PartComponent FROM Win32_GroupUser WHERE GroupComponent = "Win32_Group.Domain='{HOST}',Name='Remote Desktop Users'"`, key `{host}|{PartComponent}`.
- Condition: PartComponent matches `Name = "(Everyone|Authenticated Users|Users|INTERACTIVE|Domain Users|Domain Computers|Domain Guests|Guests)"`. Empty result = pass (nobody in the group), but a renamed/localised group also gives empty - same caveat as WS-LOCALADMIN-UNREADABLE; accept, or add a WS-RDPUSERS-UNREADABLE guard only if the tenant localises.
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-17, CIS-Controls-v8:5.4, MITRE-ATTACK:T1021.001
- Fix: remove the group; grant RDP to a named group per role. Same spec for servers: WINSRV-RDPUSERS-BROAD.
- Confidence: verified (identical WQL pattern as the local-admin rules; group name is the English built-in).

#### WS-LOCAL-ACCOUNT-EXTRA - Enabled local user account besides the built-ins
- Catches / why: an enabled local account whose RID is not 500/501/503/504 (Administrator, Guest, DefaultAccount, WDAGUtilityAccount). On a domain-joined PC these are imaging leftovers or a "technician" account with a password shared across the fleet - a local admin on every PC that no directory review sees.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_UserAccount` - Name, SID, Disabled, PasswordRequired, Lockout. Existing query: WS-LOCAL-ACCOUNT-WEAK (`WHERE LocalAccount = TRUE`), key `{host}|{Name}`.
- Condition: Disabled eq false and SID notmatch `-(500|501|503|504)$` and Name notmatch `threshold.workstations.local-account-allow-pattern` (default: nothing allowed; a LAPS-managed admin name goes here).
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.2, CIS-Controls-v8:5.4, MITRE-ATTACK:T1078.003
- Fix: disable or delete the account; where a local admin is needed, use the built-in one under LAPS.
- Confidence: verified (query already runs; RIDs are well known: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers).

#### WS-DEFENDER-TAMPER-OFF - Defender active without tamper protection
- Catches / why: `IsTamperProtected = false` while Defender is the active engine (`AMRunningMode` Normal). Without tamper protection, malware or a script with admin rights turns real-time protection off with one registry write.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/Microsoft/Windows/Defender, `MSFT_MpComputerStatus` - AMRunningMode, IsTamperProtected. Existing query: WS-DEFENDER-RTP-OFF (`SELECT * FROM MSFT_MpComputerStatus`).
- Condition: AMRunningMode matches `^Normal` and IsTamperProtected eq false.
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.1, MITRE-ATTACK:T1562.001
- Fix: turn tamper protection on from the security portal (tenant-wide) or Intune; Group Policy cannot set it.
- Confidence: verified (property list: https://learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus). Same spec for servers: WINSRV-DEFENDER-TAMPER-OFF.

#### WS-DEFENDER-COMPONENT-OFF - A real-time component of Defender is off
- Catches / why: real-time protection is on but behaviour monitoring, downloaded-file scanning (IOAV) or on-access protection is off. These are the pieces that catch living-off-the-land and fileless activity; a policy that switched one off "for performance" is a gap WS-DEFENDER-RTP-OFF does not see.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/Microsoft/Windows/Defender, `MSFT_MpComputerStatus` - AMRunningMode, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled. Existing query: WS-DEFENDER-RTP-OFF.
- Condition: AMRunningMode matches `^Normal` and RealTimeProtectionEnabled eq true and any of BehaviorMonitorEnabled / IoavProtectionEnabled / OnAccessProtectionEnabled eq false.
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.1, MITRE-ATTACK:T1562.001
- Fix: remove the policy setting that disables the component (Disable*Monitoring / DisableIOAVProtection in MpPreference show which).
- Confidence: verified (same doc).

#### WS-DEFENDER-MAPS-OFF - Cloud-delivered protection off
- Catches / why: `MAPSReporting = 0`. Without the cloud lookup Defender runs on local signatures only; block-at-first-sight, cloud block level and most zero-day detections need it.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/Microsoft/Windows/Defender, `MSFT_MpPreference` - MAPSReporting, SubmitSamplesConsent, DisableBlockAtFirstSeen, CloudBlockLevel. New query: `SELECT * FROM MSFT_MpPreference`, key host (shared by the next three rules).
- Condition: MAPSReporting eq 0 (0 off, 1 basic, 2 advanced). Evidence adds DisableBlockAtFirstSeen and CloudBlockLevel. Class missing (Defender not installed) = query failure = unknown.
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.1
- Fix: set MAPS to Advanced and sample submission to safe samples by policy.
- Confidence: verified (parameter = property names: https://learn.microsoft.com/powershell/module/defender/set-mppreference).

#### WS-DEFENDER-FEATURES-OFF - PUA blocking, network protection, script scanning or block-at-first-sight off
- Catches / why: `PUAProtection ne 1`, `EnableNetworkProtection ne 1`, `DisableScriptScanning = true` or `DisableBlockAtFirstSeen = true`. Each is a cheap control that is off by default on some builds and audit-only after a half-finished rollout.
- Severity: low (one finding per feature via a template key `{host}|<feature>` is not possible on one row; keep one finding per host listing the features in evidence). Lens: security. Scope: per host.
- Source: workstations.yaml, cim, `MSFT_MpPreference`, same query as WS-DEFENDER-MAPS-OFF.
- Condition: any of the four; features the tenant does not want are excluded by `threshold.workstations.defender-optional-features` (not expressible as a per-feature switch today - see engine gaps).
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.5, MITRE-ATTACK:T1059
- Fix: enable PUA = Block, network protection = Enabled, script scanning on, block at first sight on, by policy.
- Confidence: verified (same doc; values 0/1/2 = Disabled/Enabled/Audit for PUA and network protection).

#### WS-DEFENDER-EXCLUSIONS-BROAD - Defender excludes a whole drive, user profile or temp folder
- Catches / why: an entry in `ExclusionPath` such as `C:\`, `C:\Users`, `C:\Users\*`, `C:\Windows\Temp`, `%TEMP%`, `C:\ProgramData` or `*`. Vendors ask for these; attackers look for them first - anything dropped there is never scanned.
- Severity: high. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, `MSFT_MpPreference` - ExclusionPath (array), ExclusionExtension (array). Same query as WS-DEFENDER-MAPS-OFF.
- Condition: `ExclusionPath[]` matches `^[A-Za-z]:\\?$|\\Users\\?(\*)?$|\\(Temp|Tmp)\\?$|\\ProgramData\\?$|^\*|%(TEMP|TMP|USERPROFILE|APPDATA)%` or `ExclusionExtension[]` matches `^\.?(exe|dll|ps1|vbs|js|bat|cmd|msi)$`; threshold `workstations.defender-broad-exclusion-pattern`. Note: reading exclusions needs local admin rights on the PC since 2022 (Defender hides them from standard users) - the scan account has them.
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.1, MITRE-ATTACK:T1562.001
- Fix: narrow the exclusion to the vendor's exact folder and process; remove extension exclusions. Same spec for servers: WINSRV-DEFENDER-EXCLUSIONS-BROAD (servers also carry automatic role exclusions, which are not in this list).
- Confidence: verified (property names; array handling via `field[]` is in RULES.md).

#### WS-DEFENDER-EXCLUSION-LOLBIN - Defender excludes a script host or system tool as a process
- Catches / why: `ExclusionProcess` names powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe, regsvr32.exe, msbuild.exe, certutil.exe or explorer.exe. Files opened by an excluded process are not scanned, so excluding a script host blinds Defender to everything a script does.
- Severity: high. Lens: security. Scope: per host.
- Source: same query. Field ExclusionProcess (array).
- Condition: `ExclusionProcess[]` matches `(^|\\)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msbuild|certutil|explorer|svchost)\.exe$`, threshold `workstations.defender-lolbin-pattern`.
- Refs: NIST-800-53:SI-3, MITRE-ATTACK:T1562.001, MITRE-ATTACK:T1059.001
- Fix: remove the process exclusion; exclude the vendor's own binary by full path instead.
- Confidence: verified.

#### WS-DEFENDER-ACTIVE-THREAT - Defender reports an active threat on a workstation
- Catches / why: the server file has WINSRV-DEFENDER-ACTIVE-THREAT; workstations have nothing. A threat Defender found but could not remove (IsActive) is a live compromise.
- Severity: high. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/Microsoft/Windows/Defender, `MSFT_MpThreat` - ThreatID, ThreatName, SeverityID, IsActive. New query (copy of the server one): `SELECT * FROM MSFT_MpThreat`, key `{host}|{ThreatID}`.
- Condition: IsActive eq true. Empty = pass.
- Refs: NIST-800-53:SI-3, NIST-800-53:IR-4
- Fix: isolate, remediate in the security portal, find the entry path.
- Confidence: verified (rule already exists for servers).

#### WS-DEFENDER-PLATFORM-OLD - Defender platform older than the supported window
- Catches / why: `AMProductVersion` (format 4.18.YYMM.N) from before the current year, i.e. far outside Microsoft's N-2 monthly platform support. The platform ships through Windows Update as KB4052623; a PC that is stuck means its update path is broken even if signatures still flow.
- Severity: medium. Lens: both. Scope: per host.
- Source: workstations.yaml, cim, `MSFT_MpComputerStatus` - AMProductVersion, AMEngineVersion, AMServiceEnabled. Existing query: WS-DEFENDER-RTP-OFF.
- Condition: AMServiceEnabled eq true and AMProductVersion matches `^4\.(1[0-7]\.|18\.(1\d|2[0-5])\d{3}\.)` (anything before 2026), threshold `workstations.defender-platform-old-pattern`, raised yearly. A tighter N-2 check needs a date-from-version comparison (engine gap).
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:10.2
- Fix: approve the platform update in WSUS/SCCM (category Microsoft Defender Antivirus) and check the PC's update path.
- Confidence: verified (support policy and version format: https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-updates).

#### WS-BITLOCKER-DATA-OFF - Fixed data volume not protected by BitLocker
- Catches / why: WS-BITLOCKER-OS-OFF covers the OS volume (VolumeType 0). A second internal data volume (VolumeType 1) left clear carries the same stolen-laptop risk and is often where users keep files.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2/Security/MicrosoftVolumeEncryption, `Win32_EncryptableVolume` - DriveLetter, ProtectionStatus, ConversionStatus, VolumeType. New query: same SELECT with `WHERE VolumeType = 1`, key `{host}|{DriveLetter}`.
- Condition: ProtectionStatus ne 1. Empty = no data volume = pass.
- Refs: NIST-800-53:SC-28, CIS-Controls-v8:3.6
- Fix: enable BitLocker on fixed data drives by policy with auto-unlock.
- Confidence: verified (class already used; VolumeType enumeration: https://learn.microsoft.com/windows/win32/secprov/win32-encryptablevolume).

#### WS-WDAC-AUDIT-ONLY - Application control policy deployed in audit mode only
- Catches / why: `UsermodeCodeIntegrityPolicyEnforcementStatus = 1` (audit). An App Control (WDAC) policy left in audit for months blocks nothing; it was a pilot that never finished.
- Severity: low. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/Microsoft/Windows/DeviceGuard, `Win32_DeviceGuard` - UsermodeCodeIntegrityPolicyEnforcementStatus, CodeIntegrityPolicyEnforcementStatus. Existing query: WS-CREDGUARD-OFF (`SELECT * FROM Win32_DeviceGuard`).
- Condition: UsermodeCodeIntegrityPolicyEnforcementStatus eq 1 (0 off, 1 audit, 2 enforced). "No application control at all" (0) is not flagged here because AppLocker enforcement is invisible to CIM - see backlog.
- Refs: NIST-800-53:CM-7(5), CIS-Controls-v8:2.5, MITRE-ATTACK:T1204
- Fix: review the audit events, then move the policy to enforced.
- Confidence: likely (CodeIntegrityPolicyEnforcementStatus values verified at https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity; the Usermode twin is confirmed by DISA STIG WN11-CC-000080, not by a Microsoft class page).

#### WS-SHARE-NONADMIN - User-created file share on a workstation
- Catches / why: a disk share (Type 0) whose name does not end in `$`. Shares on user PCs are unmanaged data stores, bypass the file server's backup and DLP, and are how ransomware hops.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_Share` - Name, Path, Type, Description. New query: `SELECT Name, Path, Type, Description FROM Win32_Share WHERE Type = 0`, key `{host}|{Name}`.
- Condition: Name notmatch `\$$` and Name notmatch `threshold.workstations.share-allow-pattern`. Empty = pass.
- Refs: NIST-800-53:AC-3, CIS-Controls-v8:3.3, MITRE-ATTACK:T1135
- Fix: remove the share, move the data to a file server; block share creation by policy (Server service hardening) where nothing needs it.
- Confidence: verified (https://learn.microsoft.com/windows/win32/cimwin32prov/win32-share).

#### WS-STARTUP-USERPATH - Autostart entry runs a script or a program from a user-writable path
- Catches / why: a Run/RunOnce/Startup-folder entry whose command points into `\Users\`, `\AppData\`, `\Temp\`, or runs a script host (`wscript`, `cscript`, `mshta`, `powershell`, `rundll32`, `regsvr32`) or a `.vbs/.js/.bat/.cmd/.ps1/.hta` file. This is the commonest user-level persistence; it also catches logon scripts left behind by old tools.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_StartupCommand` - Name, Command, Location, User. New query: `SELECT Name, Command, Location, User FROM Win32_StartupCommand`, key `{host}|{Location}|{Name}`. Note: remotely the class returns HKLM entries plus the loaded user hives.
- Condition: Command matches `\\Users\\|\\AppData\\|\\Temp\\|\b(wscript|cscript|mshta|powershell|pwsh|rundll32|regsvr32)(\.exe)?\b|\.(vbs|vbe|js|jse|bat|cmd|ps1|hta|wsf)\b` and Command notmatch `threshold.workstations.startup-ignore-pattern` (default covers `\\Microsoft\\(OneDrive|Teams|EdgeUpdate|WindowsApps)\\` and `\\Programs\\Microsoft VS Code\\`).
- Refs: NIST-800-53:CM-7, MITRE-ATTACK:T1547.001, MITRE-ATTACK:T1059
- Fix: remove the entry; if it is a legitimate tool, install it machine-wide. Same spec for servers: WINSRV-STARTUP-USERPATH (severity high there).
- Confidence: verified (https://learn.microsoft.com/windows/win32/cimwin32prov/win32-startupcommand).

#### WS-DNS-PUBLIC - Adapter uses a public DNS resolver
- Catches / why: `DNSServerSearchOrder` contains 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9 or 208.67.222.222/220.220. Such a PC cannot resolve the domain reliably (logon and Group Policy fail intermittently), bypasses DNS filtering, and usually means someone set a static address by hand.
- Severity: medium. Lens: both. Scope: per host.
- Source: workstations.yaml, cim, root/cimv2, `Win32_NetworkAdapterConfiguration` - Index, Description, IPEnabled, DHCPEnabled, DNSServerSearchOrder, TcpipNetbiosOptions, DNSDomain, IPAddress, DefaultIPGateway. New query: `SELECT Index, Description, IPEnabled, DHCPEnabled, DNSServerSearchOrder, TcpipNetbiosOptions, DNSDomain FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE`, key `{host}|{Index}` (shared with WS-NETBIOS-ON, WS-IP-STATIC below).
- Condition: `DNSServerSearchOrder[]` matches `^(8\.8\.(8\.8|4\.4)|1\.(1\.1\.1|0\.0\.1)|9\.9\.9\.9|208\.67\.22[02]\.22[02])$`, threshold `workstations.public-dns-pattern`.
- Refs: NIST-800-53:SC-20, NIST-800-53:CM-6, MITRE-ATTACK:T1071.004
- Fix: set the adapter back to DHCP; block outbound 53 except from the internal resolvers. Same spec for servers: WINSRV-DNS-PUBLIC (new query there too; the existing NETBIOS query lacks the DNS field).
- Confidence: verified (https://learn.microsoft.com/windows/win32/cimwin32prov/win32-networkadapterconfiguration).

#### WS-SMB-SERVER-SIGNING-OFF - Workstation's SMB server does not require signing
- Catches / why: backlog "SMB server signing on workstations" - expressible, not written. Every PC runs the Server service for admin shares; without required signing its sessions can be relayed.
- Severity: medium. Lens: security. Scope: per host.
- Source: workstations.yaml, cim, root/Microsoft/Windows/SMB, `MSFT_SmbServerConfiguration` - RequireSecuritySignature, EnableSMB1Protocol, EnableSecuritySignature, EncryptData. New query: `SELECT * FROM MSFT_SmbServerConfiguration`, key host (also serves a WS-SMB1-SERVER-ON twin if wanted; WS-FEATURE-UNWANTED already covers the feature).
- Condition: RequireSecuritySignature eq false.
- Refs: NIST-800-53:SC-8, CIS-Controls-v8:4.1, MITRE-ATTACK:T1557.001
- Fix: 'Microsoft network server: Digitally sign communications (always)' = Enabled by policy.
- Confidence: verified (class already read on servers).

#### WS-NETBIOS-ON - NetBIOS over TCP/IP enabled on a workstation adapter
- Catches / why: backlog item (review WS-SMB-002). NetBIOS name queries are answered by whoever is on the segment - the first step of credential-relay attacks.
- Severity: low. Lens: security. Scope: per host.
- Source: same query as WS-DNS-PUBLIC. Field TcpipNetbiosOptions (0 via DHCP, 1 enabled, 2 disabled).
- Condition: TcpipNetbiosOptions ne 2 and Description notmatch `threshold.workstations.netbios-ignore-adapter-pattern` (VPN/virtual adapters).
- Refs: NIST-800-53:CM-7, MITRE-ATTACK:T1557.001
- Fix: disable NetBIOS over TCP/IP by DHCP option 001 (vendor 1 = 2) or by policy script.
- Confidence: verified (same rule exists for servers).

### Windows servers (cim, `rules\windows-server.yaml`)

#### WINSRV-SVC-USER-WRITABLE-PATH - same spec as WS-SVC-USER-WRITABLE-PATH; severity high.
#### WINSRV-SMB1-CLIENT-DRIVER - same spec as WS-SMB1-CLIENT-DRIVER; severity high.
#### WINSRV-RDPUSERS-BROAD - same spec as WS-RDPUSERS-BROAD; severity critical on servers (RDP is on by design, so a broad group means everyone can log on to the server).
#### WINSRV-STARTUP-USERPATH - same spec as WS-STARTUP-USERPATH; severity high.
#### WINSRV-DNS-PUBLIC - same spec as WS-DNS-PUBLIC with a new query (the existing NETBIOS query selects no DNS field); severity high on servers (a DC or application server on public DNS breaks the domain).
#### WINSRV-DEFENDER-TAMPER-OFF - same spec as WS-DEFENDER-TAMPER-OFF; existing query WINSRV-DEFENDER-RTP-OFF; severity medium.
#### WINSRV-DEFENDER-EXCLUSIONS-BROAD - same spec as WS-DEFENDER-EXCLUSIONS-BROAD; new MpPreference query; severity high. Note SQL, Exchange and DC automatic exclusions are not in ExclusionPath, so they do not fire.

#### WINSRV-SMB-CLIENT-SIGNING-OFF - Server's SMB client does not require signing
- Catches / why: the workstation file has it, the server file does not. Servers reach file shares, SYSVOL and backup targets as SMB clients; an unsigned client session from a server is a high-value relay.
- Severity: medium. Lens: security. Scope: per host.
- Source: windows-server.yaml, cim, root/Microsoft/Windows/SMB, `MSFT_SmbClientConfiguration` - RequireSecuritySignature, EnableInsecureGuestLogons. New query: `SELECT * FROM MSFT_SmbClientConfiguration`, key host (shared with the next rule).
- Condition: RequireSecuritySignature eq false.
- Refs: NIST-800-53:SC-8, MITRE-ATTACK:T1557.001
- Fix: 'Microsoft network client: Digitally sign communications (always)' = Enabled by policy.
- Confidence: verified (class already read on workstations).

#### WINSRV-SMB-INSECURE-GUEST - Server's SMB client allows insecure guest logons
- Same source as above; condition EnableInsecureGuestLogons eq true; severity medium; refs NIST-800-53:IA-2, MITRE-ATTACK:T1557.001; fix by policy. Confidence: verified.

#### WINSRV-LOCAL-ACCOUNT-WEAK - Guest enabled or a local account without a required password on a server
- Catches / why: twin of WS-LOCAL-ACCOUNT-WEAK, missing on servers.
- Severity: high. Lens: security. Scope: per host.
- Source: windows-server.yaml, cim, root/cimv2, `Win32_UserAccount` - Name, SID, Disabled, PasswordRequired, Lockout. New query: `SELECT Name, SID, Disabled, PasswordRequired, Lockout FROM Win32_UserAccount WHERE LocalAccount = TRUE AND Domain = '{HOST}'`. The `Domain = '{HOST}'` filter is deliberate: on a domain controller `LocalAccount = TRUE` enumerates the whole domain (slow, and wrong); with the host filter a DC returns nothing.
- Condition: Disabled eq false and (SID matches `-501$` or PasswordRequired eq false). Empty = pass (DC) - record DCs as exceptions in the same way the local-admin rules do.
- Refs: NIST-800-53:IA-5, CIS-Controls-v8:5.2
- Fix: disable Guest; require a password or disable the account.
- Confidence: verified (Win32_UserAccount Domain key: https://learn.microsoft.com/windows/win32/cimwin32prov/win32-useraccount; the DC behaviour is documented there under LocalAccount).

### SQL Server (sql, `rules\sql-server.yaml`)

#### SQL-SYSADMIN-SQL-LOGIN - SQL-authenticated login is a sysadmin
- Catches / why: an enabled login of type `S` (SQL login) other than `sa` in the sysadmin role. Its password lives outside the domain's policy and MFA; brute-forced or leaked, it owns the instance and (through xp_cmdshell or the service account) the host. SQL-SYSADMIN-MANY counts members; this names the risky kind.
- Severity: high. Lens: security. Scope: per instance, one finding per login.
- Source: sql-server.yaml, sql (master). New query:
  `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/sysadmin/' + m.name AS target, m.name AS member_name, m.type_desc, m.is_disabled, m.create_date FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id WHERE r.name = N'sysadmin' AND m.principal_id <> 1 AND m.name NOT LIKE N'NT SERVICE\%' AND m.name NOT LIKE N'NT AUTHORITY\%'`, key target, name member_name (shared with the next rule).
- Condition: is_disabled eq 0 and type_desc eq SQL_LOGIN and member_name notmatch `threshold.sql.sysadmin-sql-login-allow-pattern`.
- Refs: NIST-800-53:AC-6, NIST-800-53:IA-2, CIS-Controls-v8:5.4, CIS-MSSQL:3.1, MITRE-ATTACK:T1078.001
- Fix: replace with a Windows group login; if an application needs sysadmin, that is the finding to fix with the vendor.
- Confidence: verified (catalog views; the same join already runs in SQL-SYSADMIN-MANY).

#### SQL-SYSADMIN-USER-ACCOUNT - Individual Windows user is a sysadmin
- Same query; condition is_disabled eq 0 and type_desc eq WINDOWS_LOGIN (a person, not a group). Grants to individuals outlive their job and escape group reviews. Severity medium; refs NIST-800-53:AC-2, NIST-800-53:AC-6, CIS-Controls-v8:5.4; fix: grant through one reviewed AD group. Confidence: verified.

#### SQL-CONTROL-SERVER-GRANT - CONTROL SERVER granted outside sysadmin
- Catches / why: a GRANT of CONTROL SERVER (or IMPERSONATE ANY LOGIN / ALTER ANY LOGIN) to a login that is not in sysadmin - a hidden sysadmin that role reviews never list.
- Severity: high. Lens: security. Scope: per instance, one finding per grant.
- Source: sql. New query: `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/' + p.name + N'/' + sp.permission_name AS target, p.name AS grantee, p.type_desc, sp.permission_name, sp.state_desc, IS_SRVROLEMEMBER('sysadmin', p.name) AS is_sysadmin FROM sys.server_permissions sp JOIN sys.server_principals p ON p.principal_id = sp.grantee_principal_id WHERE sp.class = 100 AND sp.state IN ('G','W') AND sp.permission_name IN (N'CONTROL SERVER', N'IMPERSONATE ANY LOGIN', N'ALTER ANY LOGIN', N'ALTER ANY SERVER ROLE')`, key target.
- Condition: every row (is_sysadmin in evidence; a sysadmin holding it is harmless but worth seeing). Empty = pass.
- Refs: NIST-800-53:AC-6, CIS-Controls-v8:5.4, MITRE-ATTACK:T1078
- Fix: revoke; put the login in a server role that matches its job.
- Confidence: verified (sys.server_permissions class 100 = SERVER).

#### SQL-SECURITYADMIN-MEMBER - Member of securityadmin or serveradmin
- Catches / why: securityadmin can grant itself any permission and serveradmin can reconfigure the engine - both are sysadmin in practice, yet they are rarely reviewed.
- Severity: medium. Lens: security. Scope: per instance, per member.
- Source: sql. New query: as SQL-SYSADMIN-SQL-LOGIN with `r.name IN (N'securityadmin', N'serveradmin')` and r.name in the target and selected as role_name.
- Condition: is_disabled eq 0; member_name notmatch `threshold.sql.powerful-role-allow-pattern`.
- Refs: NIST-800-53:AC-6, CIS-Controls-v8:5.4
- Fix: move the member to a narrower role or to sysadmin under review.
- Confidence: verified.

#### SQL-DB-OWNER-ORPHAN - Database owned by a login that no longer exists
- Catches / why: `SUSER_SNAME(owner_sid)` is NULL. Jobs, service broker, replication and AG failover can fail on such a database, and TRUSTWORTHY on it is unreviewable. Usually the owner was a departed admin's Windows login.
- Severity: medium. Lens: both. Scope: per database.
- Source: sql. New query (per-database attributes v2, shared by SQL-DB-TDE-OFF, SQL-DB-CONTAINED, SQL-DB-LOG-REUSE-WAIT, SQL-DB-OWNER-INDIVIDUAL): `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/' + d.name AS target, d.name AS database_name, d.database_id, SUSER_SNAME(d.owner_sid) AS owner_name, sp.type_desc AS owner_type, sp.principal_id AS owner_principal_id, d.is_encrypted, d.containment_desc, d.compatibility_level, d.log_reuse_wait_desc, d.state_desc, d.is_read_only, d.create_date FROM sys.databases d LEFT JOIN sys.server_principals sp ON sp.sid = d.owner_sid WHERE d.source_database_id IS NULL`, key target, name database_name.
- Condition: owner_name absent and database_id gt 4.
- Refs: NIST-800-53:AC-2, NIST-800-53:CM-6
- Fix: `ALTER AUTHORIZATION ON DATABASE::x TO sa` (or the standard owner login).
- Confidence: verified.

#### SQL-DB-OWNER-INDIVIDUAL - User database owned by a person's Windows login
- Same query; condition owner_type eq WINDOWS_LOGIN and database_id gt 4. Low severity; the owner's rights flow through ownership chaining and TRUSTWORTHY. Refs NIST-800-53:AC-6; fix as above. Confidence: verified.

#### SQL-DB-TDE-OFF - User database not encrypted at rest
- Catches / why: `is_encrypted = 0` on a user database. Without TDE, a stolen backup file or detached MDF is the whole database in clear. Edition permitting (Standard from 2019 includes TDE).
- Severity: low (raise per tenant). Lens: security. Scope: per database.
- Source: same query. Condition: is_encrypted eq 0 and database_id gt 4 and database_name matches `threshold.sql.tde-required-database-pattern` (default `.`).
- Refs: NIST-800-53:SC-28, CIS-Controls-v8:3.11
- Fix: enable TDE with a certificate backed up off-host; or record why not.
- Confidence: verified.

#### SQL-DB-CONTAINED - Contained database present
- Same query; condition containment_desc ne NONE. Users in a contained database authenticate inside it, outside the instance's login policy, sa review and this pack's login rules; the per-database users cannot be read (engine gap). Severity low; lens security; refs CIS-MSSQL:3.4, NIST-800-53:IA-5; fix: review its SQL users, keep `contained database authentication` off where unused. Confidence: verified.

#### SQL-LOGIN-PASSWORD-OLD - Privileged SQL login password not changed for over a year
- Catches / why: `LOGINPROPERTY(name,'PasswordLastSetTime')` older than 365 days on an enabled SQL login that is sysadmin (or any SQL login, tenant choice). Such passwords are in connection strings and old tickets everywhere.
- Severity: medium. Lens: security. Scope: per login.
- Source: sql. New query: `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/' + name AS target, name AS login_name, is_disabled, LOGINPROPERTY(name, 'PasswordLastSetTime') AS password_last_set, LOGINPROPERTY(name, 'IsLocked') AS is_locked, LOGINPROPERTY(name, 'IsMustChange') AS is_must_change, LOGINPROPERTY(name, 'BadPasswordCount') AS bad_password_count, LOGINPROPERTY(name, 'LockoutTime') AS lockout_time, IS_SRVROLEMEMBER('sysadmin', name) AS is_sysadmin FROM sys.sql_logins WHERE name NOT LIKE N'##%'`, key target, name login_name (shared with SQL-LOGIN-LOCKED).
- Condition: is_disabled eq 0 and is_sysadmin eq 1 and password_last_set age-gt 365 (threshold `sql.sysadmin-password-max-age-days`).
- Refs: NIST-800-53:IA-5, CIS-MSSQL:4.2
- Fix: rotate; move to Windows authentication.
- Confidence: verified (https://learn.microsoft.com/sql/t-sql/functions/loginproperty-transact-sql).

#### SQL-LOGIN-LOCKED - SQL login is locked out
- Same query; condition is_locked eq 1 (refresh 1h). A locked login is either a brute-force attempt in progress or an application with a stale password hammering the instance; both need a person today. Severity high; refs NIST-800-53:AC-7, MITRE-ATTACK:T1110; fix: read the failed-login audit, then unlock or fix the application. Confidence: verified.

#### SQL-SVC-DOMAIN-USER-ACCOUNT - SQL service runs under a domain user account
- Catches / why: `service_account` with a backslash that is not NT SERVICE / NT AUTHORITY / virtual and does not end with `$` (gMSA). A domain user with the SPN is the classic Kerberoasting target, and its password is in LSA secrets on the host.
- Severity: medium. Lens: security. Scope: per service.
- Source: sql, existing query SQL-AGENT-NOT-RUNNING (`sys.dm_server_services`).
- Condition: service_account matches `\\` and notmatch `^(NT SERVICE|NT AUTHORITY|NT Service)\\` and notmatch `\$$`.
- Refs: NIST-800-53:IA-5, CIS-MSSQL:3.5, MITRE-ATTACK:T1558.003
- Fix: migrate to a gMSA (supported since 2016) and set the SPN on it.
- Confidence: verified (field already used).

#### SQL-BACKUP-LOCAL-DISK - Newest full backup was written to a local drive
- Catches / why: the latest full backup set's media is `device_type = 2` (disk) with a drive-letter path. Backups that live on the server die with it; ransomware encrypts them first.
- Severity: high. Lens: both. Scope: per database.
- Source: sql (msdb). New query: `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/' + b.database_name + N'/' + CAST(mf.family_sequence_number AS nvarchar(4)) AS target, b.database_name, b.backup_finish_date, b.has_backup_checksums, b.is_copy_only, mf.device_type, mf.physical_device_name FROM msdb.dbo.backupset b JOIN msdb.dbo.backupmediafamily mf ON mf.media_set_id = b.media_set_id WHERE b.type = 'D' AND b.backup_set_id = (SELECT MAX(b2.backup_set_id) FROM msdb.dbo.backupset b2 WHERE b2.database_name = b.database_name AND b2.type = 'D') AND b.database_name IN (SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' AND name <> N'tempdb')`, key target, name database_name.
- Condition: device_type eq 2 and physical_device_name matches `^[A-Za-z]:\\` and physical_device_name notmatch `threshold.sql.local-backup-path-allow-pattern` (a mounted backup appliance drive letter). Backup tools using VDI (device_type 7) or URL (9) pass.
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.4
- Fix: back up to a UNC on an immutable or off-host target, or through the backup product.
- Confidence: verified (https://learn.microsoft.com/sql/relational-databases/system-tables/backupmediafamily-transact-sql).

#### SQL-BACKUP-NO-CHECKSUM - Newest full backup taken without CHECKSUM
- Same query; condition has_backup_checksums eq 0. A backup without checksums copies corrupt pages silently. Severity low; refs NIST-800-53:CP-9, NIST-800-53:SI-7; fix: `WITH CHECKSUM` (and `backup checksum default` = 1). Confidence: verified.

#### SQL-CONNECTIONS-UNENCRYPTED - TCP sessions without encryption
- Catches / why: `sys.dm_exec_connections` rows with `net_transport = 'TCP'` and `encrypt_option = 'FALSE'`. Any such session proves Force Encryption is off (a registry setting this pack cannot read) and the application does not request TLS; credentials of SQL logins and the data cross the wire in clear.
- Severity: medium. Lens: security. Scope: per instance (count rule).
- Source: sql. New query: `SELECT session_id, net_transport, encrypt_option, auth_scheme, client_net_address, local_tcp_port FROM sys.dm_exec_connections WHERE net_transport = N'TCP'`, key `{instance}|{session_id}`.
- Condition: count gt 0 where encrypt_option eq FALSE; evidence samples client addresses. Snapshot, so refresh 1h.
- Refs: NIST-800-53:SC-8, CIS-MSSQL:7.3
- Fix: Force Encryption with a CA certificate in SQL Configuration Manager; `Encrypt=True` in connection strings.
- Confidence: verified (https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-exec-connections-transact-sql).

#### SQL-STARTUP-PROCS - Stored procedure marked to run at startup
- Catches / why: `OBJECTPROPERTY(object_id,'ExecIsStartup') = 1` in master. Startup procedures run as sysadmin at every engine start - a persistence mechanism (and the companion of `scan for startup procs`, which SQL-CFG-SURFACE-AREA flags).
- Severity: high. Lens: security. Scope: per procedure.
- Source: sql. New query: `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/startup/' + name AS target, name, create_date, modify_date FROM master.sys.procedures WHERE OBJECTPROPERTY(object_id, 'ExecIsStartup') = 1`, key target.
- Condition: every row; name notmatch `threshold.sql.startup-proc-allow-pattern`. Empty = pass.
- Refs: NIST-800-53:CM-7, MITRE-ATTACK:T1505.001
- Fix: `sp_procoption ... 'startup','off'` after reading the procedure.
- Confidence: verified.

#### SQL-LOGON-TRIGGER - Server-level logon trigger present
- Catches / why: `sys.server_triggers` rows. Logon triggers run on every connection as the trigger owner: a persistence and lockout mechanism (a broken one locks everybody out, including sa).
- Severity: medium. Lens: security. Scope: per trigger.
- Source: sql. New query: `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/trigger/' + name AS target, name, is_disabled, create_date, modify_date FROM sys.server_triggers`, key target.
- Condition: is_disabled eq 0 and name notmatch `threshold.sql.logon-trigger-allow-pattern`.
- Refs: NIST-800-53:CM-7, MITRE-ATTACK:T1505.001
- Fix: read it; drop or document it (and keep the DAC working for recovery).
- Confidence: verified.

#### SQL-AUDIT-NO-FAILED-LOGIN - No enabled audit captures failed logins
- Catches / why: SQL-NO-SERVER-AUDIT says "an audit exists"; this says it records login failures - what you need for SQL-LOGIN-LOCKED and incident work. The registry login-auditing level (CIS 5.3) is not readable here, so this is the substitute.
- Severity: medium. Lens: security. Scope: per instance (count none).
- Source: sql. New query: `SELECT s.name AS specification, s.is_state_enabled, d.audit_action_name FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON d.server_specification_id = s.server_specification_id JOIN sys.server_audits a ON a.audit_guid = s.audit_guid WHERE s.is_state_enabled = 1 AND a.is_state_enabled = 1 AND d.audit_action_name IN (N'FAILED_LOGIN_GROUP', N'LOGIN_CHANGE_PASSWORD_GROUP', N'SERVER_ROLE_MEMBER_CHANGE_GROUP')`, key `{instance}|{specification}|{audit_action_name}`.
- Condition: count lt 1 where audit_action_name eq FAILED_LOGIN_GROUP.
- Refs: NIST-800-53:AU-2, NIST-800-53:AU-12, CIS-MSSQL:5.3, CIS-MSSQL:5.4
- Fix: add FAILED_LOGIN_GROUP (and the two change groups) to an enabled server audit specification.
- Confidence: verified.

### Configuration Manager site (http AdminService, `rules\sccm.yaml`)

#### SCCM-SCRIPT-SELF-APPROVED - Run Script approved by its own author
- Catches / why: `Author = Approver` on an approved script (ApprovalState 3). Scripts run as SYSTEM on any targeted device; the console blocks self-approval by default, so a match means the hierarchy setting "authors may approve their own scripts" is on, or one person holds both roles.
- Severity: high. Lens: security. Scope: estate-wide, per script.
- Source: sccm.yaml, http, `/wmi/SMS_Scripts`, `$select: ScriptGuid,ScriptName,Author,Approver,ApprovalState,LastUpdateTime,ScriptVersion`, key ScriptGuid, name ScriptName.
- Condition: ApprovalState eq 3 and Author eq Approver (cross-field equality - engine gap; interim: Approver matches `threshold.sccm.script-approver-allow-pattern` negated, i.e. flag approvers outside the approving group). Also SCCM-SCRIPT-PENDING: ApprovalState eq 0 and LastUpdateTime age-gt 30 (low, hygiene).
- Refs: NIST-800-53:AC-5, NIST-800-53:CM-5, MITRE-ATTACK:T1072
- Fix: keep "Script authors require additional script approver" on; separate the author and approver roles.
- Confidence: likely (class and ApprovalState 0/1/3 from community material, no Microsoft class page: https://msendpointmgr.com/2017/08/22/automate-scripts-in-configmgr-using-powershell/; Approve-CMScript doc confirms the self-approval rule).

#### SCCM-DEPLOYMENT-TO-ALL-SYSTEMS - Deployment targeted at a built-in all-devices collection
- Catches / why: a deployment whose CollectionID is `SMS00001` (All Systems), `SMS00004` (All Desktop and Server Clients) or `SMSDM003` (All Mobile Devices). A Required app, package or task sequence on All Systems hits every server and every new client, and a task sequence there has reimaged estates. Built-in collection ids are Microsoft constants, not tenant data.
- Severity: by FeatureType - 7 (task sequence) critical, 1/2 Required high, Available medium. Lens: both. Scope: estate-wide, per deployment.
- Source: sccm.yaml, http, `/wmi/SMS_DeploymentSummary`, new query `$select: DeploymentID,SoftwareName,CollectionID,CollectionName,FeatureType,DeploymentIntent,DeploymentTime,EnforcementDeadline,NumberTargeted,NumberErrors,SummarizationTime,CreationTime`, key DeploymentID, name SoftwareName (shared with the next two rules).
- Condition: CollectionID in [SMS00001, SMS00004, SMSDM003] and FeatureType in [1, 2, 5, 7] and DeploymentIntent eq 1; `threshold.sccm.all-systems-allowed-feature-types` for tenants that deploy update groups to All Systems on purpose.
- Refs: NIST-800-53:CM-3, NIST-800-53:CM-5, MITRE-ATTACK:T1072
- Fix: retarget to a limited collection; keep All Systems for client settings only.
- Confidence: verified (https://learn.microsoft.com/intune/configmgr/develop/reference/apps/sms_deploymentsummary-server-wmi-class; built-in ids on the SMS_Collection page).

#### SCCM-TS-REQUIRED-BROAD - Required task sequence deployment targets many devices
- Same query; condition FeatureType eq 7 and DeploymentIntent eq 1 and NumberTargeted gt 25 (threshold `sccm.required-ts-max-targets`). A required OS deployment to a large collection runs without consent at the deadline. Severity high; refs NIST-800-53:CM-3; fix: make it Available, or target a staging collection. Confidence: verified.

#### SCCM-RBAC-SCOPE-ALL - Administrative user holds a non-read role on the All security scope and All Systems
- Deferred: SMS_Admin exposes `CategoryNames`/`CollectionNames`/`RoleNames`, but "Full Administrator on everything" is already SCCM-RBAC-FULLADMIN-USER. No new rule; listed so it is not re-proposed.

### Workstations as the site sees them (http, `rules\workstations-sccm.yaml`)

#### WSF-SVC-DOMAIN-ACCOUNT - Inventoried service runs as a domain user account (fleet, agentless)
- Catches / why: the estate-wide version of WS-SVC-DOMAIN-ACCOUNT from hardware inventory - it also covers PCs that are off when the live scan runs and devices the cim pack does not target.
- Severity: high. Lens: security. Scope: estate-wide, per device and service.
- Source: workstations-sccm.yaml, http, `/wmi/SMS_G_System_SERVICE`, `$filter: "StartName ne 'LocalSystem' and startswith(StartName,'NT ') eq false"`, `$select: ResourceID,Name,DisplayName,StartName,StartMode,State,PathName`, key `{ResourceID}|{Name}` (shared with WSF-SVC-UNQUOTED-PATH, which needs a separate filter - two queries). The Services inventory class is on by default.
- Condition: StartName matches `\\|@` and notmatch `^\.\\` and notmatch `\$$`.
- Refs: as WS-SVC-DOMAIN-ACCOUNT.
- Fix: as WS-SVC-DOMAIN-ACCOUNT.
- Confidence: likely (inventory class mirrors Win32_Service: https://learn.microsoft.com/intune/configmgr/core/clients/manage/inventory/extend-hardware-inventory; the OData `startswith(...) eq false` form is untested).

#### WSF-SVC-UNQUOTED-PATH - Inventoried service path with spaces is not quoted (fleet, agentless)
- Source: `/wmi/SMS_G_System_SERVICE`, `$filter: "startswith(PathName,'\"') eq false"` (YAML: single-quote the scalar and double the inner quotes), same $select. Condition: PathName matches `^[A-Za-z]:\\[^"]*\s[^"]*\.exe`. Severity medium; refs NIST-800-53:CM-6, MITRE-ATTACK:T1574.009; fix: quote the ImagePath. Confidence: likely (filter syntax untested).

#### WSF-EP-INFECTED - Endpoint Protection reports an infection the client could not clean
- Catches / why: `EPInfectionState` 2 (pending action) or 3 (infected) on a device. Only meaningful where the site manages Defender/EP; elsewhere the field is 0 or absent and nothing fires.
- Severity: high. Lens: security. Scope: estate-wide, per device.
- Source: workstations-sccm.yaml, http, `/wmi/SMS_CombinedDeviceResources`, new query `$select: ResourceID,Name,IsClient,IsActive,EPInfectionState,EPDeploymentState,EPLastThreatName,EPLastInfectionTime,LastClientCheckTime,ClientCheckPass,ClientRemediationSuccess,LastMPServerName,CoManaged,LastSoftwareScan,LastDDR`, key ResourceID, name Name (shared with WSF-CLIENT-CHECK-STALE and the client-health rules below).
- Condition: IsClient eq 1 and EPInfectionState in [2, 3].
- Refs: NIST-800-53:SI-3, NIST-800-53:IR-4
- Fix: open the device in the EP dashboard; full scan; isolate if the threat persists.
- Confidence: likely (no Microsoft page for SMS_CombinedDeviceResources exists; the fields appear in the console's device view and in the SQL view v_CombinedDeviceResources, where the EP columns are named EP_LastThreatName / EP_LastInfectionTime - verify the WMI spelling on the first run).

### Registry (new per-host protocol) - backlog items that become expressible

One line each; all per host, both workstations and servers unless said. Query shape per
docs\RULES.md: `protocol: registry`, `path: <key under the hive>` (the first back-quoted path in
each line), `hive: HKLM` (default), `values: [<the value names named in the line>]`, `key: host`.
The row carries `exists` (the key) and one field per value; a value the runner returns absent is
"not configured", which for most of these means the insecure default and must fail, not pass -
so conditions are written as "absent or <bad value>", never "eq <bad value>" alone.

- WS-REG-LSA-PPL - `SYSTEM\CurrentControlSet\Control\Lsa` RunAsPPL absent or 0 (and RunAsPPLBoot): LSA not protected; credential dumping tools read LSASS. High; NIST-800-53:SC-39, MITRE-ATTACK:T1003.001. Verified value name (https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection).
- WS-REG-WDIGEST - `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` UseLogonCredential eq 1: clear-text passwords kept in memory. High; MITRE-ATTACK:T1003.001. Verified.
- WS-REG-LLMNR - `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` EnableMulticast absent or ne 0: LLMNR on (responder attacks). Medium; MITRE-ATTACK:T1557.001. Verified.
- WS-REG-NBT-NODETYPE - `SYSTEM\CurrentControlSet\Services\NetBT\Parameters` NodeType ne 2 (P-node): broadcast name resolution. Low. Verified.
- WS-REG-WPAD - `SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc` Start ne 4 and `SOFTWARE\Policies\...\Internet Settings` AutoDetect ne 0: proxy auto-detect lets a rogue WPAD host intercept. Medium; MITRE-ATTACK:T1557. Likely.
- WS-REG-CACHED-LOGONS - `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` CachedLogonsCount gt 4 (servers: gt 1): cached credential hashes. Low/medium; NIST-800-53:IA-5. Verified.
- WS-REG-HARDENED-UNC - `SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths` values for `\\*\SYSVOL` and `\\*\NETLOGON` absent or without RequireMutualAuthentication=1,RequireIntegrity=1: GPO tampering via relay (MS15-011). High; MITRE-ATTACK:T1557. Verified.
- WS-REG-UAC-LOCAL - `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` EnableLUA ne 1, ConsentPromptBehaviorAdmin eq 0, FilterAdministratorToken: the effective value, not only the GPO one (closes the backlog UAC item). High; NIST-800-53:AC-6. Verified.
- WS-REG-AUTOLOGON - `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` AutoAdminLogon eq 1 or DefaultPassword present: a stored clear password. Critical; MITRE-ATTACK:T1552.002. Verified (the runner must never return DefaultPassword's value - return presence only; add it to the refused-attributes list like LAPS).
- WS-REG-WINRM-INSECURE - `SOFTWARE\Policies\Microsoft\Windows\WinRM\Service` AllowBasic eq 1 or AllowUnencryptedTraffic eq 1; `...\WinRM\Client` same, plus `SYSTEM\CurrentControlSet\Control\Lsa\Credssp\...` AllowFreshCredentials. Medium; NIST-800-53:SC-8. Verified.
- WS-REG-SCHANNEL-LEGACY - `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<TLS 1.0|TLS 1.1|SSL 3.0>\Server` Enabled ne 0 (absent = OS default: on for TLS 1.0/1.1 before Server 2022/Win11 24H2), and `...\Ciphers\RC4*`; `SOFTWARE\Microsoft\.NETFramework\v4.0.30319` SchUseStrongCrypto ne 1. Medium; NIST-800-53:SC-13. Verified value names; the per-OS default needs the OS build in the rule (cross-class) - note in gaps.
- WS-REG-KERBEROS-RC4 - `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` SupportedEncryptionTypes absent or with bit 4 (RC4) set: RC4 Kerberos tickets (roasting). Medium; MITRE-ATTACK:T1558.003. Verified.
- WS-REG-SMB1-CLIENT - `SYSTEM\CurrentControlSet\Services\mrxsmb10` Start ne 4 and `...\LanmanWorkstation` DependOnService contains MRxSmb10 - the registry twin of the driver rule. Likely.
- WS-REG-WSUS-HTTP - `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` WUServer matches `^http://`: updates fetched over clear HTTP (WSUS poisoning). High; MITRE-ATTACK:T1557. Plus UseWUServer and `...\AU` NoAutoUpdate for the dual-scan item. Verified.
- WS-REG-UBR - `SOFTWARE\Microsoft\Windows NT\CurrentVersion` UBR and CurrentBuild: the exact patch level; condition "UBR lt threshold for this build" needs a per-build table (`threshold.windows.min-ubr-<build>`) - the comparison across two values is an engine gap, but recording UBR per host already improves WS-PATCH-NONE-RECENT's evidence.
- WS-REG-SECUREBOOT-CA2023 - `SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing` UEFICA2023Status / WindowsUEFICA2023Capable: Secure Boot certificate update not applied (the 2011 CA expires 2026). Medium. Likely (value names from the Secure Boot servicing KB; verify on first run).
- WS-REG-MDE-ONBOARDED - `SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status` OnboardingState ne 1 (and `...\Advanced Threat Protection` SenseId absent): not onboarded to Defender for Endpoint. High when MDE is the EDR; CIS-Controls-v8:13.7. Verified (onboarding verification doc).
- WS-REG-APPLOCKER-ENFORCED - `SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe` EnforcementMode ne 1 (absent = no policy): AppLocker for executables not enforced - the half of the backlog item WS-WDAC-AUDIT-ONLY cannot see. Medium; CIS-Controls-v8:2.5. Verified (SrpV2 structure).
- WS-REG-SECURITY-LOG-SIZE - `SYSTEM\CurrentControlSet\Services\EventLog\Security` MaxSize lt 196608000 (policy: `SOFTWARE\Policies\Microsoft\Windows\EventLog\Security` MaxSize): Win32_NTEventlogFile needs SeSecurityPrivilege; the registry does not. Low; NIST-800-53:AU-4. Verified.
- WS-REG-REBOOT-PENDING and WS-REG-PENDING-RENAMES - see the Fleet health section.
- WS-REG-CCM-* - see the SCCM client health section.

---

## Priority 2 - what breaks

#### WS-CLOCK-SKEW / WINSRV-CLOCK-SKEW - Host clock differs from the scanner's by more than Kerberos tolerates
- Catches / why: `Win32_OperatingSystem.LocalDateTime` more than 5 minutes away from the scanner's clock at read time. Past 5 minutes Kerberos fails: logons, shares and Group Policy stop with confusing errors. The scanner is domain-joined, so its clock stands in for the domain hierarchy (the backlog item asked for a host-to-host comparison; this is the practical form).
- Severity: high. Lens: both. Scope: per host.
- Source: both cim files, root/cimv2, `Win32_OperatingSystem` - LocalDateTime, CurrentTimeZone. New query: `SELECT LocalDateTime, CurrentTimeZone, LastBootUpTime FROM Win32_OperatingSystem`, key host (the existing OS query does not select LocalDateTime).
- Condition: `any` of LocalDateTime age-gt 0.0035 (days = 5 min; threshold `windows.clock-skew-max-days`) or `not: LocalDateTime until-lt 0.0035` (clock ahead). Guard: if every host fires by the same whole number of hours, the runner dropped the CIM UTC offset - that is a runner bug, not a fleet of bad clocks; test on one host first.
- Refs: NIST-800-53:AU-8, NIST-800-53:SC-45
- Fix: fix the time source chain (PDC emulator to an external source; members to the hierarchy); restart W32Time.
- Confidence: verified field; the engine's handling of fractional days and CIM datetime offsets is the open question (`value: 0.5` already runs in WS-PROC-HUNG-TOOL).

#### WS-CCM-UPDATE-RESTART-WAIT - Installed update waits for a restart (workstation)
- Twin of WINSRV-CCM-UPDATE-RESTART-WAIT; existing query WS-CCM-UPDATE-OVERDUE (root/ccm/ClientSDK CCM_SoftwareUpdate); condition EvaluationState in [8, 9, 10]. Severity medium; refs NIST-800-53:SI-2. Confidence: verified (rule exists for servers).

#### WS-PAGEFILE-NONE / WINSRV-PAGEFILE-NONE - No page file
- Catches / why: `Win32_PageFileUsage` returns no rows. With no page file the commit limit is RAM alone: WS-COMMIT-HIGH fires early, programs fail to allocate, and no crash dump is written. Usually an image or a "performance" tweak.
- Severity: low (servers medium). Lens: maintenance. Scope: per host.
- Source: cim, root/cimv2, `Win32_PageFileUsage` - Name, AllocatedBaseSize, CurrentUsage, PeakUsage. New query: `SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage FROM Win32_PageFileUsage`, key `{host}|{Name}`.
- Condition: count lt 1 (empty = the finding; a failed query = unknown).
- Refs: none.
- Fix: let Windows manage the page file, or set a fixed one sized for a kernel dump.
- Confidence: verified (https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pagefileusage).

#### WINSRV-DISK-UNHEALTHY - Physical disk reports warning or unhealthy (server)
- Twin of WS-DISK-UNHEALTHY; new query (copy) in windows-server.yaml, root/Microsoft/Windows/Storage `MSFT_PhysicalDisk` - DeviceId, FriendlyName, MediaType, HealthStatus, OperationalStatus; condition HealthStatus ne 0. Severity high (data loss on a server). Confidence: verified (rule exists for workstations). Virtual disks on hypervisors always report healthy - that is fine.

#### WS-NOT-ACTIVATED - Windows not activated (workstation)
- Twin of WINSRV-NOT-ACTIVATED; backlog "Windows activation on workstations"; same SoftwareLicensingProduct query; condition LicenseStatus ne 1. An unactivated PC nags, loses personalisation and, past grace, restarts; it also means the KMS/AD-activation path is broken for its subnet. Severity low; category CST. Confidence: verified.

#### SQL-TDE-IN-PROGRESS - Encryption or key change stuck in progress
- Catches / why: `sys.dm_database_encryption_state.encryption_state` in (2 encryption in progress, 4 key change in progress, 5 decryption in progress) for longer than a scan interval. A stuck scan usually means the encryption scan was suspended or the DB is read-only; the database is half protected and log backups behave oddly.
- Severity: medium. Lens: both. Scope: per database.
- Source: sql. New query: `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/' + DB_NAME(database_id) AS target, DB_NAME(database_id) AS database_name, encryption_state, encryption_state_desc, percent_complete, encryption_scan_state_desc, encryption_scan_modify_date FROM sys.dm_database_encryption_state WHERE database_id <> 2`, key target (encryption_scan_* columns exist from SQL 2019; on older versions select only the first four).
- Condition: encryption_state in [2, 4, 5] (refresh 6h; two consecutive hits = stuck - run-to-run history is an engine gap, so flag on every scan at low noise).
- Refs: NIST-800-53:SC-28
- Fix: `ALTER DATABASE ... SET ENCRYPTION RESUME` / finish the key rotation.
- Confidence: verified (https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-database-encryption-state-transact-sql).

#### SQL-DB-LOG-REUSE-WAIT - Transaction log cannot truncate because of replication, mirroring or an availability replica
- Catches / why: `log_reuse_wait_desc` in (REPLICATION, AVAILABILITY_REPLICA, DATABASE_MIRRORING, OLDEST_PAGE, XTP_CHECKPOINT). Unlike LOG_BACKUP (covered by SQL-BACKUP-LOG-OLD) these do not clear by backing up; the log grows until the volume is full. ACTIVE_TRANSACTION is left out: at any instant it is normal.
- Severity: medium. Lens: maintenance. Scope: per database. Refresh 6h.
- Source: the per-database attributes v2 query (SQL-DB-OWNER-ORPHAN).
- Condition: log_reuse_wait_desc in the list above and state_desc eq ONLINE.
- Refs: none.
- Fix: fix the replication agent / resume the replica / finish the mirror; for a dead publisher, `sp_repldone` after confirming.
- Confidence: verified.

#### SQL-AGENT-STARTUP-NOT-AUTO - SQL Agent running but not set to start automatically
- Existing query SQL-AGENT-NOT-RUNNING (`sys.dm_server_services`); condition servicename matches `^SQL Server Agent` and status_desc eq Running and startup_type_desc ne Automatic. After the next restart no job runs and nobody is told. Severity medium. Confidence: verified.

#### SQL-OS-MEMORY-LOW - Windows signals low memory to SQL Server
- Catches / why: `sys.dm_os_sys_memory.system_memory_state_desc` says "Available physical memory is low" or `sys.dm_os_process_memory.process_physical_memory_low = 1`. SQL Server is being trimmed; plans and buffers are evicted and everything slows. Companion of SQL-CFG-MAX-MEMORY-DEFAULT.
- Severity: medium. Lens: maintenance. Scope: per instance. Refresh 1h.
- Source: sql. New query: `SELECT m.total_physical_memory_kb, m.available_physical_memory_kb, m.system_memory_state_desc, p.physical_memory_in_use_kb, p.process_physical_memory_low, p.process_virtual_memory_low FROM sys.dm_os_sys_memory m CROSS JOIN sys.dm_os_process_memory p`, key instance.
- Condition: system_memory_state_desc matches `low` or process_physical_memory_low eq 1 or process_virtual_memory_low eq 1.
- Refs: none.
- Fix: set max server memory with headroom; find the other consumer on the host; add memory.
- Confidence: verified (https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-os-sys-memory-transact-sql).

#### SQL-AGENT-NO-OPERATOR - No enabled Agent operator
- Catches / why: `msdb.dbo.sysoperators` has no enabled row. Without an operator no job failure or alert can notify anyone; SQL-AGENT-JOB-FAILING findings are then the only warning.
- Severity: medium. Lens: maintenance. Scope: per instance (count none).
- Source: sql (msdb). New query: `SELECT id, name, enabled, email_address FROM msdb.dbo.sysoperators`, key `{instance}|{name}`.
- Condition: count lt 1 where enabled eq 1.
- Refs: NIST-800-53:SI-4
- Fix: create an operator with a team mailbox; set Database Mail; put the operator on every backup and integrity job (`notify_level_email`).
- Confidence: verified.

#### SQL-AGENT-ALERTS-NONE - No alerts for severity 19-25 and corruption errors 823/824/825
- Catches / why: `msdb.dbo.sysalerts` lacks enabled alerts for these. These are the errors that mean corruption or a crash; without alerts they are found at restore time.
- Severity: medium. Lens: maintenance. Scope: per instance.
- Source: sql (msdb). New query: `SELECT id, name, enabled, severity, message_id, has_notification FROM msdb.dbo.sysalerts`, key `{instance}|{name}`.
- Condition: count lt 1 where enabled eq 1 and (severity ge 19 or message_id in [823, 824, 825]) - a second rule or a stricter where (count lt 10) for "all of them" if wanted.
- Refs: NIST-800-53:SI-4, NIST-800-53:SI-7
- Fix: create the standard alert set with a notification to the operator.
- Confidence: verified.

#### SQL-AGENT-JOB-RUNNING-LONG - Agent job running for more than 12 hours
- Catches / why: `msdb.dbo.sysjobactivity` rows of the current Agent session with `start_execution_date` set and `stop_execution_date` NULL for longer than the threshold - a hung backup or maintenance job holding locks and blocking the next run.
- Severity: medium. Lens: maintenance. Scope: per job. Refresh 1h.
- Source: sql (msdb). New query: `SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) + N'/' + j.name AS target, j.name AS job_name, a.start_execution_date, a.last_executed_step_id FROM msdb.dbo.sysjobactivity a JOIN msdb.dbo.sysjobs j ON j.job_id = a.job_id WHERE a.session_id = (SELECT MAX(session_id) FROM msdb.dbo.syssessions) AND a.start_execution_date IS NOT NULL AND a.stop_execution_date IS NULL`, key target.
- Condition: start_execution_date age-gt 0.5 (threshold `sql.job-max-run-days`).
- Refs: none.
- Fix: look at the step and its blocking session; stop the job if it is wedged.
- Confidence: verified.

#### SCCM-DP-DRIVE-LOW-SPACE - Distribution point drive is low on free space
- Catches / why: `SMS_DistributionPointDriveInfo.PercentFree` below the floor. The site-system summarizer rule sees site-server storage objects; remote and pull DPs show here, and a full DP fails every new package silently (and Status carries the last copy error).
- Severity: PercentFree < 5 critical, else high. Lens: maintenance. Scope: estate-wide, per DP drive.
- Source: sccm.yaml, http, `/wmi/SMS_DistributionPointDriveInfo`, `$select: NALPath,Drive,BytesTotal,BytesFree,PercentFree,Status,SiteCode`, key `{NALPath}|{Drive}`, name NALPath.
- Condition: BytesTotal gt 0 and PercentFree lt 10 (threshold `sccm.dp-drive-free-pct-min`); a second rule SCCM-DP-DRIVE-COPY-ERROR: Status ne 0.
- Refs: NIST-800-53:SC-5
- Fix: clean the content library (orphans, old images), set the drive priority, or extend the volume.
- Confidence: verified (https://learn.microsoft.com/intune/configmgr/develop/reference/core/servers/configure/sms_distributionpointdriveinfo-server-wmi-class; BytesFree/BytesTotal are in KB).

#### SCCM-DP-CONTENT-ERRORS - Distribution point with failed content installations
- Catches / why: `SMS_DPStatusInfo.NumberErrors > 0` or `MessageState = 3`. SCCM-DP-CONTENT-FAILED lists packages; this names the sick DP (one finding per DP with the count) and the last time it reported (`LastStatusTime`).
- Severity: high. Lens: maintenance. Scope: estate-wide, per DP.
- Source: sccm.yaml, http, `/wmi/SMS_DPStatusInfo`, `$select: NALPath,Name,MessageState,MessageCount,NumberErrors,NumberInProgress,NumberInstalled,NumberUnknown,LastStatusTime,IsPullDP,IsPXE,Version`, key NALPath, name Name.
- Condition: NumberErrors gt 0 or MessageState eq 3. Also SCCM-DP-STATUS-STALE: LastStatusTime age-gt 2 (a DP that stopped reporting). Also SCCM-DP-VERSION-BEHIND: Version notmatch the site's version pattern (`threshold.sccm.dp-version-pattern`) - a DP that failed to upgrade with the site.
- Refs: NIST-800-53:SI-2 (DP version), none otherwise.
- Fix: Distribution Status > Distribution Point Configuration Status; redistribute failed content; reinstall the DP role if the upgrade failed.
- Confidence: verified (https://learn.microsoft.com/intune/configmgr/develop/reference/core/servers/configure/sms_dpstatusinfo-server-wmi-class).

#### SCCM-COLLECTION-REFRESH-STALE - Scheduled collection has not been evaluated for days
- Catches / why: a collection with periodic refresh (RefreshType 2 or 6) whose `LastRefreshTime` is older than its longest plausible schedule. The collection evaluator is stuck or the schedule is broken; deployments to it never gain new members.
- Severity: medium. Lens: maintenance. Scope: estate-wide, per collection.
- Source: sccm.yaml, http, `/wmi/SMS_Collection`, `$filter: "RefreshType eq 2 or RefreshType eq 6"`, `$select: CollectionID,Name,RefreshType,MemberCount,LastRefreshTime,LastMemberChangeTime,LastChangeTime,CurrentStatus,IsBuiltIn,FullEvaluationRunTime,IncrementalEvaluationRunTime,FullEvaluationNextRefreshTime`, key CollectionID, name Name (shared with the next two).
- Condition: LastRefreshTime age-gt 8 (threshold `sccm.collection-refresh-max-days`) and IsBuiltIn eq false. Note RefreshType is marked lazy in the SDK page; the existing SCCM-COLLECTIONS-INCREMENTAL-MANY already filters on it through AdminService, so it is returned.
- Refs: none.
- Fix: colleval.log; check the schedule token; restart the collection evaluator queue.
- Confidence: verified (https://learn.microsoft.com/intune/configmgr/develop/reference/core/clients/collections/sms_collection-server-wmi-class).

#### SCCM-COLLECTION-EVAL-SLOW - Collection takes minutes to evaluate
- Same query without the filter; condition FullEvaluationRunTime gt 300 or IncrementalEvaluationRunTime gt 60 (seconds; thresholds `sccm.collection-full-eval-max-seconds`, `...-incremental-...`). Slow query rules (nested includes, SMS_G_System_* joins) hold the evaluator for everyone. Severity low. Confidence: verified (properties exist since version 2010).

#### SCCM-COLLECTION-EMPTY-STALE - Empty collection untouched for six months
- Same query; condition MemberCount eq 0 and IsBuiltIn eq false and LastChangeTime age-gt 180 and LastMemberChangeTime age-gt 180. Hygiene: dead collections still cost evaluation time and confuse targeting. Severity low; category HYG. Confidence: verified.

#### SCCM-DEPLOYMENT-SUMMARY-STALE - Deployment summary not refreshed for days
- Query of SCCM-DEPLOYMENT-TO-ALL-SYSTEMS; condition SummarizationTime age-gt 3 and DeploymentTime age-lt 90 (threshold `sccm.summary-max-age-days`). The console (and every count-based rule here) shows numbers days old; the summarizer is backed up. Severity low. Confidence: verified.

#### WSF-CLIENT-CHECK-STALE - Active client has not run the client health evaluation
- Catches / why: IsClient 1, IsActive 1 and `LastClientCheckTime` absent or older than 7 days. ccmeval runs daily from a scheduled task; silence means the Task Scheduler is broken on the PC (a cause of stuck gpsvc/schtasks seen in the field) or ccmeval itself fails before reporting. The site still shows the client as active - this is the case where "active" lies.
- Severity: medium. Lens: maintenance. Scope: estate-wide, per device.
- Source: the SMS_CombinedDeviceResources query of WSF-EP-INFECTED.
- Condition: IsClient eq 1 and IsActive eq 1 and (LastClientCheckTime absent or age-gt 7; threshold `workstations.client-check-max-age-days`). Also WSF-CLIENT-REMEDIATION-FAILED: ClientRemediationSuccess eq 0 with ClientCheckPass eq 2 (ccmeval found a fault and could not fix it) - value meanings are a guess; verify on first run.
- Refs: NIST-800-53:SI-4
- Fix: on the PC: Task Scheduler service, the "Configuration Manager Health Evaluation" task, CcmEval.log.
- Confidence: likely (console column "Last Client Check Time" = LastClientCheckTime in v_CombinedDeviceResources; WMI spelling unverified).

---

## Priority 3 - lifecycle and hygiene

#### WS-OS-PRO-BUILD-UNSUPPORTED - Home/Pro edition on a build whose shorter servicing ended
- Catches / why: WS-OS-BUILD-UNSUPPORTED judges by Enterprise/Education dates. Home, Pro, Pro Education and Pro for Workstations get 24 months: 23H2 (22631) ended 2025-11-11 and 24H2 (26100) ended 2026-10-13. A Pro PC on 24H2 gets no more security updates today, while the Enterprise rule calls it fine until 2027.
- Severity: high. Lens: both. Scope: per host.
- Source: workstations.yaml, cim, existing query WS-UPTIME-LONG (`Win32_OperatingSystem` Caption, BuildNumber).
- Condition: Caption matches `Windows 1[01] (Home|Pro)` and Caption notmatch `Enterprise|Education|LTSC` and BuildNumber in [22631, 26100] (threshold `workstations.pro-unsupported-builds`; add 26200 on 2027-10-12). Note: Win32_OperatingSystem has `OperatingSystemSKU` too (48 Pro, 4 Enterprise, 125/126 Enterprise LTSC, 101 Home) - more robust than Caption on localised builds; add it to the select.
- Refs: NIST-800-53:SA-22, NIST-800-53:SI-2, CIS-Controls-v8:2.2
- Fix: feature-update the device (Pro 25H2 runs to 2027-10-12) or license Enterprise.
- Confidence: verified dates (https://learn.microsoft.com/windows/release-health/windows11-release-information, read 2026-10-20); SKU values https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem.

#### WSF-OS-PRO-BUILD-UNSUPPORTED - same from inventory
- Source: workstations-sccm.yaml, http, existing query WSF-UPTIME-LONG (`SMS_G_System_OPERATING_SYSTEM` Caption, BuildNumber; add OperatingSystemSKU to the select). Same condition on Caption/BuildNumber. Severity high. Confidence: verified.

#### WINSRV-OS-MAINSTREAM-ENDED - Server release in extended support only
- Catches / why: build 17763 (2019, mainstream ended 2024-01-09) or 20348 (2022, mainstream ended 2026-10-13). Extended support means security fixes only: no non-security fixes, no new features, hotpatch ends for 2022 Azure Edition. It is the planning signal before WINSRV-OS-ENDING.
- Severity: low. Lens: both. Scope: per host. Refresh 7d.
- Source: windows-server.yaml, cim, existing query WINSRV-OS-UNSUPPORTED.
- Condition: BuildNumber in [17763, 20348] (threshold `windows-server.builds-mainstream-ended`).
- Refs: NIST-800-53:SA-22
- Fix: plan the move to Server 2025 (mainstream to 2029-11-13).
- Confidence: verified (https://learn.microsoft.com/lifecycle/products/windows-server-2022, .../windows-server-2019, .../windows-server-2025).

#### SQL-VERSION-MAINSTREAM-ENDED - SQL Server in extended support only (no more CUs)
- Existing query SQL-VERSION-EOS; condition major_version in [15] (threshold `sql.major-versions-mainstream-ended`; 2019 mainstream ended 2025-02-28, final CU32, security GDRs only). Severity low; refs NIST-800-53:SA-22. Confidence: verified (https://learn.microsoft.com/lifecycle/products/sql-server-2019).

#### SQL-BUILD-OLD (existing) - raise the floor pattern
- Not a new rule: the default of `sql.outdated-build-pattern` should also flag 2019 below CU32 (`15\.0\.([0-3]\d{3}|4[0-3]\d\d|44[0-2]\d)\.`) and 2022 more than three CUs behind CU27 (`16\.0\.4([01]\d\d|2[0-4]\d|25[0-4])\.` - below CU25 16.0.4255). Builds verified today: 2019 CU32 = 15.0.4430.1, CU32+GDR 15.0.4500.2; 2022 CU25 16.0.4255.1, CU26 16.0.4265.3, CU27 16.0.4295.3, CU27+GDR 16.0.4305.5 (https://support.microsoft.com/servicing/sql/sql-server-2019/kb4518398-build-versions and .../sql-server-2022/kb5023451-build-versions). The GDR-only branches (15.0.2xxx, 16.0.1xxx) are security-current but CU-less; the pattern must not flag them as old - treat `15\.0\.2\d{3}\.` and `16\.0\.1\d{3}\.` as "GDR branch" in a separate low-severity rule SQL-BUILD-GDR-BRANCH.

#### SCCM-SUG-SUPERSEDED-UPDATES - Deployed update group still contains superseded updates
- Existing query SCCM-SUG-EXPIRED-UPDATES; condition IsDeployed eq true and ContainsSupersededUpdates eq true and DateLastModified age-gt 60. Superseded updates are still evaluated and can still install, then be replaced - double work on every client. Severity low; HYG. Confidence: verified (field already selected).

#### SCCM-ADR-DISABLED - Automatic deployment rule disabled
- Existing query SCCM-ADR-FAILING; condition AutoDeploymentEnabled eq false and LastRunTime age-gt 60. A rule somebody turned off "for a month" means its collections stopped receiving updates. Severity medium; refs NIST-800-53:SI-2. Confidence: verified.

#### SCCM-DRIVER-PACKAGE-STALE - Driver package not updated for two years
- Backlog "expressible, not written". http `/wmi/SMS_DriverPackage`, `$select: PackageID,Name,SourceDate,LastRefreshTime,PackageSize`, key PackageID; condition SourceDate age-gt 730 (threshold `sccm.driver-package-max-age-days`). Old drivers in task sequences image new hardware with wrong storage/NIC drivers. Severity low. Confidence: likely (SMS_DriverPackage derives from SMS_PackageBaseclass, which has SourceDate).

#### SCCM-OSIMAGE-STALE - OS image not serviced for a year
- http `/wmi/SMS_ImagePackage`, `$select: PackageID,Name,SourceDate,LastRefreshTime,ImageOSVersion`, key PackageID; condition SourceDate age-gt 365. An image a year behind needs an hour of cumulative updates at every deployment and ships known holes until then. Severity low. (ImageOSVersion is lazy per the backlog; SourceDate is not.) Confidence: likely.

#### WS-PROFILE-STALE - User profiles unused for a long time pile up on a workstation
- Backlog "expressible, not written" - with a caveat: `Win32_UserProfile.LastUseTime` is refreshed by background activity on Windows 10 1809+ and is unreliable; `LastUseTime` on Windows 11 is better. cim root/cimv2 `Win32_UserProfile WHERE Special = FALSE AND Loaded = FALSE` - SID, LocalPath, LastUseTime, LastDownloadTime; key `{host}|{SID}`; condition count gt 15 (profiles present) as the reliable rule (`threshold.workstations.profiles-max`), and LastUseTime age-gt 180 as a second, low-confidence rule. Severity low; HYG. Fix: delete profiles older than N days by policy. Confidence: verified class; unreliable semantics.

#### SQL-SA-NOT-RENAMED - The sa login still carries its default name
- Existing query SQL-SA-ENABLED; condition name eq sa. CIS-MSSQL:2.14; low. Confidence: verified.

#### SQL-TCP-DEFAULT-PORT - Engine listens on 1433
- sql `SELECT listener_id, ip_address, port, type_desc, state_desc FROM sys.dm_tcp_listener_states WHERE type_desc = N'TSQL'`, key `{instance}|{listener_id}`; condition port eq 1433 and ip_address ne 127.0.0.1. CIS-MSSQL:2.11; low (obscurity, but scanners try 1433 first). Confidence: verified (https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-tcp-listener-states-transact-sql).

#### SQL-BROWSER-RUNNING - SQL Server Browser service running
- Existing query SQL-AGENT-NOT-RUNNING; condition servicename matches `^SQL Server Browser` and status_desc eq Running. The Browser answers UDP 1434 enumeration; needed only for named instances without fixed ports. CIS-MSSQL:2.12 (hide instance) context; low. Confidence: verified (the Browser appears in sys.dm_server_services from 2016 SP2).

---

## SCCM client health - from both sides, per device

A client the site calls "active" can be broken (ccmexec running, inventory and policy dead), and a
PC the site calls "inactive" can be fine (the record is stale or duplicated). Every check below
runs per device; the site side is one list per check, the PC side one read per host. **Authoritative**
says which side to believe when they disagree, and the pairs are keyed so the ranker can show them
together (site rows by device name, PC rows by host).

### Site side (http AdminService, `rules\workstations-sccm.yaml`; servers in `rules\sccm.yaml`)

Query A (new): `/wmi/SMS_CombinedDeviceResources`, `$select: ResourceID,Name,SMSID,IsClient,IsActive,IsObsolete,IsApproved,IsBlocked,SiteCode,ClientVersion,ClientCheckPass,ClientRemediationSuccess,LastClientCheckTime,LastPolicyRequest,LastDDR,LastHardwareScan,LastSoftwareScan,LastStatusMessage,LastActiveTime,LastMPServerName,CNIsOnline,CNLastOnlineTime,ADLastLogonTime,DeviceOS,MACAddress,SerialNumber`, key ResourceID, name Name. Field names are **likely** (console columns / v_CombinedDeviceResources; no Microsoft class page); the ones already used by WSF rules are verified in practice.

- **WSF-CLIENT-INACTIVE** (exists) - IsActive 0. Authoritative: PC side (ccmexec running + recent inventory on the PC = the site record is stale, fix the record; not running = the PC).
- **WSF-CLIENT-CHECK-FAILED** (exists) and **WSF-CLIENT-CHECK-STALE** (P2 above) - ClientCheckPass 2 / LastClientCheckTime old. Client-check *details*: `/wmi/SMS_CH_EvalResults` (ResourceID, HealthCheckDescription, Result, ResultCode, ResultDetail, EvaluationTime) keyed `{ResourceID}|{HealthCheckDescription}` - **guess** at the class name (the SQL view is v_CH_EvalResults); condition Result ne 7 (7 = passed in the view; verify). Authoritative: site (it is the PC's own ccmeval report).
- **WSF-POLICY-STALE** (exists) - LastPolicyRequest > 7 d. Authoritative: site.
- **WSF-HEARTBEAT-STALE** (new) - IsClient 1, IsActive 1 and LastDDR absent or age-gt 7 (`workstations.ddr-max-age-days`): the heartbeat discovery record is what keeps the record active; a stale DDR with a recent policy request means the DDR inbox is backed up or the client's heartbeat schedule is broken. Severity medium. Authoritative: site.
- **WSF-HWINV-STALE** (exists) and **WSF-SWINV-STALE** (new, only when software inventory is enabled: LastSoftwareScan age-gt 30, `workstations.sw-inventory-max-age-days`, low, off by default via a threshold that disables it). Authoritative: PC side for the cause (InventoryActionStatus), site for the fact.
- **WSF-STATUS-MESSAGE-STALE** (new) - LastStatusMessage age-gt 14 on an active client: state/status messages are not reaching the MP (certificate, MP down, inbox backlog). Medium. Authoritative: site.
- **WSF-CLIENT-VERSION-BEHIND-SITE** (new) - ClientVersion below the site's build: SCCM-CLIENT-VERSION-UNSUPPORTED uses a fixed pattern; comparing to `SMS_Site.Version` is a cross-query comparison (engine gap). Interim: `threshold.sccm.site-client-version-pattern` set to the site's current build on each upgrade; condition ClientVersion notmatch it and IsClient 1. Medium. Authoritative: PC side (`SMS_Client.ClientVersion`) when they differ - the site's copy comes from the last heartbeat.
- **WSF-NO-ASSIGNED-SITE** (new) - IsClient 1 and SiteCode empty: a client that lost its assignment gets no policy. High. Authoritative: PC side (SMS_Authority).
- **WSF-CLIENT-BLOCKED-OR-UNAPPROVED** (new) - IsBlocked 1, or IsApproved 0 with IsClient 1 and IsActive 1 (approval set to manual and nobody approving): the client is denied policy while it looks healthy. Medium. Authoritative: site (it is a site decision).
- **WSF-RECORD-DUPLICATE-NAME** / **-SMBIOS** (new) - two records with the same Name (one obsolete, one not) or the same SMBIOS GUID / SerialNumber: reimaged PCs that keep the old record, which deployments and reports then count twice. Needs group-by - engine gap; interim: `/wmi/SMS_R_System` with `$filter: "Obsolete eq 1 and Client eq 1"` (obsolete records that still claim a client) each any, low. Authoritative: site.
- **WSF-NO-BOUNDARY-GROUP** (new) - BoundaryGroups absent/empty on an active client (`SMS_CombinedDeviceResources.BoundaryGroups` - **guess**; the console shows a "Boundary Group(s)" column). A client in no boundary group has no content location (the field case behind WSF-NO-AD-SITE). High. Authoritative: site (the client's current IP decides; cim can show the IP, the site the groups).
- **WSF-MP-STALE** (new) - LastMPServerName names an MP that no longer exists (`$select` from `/wmi/SMS_SystemResourceList` with RoleName 'SMS Management Point' - cross-query; interim threshold `sccm.mp-name-pattern`). Low. Authoritative: PC side (SMS_Authority.CurrentManagementPoint).

### PC side (cim / registry / eventlog, `rules\workstations.yaml` and `rules\windows-server.yaml`)

- **WS-CCM-SERVICE** - cim root/cimv2 `Win32_Service WHERE Name = 'CcmExec'` - Name, State, StartMode, StartName, PathName; key host. Conditions: (a) count lt 1 -> **WS-CCM-SERVICE-MISSING**: the client is not installed on an in-scope PC (confirmed by cim, the site says what it says - authoritative: PC; pairs with WSF-NO-CLIENT); (b) State ne Running or StartMode ne Auto -> **WS-CCM-SERVICE-DOWN** (existing WS-SVC-AGENT-STOPPED catches the stopped case; this adds Disabled/Manual). High. Verified (Win32_Service).
- **WS-CCM-INSTALLED-NO-SERVICE** - the "installed but service missing" case: registry `path: SOFTWARE\Microsoft\SMS\Mobile Client`, values [ProductVersion, AssignedSiteCode, GPRequestedSiteAssignmentCode], key host, condition exists eq true - and WS-CCM-SERVICE-MISSING on the same host. Cross-rule correlation is the ranker's job; alone each is a finding. **Likely** (the key is documented in client install troubleshooting; value names from field use).
- **WS-CCM-CLIENT-VERSION** - cim root/ccm `SMS_Client` - ClientVersion, AllowLocalAdminOverride, EnableAutoAssignment; key host. Condition ClientVersion notmatch `threshold.sccm.site-client-version-pattern` -> **WS-CCM-VERSION-BEHIND**. Also AllowLocalAdminOverride eq true -> **WS-CCM-LOCAL-OVERRIDE** (a local admin may point the client at another MP; low, security). Authoritative: PC. **Verified** class (SMS_Client is documented: https://learn.microsoft.com/intune/configmgr/develop/reference/core/clients/client-classes/sms_client-client-wmi-class).
- **WS-CCM-ASSIGNMENT** - cim root/ccm `SMS_Authority` - Name (`SMS:<site>`), CurrentManagementPoint, Capabilities; key host. Conditions: count lt 1 -> **WS-CCM-NO-ASSIGNMENT** (client not assigned; high); Name notmatch `^SMS:` + `threshold.sccm.site-code-pattern` -> **WS-CCM-WRONG-SITE** (a client talking to another site/lab); CurrentManagementPoint empty -> **WS-CCM-NO-MP**. Authoritative: PC. **Verified** class (SMS_Authority documented, 2007-era page: https://learn.microsoft.com/previous-versions/system-center/developer/cc145440(v=msdn.10)); registry twin `SOFTWARE\Microsoft\SMS\Mobile Client` AssignedSiteCode (likely).
- **WS-CCM-INVENTORY-CYCLE-STALE** - cim root/ccm/invagt `InventoryActionStatus` - InventoryActionID, LastCycleStartedDate, LastReportDate, LastMajorReportVersion; key `{host}|{InventoryActionID}`. Action ids are Microsoft constants: `{00000000-0000-0000-0000-000000000001}` hardware inventory, `{...002}` software inventory, `{...003}` heartbeat discovery, `{...010}` file collection. Conditions per id (template key gives one finding per action): LastReportDate age-gt 7 for 001 and 003 (hardware inventory, heartbeat), 30 for 002 when enabled; `LastCycleStartedDate` newer than `LastReportDate` by days = the cycle starts and never reports (inventory too large, WMI broken) - cross-field, engine gap; interim: LastReportDate alone. Also count lt 1 where InventoryActionID eq 001 -> **WS-CCM-INVENTORY-NEVER**: the class has no hardware-inventory row at all (policy never applied). High/medium. Authoritative: **PC** - this is the ground truth behind WSF-HWINV-STALE and WSF-HEARTBEAT-STALE; when the site says stale and the PC says reported yesterday, the site's inbox/MP is the problem, not the PC. **Verified** class and fields (https://learn.microsoft.com/previous-versions/system-center/developer/cc143565(v=msdn.10)); the action GUIDs are **likely** (widely documented in community material, not on that page).
- **WS-CCM-CACHE** - cim root/ccm/SoftMgmtAgent `CacheConfig` - Size (MB), Location, NextAvailableId, InUse; key host. Conditions: Size lt 5120 (`workstations.ccm-cache-min-mb`) -> **WS-CCM-CACHE-SMALL** (feature updates and large apps fail to download; low); Location notmatch `^[A-Za-z]:\\Windows\\ccmcache$` -> **WS-CCM-CACHE-MOVED** (info). Free space in the cache is not a property; the cache's used bytes need a sum over `CacheInfoEx` rows (ContentSize, LastReferenced) - engine gap (sum); interim: count gt 200 rows -> **WS-CCM-CACHE-CROWDED**, low. Authoritative: PC (the site has no view of the cache). **Likely** (class and Size/Location widely used; no Microsoft page found today).
- **WS-CCM-EVAL** - registry `path: SOFTWARE\Microsoft\CCM\CcmEval`, values [LastEvalTime, LastSiteCode] (**likely**: a third-party inventory report names exactly these two; `LastEvalResult` could not be confirmed and should be treated as **guess** - the result lives in CcmEval.log and in the site's SMS_CH_EvalResults), key host. Condition: exists eq false -> **WS-CCM-EVAL-NEVER** (ccmeval never ran: the scheduled task is missing/broken); LastEvalTime age-gt 7 -> **WS-CCM-EVAL-STALE**. The value is a CIM datetime string (`yyyyMMddHHmmss.ffffff+zzz`) - the registry runner must parse it or the rule must use `match` on the year/month. Authoritative: PC for *when* it ran, site for *what it found*.
- **WS-CCM-EVAL-TASK** - the "Configuration Manager Health Evaluation" scheduled task: MSFT_ScheduledTask (root/Microsoft/Windows/TaskScheduler) State, LastRunTime via method - engine gap (methods). Interim: WS-CCM-EVAL covers it.
- **WS-CCM-PKI-CERT** - cim root/ccm `CCM_ClientIdentificationInformation`? **guess**; the reliable reads are `SMS_Client`-side `ClientCertificate` in `CCM_Client`... not documented; use registry `path: SOFTWARE\Microsoft\CCM`, values [HttpsState, ClientCertificateSelectionCriteria] (**guess**) and eventlog: the client logs certificate failures to ClientIDManagerStartup.log only, not the event log. Mark as **not possible** today beyond "HTTPS mode flag set but no machine certificate" - machine certificates are not readable over CIM (backlog). Authoritative: PC.
- **WS-WMI-REPOSITORY** - eventlog `log: Microsoft-Windows-WMI-Activity/Operational`, ids [5858], days 7 - count gt 50 per host (`workstations.wmi-error-max-7d`) -> **WS-EVT-WMI-ERRORS** (see Fleet health); plus cim root/cimv2 a trivial `SELECT Name FROM Win32_ComputerSystem` already proves WMI answers; the SCCM-specific proof is `root/ccm` answering at all: a failing SMS_Client query on a PC whose cimv2 answers -> **WS-CCM-NAMESPACE-BROKEN** (the client's WMI namespace is damaged; ccmrepair needed) - needs the runner to distinguish "namespace not found" from "host unreachable" in the unknown reason (engine note). Authoritative: PC.
- **WS-CCM-EVENTLOG** - what the client writes to Windows event logs: little. The CcmExec service logs through SCM (7000/7009/7011/7031/7034 with param1/param2 = CcmExec) -> covered by **WS-EVT-SERVICE-FAIL** / **WS-EVT-SERVICE-TIMEOUT** (Fleet health) with a `providers`/service-name filter on CcmExec; Software Center / client restart notices appear under provider `Microsoft-Windows-ConfigMgr`? **guess** - not relied on. Everything else is in the CCM log files, which no protocol reads.

### Which side wins

| Check | Authoritative | Why |
|---|---|---|
| client installed / service present | PC | the site record lags days and keeps obsolete rows |
| active / inactive | PC when it answers; site when the PC is offline | an offline PC is a PC fact, not a client fault |
| client check pass/fail | site (ccmeval's own report) | the PC only holds the time |
| last policy request, status message, heartbeat | site | they are MP-side facts |
| inventory last reported | PC (InventoryActionStatus) | the site's date is after the inbox; a gap between them locates the fault |
| client version, assigned site, MP | PC | the site's copy is from the last heartbeat |
| blocked / unapproved | site | a site decision |
| duplicates, boundary groups | site | need the site's view of all records / the IP-to-group mapping |
| cache | PC | the site has no view |

---

## Fleet health (from Get-FleetSlowness)

Source: `03-Windows-Estate\Windows\fleet-slowness\Get-FleetSlowness.ps1` (read in full, not run or
edited). The script's unit is the fleet (how many PCs share a signal, in which subnet and hour);
Keeper's unit is the host, and the ranker folds a check that fails on many hosts into one task with
its count - that is the "WIDE/SPREAD" column. What the script does per PC maps as below; what it
does *across* PCs (subnet %, same-hour incidents, with/without medians, baseline compare) is
listed under engine gaps. Tenant specifics in the script (agent names, server names, OU naming) are
not carried over: agents become `threshold.workstations.required-agent-pattern` and friends,
server names come out of the event rows themselves.

Conventions: all eventlog checks are per host over all workstations (servers where said), `days: 7`
(`threshold.workstations.eventlog-window-days`), `count` with `where`, thresholds as settings. The
script's `Prov` regexes become `providers` lists (the protocol takes names, not a regex): where the
script used a regex over many drivers (NIC link-down event 27) the list must name the common NIC
drivers (`threshold.workstations.nic-driver-providers`) - a gap noted below. The `Key` columns (DNS
name, server, program, service) are event data fields the protocol returns as attributes, so each
finding's evidence names the thing, and the ranker's grouping by evidence gives the script's "Top"
column.

### Event-log signal table -> eventlog rules (`WS-EVT-*`, `rules\workstations.yaml`)

| Script tag | Log / ids / provider | Proposal | Condition (per host, 7 d) | Severity | Evidence field |
|---|---|---|---|---|---|
| DnsTimeout | System 1014, DNS-Client | WS-EVT-DNS-TIMEOUT | count ge 20 (`dns-timeouts-max-7d`) | medium | QueryName |
| DnsRegFail | System 8015/8018/8019/8020, DNS-Client | WS-EVT-DNS-REGISTER-FAIL | count ge 3 | low | - (pairs with WS-DNS-STALE-RECORD below) |
| NoDc | System 5719/5783, NETLOGON | WS-EVT-NO-DC | count ge 1 (any 5719 outside boot is a finding; `nodc-max-7d`) | high | param1 (domain) |
| LsaNegotiate | System 40960/40961, LsaSrv | WS-EVT-LSA-NEGOTIATE | count ge 5 | medium | target name (param) |
| Kerberos | System 3/4/14, Microsoft-Windows-Security-Kerberos | WS-EVT-KERBEROS-ERROR | count ge 1 for id 4 (duplicate SPN - always real), ge 5 for 3/14 | medium | SPN / server |
| GpNoDc | System 1006/1030/1053/1054/1055/1058/1129, GroupPolicy | WS-EVT-GP-FAILURE | count ge 2 | high | ErrorCode, ErrorDescription |
| TimeSync | System 36/47/50/129/134, Microsoft-Windows-Time-Service | WS-EVT-TIME-SYNC-FAIL | count ge 2 (and WS-CLOCK-SKEW for the effect) | medium | time source |
| DhcpFail | System 1001/1002/1003, Dhcp (Microsoft-Windows-Dhcp-Client) | WS-EVT-DHCP-FAIL | count ge 2 | medium | adapter |
| IpConflict | System 4199, Tcpip | WS-EVT-IP-CONFLICT | count ge 1 | high | conflicting MAC |
| PortExhaust | System 4227/4231, Tcpip | WS-EVT-PORT-EXHAUSTION | count ge 1 | high | - |
| NicReset | System 10400/10401/10402, NDIS | WS-EVT-NIC-RESET | count ge 2 | medium | adapter |
| NicLinkDown | System 27, NIC driver providers | WS-EVT-NIC-LINK-DOWN | count ge 10 (`nic-linkdown-max-7d`; docking PCs flap) | low | adapter |
| WifiDrop | WLAN-AutoConfig/Operational 8002/8003 | WS-EVT-WIFI-DROP | count ge 30 (`wifi-drops-max-7d`) | low | SSID |
| WifiConnect | WLAN-AutoConfig/Operational 8001 | WS-EVT-WIFI-UNMANAGED-SSID | count ge 1 where SSID notmatch `threshold.workstations.managed-ssid-pattern` (a wired PC on a phone hotspot - the 20.10 field case) | medium (security: data leaves the perimeter) | SSID |
| NcsiChange | NCSI/Operational 4042 | WS-EVT-NCSI-FLAP | count ge 20 (`ncsi-changes-max-7d`) | low | Capability (name unconfirmed) |
| CrlFetch | Application 11/4107, Microsoft-Windows-CAPI2 | WS-EVT-CRL-FETCH-FAIL | count ge 5 | medium | URL |
| Tls | System 36871/36874/36887/36888, Schannel | WS-EVT-SCHANNEL-FAIL | count ge 50 (noisy by nature) | low | alert code |
| SmbFail | SMBClient/Connectivity 30803 | WS-EVT-SMB-CONNECT-FAIL | count ge 3 | medium | ServerName (confirmed) |
| SmbDrop | SMBClient/Connectivity 30804/30805/30807 | WS-EVT-SMB-SESSION-DROP | count ge 5 | medium | ServerName |
| SmbNoName | SMBClient/Connectivity 30800 | WS-EVT-SMB-NAME-UNRESOLVED | count ge 1 (a retired server still referenced) | medium | ServerName (confirmed) |
| SmbAuthFail | SMBClient/Security 31001/31002 | WS-EVT-SMB-AUTH-FAIL | count ge 10 (`smb-auth-fail-max-7d`; the field case was hundreds a day) | medium (security) | ServerName (confirmed) |
| Disk | System 7/51/55/129/140/153, providers disk, storahci/stornvme/storport, iaStor*, Ntfs, volmgr, partmgr | WS-EVT-DISK-ERROR | count ge 1 for 7/51/55, ge 5 for 129/153 (retries) | high | device |
| LowMemory | System 2004, Resource-Exhaustion-Detector | WS-EVT-OUT-OF-MEMORY | count ge 1 | medium | process names in event data |
| CpuLimited | System 37, Kernel-Processor-Power | WS-EVT-CPU-THROTTLED | count ge 1 | medium | - (pairs with model via Win32_ComputerSystem) |
| BadShutdown | System 41 Kernel-Power, 6008 EventLog, 1001 BugCheck/WER-SystemErrorReporting | WS-EVT-UNEXPECTED-SHUTDOWN | count ge 1 (41/1001), ge 2 (6008) | high for 1001, medium otherwise | BugcheckCode |
| ServiceFail | System 7000/7022/7023/7024/7031/7034, Service Control Manager | WS-EVT-SERVICE-FAIL | count ge 1 where param1 notmatch `threshold.workstations.service-fail-ignore-pattern` (the Diagnostic Service Host 7000 noise) | medium | param1 (service) |
| SvcTimeout | System 7009/7011, Service Control Manager | WS-EVT-SERVICE-TIMEOUT | count ge 1 | medium | param2 (service; confirmed) |
| SvcStopWait | System 10029, Microsoft-Windows-DistributedCOM | WS-EVT-COM-WAIT-STOP-PENDING | count ge 1 (pairs with WS-SVC-STUCK) | medium | param2 (service; confirmed) |
| UpdateFail | System 20, WindowsUpdateClient | WS-EVT-UPDATE-INSTALL-FAIL | count ge 2 | medium | updateTitle, errorCode |
| AppHang | Application 1002, Application Hang | WS-EVT-APP-HANG | count ge 3 per program - needs group-by name; interim count ge 5 overall | low | program (positional 0) |
| AppCrash | Application 1000, Application Error | WS-EVT-APP-CRASH | count ge 5 overall; a second rule where program matches `threshold.workstations.security-agent-process-pattern` count ge 1 (a crashing security agent) | low / high | program, faulting module |
| WmiError | WMI-Activity/Operational 5858 | WS-EVT-WMI-ERRORS | count ge 50 (`wmi-errors-max-7d`) | low | ResultCode, ClientProcessId |
| ProfileFail | Application 1500/1502/1504/1508/1511/1515/1521, User Profile Service | WS-EVT-PROFILE-FAIL | count ge 1 (1511/1515 temporary profile = high) | medium | - |
| WinlogonSlow | Application 6005/6006, Winlogon | WS-EVT-WINLOGON-SLOW | count ge 3 | low | subscriber (positional 0) |
| AvScan | Defender/Operational 1000 | not a problem - measure; **WS-EVT-DEFENDER-SCAN-WORK-HOURS**: count ge 3 where time's hour between 8 and 17 - needs an hour-of-day op (gap); otherwise skip | low | Scan Type |
| Downloads | Bits-Client/Operational 60 | not a problem - skip (activity by hour is an analysis, not a rule) | - | - |
| BootSec | Diagnostics-Performance/Operational 100, BootTime | WS-EVT-BOOT-SLOW | count ge 2 where BootTime gt 120000 (ms; `boot-max-ms`) | low | BootTime |
| PostBootSec | same event, BootPostBootTime | WS-EVT-POST-BOOT-SLOW | count ge 2 where BootPostBootTime gt 60000 | low | - |
| ShutdownSec | Diagnostics-Performance 200, ShutdownTime | WS-EVT-SHUTDOWN-SLOW | count ge 2 where ShutdownTime gt 60000 | low | - |
| BootBlame | Diagnostics-Performance 101-110, 201-210 | WS-EVT-BOOT-DEGRADED-BY | count ge 2 where DegradationTime gt 10000; evidence FriendlyName/Name = what Windows blamed (the script's boot-blame.csv) | low | FriendlyName, Name |
| GpStartupSec | GroupPolicy/Operational 8000, ElapsedTime (script also tries the misspelt ElaspedTime) | WS-EVT-GP-STARTUP-SLOW | count ge 2 where ElapsedTime gt 30 (s) | low | - |
| GpLogonSec | GroupPolicy/Operational 8001 | WS-EVT-GP-LOGON-SLOW | count ge 2 where ElapsedTime gt 30 | low | - |
| GpCse | GroupPolicy/Operational 5016, CSEExtensionName, CSEElapsedTime | WS-EVT-GP-EXTENSION-SLOW | count ge 2 where CSEElapsedTime gt 5000 (ms); evidence names the extension | low | CSEExtensionName |
| GpBandwidthKbps | GroupPolicy/Operational 5314/5327 | WS-EVT-GP-SLOW-LINK | count ge 1 where bandwidth lt 500 (kbps; field name unconfirmed - the script says so) | medium | bandwidth |
| GpDcFindMs | GroupPolicy/Operational 5326 | WS-EVT-GP-DC-DISCOVERY-SLOW | count ge 2 where discovery time gt 1000 ms (field name unconfirmed) | low | - |
| GpDc | GroupPolicy/Operational 5308, DCName (confirmed 20.10) | **WS-EVT-GP-DC-REMOTE**: count ge 1 where DCName notmatch `threshold.workstations.local-dc-pattern` - a PC served by a DC in another site/region (the "which DC each site uses" table becomes a per-host check) | medium | DCName |
| Critical/Error by source (any) | System + Application, Level 1/2 | **WS-EVT-ERROR-SOURCE-FLOOD**: count ge 500 (`error-events-max-7d`) - one source flooding; the per-source grouping is a gap, the evidence sample names the top providers | low | provider, id |
| AppLogHours (log span < 24 h) | oldest Application record | not expressible as a count; cim `Win32_NTEventlogFile` (Application) gives MaxFileSize and NumberOfRecords - **WS-EVENTLOG-FULL**: NumberOfRecords gt 0 and FileSize ge MaxFileSize (cross-field: gap) - interim WS-EVENTLOG-SMALL (exists); the eventlog protocol could return the oldest record time as a per-log attribute (gap) | low | top provider |
| GpLastHours (GP log silent) | newest GroupPolicy/Operational record | **WS-EVT-GP-SILENT**: count lt 1 over GroupPolicy/Operational ids [4016, 5016, 8000, 8001, 8004, 8005] days 2, on a host whose uptime > 1.5 d (uptime is another query - gap; interim: days 2 alone, pairs with WS-SVC-STUCK gpsvc) | medium | - |

### The 13 health rows -> rules

| Health row | Mapping |
|---|---|
| Up more than 30 days | existing WS-UPTIME-LONG |
| Commit charge >= 80 % | existing WS-COMMIT-HIGH (perf counter; the script computes it from Win32_OperatingSystem TotalVirtualMemorySize/FreeVirtualMemorySize - arithmetic, gap; WS-PERF-COUNTERS-MISSING guards the counter path) |
| Service stuck in Stop/Start Pending | existing WS-SVC-STUCK |
| Newest update older than 60 days | existing WS-PATCH-NONE-RECENT (45 d; the hotfix date-format gap remains) |
| services.exe busy (>= 10 % of a core since boot) | **not possible** as a rule: needs (KernelModeTime+UserModeTime)/uptime - arithmetic across two classes (gap). Interim cim `Win32_PerfFormattedData_PerfProc_Process WHERE Name = 'services'` PercentProcessorTime ge 10 -> **WS-SERVICES-EXE-BUSY** (instantaneous, often empty remotely - counted as unknown, not pass) |
| A program piled up (10+ copies) | existing WS-PROC-PILED-UP (listed names); "any program" needs group-by (gap, already in backlog) |
| dwm.exe >= 20,000 handles | existing WS-PROC-HANDLES-HIGH |
| sppsvc running 1 h+ | existing WS-PROC-HUNG-TOOL (sppsvc is in its pattern, 12 h); propose a 1 h threshold entry in `hung-tool-age-days` for sppsvc only - per-name thresholds are a gap; interim: separate rule **WS-PROC-SPPSVC-LONG** with the same query, Name eq sppsvc.exe, CreationDate age-gt 0.042 |
| WSD printers installed | existing WS-PRINTER-WSD |
| Restart pending (CBS / WU / SCCM) | **WS-REG-REBOOT-PENDING** (registry): `path: SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`, key host, condition exists eq true; second query `path: SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, exists eq true. SCCM side: existing SCCM-CLIENT-RESTART-PENDING; PC side via CCM_ClientUtilities.DetermineIfRebootPending is a method (gap). Severity medium; closes the backlog registry item. Verified key names. |
| 100+ file replacements queued | **WS-REG-PENDING-RENAMES** (registry): `path: SYSTEM\CurrentControlSet\Control\Session Manager`, values [PendingFileRenameOperations], key host, condition PendingFileRenameOperations size-gt 200 (pairs = 100 renames; `pending-renames-max`). Verified. |
| Group Policy log silent 24 h+ | WS-EVT-GP-SILENT above |
| Application log holds < 24 h | WS-EVT-ERROR-SOURCE-FLOOD + the log-span gap above |

### Network and NIC facts -> rules

| Fact | Mapping |
|---|---|
| Wired link at 100 Mbps or less | **WS-NIC-SLOW-LINK**: cim root/StandardCimv2 `MSFT_NetAdapter WHERE HardwareInterface = TRUE AND MediaConnectState = 1` - Name, InterfaceDescription, Speed, FullDuplex, NdisPhysicalMedium, DriverVersionString, DriverDate; key `{host}|{Name}`; condition NdisPhysicalMedium ne 9 and Speed le 100000000 (bits/s; `wired-min-bps`) or FullDuplex eq false. Medium. Verified (https://learn.microsoft.com/previous-versions/windows/desktop/netadaptercimprov/msft-netadapter). |
| Primary NIC Wi-Fi / Wi-Fi connected next to wired | **WS-NIC-WIFI-AND-WIRED**: same query, count gt 1 where MediaConnectState eq 1 (two physical links up); evidence names them. Low. The "primary = has a gateway" logic needs a join with Win32_NetworkAdapterConfiguration (gap). |
| Primary NIC virtual / VPN | **WS-NIC-VIRTUAL-UP**: `MSFT_NetAdapter WHERE HardwareInterface = FALSE AND MediaConnectState = 1`, InterfaceDescription notmatch `threshold.workstations.virtual-adapter-ignore-pattern`; low (an on-site PC routing through VPN). |
| NIC driver old | **WS-NIC-DRIVER-OLD**: same query, DriverDate age-gt 1095; low. |
| NIC power saving / EEE / forced speed | **WS-NIC-POWER-SAVING**: root/StandardCimv2 `MSFT_NetAdapterAdvancedPropertySettingData` - Name, RegistryKeyword, DisplayValue, RegistryValue; key `{host}|{Name}|{RegistryKeyword}`; condition RegistryKeyword matches `^\*(EEE|SpeedDuplex|FlowControl)$|GreenEthernet|AdvancedEEE|GigaLite|PowerSaving|AutoDisableGigabit|ReduceSpeed|EnableEEE` and DisplayValue notmatch `Disabled|Off|Auto` (threshold); low. Likely (class verified, keyword set from the script). |
| System disk HDD | **WS-DISK-HDD-SYSTEM**: root/Microsoft/Windows/Storage `MSFT_PhysicalDisk` - DeviceId, MediaType (3 HDD, 4 SSD), BusType, FriendlyName; key `{host}|{DeviceId}`; condition MediaType eq 3 (the boot-disk join via MSFT_Disk.IsBoot is a gap; a PC with any HDD is close enough). Low, lens maintenance ("the single biggest slow-PC hardware cause"). Verified. |
| RAM <= 4 GB / <= 8 GB | **WS-MEMORY-LOW-TOTAL**: existing OS query, TotalVisibleMemorySize lt 8000000 KB (`min-memory-kb`); WSF-W11-RAM covers 4 GB from inventory. Low. |
| Up > 14 days | WS-UPTIME-LONG with a tenant threshold |
| C: < 10 % free | existing WS-SYSTEM-DRIVE-FREE-PCT-LOW |
| DNS name points at another address (stale DNS) | **WS-DNS-STALE-RECORD**: needs the scanner's resolution of the target compared with the host's IPAddress array - a runner-side fact the cim runner could emit as `resolvedAddresses` per host (gap). |
| DNS name reaches another PC (wrong-pc) | **WS-HOST-NAME-MISMATCH**: cim `Win32_ComputerSystem` Name vs the target's name - the runner should refuse rows whose Name is not the target (`{HOST}`), or the rule: Name ne `{HOST}` (needs `{HOST}` in conditions - gap). High (every per-host finding would otherwise be attributed to the wrong PC). |
| Subnet has no AD site | existing WSF-NO-AD-SITE (site view); live: Win32_NTDomain ClientSiteName empty with the trusted-domain caveat (backlog). |
| Static IP on the primary NIC | **WS-IP-STATIC**: Win32_NetworkAdapterConfiguration query of WS-DNS-PUBLIC, DHCPEnabled eq false and Description notmatch the virtual-adapter pattern; low. Verified. |
| hosts file has entries | **not possible** (file read over admin$; no file protocol to hosts). Gap. |
| Static routes | **WS-STATIC-ROUTES**: root/StandardCimv2 `MSFT_NetRoute WHERE AddressFamily = 2 AND Protocol = 3` - DestinationPrefix, NextHop, InterfaceAlias; key `{host}|{DestinationPrefix}`; condition DestinationPrefix ne 0.0.0.0/0; low. Verified class. |
| DNS servers grouping, gateways per subnet, OS builds, models | analysis (group-by) - the ranker's count per failing value is the substitute; a `store` rule over `row_seen` can group (`json_extract(attrs,'$.DNSServerSearchOrder')`) once the cim rows are stored - proposal **WS-STORE-DNS-SERVER-SETS**: distinct DNS server lists with host counts, flag sets outside `threshold.workstations.dns-server-pattern`. |
| DNS suffix list | **WS-DNS-SUFFIX-MISSING**: root/StandardCimv2 `MSFT_DNSClientGlobalSetting` SuffixSearchList notcontains `threshold.workstations.dns-suffix` (tenant value); low. |
| Saved Wi-Fi profiles | file read over admin$ - **not possible**; WS-EVT-WIFI-UNMANAGED-SSID covers the live joins. |
| Network profile category (Public on a domain PC) | **WS-NET-PROFILE-PUBLIC**: root/StandardCimv2 `MSFT_NetConnectionProfile` - InterfaceAlias, Name, NetworkCategory (0 Public, 1 Private, 2 DomainAuthenticated), IPv4Connectivity; key `{host}|{InterfaceAlias}`; condition NetworkCategory eq 0 on a physical adapter -> the domain was not detected at connect (Public firewall profile blocks management). Medium. Verified class. |

### Patch by OS build

- Per host: existing WS-PATCH-NONE-RECENT (and the proposed WS-REG-UBR for the exact level). The "newest update per OS build" table is a group-by across hosts: proposal **WS-STORE-PATCH-BY-BUILD** as a `store` rule over `row_seen` joining the OS row and the newest hotfix row per host - needs the hotfix date gap fixed first.

### Agents vs services.exe (the comparison)

- Which agents run: existing WS-SVC-AGENT-STOPPED (required agents not running), WS-EDR-MULTIPLE, WS-AV-MULTIPLE, WS-AV-UNAPPROVED; add **WS-AGENT-UNEXPECTED**: `Win32_Service WHERE State = 'Running'` Name matches `threshold.workstations.known-agent-pattern` and notmatch `threshold.workstations.approved-agent-pattern` (an agent the organisation did not approve - the mislabelled pair of the 19.10 sample is exactly this); medium. The SCCM agent itself: WS-CCM-SERVICE above.
- The with/without median of services.exe CPU: **not possible** - needs per-process CPU since boot (arithmetic, two classes) and a cross-host comparison (analysis). Listed under engine gaps; WS-SERVICES-EXE-BUSY is the instantaneous substitute.
- Agent build vs load (file version of a service binary): `CIM_DataFile` by exact path is a lookup the cim protocol can do (`SELECT Name, Version FROM CIM_DataFile WHERE Name = '...'`) but the path comes from the service row (join - gap). Interim: **WS-AGENT-VERSION-OLD** with the path as a threshold (`threshold.workstations.agent-binary-path`, `...-min-version-pattern`); low.

### Browser and proxy facts

- Per-user hive reads (proxy, default browser, PDF handler) need `hive: HKU` + the console user's SID: the registry protocol supports HKU, the SID comes from `Win32_ComputerSystem.UserName` (join - gap). Machine-wide ones are expressible: **WS-REG-BROWSER-PROXY-POLICY** (`path: SOFTWARE\Policies\Google\Chrome` and `...\Microsoft\Edge`, values [ProxyMode, ProxyPacUrl, ProxyServer]; condition ProxyPacUrl notmatch `threshold.workstations.pac-url-pattern`), **WS-REG-BROWSER-FORCED-EXTENSIONS** (`...\ExtensionInstallForcelist`, `subkeys` no - values; condition any value notmatch `threshold.workstations.approved-extension-ids`; medium, security), **WS-REG-PROXY-PER-MACHINE** (`SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings` ProxySettingsPerUser absent -> per-user proxies, low). Browser versions: `CIM_DataFile` by path (threshold path) -> **WS-BROWSER-VERSION-OLD** (low; Chrome/Edge release monthly, pattern threshold). Browser process count/memory: existing WS-PROC-MEMORY-HIGH pattern can include `chrome|msedge`.

### Stuck services, piled programs, log floods, reach

- Stuck services -> WS-SVC-STUCK (exists); piled programs -> WS-PROC-PILED-UP (exists) + gap; log floods -> WS-EVT-ERROR-SOURCE-FLOOD + the log-span gap; reach (offline, rpc-closed, eventlog-rpc, wrong-pc) -> coverage, not findings: the runner's unknown reason should distinguish DNS failure / port closed / access denied / namespace missing so a `store` rule can turn "N hosts unreachable" into one finding (**WS-STORE-UNREACHABLE-MANY**, over `coverage`).

---

## Engine gaps that blocked proposals (or forced an interim form)

1. **Cross-field comparison in one row** - `Author eq Approver` (SCCM-SCRIPT-SELF-APPROVED), `LastCycleStartedDate gt LastReportDate` (inventory cycles that never report), `FileSize ge MaxFileSize`, `size ge max_size`. Needs `op` with `field` on the right-hand side.
2. **Arithmetic** - CPU share since boot (KernelModeTime+UserModeTime over uptime), commit % from Win32_OperatingSystem, free % from FreeSpace/Size, cache bytes used (sum over CacheInfoEx). Already in the backlog; blocks the services.exe check and the agents-vs-services comparison entirely.
3. **Cross-query / cross-class join per host** - primary NIC (adapter with a gateway), boot disk (MSFT_Disk.IsBoot to MSFT_PhysicalDisk), service path to CIM_DataFile version, console user SID to HKU hive, uptime gate on WS-EVT-GP-SILENT, Schannel defaults by OS build, client version vs `SMS_Site.Version`.
4. **Group-by** - duplicates by name/SMBIOS GUID, piles of any program, app hangs per program, error sources per provider, DNS server sets, patch level by build. A `store` rule over `row_seen` can do some once rows are stored; a `group:` on the query would do it in-rule.
5. **Methods** - `CCM_ClientUtilities.DetermineIfRebootPending`, scheduled-task last run (MSFT_ScheduledTask), StdRegProv beyond Enum/Get - deliberately excluded; registry covers the reboot flags instead.
6. **`{HOST}` in conditions and runner-side facts** - WS-HOST-NAME-MISMATCH (wrong-pc) and WS-DNS-STALE-RECORD need the target's name/resolved addresses as row fields (`_target`, `_resolved`) or a runner guard that refuses rows from a host whose Win32_ComputerSystem.Name is not the target.
7. **Per-feature switch inside one row** - WS-DEFENDER-FEATURES-OFF would be four findings if a rule could fan one row out into several keyed by feature; today it is one finding with the list in evidence, and a tenant cannot waive one feature without a regex hack.
8. **Date-from-text** - CcmEval LastEvalTime (CIM datetime string in the registry), hotfix InstalledOn formats (backlog), Defender platform version as a date (N-2 check instead of a yearly regex).
9. **Eventlog protocol details** - `providers` as names only (NIC drivers need a list threshold or a regex option); per-log metadata (oldest record time = log span, record count) as a host attribute; an hour-of-day operator for "scans in work hours"; run-to-run memory (new error signatures, "stuck for two scans" on SQL TDE).
10. **Registry protocol details** - a value that must never be returned (Winlogon DefaultPassword) is covered by the "set, never the value" rule - keep it; `size-gt` on REG_MULTI_SZ needs the runner to return arrays; a CIM-datetime string type hint for values like LastEvalTime.
11. **Unknown-reason taxonomy** - per-host failures should say DNS / port / access denied / namespace missing so client-health rules can tell "root/ccm broken" from "PC off", and a `store` rule can count unreachable hosts as one finding.
12. **File reads** - hosts file and saved Wi-Fi profiles over admin$ (the script does it; Keeper's `file` protocol stays inside imports\ by design) - not proposed; WS-EVT-WIFI-UNMANAGED-SSID is the substitute.
13. **Per-name thresholds in one pattern** - WS-PROC-HUNG-TOOL wants 1 h for sppsvc and 12 h for the rest; today that is two rules.

Backlog items this document closes once implemented (move from "Expressible, not written yet" / "Registry" / "Event logs" to rules): Defender tamper/MAPS/PUA/network protection; stale profiles (with caveat); SMB server signing, NetBIOS and activation on workstations; driver packages stale; SMB1 client driver; pending reboot and pending renames; LSA PPL, WDigest, LLMNR, NetBIOS node type, WPAD, cached logons, hardened UNC, UAC local, autologon, WinRM, Schannel, Kerberos RC4, WSUS URL, Secure Boot CA, MDE onboarding, AppLocker enforcement, Security log size; every event-log line of the backlog's "Event logs" section except recurring/new signatures between runs.
