# Windows estate catalogue port: new checks and missing reads

Source: the retired health tool's catalogue for Active Directory, PKI, Windows servers and clients, Configuration Manager, SQL Server, file, DHCP and print servers, security agents and application baselines. Every row was compared with the current rule packs and with docs\proposals; this file holds only what has no rule yet. Tenant specifics are kept out; anything tenant-shaped is a `threshold` the rule reads (dormant until set).

Reading guide: "Rows" lists catalogue ids that depend on the proposal (the mapping with every row and its status is kept outside the repository). Severity, lens and category follow RULES.md. "new pack" files do not exist yet: a Windows domain-controller pack, a file-server pack, a DHCP pack and a print-server pack.

## Protocols to add

Rows in this mapping that are expressible only with a read Keeper does not have yet, grouped by the missing read. Counts are catalogue rows, not estate objects.

- **smb-file-read** - 69 rows. read files and folders over SMB or the admin share (SYSVOL policy files, logs, installers, inbox folders, config files)
- **ntfs-acl-read** - 29 rows. read NTFS and share security descriptors, decoded to principals and rights
- **ldap-security-descriptor** - 24 rows. decode nTSecurityDescriptor over LDAP (object ACLs, owners, AdminSDHolder, extended rights)
- **cert-store-read** - 20 rows. enumerate LocalMachine certificate stores with expiry, EKU and key size
- **run-to-run-diff** - 16 rows. compare a value with the previous scan (growth, new signatures, changes since last run)
- **dns-query** - 13 rows. DNS lookups (A, PTR, SRV, SOA, CNAME) from the scanner
- **tcp-port-probe** - 11 rows. TCP connect and round-trip checks per host and port
- **ldap-binary-attribute** - 10 rows. LDAP attributes the runner drops today (certificates, CRLs, DNS record blobs, schedules, DN-binary values)
- **other:sql-per-database-query** - 10 rows. run a catalog query in each database context of an instance
- **gpo-content-parse** - 9 rows. parse registry.pol, GptTmpl.inf, audit.csv and preference XML (needs smb-file-read too)
- **ca-api** - 8 rows. certificate authority API or database reads
- **other:crl-fetch** - 8 rows. download and parse CRL files from HTTP and LDAP distribution points
- **rootdse-per-dc** - 7 rows. LDAP RootDSE and replication attributes read from each DC separately
- **other:sql-stored-procedure** - 5 rows. call a stored procedure (error log reader, agent properties, trace flags) instead of a SELECT
- **other:registry-binary-value** - 4 rows. read binary registry values (proxy settings, service failure actions, certificate hashes)
- **winrm-powershell** - 4 rows. cmdlets or WMI method calls with no query form (backlog, listeners, driver signatures, secure channel test)
- **other:security-descriptor-decode** - 3 rows. decode binary security descriptors from registry or WMI (service and printer ACLs)
- **perf-sampling** - 2 rows. several samples over seconds or minutes (waits, CPU averages, counters)
- **rsop-user** - 2 rows. user-side RSOP or loaded user hives
- **snmp** - 2 rows. SNMP read of printers and devices
- **other:tls-forced-protocol-probe** - 1 rows. handshake that forces an old TLS version to prove it is refused
- **other:ocsp-probe** - 1 rows. OCSP request and response check
- **other:ntp-udp-probe** - 1 rows. UDP NTP request from the scanner or a DC
- **other:dhcp-discover-probe** - 1 rows. controlled DHCP discover broadcast or switch snooping data

Reads that exist in Keeper but have a limit worth lifting (each unlocks the rows tagged "new" with confidence guess in this file):

- sql: one SELECT per instance. A per-database loop (or three-part names from a default context) would unlock the rows tagged other:sql-per-database-query and several guess-level SQL proposals.
- sql: stored procedures are not SELECTs (error log reader, agent properties, trace flags); the Application-log form (SQL-EVT-ENGINE-ERRORS) replaces most of them.
- registry: confirm that a subkey read returns each subkey's values and that value names (not data) can be listed; several proposals rely on it.
- http: confirm response headers and XML bodies are available to conditions (console hardening, management point probe).
- cim: the firewall rule/port-filter/address-filter association needs a join the runner may not support.

## Integrations to add

Rows that need a product API or console export Keeper has no integration type for. The product token is the key; the rows are in the CSV.

- **integration:eset-protect** - 44 rows
- **integration:wss-console** - 33 rows
- **integration:eproc** - 30 rows
- **integration:gytpol** - 26 rows
- **integration:other-aws-ec2** - 21 rows
- **integration:anydesk** - 15 rows
- **integration:lansweeper** - 9 rows
- **integration:other-aws-rds** - 7 rows
- **integration:monitoring-product** - 6 rows
- **integration:ticketing** - 6 rows
- **integration:other-aws-cloudwatch** - 6 rows
- **integration:other-entra-conditional-access** - 4 rows
- **integration:defender-xdr** - 4 rows
- **integration:backup-product** - 3 rows
- **integration:other-aws-cost** - 2 rows
- **integration:other-aws-waf** - 2 rows
- **integration:other-vulnerability-scanner** - 2 rows
- **integration:siem** - 2 rows
- **integration:other-aws** - 2 rows
- **integration:vendor-portal** - 1 rows
- **integration:other-aws-appstream** - 1 rows
- **integration:other-entra-signin-logs** - 1 rows
- **integration:other-intune-detected-apps** - 1 rows
- **integration:other-network-firewall** - 1 rows
- **integration:other-aws-fsx** - 1 rows
- **integration:other-aws-ssm** - 1 rows

## New checks from this pass

### AD-COMP-SERVER-NO-MANAGEDBY - Server object without an owner or description
- Rows: WINSRV-HYG-005
- What and why: Server objects with no managedBy and no description leave nobody accountable when the machine misbehaves or goes stale; the cleanup trail starts at these two attributes.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\active-directory.yaml
- Data: protocol ldap; filter computers with a server operating system that signed in recently ({COMPUTER}{ENABLED}, operatingSystem contains "Server"); attributes sAMAccountName, managedBy, description; estate-wide; key sAMAccountName
- Condition: finding when managedBy is empty or description is empty.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1
- Fix: Fill both attributes from the system register.
- Confidence: verified - plain LDAP attributes.

### AD-COMP-SERVER-OUTSIDE-SERVER-OU - Server computer object outside the server OUs
- Rows: WINSRV-CFG-006
- What and why: Servers sitting in the default container or in a workstation OU miss the server hardening and patch policies that are linked only to the server OUs.
- Severity: medium. Lens: both. Category: CFG
- File: rules\active-directory.yaml
- Data: protocol ldap; {COMPUTER}{ENABLED} with operatingSystem containing "Server"; attributes sAMAccountName, distinguishedName, operatingSystem, lastLogonTimestamp; estate-wide; key sAMAccountName
- Condition: finding when distinguishedName does not match the regex threshold ad.server-ou-pattern (dormant until the tenant sets its server OU names).
- Refs: NIST-800-53:CM-6, NIST-800-53:CM-8
- Fix: Move the object to its server OU and confirm the policy set applies.
- Confidence: likely - needs a tenant OU pattern; query shape verified.

### AD-COMP-TEST-IN-PRODUCTION-OU - Test-named computer in a production OU
- Rows: WINCLIENT-HYG-018
- What and why: Machines whose names mark them as test or lab but which sit in production OUs receive production policy and may hold production credentials.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\active-directory.yaml
- Data: protocol ldap; {COMPUTER}{ENABLED}; attributes sAMAccountName, distinguishedName, lastLogonTimestamp; estate-wide
- Condition: finding when the name matches threshold ad.test-name-pattern and the DN is outside threshold ad.test-ou-pattern.
- Refs: NIST-800-53:CM-4, NIST-800-53:CM-8
- Fix: Move test machines to the test OU or rename the object.
- Confidence: likely - patterns come from the tenant.

### AD-COMP-WORKSTATION-OUTSIDE-OU - Workstation object outside the workstation OU tree
- Rows: WINCLIENT-CFG-031
- What and why: Client computers outside the workstation OUs (default container, server OUs) miss workstation policy and are invisible to OU-scoped collections.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\active-directory.yaml
- Data: protocol ldap; {COMPUTER}{ENABLED} with a client operatingSystem (Windows 10/11); attributes sAMAccountName, distinguishedName; estate-wide
- Condition: finding when distinguishedName does not match threshold ad.workstation-ou-pattern.
- Refs: NIST-800-53:CM-6, NIST-800-53:CM-8
- Fix: Move the object into the workstation OU tree.
- Confidence: verified - same attribute set as the existing default-container rule.

### AD-DEVICE-REG-SCP-RESIDUE - Device registration service connection point left in place
- Rows: AD-505
- What and why: A service connection point under the Device Registration Configuration container that points at an old tenant or stale join configuration steers devices to the wrong place.
- Severity: low. Lens: both. Category: CFG
- File: rules\active-directory.yaml
- Data: protocol ldap; base CN=Device Registration Configuration,CN=Services,{CONFIGDN}; filter (objectClass=serviceConnectionPoint); attributes keywords, serviceDNSName, whenChanged; estate-wide
- Condition: finding when the keywords do not name the expected tenant (threshold ad.device-reg-tenant) or when more than one connection point exists.
- Refs: NIST-800-53:CM-6
- Fix: Remove stale connection points and keep the one for the current tenant.
- Confidence: guess - container and keyword layout to confirm on a live read.

### AD-GPO-BASELINE-NOT-LINKED - Security baseline GPO not linked where intended
- Rows: GPO-027
- What and why: A baseline GPO that exists but is not linked to its target OUs protects nothing; the link is visible in gPLink even without reading GPO files.
- Severity: medium. Lens: security. Category: CFG
- File: rules\active-directory.yaml
- Data: protocol ldap; OU and domain objects with gPLink; attributes name, gPLink, distinguishedName; store join with the GPO list on the baseline GPO GUIDs given in threshold ad.baseline-gpo-guids; estate-wide
- Condition: finding for each (baseline GPO, target OU class) pair with no enabled link.
- Refs: NIST-800-53:CM-6, CIS-Controls-v8:4.1
- Fix: Link the baseline to the intended OUs, or record the exception.
- Confidence: guess - GUID list and target mapping are tenant input.

### AD-GROUP-WATCHED-MEMBERS - Disabled or inactive account in a watched group
- Rows: WINCLIENT-IAM-003, DHCP-IAM-004, GYTPOL-IAM-004, EPROC-IAM-003, AD-137, AD-503
- What and why: Groups that grant local administration or operate a management product are reviewed by hand today; members who left or never sign in are the usual rot.
- Severity: medium. Lens: security. Category: IAM
- File: rules\active-directory.yaml
- Data: protocol ldap; filter users that are nested members of the group names in threshold ad.watched-groups ((memberOf:1.2.840.113556.1.4.1941:=<group DN>)); attributes sAMAccountName, userAccountControl, lastLogonTimestamp, employeeType; estate-wide; key group|sAMAccountName
- Condition: finding when the member is disabled, or has not signed in for more than threshold ad.watched-group-inactive-days (default 90).
- Refs: NIST-800-53:AC-2(3), CIS-Controls-v8:5.3
- Fix: Remove the member or document the exception.
- Confidence: verified - same nested-member filter as the protected-group rules.

### AD-RID-POOL-LOW - RID pool close to exhaustion
- Rows: AD-004
- What and why: When the domain-wide pool of relative identifiers runs out no new accounts or groups can be created; consumption is rare but the failure is abrupt.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\active-directory.yaml
- Data: protocol ldap; base CN=RID Manager$,CN=System,{DOMAINDN}; attribute rIDAvailablePool (64-bit: upper half is the ceiling, lower half the next free pool); estate-wide
- Condition: finding when the remaining share (ceiling minus next free, over ceiling) is below threshold ad.rid-pool-min-free-percent (default 10).
- Refs: NIST-800-53:SC-5, NIST-800-53:CP-2
- Fix: Raise the ceiling per the directory vendor's procedure before it is reached.
- Confidence: guess - the runner must expose the 64-bit value so the halves can be split; verify on a read.

### AD-VENDOR-ACCOUNT-NO-EXPIRY - Vendor account without an expiry date
- Rows: APP-BASELINE-IAM-006
- What and why: Accounts handed to suppliers should lapse unless someone renews them; an account that never expires keeps access after the contract ends.
- Severity: medium. Lens: security. Category: IAM
- File: rules\active-directory.yaml
- Data: protocol ldap; users that are members of the vendor group named in threshold ad.vendor-group; attributes sAMAccountName, accountExpires, lastLogonTimestamp; estate-wide
- Condition: finding when accountExpires is 0 or 9223372036854775807, or more than 12 months ahead.
- Refs: NIST-800-53:AC-2(2), NIST-800-53:PS-7, CIS-Controls-v8:5.3
- Fix: Set an expiry on the account and record the owner.
- Confidence: verified - standard attribute.

### DC-EVT-HONEYTOKEN-USE - Decoy account used
- Rows: AD-139
- What and why: A decoy account no one should ever use is a cheap tripwire; any logon or ticket request naming it is hostile or a misconfigured tool.
- Severity: high. Lens: security. Category: MON
- File: rules\domain-controllers.yaml (new pack)
- Data: protocol eventlog on each DC, log Security, ids [4624, 4625, 4768, 4769, 4776], days 7, max 500; fields TargetUserName, ServiceName, IpAddress, time; per-host; key {host}|{id}|{recordId}
- Condition: finding when TargetUserName or ServiceName matches threshold dc.honeytoken-pattern (empty list keeps the rule dormant).
- Refs: NIST-800-53:SI-4, MITRE-ATTACK:T1078
- Fix: Treat as an incident and trace the source address in the event.
- Confidence: guess - depends on tenant-created decoys and on audit subcategories being on.

### DC-RSOP-KERBEROS-POLICY - Kerberos ticket lifetimes off the standard values
- Rows: AD-IAM-036
- What and why: Longer ticket or renewal lifetimes widen the window in which a stolen ticket works; the clock-skew tolerance should stay at the default.
- Severity: medium. Lens: security. Category: CFG
- File: rules\domain-controllers.yaml (new pack)
- Data: protocol cim, namespace root/rsop/computer, WQL SELECT KeyName, Setting FROM RSOP_SecuritySettingNumeric WHERE precedence = 1 AND (KeyName = 'MaxTicketAge' OR KeyName = 'MaxRenewAge' OR KeyName = 'MaxServiceAge' OR KeyName = 'MaxClockSkew'); per-DC; key {host}|{KeyName}
- Condition: finding when MaxTicketAge > 10, MaxRenewAge > 7, MaxServiceAge > 600 or MaxClockSkew > 5.
- Refs: NIST-800-53:IA-5, MITRE-ATTACK:T1558
- Fix: Restore the defaults in the Default Domain Policy.
- Confidence: likely - class and key names documented; availability of RSOP data on DCs to confirm.

### DC-TIME-SYNC-STALE - No successful time-source selection recently
- Rows: AD-AVL-033
- What and why: The time service logs a source selection whenever it syncs; a week without one means the clock is free-running even if no error was logged.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\domain-controllers.yaml (new pack)
- Data: protocol eventlog, log System, provider Microsoft-Windows-Time-Service, ids [35, 37], days 7; per-DC
- Condition: count none per host is the finding.
- Refs: NIST-800-53:AU-8
- Fix: Fix the hierarchy (DC-TIME-SOURCE) and the PDC's external source.
- Confidence: verified - event ids per the time-service documentation.

### DHCP-ADMINS-MEMBERS - Members of the DHCP administration groups
- Rows: DHCP-IAM-002
- What and why: These groups can change scopes and options for the whole network.
- Severity: medium. Lens: security. Category: IAM
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/cimv2, Win32_GroupUser for DHCP Administrators and DHCP Users on each DHCP server; per-host
- Condition: member outside threshold dhcp.admins-allowed.
- Refs: NIST-800-53:AC-6
- Fix: Remove.
- Confidence: verified.

### DHCP-AUDIT-LOG-DISABLED - DHCP audit logging off
- Rows: DHCP-LOG-001
- What and why: No audit log means no lease evidence.
- Severity: medium. Lens: security. Category: LOG
- File: rules\dhcp.yaml (new pack)
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters ActivityLogFlag; per-host
- Condition: value 0 or absent.
- Refs: NIST-800-53:AU-2, NIST-800-53:AU-12
- Fix: Enable.
- Confidence: likely.

### DHCP-DATABASE-LARGE - Lease database large
- Rows: DHCP-HLT-006
- What and why: Needs compaction or points to growth.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/cimv2, SELECT FileSize FROM CIM_DataFile WHERE Name = 'C:\\Windows\\System32\\dhcp\\dhcp.mdb'; per-host
- Condition: above threshold dhcp.mdb-max-bytes.
- Refs: NIST-800-53:SC-5
- Fix: Compact offline.
- Confidence: likely.

### DHCP-DNS-CREDENTIAL-PRIVILEGED - Dynamic update credential is privileged
- Rows: DHCP-IAM-003
- What and why: A privileged account saved on a DHCP server is a high-value target.
- Severity: high. Lens: security. Category: IAM
- File: rules\dhcp.yaml (new pack)
- Data: protocol store; DHCP DNS credential user name (secret never read) joined to AD memberOf and pwdLastSet
- Condition: protected-group member, or password older than 365 days.
- Refs: NIST-800-53:AC-6, NIST-800-53:IA-5
- Fix: Use a dedicated low-privilege account.
- Confidence: guess.

### DHCP-DNS-OPTION-STALE-DC - Scope hands out a resolver that is not a live DC
- Rows: DHCP-CFG-002
- What and why: Stale option 6 values send clients to dead resolvers.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\dhcp.yaml (new pack)
- Data: protocol store; DHCP option 6 values per scope joined to AD DC addresses
- Condition: value not matching a live DC.
- Refs: NIST-800-53:SC-20
- Fix: Update option 6.
- Confidence: likely.

### DHCP-DNS-UPDATE-SETTINGS - DNS update behaviour of scopes
- Rows: DHCP-AUT-001, DHCP-AUT-002, DHCP-AUT-003
- What and why: Records should be deleted on expiry and names protected.
- Severity: low. Lens: security. Category: CFG
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP, DNS settings classes per scope (DynamicUpdates, DeleteDnsRROnLeaseExpiry, NameProtection)
- Condition: DeleteDnsRROnLeaseExpiry false, NameProtection false, or updates disabled where the zone expects them.
- Refs: NIST-800-53:SC-20
- Fix: Set.
- Confidence: likely.

### DHCP-EVT-SERVER - DHCP server events
- Rows: DHCP-HLT-008, DHCP-LOG-003, DHCP-LOG-004
- What and why: Conflicts, errors and pool exhaustion appear in the server channels.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\dhcp.yaml (new pack)
- Data: protocol eventlog logs Microsoft-Windows-DHCP-Server/Operational and System (provider Microsoft-Windows-DHCP-Server), ids [1341, 1342, 1020], level 1-3, days 7; per-host
- Condition: any 1020; count > 0 for errors.
- Refs: NIST-800-53:SI-4
- Fix: Read the event.
- Confidence: verified.

### DHCP-FAILOVER-NOT-NORMAL - Failover relationship not in Normal state
- Rows: DHCP-AVL-001
- What and why: Not normal means one partner is alone.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP, failover relationship class (State, Mode, PartnerServer)
- Condition: State is not Normal.
- Refs: NIST-800-53:CP-10
- Fix: Resolve.
- Confidence: likely.

### DHCP-LEASE-DURATION-UNSUITED - Lease duration unsuited to the scope
- Rows: DHCP-HLT-005
- What and why: Long leases on transient scopes exhaust pools.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP, scope LeaseDuration
- Condition: against threshold dhcp.lease-by-scope-kind.
- Refs: NIST-800-53:CM-6
- Fix: Adjust.
- Confidence: guess.

### DHCP-RESERVATION-HYGIENE - Duplicate or out-of-range reservations
- Rows: DHCP-CFG-005
- What and why: Reservations conflict.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP reservation class
- Condition: duplicate ClientId or address outside scope range.
- Refs: NIST-800-53:CM-8
- Fix: Fix.
- Confidence: likely.

### DHCP-SCOPE-INACTIVE - Scope inactive
- Rows: DHCP-AVL-007
- What and why: Inactive scopes stop service.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP scope State
- Condition: not Active.
- Refs: NIST-800-53:CP-2
- Fix: Activate or retire.
- Confidence: likely.

### DHCP-SCOPE-NO-FAILOVER - Active scope without failover
- Rows: DHCP-AVL-002
- What and why: Single points of failure.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\dhcp.yaml (new pack)
- Data: protocol store; scope and failover relationship rows
- Condition: active scope not in a relationship.
- Refs: NIST-800-53:CP-2
- Fix: Add.
- Confidence: likely.

### DHCP-SCOPE-OPTIONS-MISSING - Scope lacks router, DNS or domain option
- Rows: DHCP-CFG-001, DHCP-CFG-003
- What and why: Clients need options 3, 6, 15.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP option value classes at scope and server level
- Condition: options 3, 6 or 15 resolved neither at scope nor server level.
- Refs: NIST-800-53:CM-6
- Fix: Add.
- Confidence: likely.

### DHCP-SCOPE-UNUSED - Scope with no leases
- Rows: DHCP-HYG-002
- What and why: Dead scopes.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP scope statistics
- Condition: zero in use across runs.
- Refs: NIST-800-53:CM-8
- Fix: Retire.
- Confidence: likely.

### DHCP-SCOPE-UTILISATION-HIGH - Address pool nearly full
- Rows: DHCP-HLT-003
- What and why: Exhaustion stops new devices.
- Severity: high. Lens: maintenance. Category: HLT
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP scope statistics (PercentageInUse)
- Condition: >= 80 % high, >= 95 % critical.
- Refs: NIST-800-53:SC-5
- Fix: Grow scope.
- Confidence: verified.

### DHCP-SERVER-AUTHORISATION - Serving and authorised servers differ
- Rows: DHCP-HLT-001, DHCP-IAM-001
- What and why: Rogue or unauthorised servers.
- Severity: high. Lens: security. Category: CFG
- File: rules\dhcp.yaml (new pack)
- Data: protocol ldap CN=NetServices,CN=Services,{CONFIGDN} dHCPClass; store join with servers answering scope queries
- Condition: authorised-not-serving or serving-not-authorised.
- Refs: NIST-800-53:CM-8, NIST-800-53:AC-3
- Fix: Align.
- Confidence: likely.

### DHCP-UNEXPECTED-OPTIONS - Unexpected server or scope options
- Rows: DHCP-CFG-006, DHCP-CFG-008
- What and why: Options 43, 60, 66, 67, 252 redirect clients.
- Severity: medium. Lens: security. Category: CFG
- File: rules\dhcp.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DHCP option value classes
- Condition: option ids in threshold dhcp.unexpected-options present.
- Refs: NIST-800-53:CM-6
- Fix: Remove.
- Confidence: likely.

### FILESRV-DEDUP-JOB-STALE - Deduplication jobs not completing
- Rows: FILESRV-HLT-014
- What and why: Unrun jobs stop savings and integrity scrubs.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/Deduplication MSFT_DedupStatus (LastOptimizationTime, LastGarbageCollectionTime, LastScrubbingTime, LastOptimizationResult)
- Condition: optimisation older than 7 days, scrub older than 30 days, or result non-zero.
- Refs: NIST-800-53:SI-7
- Fix: Check schedule.
- Confidence: likely.

### FILESRV-DFSN-LEGACY-MODE - Namespace in legacy mode
- Rows: FILESRV-AVL-006
- What and why: Legacy namespaces lack scale and ABE.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\file-servers.yaml (new pack)
- Data: protocol ldap CN=Dfs-Configuration,CN=System,{DOMAINDN} objectClass fTDfs
- Condition: any.
- Refs: NIST-800-53:SA-22
- Fix: Migrate.
- Confidence: likely.

### FILESRV-DFSN-REFERRAL-SETTINGS - Namespace referral settings off
- Rows: FILESRV-AVL-005
- What and why: Referral behaviour decides which server users hit.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DFSN MSFT_DfsNamespaceServerConfiguration
- Condition: UseFqdn false or site costing off.
- Refs: NIST-800-53:CM-6
- Fix: Set.
- Confidence: likely.

### FILESRV-DFSN-TARGET-OFFLINE - Namespace target offline
- Rows: FILESRV-AVL-003
- What and why: Offline targets give timeouts.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/DFSN MSFT_DfsNamespaceRootTarget and FolderTarget State
- Condition: State not Online.
- Refs: NIST-800-53:CP-2
- Fix: Fix.
- Confidence: verified.

### FILESRV-DFSR-CONFLICT-QUOTA - Conflict and deleted folder near quota
- Rows: FILESRV-AVL-011
- What and why: A full folder blocks replication.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/MicrosoftDfs DfsrReplicatedFolderInfo CurrentConflictSizeInMb vs DfsrReplicatedFolderConfig ConflictSizeInMb
- Condition: above 80 %.
- Refs: NIST-800-53:SC-5
- Fix: Raise quota.
- Confidence: verified.

### FILESRV-DFSR-CONNECTION - Replication connection disabled or stale
- Rows: FILESRV-AVL-009
- What and why: Stopped connections stall replication.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/MicrosoftDfs DfsrConnectionInfo and DfsrConnectionConfig
- Condition: disabled or LastSyncTime older than 24 h.
- Refs: NIST-800-53:CP-10
- Fix: Enable.
- Confidence: likely.

### FILESRV-DFSR-FOLDER-STATE - Replicated folder not in Normal state
- Rows: FILESRV-AVL-007
- What and why: Any other state means replication is not working.
- Severity: critical. Lens: maintenance. Category: AVL
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/MicrosoftDfs DfsrReplicatedFolderInfo State
- Condition: State not 4.
- Refs: NIST-800-53:CP-10
- Fix: Resume.
- Confidence: verified.

### FILESRV-DFSR-VOLUME-STATE - Replication volume state
- Rows: FILESRV-AVL-013
- What and why: Database or journal problems.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/MicrosoftDfs DfsrVolumeInfo State
- Condition: not normal.
- Refs: NIST-800-53:CP-10
- Fix: Recover.
- Confidence: likely.

### FILESRV-EVT-ACL-SHARE-CHANGES - Permission and share changes
- Rows: FILESRV-MON-003
- What and why: Audit trail for rights changes.
- Severity: info. Lens: security. Category: MON
- File: rules\file-servers.yaml (new pack)
- Data: protocol eventlog log Security ids [4670, 5142, 5143, 5144], days 7; per-host
- Condition: any.
- Refs: NIST-800-53:AU-6, NIST-800-53:CM-3
- Fix: Match tickets.
- Confidence: verified.

### FILESRV-EVT-DFSR - DFS Replication events
- Rows: FILESRV-LOG-010, FILESRV-LOG-011
- What and why: State, staging, conflict, connection events.
- Severity: high. Lens: maintenance. Category: LOG
- File: rules\file-servers.yaml (new pack)
- Data: protocol eventlog log DFS Replication ids [2104, 2108, 2212, 2213, 4012, 4202, 4204, 4206, 4208, 4302, 4304, 5002, 5008, 5014, 6402, 6404], days 30
- Condition: any of 2104, 2213, 4012, 4206, 4208; count thresholds for others.
- Refs: NIST-800-53:CP-10
- Fix: Per id.
- Confidence: verified.

### FILESRV-EVT-NTLM-LOGON - Network logons using NTLM
- Rows: FILESRV-AUT-007
- What and why: Identifies clients and aliases without Kerberos.
- Severity: low. Lens: security. Category: AUT
- File: rules\file-servers.yaml (new pack)
- Data: protocol eventlog log Security id 4624 LogonType 3, AuthenticationPackageName NTLM, days 7, max 500
- Condition: share above 5 %.
- Refs: NIST-800-53:IA-2
- Fix: Fix names and SPNs.
- Confidence: likely.

### FILESRV-EVT-SMB1-ACCESS - SMB1 access recorded
- Rows: FILESRV-LOG-003
- What and why: Names clients still using SMB1.
- Severity: medium. Lens: security. Category: MON
- File: rules\file-servers.yaml (new pack)
- Data: protocol eventlog logs Microsoft-Windows-SMBServer/Audit id 3000 and /Security id 551, days 30
- Condition: any.
- Refs: NIST-800-53:CM-7
- Fix: Retire client.
- Confidence: verified.

### FILESRV-EVT-SMBSERVER-ERRORS - SMB server errors and failed authentications
- Rows: FILESRV-LOG-001, FILESRV-LOG-002, FILESRV-LOG-004
- What and why: Operational errors and burst of failed access.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\file-servers.yaml (new pack)
- Data: protocol eventlog logs Microsoft-Windows-SMBServer/Operational, /Security and /Connectivity, levels 1-3, days 7; ids 1006, 1020 counted separately
- Condition: count > 0; 1006/1020 above 50 per client per day.
- Refs: NIST-800-53:AU-6, NIST-800-53:SI-4
- Fix: Read id.
- Confidence: verified.

### FILESRV-EVT-SRV-POOL - Server service resource events
- Rows: FILESRV-LOG-005
- What and why: Pool failures.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\file-servers.yaml (new pack)
- Data: protocol eventlog log System provider srv ids [2013, 2017, 2019, 2020], days 7
- Condition: any.
- Refs: NIST-800-53:SC-5
- Fix: Memory review.
- Confidence: verified.

### FILESRV-FSRM-FILESCREEN-MISSING - No active file screen on a share root
- Rows: FILESRV-MON-006
- What and why: Screens block unwanted or ransomware file types.
- Severity: medium. Lens: security. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/FSRM MSFT_FSRMFileScreen (Path, Active, IncludeGroup)
- Condition: share root with no active screen.
- Refs: NIST-800-53:SI-3
- Fix: Add.
- Confidence: likely.

### FILESRV-FSRM-NOTIFICATION - FSRM notification settings invalid
- Rows: FILESRV-CFG-019
- What and why: Alerts go nowhere.
- Severity: low. Lens: maintenance. Category: MON
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/FSRM MSFT_FSRMSetting AdminEmailAddress, SmtpServer
- Condition: empty or recipient not active.
- Refs: NIST-800-53:IR-6
- Fix: Fix.
- Confidence: likely.

### FILESRV-FSRM-QUOTA-MISSING - Share without a quota
- Rows: FILESRV-CFG-017, FILESRV-CFG-018
- What and why: Unbounded growth.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/FSRM MSFT_FSRMQuota, MSFT_FSRMAutoQuota; store join with share paths
- Condition: no quota on a home or departmental root, or quota not matching its template.
- Refs: NIST-800-53:SC-5
- Fix: Add.
- Confidence: likely.

### FILESRV-FSRM-QUOTA-NEAR-LIMIT - Quota almost used
- Rows: FILESRV-MON-007
- What and why: Users hit limits.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/FSRM MSFT_FSRMQuota Usage, Size
- Condition: Usage/Size >= 0.85 (high at 0.95).
- Refs: NIST-800-53:SC-5
- Fix: Raise or clean.
- Confidence: verified.

### FILESRV-FSRM-REPORT-STALE - Storage reports not running
- Rows: FILESRV-CFG-020
- What and why: No reports no capacity view.
- Severity: low. Lens: maintenance. Category: MON
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/FSRM MSFT_FSRMStorageReport LastRun, LastResult
- Condition: older than 35 days or failed.
- Refs: NIST-800-53:CA-7
- Fix: Fix schedule.
- Confidence: likely.

### FILESRV-NO-SESSIONS - File server with no sessions
- Rows: FILESRV-HLT-011
- What and why: Zero sessions at work hours means a broken path.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/SMB MSFT_SmbSession; per-host
- Condition: count none on weekdays within hours.
- Refs: NIST-800-53:SI-4
- Fix: Check network.
- Confidence: likely.

### FILESRV-OTHER-PROTOCOL-SERVICES - Extra file protocols
- Rows: FILESRV-CFG-024
- What and why: NFS, iSCSI, Work Folders, FTP widen exposure.
- Severity: low. Lens: security. Category: HYG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim Win32_Service for NfsService, WinTarget, SyncShareSvc, ftpsvc
- Condition: running unless in threshold filesrv.protocols-allowed.
- Refs: NIST-800-53:CM-7
- Fix: Remove.
- Confidence: verified.

### FILESRV-SHADOW-COPY - Previous versions coverage
- Rows: FILESRV-BCK-001, FILESRV-BCK-002, FILESRV-BCK-003
- What and why: Shadow copies give self-service restore.
- Severity: medium. Lens: maintenance. Category: BCK
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/cimv2 Win32_ShadowCopy grouped by VolumeName with Win32_Volume
- Condition: share volume with no copy, newest older than 24 h, oldest younger than 7 days or fewer than 10 copies.
- Refs: NIST-800-53:CP-9
- Fix: Schedule.
- Confidence: verified.

### FILESRV-SHADOW-STORAGE-LIMIT - Shadow storage limit or placement
- Rows: FILESRV-BCK-004, FILESRV-BCK-005
- What and why: Too small limit loses copies.
- Severity: low. Lens: maintenance. Category: BCK
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim Win32_ShadowStorage
- Condition: MaxSpace below 10 % or UsedSpace above 90 % of MaxSpace; DiffVolume same as Volume above 1 TB.
- Refs: NIST-800-53:CP-9
- Fix: Adjust.
- Confidence: verified.

### FILESRV-SHARE-ACL-BROAD - Share ACL grants Full or Change to everyone
- Rows: FILESRV-IAM-001, FILESRV-IAM-002
- What and why: Share rights above NTFS.
- Severity: high. Lens: security. Category: IAM
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/SMB access entries (class to confirm)
- Condition: broad principal with Full or Change; Everyone present.
- Refs: NIST-800-53:AC-3, NIST-800-53:AC-6
- Fix: Narrow.
- Confidence: guess.

### FILESRV-SHARE-HIDDEN - Undocumented hidden share
- Rows: FILESRV-CFG-002
- What and why: Hidden shares escape review.
- Severity: low. Lens: security. Category: HYG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim MSFT_SmbShare where Name ends with $ and Special false
- Condition: not in threshold filesrv.hidden-allowed.
- Refs: NIST-800-53:CM-7
- Fix: Document or remove.
- Confidence: verified.

### FILESRV-SHARE-NOT-ACCESSED - Share unused for 90 days
- Rows: FILESRV-HYG-009
- What and why: Archive candidates.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\file-servers.yaml (new pack)
- Data: protocol eventlog Security 5140 per share name over 90 days (File Share auditing on)
- Condition: none.
- Refs: NIST-800-53:SI-12
- Fix: Archive.
- Confidence: guess.

### FILESRV-SHARE-OFFLINE - Share not online
- Rows: FILESRV-HLT-018
- What and why: Offline share equals outage.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim MSFT_SmbShare ShareState
- Condition: not Online.
- Refs: NIST-800-53:CP-2
- Fix: Fix.
- Confidence: verified.

### FILESRV-SHARE-ON-SYSTEM-DRIVE - Share on the system drive
- Rows: FILESRV-CFG-006
- What and why: Data on C: risks the OS and backups.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim MSFT_SmbShare Path with Win32_OperatingSystem SystemDrive
- Condition: path on system drive, non-special.
- Refs: NIST-800-53:CP-9
- Fix: Move.
- Confidence: verified.

### FILESRV-SHARE-SETTINGS - Share enumeration, caching, encryption and availability settings
- Rows: FILESRV-AVL-014, FILESRV-CFG-004, FILESRV-CFG-005, FILESRV-CFG-007, FILESRV-CFG-008, FILESRV-AUT-004
- What and why: ABE, caching, encryption and continuous availability per share.
- Severity: medium. Lens: security. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/SMB MSFT_SmbShare (FolderEnumerationMode, CachingMode, EncryptData, ContinuouslyAvailable, ConcurrentUserLimit, Description)
- Condition: findings: departmental or home shares without access-based enumeration; caching other than None on sensitive shares; sensitive shares without EncryptData; ContinuouslyAvailable on a non-cluster; empty description (info).
- Refs: NIST-800-53:AC-3, NIST-800-53:SC-8
- Fix: Set.
- Confidence: verified.

### FILESRV-SMB-SERVER-LATENCY - SMB server latency or queue
- Rows: FILESRV-HLT-007
- What and why: Latency and work item shortages.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim Win32_PerfFormattedData_SMBServerShares_SMBServerShares, Win32_PerfFormattedData_PerfNet_ServerWorkQueues, Win32_PerfFormattedData_PerfNet_Server
- Condition: AvgsecPerRequest > 0.02, QueueLength > 4, pool failures > 0.
- Refs: NIST-800-53:SI-4
- Fix: Tune.
- Confidence: likely.

### FILESRV-SMB-SERVER-POSTURE - SMB server configuration posture
- Rows: FILESRV-AUT-005, FILESRV-AUT-014, FILESRV-AUT-016, FILESRV-PKI-002
- What and why: Encryption, QUIC, audit and certificate mapping.
- Severity: low. Lens: security. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/SMB MSFT_SmbServerConfiguration (EncryptData, RejectUnencryptedAccess, EnableSMBQUIC, AuditSmb1Access) and MSFT_SmbServerCertificateMapping
- Condition: AuditSmb1Access off while SMB1 on; QUIC enabled without mapping; inconsistent encryption.
- Refs: NIST-800-53:SC-8
- Fix: Align.
- Confidence: likely.

### FILESRV-SMB1-CLIENTS-CONNECTED - Sessions below the current dialect
- Rows: FILESRV-AUT-002, FILESRV-AUT-006
- What and why: Older dialect clients.
- Severity: medium. Lens: security. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim, root/Microsoft/Windows/SMB MSFT_SmbSession Dialect
- Condition: any below 2.02 (and share below 3.0 above 5 %).
- Refs: NIST-800-53:CM-7
- Fix: Update client.
- Confidence: verified.

### FILESRV-VOLUME-COMPRESSED - Compressed data volume
- Rows: FILESRV-HLT-012
- What and why: Compression hurts shares.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim Win32_Volume Compressed
- Condition: true.
- Refs: NIST-800-53:SC-5
- Fix: Disable.
- Confidence: verified.

### FILESRV-VOLUME-OVERSIZED - Over-provisioned data volume
- Rows: FILESRV-CST-002
- What and why: Cost.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\file-servers.yaml (new pack)
- Data: protocol cim Win32_Volume Capacity, FreeSpace
- Condition: capacity > 1 TB and > 50 % free for 3 runs.
- Refs: NIST-800-53:SC-5
- Fix: Right-size.
- Confidence: likely.

### HYB-EVT-PHS-FAILURE - Password hash synchronisation errors on the sync server
- Rows: AD-501
- What and why: Hash sync runs every couple of minutes; events 611, 650, 656, 657 mean cycles are failing or never started, so cloud passwords lag the directory.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\hybrid-identity.yaml
- Data: protocol eventlog on the sync server, log Application, provider Directory Synchronization, ids [611, 650, 656, 657], days 2; per-host
- Condition: count > 0 for 611, 656, 657; absence of 650/651 for two days (second rule, count none).
- Refs: NIST-800-53:SI-4, NIST-800-53:IA-5
- Fix: Restart the sync scheduler, check the connector account and the cloud credentials.
- Confidence: likely - ids from the sync product documentation.

### INTUNE-CONFIG-SCOPE-REVIEW - Sensitive configuration profile scoped too wide
- Rows: WINCLIENT-CFG-028, WINCLIENT-CFG-029
- What and why: Profiles that block tools or switch device mode (shared PC, command-prompt block) harm admins when assigned to everyone; the assignment and exclusion lists show the reach.
- Severity: medium. Lens: both. Category: CFG
- File: rules\intune.yaml
- Data: protocol http (Graph) deviceManagement/deviceConfigurations with $expand=assignments; fields displayName, @odata.type, assignments[].target; estate-wide
- Condition: finding when a profile whose type or name matches threshold intune.sensitive-profile-pattern targets all devices/all users or has no exclusion group.
- Refs: NIST-800-53:CM-6, NIST-800-53:AC-6
- Fix: Scope the profile to the intended group and add admin exclusions.
- Confidence: guess - the profile list is tenant input.

### INTUNE-ENDPOINT-ANALYTICS-COVERAGE - Managed Windows devices missing from Endpoint analytics
- Rows: WINCLIENT-MON-021
- What and why: Without startup and reliability scores a slow-fleet complaint cannot be checked against data.
- Severity: low. Lens: maintenance. Category: MON
- File: rules\intune.yaml
- Data: protocol http (Graph) deviceManagement/userExperienceAnalyticsDeviceScores ($count) against managed Windows devices ($count); estate-wide
- Condition: finding when scored devices are below threshold intune.analytics-min-percent (default 90) of managed Windows devices.
- Refs: NIST-800-53:CA-7
- Fix: Enable data collection in the enrolment policy.
- Confidence: guess - endpoint names to confirm.

### PRINT-DRIVER-OLD - Print driver of an old model
- Rows: PRINT-LCM-003
- What and why: Version 3 or unsigned drivers.
- Severity: low. Lens: security. Category: LCM
- File: rules\print-servers.yaml (new pack)
- Data: protocol cim, root/StandardCimv2 MSFT_PrinterDriver (MajorVersion, DriverVersion)
- Condition: MajorVersion 3 where v4 exists, or unsigned.
- Refs: NIST-800-53:SI-7
- Fix: Replace.
- Confidence: likely.

### PRINT-DRIVER-UNUSED - Installed driver without a queue
- Rows: PRINT-LCM-004
- What and why: Unused drivers widen the spooler surface.
- Severity: low. Lens: security. Category: HYG
- File: rules\print-servers.yaml (new pack)
- Data: protocol store; MSFT_PrinterDriver vs MSFT_Printer DriverName
- Condition: unused.
- Refs: NIST-800-53:CM-7
- Fix: Remove.
- Confidence: likely.

### PRINT-EVT-SERVER - Print service errors
- Rows: PRINT-LOG-001
- What and why: Admin channel errors.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\print-servers.yaml (new pack)
- Data: protocol eventlog logs Microsoft-Windows-PrintService/Admin and System, level 1-3, days 7
- Condition: any.
- Refs: NIST-800-53:SI-4
- Fix: Read.
- Confidence: verified.

### PRINT-JOB-STUCK - Print job stuck
- Rows: PRINT-HLT-003
- What and why: Stuck jobs block queues.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\print-servers.yaml (new pack)
- Data: protocol cim, root/StandardCimv2 MSFT_PrintJob (SubmittedTime, JobStatus)
- Condition: older than 24 h or error.
- Refs: NIST-800-53:SI-4
- Fix: Clear.
- Confidence: likely.

### PRINT-OPERATIONAL-LOG-ENABLED - Per-user print log enabled without a decision
- Rows: PRINT-LOG-002
- What and why: Personal data log.
- Severity: medium. Lens: security. Category: LOG
- File: rules\print-servers.yaml (new pack)
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Operational value Enabled
- Condition: enabled while threshold print.operational-log-allowed is false.
- Refs: NIST-800-53:AU-2, NIST-800-53:PT-2
- Fix: Align with the decision.
- Confidence: likely.

### PRINT-PORT-SNMP-DEFAULT-COMMUNITY - Printer port with a default SNMP community
- Rows: PRINT-CFG-005, PRINT-AUT-005
- What and why: Default communities expose devices.
- Severity: medium. Lens: security. Category: AUT
- File: rules\print-servers.yaml (new pack)
- Data: protocol cim, root/StandardCimv2 MSFT_PrinterPort (SNMPEnabled, SNMPCommunity)
- Condition: community public.
- Refs: NIST-800-53:IA-5, NIST-800-53:CM-7
- Fix: Use v3.
- Confidence: likely.

### PRINT-PUBLISHED-QUEUE-DEAD - Published queue without a live share
- Rows: PRINT-CFG-002
- What and why: Directory lists dead queues.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\print-servers.yaml (new pack)
- Data: protocol store; ldap printQueue objects vs MSFT_Printer shares
- Condition: no live share.
- Refs: NIST-800-53:CM-8
- Fix: Delete.
- Confidence: likely.

### PRINT-QUEUE-DUPLICATE-PORT - Two queues on one port
- Rows: PRINT-CFG-001
- What and why: Duplicates distort counts.
- Severity: info. Lens: maintenance. Category: HYG
- File: rules\print-servers.yaml (new pack)
- Data: protocol store; MSFT_Printer grouped by PortName
- Condition: > 1.
- Refs: NIST-800-53:CM-8
- Fix: Merge.
- Confidence: guess.

### PRINT-QUEUE-ERROR - Queue in error or offline
- Rows: PRINT-HLT-004
- What and why: Users cannot print.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\print-servers.yaml (new pack)
- Data: protocol cim, root/StandardCimv2 MSFT_Printer PrinterStatus, WorkOffline
- Condition: error or offline on shared queues.
- Refs: NIST-800-53:CP-2
- Fix: Fix.
- Confidence: verified.

### SCCM-AD-PUBLISHING-STALE - Site objects in the directory for sites or boundaries that no longer exist
- Rows: SCCM-HYG-011
- What and why: Old publishing objects mislead clients that look up management points in AD.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol ldap CN=System Management,CN=System,{DOMAINDN} (objectClass mSSMSSite, mSSMSManagementPoint, mSSMSRoamingBoundaryRange); store join with /wmi/SMS_Site and /wmi/SMS_Boundary
- Condition: finding when the site code or range has no live counterpart.
- Refs: NIST-800-53:CM-8
- Fix: Delete the objects.
- Confidence: likely.

### SCCM-ALERT-RECIPIENT-STALE - Alert recipient is not an active mailbox
- Rows: SCCM-MON-002
- What and why: Site alerts addressed to departed staff are never read.
- Severity: medium. Lens: maintenance. Category: MON
- File: rules\sccm.yaml
- Data: protocol store; alert subscription recipients (class to confirm) joined to AD/Exchange recipient state
- Condition: finding when the recipient is disabled or missing.
- Refs: NIST-800-53:IR-6
- Fix: Point the subscription at a shared mailbox.
- Confidence: guess.

### SCCM-ALERTS-NOT-CONFIGURED - Key site alerts not enabled or not subscribed
- Rows: SCCM-MON-001, SCCM-MON-011
- What and why: Without alerts nobody hears about database space, sync or client health.
- Severity: medium. Lens: maintenance. Category: MON
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Alert and subscription class (to confirm); fields TypeID, IsEnabled
- Condition: finding when an alert type in threshold sccm.required-alerts has no enabled definition with a subscription.
- Refs: NIST-800-53:SI-4(5)
- Fix: Create and subscribe.
- Confidence: guess.

### SCCM-APPLICATION-UNUSED - Applications and packages that are neither deployed nor referenced
- Rows: SCCM-HYG-008, SCCM-HYG-010, GYTPOL-LCM-005, WSS-LCM-006
- What and why: Dead content wastes distribution space and hides what matters.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Application (IsDeployed, IsExpired) and /wmi/SMS_Package with /wmi/SMS_TaskSequencePackageReference
- Condition: finding when undeployed and unreferenced for more than 12 months.
- Refs: NIST-800-53:CM-7
- Fix: Retire and delete.
- Confidence: likely.

### SCCM-AUDIT-CHANGES-RECENT - Administrative changes and executions in the last week
- Rows: SCCM-MON-006, SCCM-MON-007
- What and why: A weekly list of role, deployment and script-run changes is the change-control check.
- Severity: info. Lens: security. Category: MON
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_StatusMessage filter MessageType 768 (audit) and /wmi/SMS_ScriptsExecutionStatus
- Condition: any row in the window, grouped by user.
- Refs: NIST-800-53:AU-6, NIST-800-53:CM-3
- Fix: Compare with change records.
- Confidence: likely.

### SCCM-AVAILABLE-APP-NO-APPROVAL - Sensitive application available without approval
- Rows: SCCM-IAM-025
- What and why: Remote tools or admin software offered to users freely.
- Severity: low. Lens: security. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_ApplicationAssignment (RequireApproval, ApplicationName)
- Condition: finding when RequireApproval is false and the name matches threshold sccm.sensitive-app-pattern.
- Refs: NIST-800-53:CM-11
- Fix: Require approval.
- Confidence: guess.

### SCCM-BACKUP-STALE - Site backup too old
- Rows: SCCM-BCK-002
- What and why: The site backup is the main recovery asset.
- Severity: high. Lens: maintenance. Category: BCK
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SQLTaskStatus?$filter=TaskName eq 'Backup SMS Site Server' (LastCompletionTime, CompletionStatus)
- Condition: finding when no success within 26 hours.
- Refs: NIST-800-53:CP-9
- Fix: Read smsbkup.log; fix the target.
- Confidence: likely.

### SCCM-BOOTIMAGE-COMMAND-SUPPORT - Command support on a production boot image
- Rows: SCCM-AUT-011
- What and why: Command support in WinPE gives a shell to anyone with media.
- Severity: medium. Lens: security. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_BootImagePackage (EnableLabShell)
- Condition: finding when true on images referenced by deployed sequences.
- Refs: NIST-800-53:CM-7
- Fix: Disable.
- Confidence: verified.

### SCCM-BOUNDARY-DEFAULT-GROUP-HAS-DP - Default boundary group lists a distribution point
- Rows: SCCM-AVL-008
- What and why: Clients outside all groups then pull content from a possibly remote server.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_BoundaryGroupSiteSystems for the default group
- Condition: any row unless intended.
- Refs: NIST-800-53:CM-6
- Fix: Remove or document.
- Confidence: likely.

### SCCM-BOUNDARY-OVERLAP - Overlapping boundary ranges
- Rows: SCCM-CFG-002
- What and why: Overlap makes content location unpredictable.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Boundary (BoundaryType, Value); range overlap computed in the store
- Condition: finding for each overlapping pair across groups.
- Refs: NIST-800-53:CM-2
- Fix: Merge boundaries.
- Confidence: guess - IPv4 integer math.

### SCCM-CLIENT-SETTINGS-DRIFT - Client settings off the intended values
- Rows: SCCM-CFG-010, SCCM-CFG-011, SCCM-CFG-012, SCCM-CFG-013, SCCM-CFG-014, SCCM-CFG-015, SCCM-CFG-016, SCCM-CFG-017, SCCM-CFG-051, SCCM-IAM-018, SCCM-AUT-020
- What and why: Polling, inventory scope, restart behaviour, remote control prompts and viewers are set once and rarely reviewed.
- Severity: medium. Lens: both. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_ClientSettings and SMS_ClientSettingsAssignment plus site definition properties (names to confirm); fields area, key, value
- Condition: finding when a value differs from threshold sccm.client-settings-expected.
- Refs: NIST-800-53:CM-6, NIST-800-53:AC-17
- Fix: Edit the setting.
- Confidence: guess - property names unconfirmed.

### SCCM-CLIENT-SETTINGS-POWERSHELL-BYPASS - Client execution policy set to bypass
- Rows: SCCM-AUT-008, KN-client-powershell-policy-bypass
- What and why: Bypass runs unsigned scripts from deployments.
- Severity: high. Lens: security. Category: AUT
- File: rules\sccm.yaml
- Data: protocol http client settings 'Computer Agent' PowerShellExecutionPolicy
- Condition: finding when Bypass (or Unrestricted).
- Refs: NIST-800-53:CM-7, NIST-800-53:SI-7
- Fix: AllSigned once content is signed.
- Confidence: likely.

### SCCM-CLIENT-UPGRADE-AUTO-OFF - Automatic client upgrade off
- Rows: SCCM-LCM-006
- What and why: Clients drift behind the site version.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SCI_SiteDefinition properties for client upgrade (names to confirm)
- Condition: finding when disabled.
- Refs: NIST-800-53:SI-2
- Fix: Enable with a pilot window.
- Confidence: guess.

### SCCM-COLLECTION-DESIGN - Collection evaluation and limiting design problems
- Rows: SCCM-CFG-020, SCCM-CFG-021, SCCM-CFG-022, SCCM-CFG-023
- What and why: Frequent full evaluations, deployments limited to the all-systems collection and direct-only collections cause load and mis-targeting.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Collection (RefreshType, RefreshSchedule, LimitToCollectionID, MemberCount) and /wmi/SMS_DeploymentSummary
- Condition: findings for full schedule more often than 4 h; Required deployment limited to the built-in all-systems collection; Required deployment to a collection with only direct rules.
- Refs: NIST-800-53:CM-3
- Fix: Redesign.
- Confidence: likely.

### SCCM-COMMANDLINE-SECRET - Secret in a program command line
- Rows: SCCM-AUT-022
- What and why: Command lines are readable by all admins and by clients.
- Severity: high. Lens: security. Category: AUT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Program CommandLine and deployment type install commands; regex scan, values masked in evidence
- Condition: finding on match of (?i)(password|pwd|secret|token|apikey)\s*[=:] or /p:\S+.
- Refs: NIST-800-53:IA-5(7), CIS-Controls-v8:3.11
- Fix: Move the secret to a vault.
- Confidence: likely.

### SCCM-COMPONENT-STALE - Site component not reporting
- Rows: SCCM-HLT-005
- What and why: A component that stopped reporting hides failures.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_ComponentSummarizer (ComponentName, LastContacted, State)
- Condition: finding when LastContacted older than its interval plus 2 h.
- Refs: NIST-800-53:SI-4
- Fix: Check the component log.
- Confidence: likely.

### SCCM-CONFIGBASELINE-NONE - No configuration baseline deployed
- Rows: SCCM-CFG-045
- What and why: Compliance settings give the SCCM view of hardening.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_ConfigurationBaselineInfo (IsAssigned, IsEnabled)
- Condition: finding when no baseline is assigned.
- Refs: NIST-800-53:CM-6
- Fix: Deploy a baseline or record the decision.
- Confidence: guess.

### SCCM-CONSOLE-VERSION-OLD - Console below the site version
- Rows: SCCM-LCM-008
- What and why: Old consoles fail or write wrong data.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_ConsoleAdminsData (ConsoleVersion, LastConnectedConsoleTime)
- Condition: finding when version differs from the site build for connections in 90 days.
- Refs: NIST-800-53:SI-2
- Fix: Update the console.
- Confidence: likely.

### SCCM-DEPLOYMENT-CONTENT-MISSING - Required deployment without content on a distribution point
- Rows: SCCM-AVL-010
- What and why: Content missing from the serving DP makes the deployment fail.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_DeploymentSummary joined to /wmi/SMS_PackageStatusDistPointsSummarizer
- Condition: finding when no DP in the target's group holds the content.
- Refs: NIST-800-53:CP-2
- Fix: Distribute the content.
- Confidence: guess.

### SCCM-DEPLOYMENT-DUPLICATE - Same software deployed to overlapping collections
- Rows: SCCM-CFG-036, WSS-LCM-005
- What and why: Duplicates multiply errors and policy size.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_DeploymentSummary grouped by SoftwareName and collection
- Condition: finding for more than 2 active deployments of one application.
- Refs: NIST-800-53:CM-2
- Fix: Consolidate.
- Confidence: guess.

### SCCM-DEPLOYMENT-NO-PILOT - Broad deployment without an earlier pilot
- Rows: SCCM-CFG-035
- What and why: Changes should reach few machines first.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_ApplicationAssignment (CreationTime, TargetCollectionID) with collection member counts
- Condition: finding when a Required deployment to a collection above 25 members has no earlier deployment of the same item to a collection below 25.
- Refs: NIST-800-53:CM-3, NIST-800-53:CM-4
- Fix: Pilot first.
- Confidence: guess.

### SCCM-DEPLOYMENT-NO-TARGETS - Deployment that targets no devices
- Rows: SCCM-HYG-003
- What and why: Dead deployments clutter and confuse reporting.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_DeploymentSummary (NumberTargeted, DeploymentTime)
- Condition: NumberTargeted 0 after 7 days.
- Refs: NIST-800-53:CM-2
- Fix: Delete.
- Confidence: verified.

### SCCM-DEVICE-OBSOLETE-RECORDS - Obsolete or duplicate device records
- Rows: WINCLIENT-HYG-003, SCCM-HYG-005, SCCM-HYG-006
- What and why: Duplicates and obsolete records skew counts and cause conflicts.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_R_System (Obsolete, Decommissioned, Name, SMBIOSGUID)
- Condition: findings for Obsolete=1 older than 7 days; duplicate Name or SMBIOSGUID among non-obsolete rows.
- Refs: NIST-800-53:CM-8
- Fix: Run the maintenance tasks.
- Confidence: likely.

### SCCM-DISCOVERY-CONFIG - Discovery methods off the intended design
- Rows: SCCM-CFG-004, SCCM-CFG-005, SCCM-CFG-006, SCCM-CFG-007
- What and why: Scope, schedule and filters of discovery decide what the site knows.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SCI_Component for the discovery agents and /wmi/SMS_SCI_ClientConfig (Heartbeat Discovery) with Props/PropLists
- Condition: findings for disabled AD system discovery, delta interval above 60 min, activity filters off, heartbeat above 7 days, network discovery enabled, or forest discovery auto-creating boundaries.
- Refs: NIST-800-53:CM-8
- Fix: Edit discovery.
- Confidence: guess - property names unconfirmed.

### SCCM-DP-CERT-EXPIRY - Distribution point certificate near expiry
- Rows: SCCM-PKI-003
- What and why: An expired DP certificate stops content transfer.
- Severity: medium. Lens: maintenance. Category: PKI
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_DistributionPointInfo certificate expiry property (to confirm)
- Condition: finding when under 90 days.
- Refs: NIST-800-53:SC-17
- Fix: Renew.
- Confidence: guess.

### SCCM-DP-CONTENT-VALIDATION-OFF - Content validation not scheduled
- Rows: SCCM-CFG-040, KN-dp-content-validation-stale
- What and why: Validation finds corrupt content before clients do.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SCI_SysResUse DP properties DPMonEnabled, DPMonSchedule
- Condition: finding when disabled.
- Refs: NIST-800-53:SI-7
- Fix: Enable weekly.
- Confidence: guess.

### SCCM-DP-SETTINGS-DRIFT - Distribution point role settings off the design
- Rows: SCCM-CFG-039, SCCM-CFG-041, SCCM-CFG-042, SCCM-AUT-010
- What and why: PXE password, unknown-computer support, content location and group usage deserve review.
- Severity: medium. Lens: security. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SCI_SysResUse DP properties (IsPXE, SupportUnknownMachines, PxePassword present flag, ContentLibraryLocation) and SMS_DPGroupContentInfo
- Condition: findings for PXE without password, unknown-computer support enabled, content on the system drive, content outside DP groups.
- Refs: NIST-800-53:CM-6, NIST-800-53:AC-3
- Fix: Adjust.
- Confidence: guess.

### SCCM-INCONSOLE-UPDATE-PENDING - Site update or hotfix available and not installed
- Rows: SCCM-LCM-002
- What and why: Hotfixes accumulate.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_CM_UpdatePackages (State, DateReleased)
- Condition: finding when State is available and released more than 30 days ago.
- Refs: NIST-800-53:SI-2
- Fix: Install or record a skip reason.
- Confidence: verified.

### SCCM-MAINT-TASK-CONFIG - Maintenance task retention off the design
- Rows: SCCM-CFG-008, SCCM-CFG-009, SCCM-MON-005
- What and why: Missing cleanup and retention settings cause database growth and stale data.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SCI_SQLTask (TaskName, Enabled, DeleteOlderThan)
- Condition: findings for disabled required tasks, retention above thresholds sccm.maint-retention-days.
- Refs: NIST-800-53:CM-6, NIST-800-53:AU-11
- Fix: Enable and set retention.
- Confidence: likely.

### SCCM-MAINT-TASK-FAILED - Maintenance task not completing
- Rows: SCCM-LOG-014
- What and why: Failed tasks stop cleanup and backups.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SQLTaskStatus (CompletionStatus, LastCompletionTime)
- Condition: finding when CompletionStatus indicates failure.
- Refs: NIST-800-53:SI-4
- Fix: Read smsdbmon.log.
- Confidence: likely.

### SCCM-METERED-SOFTWARE-UNUSED - Installed paid software not used
- Rows: WINCLIENT-CST-010
- What and why: Metering shows licences nobody uses.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_MonthlyUsageSummary (FileName, LastUsage) with metering rules
- Condition: finding when no use for 90 days.
- Refs: NIST-800-53:CM-10
- Fix: Reclaim.
- Confidence: guess.

### SCCM-MGMT-INSIGHTS-ACTION-NEEDED - Management insight rule needs action
- Rows: SCCM-MON-008
- What and why: Built-in advice from the product.
- Severity: low. Lens: maintenance. Category: MON
- File: rules\sccm.yaml
- Data: protocol http insight result class (name unconfirmed)
- Condition: finding when state is action needed.
- Refs: NIST-800-53:CM-6
- Fix: Act or record.
- Confidence: guess.

### SCCM-MP-NOT-ANSWERING - Management point does not answer its probe URLs
- Rows: SCCM-HLT-017
- What and why: A reachable MP is the core service.
- Severity: critical. Lens: maintenance. Category: AVL
- File: rules\sccm.yaml
- Data: protocol http GET http://<mp>/sms_mp/.sms_aut?mplist and ?mpcert; status and body
- Condition: finding when status not 200 or timeout over 5 s.
- Refs: NIST-800-53:CP-2, NIST-800-53:SI-4
- Fix: Check IIS and the MP log.
- Confidence: guess - XML body handling.

### SCCM-PATCH-RING-MISSING - Host not in a patch ring
- Rows: SCCM-CFG-030, APP-BASELINE-LCM-016
- What and why: Servers in no ring are patched by accident or never.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_FullCollectionMembership for ring collections named in threshold sccm.patch-ring-collections
- Condition: finding when an active server is in none or more than one ring.
- Refs: NIST-800-53:SI-2, NIST-800-53:CM-3
- Fix: Place it.
- Confidence: guess.

### SCCM-PENDING-REGISTRATION-RECORDS - Pending registration conflicts
- Rows: SCCM-CFG-050
- What and why: Conflicting records block clients.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_PendingRegistrationRecord
- Condition: finding when older than 7 days.
- Refs: NIST-800-53:CM-8
- Fix: Resolve.
- Confidence: likely.

### SCCM-PROGRAM-ADMIN-INTERACTIVE - Program runs as administrator and allows user interaction
- Rows: SCCM-AUT-013
- What and why: That combination is a privilege-escalation path.
- Severity: high. Lens: security. Category: AUT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Program ProgramFlags bits for run-with-administrative-rights and user-interaction
- Condition: both set on a deployed program.
- Refs: NIST-800-53:AC-6
- Fix: Remove interaction or run hidden.
- Confidence: verified.

### SCCM-RBAC-ADMIN-NAMING - Administrative user not an admin-tier account
- Rows: SCCM-IAM-026
- What and why: Admin work should use separate accounts.
- Severity: medium. Lens: security. Category: IAM
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Admin LogonName
- Condition: finding when LogonName does not match threshold sccm.admin-account-pattern.
- Refs: NIST-800-53:AC-6(2)
- Fix: Use a dedicated account.
- Confidence: likely.

### SCCM-RBAC-BUILTIN-AD-GROUP - Built-in AD admin group holds a site role
- Rows: SCCM-IAM-002
- What and why: Domain-wide groups should not control the site.
- Severity: high. Lens: security. Category: IAM
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Admin (LogonName, RoleNames)
- Condition: LogonName ends in Domain Admins, Enterprise Admins or Administrators.
- Refs: NIST-800-53:AC-6(1)
- Fix: Use a dedicated group.
- Confidence: verified.

### SCCM-RBAC-REMOTE-CODE-ROLES - Roles that can run code on clients
- Rows: SCCM-IAM-006
- What and why: Remote control, scripts and deployment rights define who can execute on every client.
- Severity: medium. Lens: security. Category: IAM
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Role operations (decoded) with /wmi/SMS_Admin holders
- Condition: finding for holders outside threshold sccm.code-exec-allowed.
- Refs: NIST-800-53:AC-6
- Fix: Remove rights.
- Confidence: guess - operations decoding.

### SCCM-RETIRED-PRODUCT-DEPLOYED - Deployment of a retired product
- Rows: SCCM-HYG-009, SCCM-HYG-021, ESET-CFG-014
- What and why: Retired products must not be pushed.
- Severity: medium. Lens: security. Category: HYG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_DeploymentSummary SoftwareName
- Condition: finding when it matches threshold sccm.retired-products.
- Refs: NIST-800-53:CM-7, NIST-800-53:SA-22
- Fix: Remove the deployment.
- Confidence: likely.

### SCCM-SCRIPT-EMBEDDED-SECRET - Secret in a run script body
- Rows: SCCM-AUT-021
- What and why: Script bodies are readable by admins.
- Severity: high. Lens: security. Category: AUT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Scripts Script body; regex scan
- Condition: match of credential patterns.
- Refs: NIST-800-53:IA-5(7)
- Fix: Use a vault.
- Confidence: guess.

### SCCM-SCRIPT-UNSIGNED - Script without a valid signature
- Rows: SCCM-AUT-009, SCCM-HYG-017, GYTPOL-HYG-004
- What and why: Unsigned scripts bypass review control.
- Severity: medium. Lens: security. Category: AUT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_Scripts Script body checked for a signature block
- Condition: finding when absent for an approved script.
- Refs: NIST-800-53:SI-7, NIST-800-53:CM-14
- Fix: Sign.
- Confidence: guess.

### SCCM-SERVER-NO-MAINT-WINDOW - Active server without a maintenance window
- Rows: WINSRV-LCM-010, SCCM-AVL-014, APP-BASELINE-AVL-006
- What and why: Servers must patch inside agreed windows.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_FullCollectionMembership and /wmi/SMS_ServiceWindow
- Condition: finding when no enabled update window of at least 3 hours applies.
- Refs: NIST-800-53:SI-2, NIST-800-53:CM-3
- Fix: Add the host to a ring.
- Confidence: likely.

### SCCM-SERVER-UPDATE-SCAN-STALE - Server update scan too old
- Rows: WINSRV-LCM-007
- What and why: See the workstation form.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_UpdateScanStatus for server resources
- Condition: older than 7 days or error.
- Refs: NIST-800-53:SI-2
- Fix: Repair.
- Confidence: likely.

### SCCM-SITE-COMM-SECURITY - Site communication and approval settings weak
- Rows: SCCM-AUT-001, SCCM-AUT-002, SCCM-AUT-003, SCCM-AUT-004, SCCM-AUT-005, SCCM-PKI-006, SCCM-PKI-007
- What and why: Client communication mode, signing, approval and push fallback settings define transport security.
- Severity: high. Lens: security. Category: AUT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SCI_SiteDefinition and ClientConfig properties (names to confirm)
- Condition: findings for HTTP-only communication, signing not required, SHA-256 not required, automatic approval of all, NTLM fallback on, CRL checking off, push enabled to servers.
- Refs: NIST-800-53:SC-8, NIST-800-53:IA-3
- Fix: Change in site properties.
- Confidence: guess.

### SCCM-SITE-ROLES-ON-ONE-SERVER - Single point of failure for all site roles
- Rows: SCCM-AVL-001, SCCM-AVL-002, SCCM-AVL-012, KN-single-server-all-roles
- What and why: One server carrying every role loses everything at once.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SCI_SysResUse (NetworkOSPath, RoleName)
- Condition: finding when roles of type management point, distribution point, software update point or provider exist on a single host only.
- Refs: NIST-800-53:CP-2, NIST-800-53:CP-10
- Fix: Add a second role holder or record the accepted risk.
- Confidence: verified.

### SCCM-SITE-SYSTEM-ROLE-STALE - Site role on a retired or unknown server
- Rows: SCCM-CFG-001, SCCM-HYG-020
- What and why: Roles remaining on gone hosts break discovery.
- Severity: medium. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol store; /wmi/SMS_SystemResourceList joined to AD computer state
- Condition: finding when the server is disabled or missing.
- Refs: NIST-800-53:CM-8
- Fix: Remove the role.
- Confidence: likely.

### SCCM-SMSADMINS-GROUP-MEMBERS - Members of the provider admin group
- Rows: SCCM-IAM-012
- What and why: The local group grants provider access.
- Severity: medium. Lens: security. Category: IAM
- File: rules\sccm.yaml
- Data: protocol cim Win32_GroupUser for 'SMS Admins' on the provider host
- Condition: any member outside threshold sccm.sms-admins-allowed.
- Refs: NIST-800-53:AC-6
- Fix: Remove.
- Confidence: verified.

### SCCM-SSRS-FAILING - Report server failures
- Rows: SCCM-HLT-037
- What and why: Reports used for compliance stop working.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol sql on ReportServer: SELECT Status, TimeStart FROM dbo.ExecutionLog3 WHERE TimeStart > dateadd(day,-7,getdate())
- Condition: finding when failed share exceeds 5 %.
- Refs: NIST-800-53:SI-4
- Fix: Read the report server log.
- Confidence: verified.

### SCCM-SSRS-ROLE-ASSIGNMENTS - Report server role assignments
- Rows: SCCM-IAM-017
- What and why: Content Manager rights over the report server.
- Severity: low. Lens: security. Category: IAM
- File: rules\sccm.yaml
- Data: protocol sql on ReportServer: dbo.PolicyUserRole joined to Users and Roles
- Condition: finding for principals outside threshold sccm.ssrs-admins-allowed.
- Refs: NIST-800-53:AC-6
- Fix: Remove.
- Confidence: guess.

### SCCM-STATUS-MESSAGE-ERRORS - Error status messages per site component
- Rows: SCCM-HLT-018, SCCM-LOG-001, SCCM-LOG-005, SCCM-LOG-007, SCCM-LOG-008, SCCM-LOG-015, SCCM-LOG-016, SCCM-LOG-017, SCCM-LOG-018, SCCM-LOG-021, SCCM-LOG-022
- What and why: Status messages are the site's own error log.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_StatusMessage?$filter=Severity eq -1073741824 and Time ge <now-24h> grouped by Component and MessageID; one rule per component family (management point, distribution, software update sync, client config, inventory, collection, discovery, task sequence, PXE)
- Condition: count > 0 per signature; severity high for management point and distribution manager.
- Refs: NIST-800-53:AU-6, NIST-800-53:SI-4
- Fix: Read the message and the component log.
- Confidence: likely.

### SCCM-STORED-ACCOUNT-PRIVILEGED - Account stored in the site is privileged or old
- Rows: SCCM-IAM-008, SCCM-IAM-009, SCCM-IAM-010, SCCM-IAM-019
- What and why: Push, network access and join accounts must not be admins.
- Severity: high. Lens: security. Category: IAM
- File: rules\sccm.yaml
- Data: protocol store; stored account names (SMS_SCI_Reserved / task sequence XML, secrets never read) joined to AD memberOf and pwdLastSet
- Condition: finding when the account is in a protected group, or pwdLastSet older than 365 days, or an interactive logon is possible.
- Refs: NIST-800-53:AC-6, NIST-800-53:IA-5
- Fix: Reduce rights; rotate.
- Confidence: guess.

### SCCM-SUP-CONFIG - Software update point configuration off the plan
- Rows: SCCM-CFG-024, SCCM-CFG-025, SCCM-CFG-026, SCCM-CFG-027, SCCM-CFG-032
- What and why: Products, sync schedule, languages, supersedence and third-party catalogues decide what is patchable.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_UpdateCategoryInstance (IsSubscribed) and SMS_SCI_Component for sync manager and configuration manager
- Condition: findings for products with no devices, installed OS or product with no subscription, sync less than daily, unneeded languages, expiry of superseded updates beyond 3 months.
- Refs: NIST-800-53:SI-2
- Fix: Edit the point.
- Confidence: guess.

### SCCM-SUP-ENDPOINT-NOT-ANSWERING - Update point web service not answering
- Rows: SCCM-AVL-011
- What and why: Clients cannot scan.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\sccm.yaml
- Data: protocol http GET <sup>:8530(8531)/ClientWebService/client.asmx and /SimpleAuthWebService/SimpleAuth.asmx
- Condition: not 200 or timeout over 5 s.
- Refs: NIST-800-53:SI-2
- Fix: Check IIS and the pool.
- Confidence: guess.

### SCCM-TS-REFERENCES-UNDEPLOYED-APP - Task sequence references content that is not available
- Rows: SCCM-CFG-038, GYTPOL-LCM-004, KN-ts-deployment-broken-gytpol-reference
- What and why: A reference to an undistributed application makes the sequence and policy generation fail.
- Severity: medium. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_TaskSequencePackageReference joined to SMS_Application deployment state and content status
- Condition: finding when the referenced item is undeployed or has no content.
- Refs: NIST-800-53:CM-3
- Fix: Fix the reference.
- Confidence: guess.

### SCCM-UPDATE-DEPLOYMENT-OBSOLETE - Old update deployments still live
- Rows: SCCM-HYG-004
- What and why: Deployments from past years clutter and slow policy.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_DeploymentSummary FeatureType 5 DeploymentTime
- Condition: older than 12 months and not the current ADR target.
- Refs: NIST-800-53:SI-2
- Fix: Delete.
- Confidence: likely.

### SCCM-UPDATE-DEPLOYMENT-SERVER-SETTINGS - Server update deployments allow restart outside windows
- Rows: SCCM-CFG-031
- What and why: Server restarts must respect windows.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_UpdatesAssignment (SuppressReboot, RebootOutsideOfServiceWindows, OverrideServiceWindows) for server collections
- Condition: finding when RebootOutsideOfServiceWindows or OverrideServiceWindows is true.
- Refs: NIST-800-53:CM-3
- Fix: Change the deployment.
- Confidence: likely.

### SCCM-UPDATE-PACKAGE-LARGE - Update deployment package very large
- Rows: SCCM-HLT-024
- What and why: Huge packages slow distribution.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol http /wmi/SMS_SoftwareUpdatesPackage PackageSize
- Condition: above 100 GB.
- Refs: NIST-800-53:SC-5
- Fix: Split by year.
- Confidence: verified.

### SCCM-WSUS-SUSDB-LARGE - Update database large or full of expired updates
- Rows: SCCM-HLT-015
- What and why: The database needs cleanup.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sccm.yaml
- Data: protocol sql on SUSDB: file size from sys.master_files and expired update count from tbUpdate
- Condition: size over 15 GB or expired count > 0.
- Refs: NIST-800-53:SI-2
- Fix: Run the cleanup.
- Confidence: guess - table names to confirm.

### SQL-AG-FAILOVER-NOT-READY - Availability database not failover-ready
- Rows: SQL-AVL-003
- What and why: A database that cannot fail over defeats the group.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT database_name, is_failover_ready FROM sys.dm_hadr_database_replica_cluster_states
- Condition: is_failover_ready = 0 on automatic failover groups.
- Refs: NIST-800-53:CP-10
- Fix: Resolve the sync state.
- Confidence: verified.

### SQL-AGENT-JOB-NO-NOTIFY - Enabled job does not notify on failure
- Rows: SQL-MON-004
- What and why: Failures go unseen.
- Severity: low. Lens: maintenance. Category: MON
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT name, notify_level_email, notify_email_operator_id FROM msdb.dbo.sysjobs WHERE enabled = 1
- Condition: notify_level_email = 0.
- Refs: NIST-800-53:SI-4
- Fix: Add an operator.
- Confidence: verified.

### SQL-AGENT-JOB-STALE - Job has not succeeded within two intervals
- Rows: SQL-MON-003
- What and why: Silent non-runs.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sysjobservers/sysjobhistory last success vs schedule frequency
- Condition: last success older than twice the interval.
- Refs: NIST-800-53:SI-4
- Fix: Check the schedule.
- Confidence: guess.

### SQL-AGENT-MAINTENANCE-JOB-MISSING - Maintenance job class missing, disabled or failing
- Rows: SQL-BCK-015, SQL-BCK-021, SQL-MON-002
- What and why: Backups, integrity checks, index and history cleanup must run.
- Severity: high. Lens: maintenance. Category: BCK
- File: rules\sql-server.yaml
- Data: protocol sql: msdb.dbo.sysjobs with sysjobsteps command text classified by BACKUP, CHECKDB, ALTER INDEX/UPDATE STATISTICS, sp_delete_backuphistory; enabled, schedule, last outcome
- Condition: finding when a class has no enabled scheduled job with last success.
- Refs: NIST-800-53:CP-9, NIST-800-53:SI-7
- Fix: Create or fix.
- Confidence: likely.

### SQL-AGENT-PROXY-PUBLIC - Credential or proxy usable by everyone
- Rows: SQL-IAM-021
- What and why: Proxies let jobs run as other accounts.
- Severity: medium. Lens: security. Category: IAM
- File: rules\sql-server.yaml
- Data: protocol sql: sys.credentials, msdb.dbo.sysproxies/sysproxylogin
- Condition: proxy granted to public.
- Refs: NIST-800-53:AC-6
- Fix: Restrict.
- Confidence: likely.

### SQL-AUDIT-GROUPS-MISSING - Audit specification lacks required action groups
- Rows: SQL-MON-011
- What and why: Login and privilege changes must be audited.
- Severity: medium. Lens: security. Category: MON
- File: rules\sql-server.yaml
- Data: protocol sql: sys.server_audit_specification_details
- Condition: required groups (FAILED_LOGIN_GROUP, SUCCESSFUL_LOGIN_GROUP, SERVER_ROLE_MEMBER_CHANGE_GROUP, SERVER_PERMISSION_CHANGE_GROUP, AUDIT_CHANGE_GROUP) absent.
- Refs: NIST-800-53:AU-2
- Fix: Add groups.
- Confidence: verified.

### SQL-AUDIT-TARGET-RISK - Audit target on a data volume or short retention
- Rows: SQL-MON-012
- What and why: Audit files filling data volumes stop the instance.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.server_file_audits
- Condition: path on a data volume or max_rollover_files too low.
- Refs: NIST-800-53:AU-4
- Fix: Move.
- Confidence: guess.

### SQL-AUTOGROW-FREQUENT - Frequent or slow file growth
- Rows: SQL-HLT-021
- What and why: Growth stalls.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT ... FROM sys.fn_trace_gettable((SELECT path FROM sys.traces WHERE is_default=1), DEFAULT) WHERE EventClass IN (92,93)
- Condition: more than 10 per file per week or duration over 1 s.
- Refs: NIST-800-53:SC-5
- Fix: Pre-size files.
- Confidence: likely.

### SQL-AV-EXCLUSIONS-MISSING - Required antivirus exclusions absent
- Rows: SQL-CFG-025
- What and why: Scanning database files hurts performance and risks corruption.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol cim root/Microsoft/Windows/Defender MSFT_MpPreference ExclusionExtension, ExclusionProcess on SQL hosts
- Condition: finding when mdf, ndf, ldf extensions or sqlservr.exe are not excluded while Defender is active.
- Refs: NIST-800-53:SI-3
- Fix: Add exclusions per the vendor list.
- Confidence: guess.

### SQL-BACKUP-HISTORY-SHORT - Backup history retention too short
- Rows: SQL-BCK-012
- What and why: Short history hides missed backups.
- Severity: low. Lens: maintenance. Category: BCK
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT MIN(backup_start_date) FROM msdb.dbo.backupset
- Condition: oldest row younger than 30 days.
- Refs: NIST-800-53:AU-11
- Fix: Adjust cleanup.
- Confidence: verified.

### SQL-BACKUP-LOG-CHAIN-BROKEN - Log backup chain broken
- Rows: SQL-BCK-011
- What and why: A gap makes point-in-time restore impossible.
- Severity: high. Lens: maintenance. Category: BCK
- File: rules\sql-server.yaml
- Data: protocol sql: msdb.dbo.backupset type L rows ordered with LAG on first_lsn/last_lsn
- Condition: first_lsn of a row differs from the previous last_lsn since the last full.
- Refs: NIST-800-53:CP-9
- Fix: Take a full backup and review who else backs up logs.
- Confidence: guess - window function over msdb.

### SQL-BACKUP-SNAPSHOT-CHAIN - Several tools back up the same database
- Rows: SQL-BCK-010
- What and why: Snapshot backups and native log backups from different tools break chains.
- Severity: medium. Lens: maintenance. Category: BCK
- File: rules\sql-server.yaml
- Data: protocol sql: msdb.dbo.backupset is_snapshot, is_copy_only, user_name, device_type
- Condition: more than one user name takes log backups, or snapshot backups are not copy-only.
- Refs: NIST-800-53:CP-9
- Fix: One owner of the chain.
- Confidence: guess.

### SQL-BACKUP-SYSTEM-DB-OLD - System databases not backed up
- Rows: SQL-BCK-005
- What and why: master and msdb hold logins and jobs.
- Severity: high. Lens: maintenance. Category: BCK
- File: rules\sql-server.yaml
- Data: protocol sql: msdb.dbo.backupset newest type D for master, msdb, model
- Condition: older than 7 days.
- Refs: NIST-800-53:CP-9
- Fix: Add to the plan.
- Confidence: verified.

### SQL-BACKUP-UNENCRYPTED - Backups of personal data not encrypted
- Rows: SQL-BCK-009
- What and why: Backup files leave the instance.
- Severity: medium. Lens: security. Category: BCK
- File: rules\sql-server.yaml
- Data: protocol sql: msdb.dbo.backupset key_algorithm, encryptor_type
- Condition: key_algorithm null for databases listed in threshold sql.encrypt-backup-databases (or TDE absent).
- Refs: NIST-800-53:SC-28
- Fix: Encrypt.
- Confidence: guess.

### SQL-BLOCKED-PROCESS-REPORT-OFF - Blocked process threshold not set
- Rows: SQL-MON-017
- What and why: Blocking is invisible after the fact.
- Severity: info. Lens: maintenance. Category: MON
- File: rules\sql-server.yaml
- Data: protocol sql: sys.configurations 'blocked process threshold (s)'
- Condition: value 0.
- Refs: NIST-800-53:SI-4
- Fix: Set 20.
- Confidence: verified.

### SQL-BLOCKING-LONG - Long blocking chain
- Rows: SQL-HLT-016
- What and why: Blocked sessions stall applications.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT session_id, blocking_session_id, wait_time FROM sys.dm_exec_requests WHERE blocking_session_id <> 0
- Condition: wait_time over 60000 ms (point in time).
- Refs: NIST-800-53:SC-5
- Fix: Find the head blocker.
- Confidence: verified.

### SQL-CERT-PRIVATE-KEY-NOT-BACKED-UP - Certificate whose private key was never backed up
- Rows: SQL-PKI-003, SQL-PKI-004, APP-BASELINE-BCK-009
- What and why: A TDE or backup-encryption certificate without a key backup makes encrypted data unrecoverable.
- Severity: high. Lens: maintenance. Category: PKI
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT name, thumbprint, expiry_date, pvt_key_last_backup_date FROM master.sys.certificates
- Condition: pvt_key_last_backup_date is null for a certificate used by a database or backup.
- Refs: NIST-800-53:SC-12, NIST-800-53:CP-9
- Fix: Back up the key and store it away from the data.
- Confidence: verified.

### SQL-CFG-ERRORLOG-RETENTION - Few error log files retained
- Rows: SQL-LOG-012
- What and why: Short retention loses history.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT value_data FROM sys.dm_server_registry WHERE value_name = 'NumErrorLogs'
- Condition: below 12 or absent.
- Refs: NIST-800-53:AU-11
- Fix: Raise.
- Confidence: verified.

### SQL-CFG-IFI-OFF - Instant file initialisation off
- Rows: SQL-CFG-020
- What and why: Slows growth and restores.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT servicename, instant_file_initialization_enabled FROM sys.dm_server_services
- Condition: N for the engine.
- Refs: NIST-800-53:CM-6
- Fix: Grant the right.
- Confidence: verified.

### SQL-CFG-INSTANCE-DEFAULTS - Instance options off the recommended values
- Rows: SQL-CFG-005, SQL-CFG-021, SQL-CFG-022, SQL-CFG-028, SQL-CFG-029
- What and why: A set of single options (ad hoc workload optimisation, backup compression and checksum defaults, priority boost, lightweight pooling, worker and connection limits, lock pages in memory) should keep their recommended values.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT name, value_in_use FROM sys.configurations plus sql_memory_model_desc FROM sys.dm_os_sys_info
- Condition: findings per option: optimize for ad hoc 0, backup compression default 0, backup checksum default 0, priority boost 1, lightweight pooling 1, max worker threads or user connections non-zero.
- Refs: NIST-800-53:CM-6
- Fix: Reconfigure.
- Confidence: verified.

### SQL-CFG-MAXDOP-COST-THRESHOLD - Parallelism settings off the guidance
- Rows: SCCM-CFG-048, SQL-CFG-003, SQL-CFG-004
- What and why: Defaults hurt mixed workloads.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.configurations plus cpu_count, numa_node_count FROM sys.dm_os_sys_info
- Condition: MAXDOP above 8 or above cores per node; cost threshold below 25.
- Refs: NIST-800-53:CM-6
- Fix: Set.
- Confidence: verified.

### SQL-CLUSTER-UNHEALTHY - Cluster quorum or node problem
- Rows: SQL-AVL-004, SQL-AVL-005
- What and why: Lost quorum stops the group.
- Severity: critical. Lens: maintenance. Category: AVL
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_hadr_cluster, sys.dm_hadr_cluster_members, sys.dm_os_cluster_nodes
- Condition: quorum not normal or a member not up.
- Refs: NIST-800-53:CP-2
- Fix: Restore node/quorum.
- Confidence: verified.

### SQL-CONNECTIONS-NTLM - Windows logins using NTLM
- Rows: SQL-AUT-005
- What and why: NTLM means missing SPNs or non-Kerberos clients.
- Severity: low. Lens: security. Category: AUT
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT auth_scheme, COUNT(*) FROM sys.dm_exec_connections GROUP BY auth_scheme
- Condition: NTLM share above 5 % of Windows-authenticated connections.
- Refs: NIST-800-53:IA-2
- Fix: Fix SPNs.
- Confidence: verified.

### SQL-CONNECTIONS-PER-CLIENT-HIGH - One client holds very many sessions
- Rows: SQL-HLT-026
- What and why: Pool leaks.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_exec_sessions grouped by host_name, program_name
- Condition: above 500 sessions.
- Refs: NIST-800-53:SC-5
- Fix: Fix the pool.
- Confidence: verified.

### SQL-CPU-HIGH - SQL process CPU high
- Rows: SQL-HLT-012
- What and why: Sustained high CPU hurts.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: parse sys.dm_os_ring_buffers RING_BUFFER_SCHEDULER_MONITOR
- Condition: SQLProcessUtilization average over 80 %.
- Refs: NIST-800-53:SI-4
- Fix: Find top queries.
- Confidence: guess.

### SQL-DB-FILE-MOSTLY-EMPTY - Large allocated space unused inside a file
- Rows: SCCM-CST-006
- What and why: Space reclaim candidates.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\sql-server.yaml
- Data: protocol sql: size and FILEPROPERTY(name,'SpaceUsed') per file (per-database context)
- Condition: allocated minus used above 30 %.
- Refs: NIST-800-53:SC-5
- Fix: Decide to keep or shrink.
- Confidence: guess - per-database query.

### SQL-DB-LEFTOVER-NAMES - Copy or backup databases left behind
- Rows: SQL-HYG-005
- What and why: Names like _old and _copy show forgotten data.
- Severity: low. Lens: security. Category: HYG
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT name, create_date FROM sys.databases
- Condition: name matches (?i)(_old|_bak|_copy|_test|_tmp) and older than 30 days.
- Refs: NIST-800-53:SI-12
- Fix: Archive or drop.
- Confidence: verified.

### SQL-DB-NO-ACTIVITY - Database with no use
- Rows: SQL-HYG-003
- What and why: Unused databases are risk without value.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_db_index_usage_stats max user activity per database
- Condition: none since restart, with restart older than 30 days.
- Refs: NIST-800-53:CM-7
- Fix: Decide with the owner.
- Confidence: guess.

### SQL-DB-SETTINGS-DRIFT - Database options off the standard
- Rows: SCCM-CFG-047, SQL-CFG-016, SQL-CFG-017, SQL-CFG-019, SQL-CFG-031, APP-BASELINE-LCM-013
- What and why: Collation, compatibility level, statistics options, indirect checkpoint and growth settings.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.databases (collation_name, compatibility_level, is_auto_create_stats_on, is_auto_update_stats_on, target_recovery_time_in_seconds) and sys.master_files growth
- Condition: findings per option against threshold sql.db-standard.
- Refs: NIST-800-53:CM-6
- Fix: Align.
- Confidence: verified.

### SQL-DB-SNAPSHOT-OLD - Old database snapshot
- Rows: SQL-HYG-008
- What and why: Snapshots grow.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT name, create_date FROM sys.databases WHERE source_database_id IS NOT NULL
- Condition: older than 7 days.
- Refs: NIST-800-53:SC-5
- Fix: Drop.
- Confidence: verified.

### SQL-DB-UNEXPECTED - Database not in the expected set
- Rows: SCCM-CFG-049, SCCM-CST-003
- What and why: Foreign databases on a dedicated instance break licensing and support.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT name FROM sys.databases
- Condition: not in threshold sql.expected-databases.
- Refs: NIST-800-53:CM-8
- Fix: Move.
- Confidence: verified.

### SQL-DBMAIL-FAILING - Database Mail failures
- Rows: SQL-MON-008
- What and why: Alerts fail silently.
- Severity: medium. Lens: maintenance. Category: MON
- File: rules\sql-server.yaml
- Data: protocol sql: msdb.dbo.sysmail_faileditems and sysmail_event_log
- Condition: failures in 7 days.
- Refs: NIST-800-53:SI-4
- Fix: Fix profile.
- Confidence: guess.

### SQL-DEADLOCKS-RECENT - Deadlocks recorded
- Rows: SQL-HLT-018
- What and why: Deadlocks cost user work.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.fn_xe_file_target_read_file('system_health*.xel') filtered to xml_deadlock_report in 7 days
- Condition: more than 10 per database per week.
- Refs: NIST-800-53:SI-4
- Fix: Tune.
- Confidence: likely.

### SQL-EDITION-NONPRODUCTION-IN-PRODUCTION - Developer, evaluation or express edition on production
- Rows: SQL-CST-004
- What and why: Terms and limits prohibit it.
- Severity: high. Lens: maintenance. Category: CST
- File: rules\sql-server.yaml
- Data: protocol sql: SERVERPROPERTY('Edition')
- Condition: matches threshold sql.nonproduction-editions on instances mapped as production.
- Refs: NIST-800-53:CM-10
- Fix: Upgrade edition.
- Confidence: guess.

### SQL-ENCRYPTION-SETTINGS - Connection encryption and extended protection
- Rows: SQL-AUT-002, SQL-AUT-028
- What and why: Forced encryption and extended protection are server-side switches.
- Severity: medium. Lens: security. Category: AUT
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT value_name, value_data FROM sys.dm_server_registry WHERE value_name IN ('ForceEncryption','ExtendedProtection','Certificate')
- Condition: ForceEncryption 0 or ExtendedProtection 0.
- Refs: NIST-800-53:SC-8
- Fix: Enable after client check.
- Confidence: verified.

### SQL-ENDPOINT-ENCRYPTION-WEAK - Mirroring or availability endpoint weak
- Rows: SQL-AUT-023
- What and why: Endpoint encryption must be AES.
- Severity: low. Lens: security. Category: AUT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.database_mirroring_endpoints encryption_algorithm_desc
- Condition: not AES.
- Refs: NIST-800-53:SC-8
- Fix: Change.
- Confidence: guess.

### SQL-EVT-ENGINE-ERRORS - Engine errors in the Application log
- Rows: SQL-LOG-001, SQL-LOG-002, SQL-LOG-003, SQL-LOG-004, SQL-LOG-005, SQL-LOG-006, SQL-LOG-007, SQL-LOG-008, SQL-LOG-009, SQL-LOG-011, SQL-LOG-015
- What and why: The Application log carries engine errors with the error number as event id, replacing a log-reading procedure call.
- Severity: high. Lens: maintenance. Category: LOG
- File: rules\sql-server.yaml
- Data: protocol eventlog on the SQL host, log Application, providers [MSSQLSERVER, MSSQL$*, SQLWRITER, VSS], days 7; ids by family: login failures 18456; IO 823, 824, 825, 833; stability 17883, 17884, 17888; memory 701, 802, 17890; space 9002, 1105; backup 3041, 18204, 18210; availability 35206, 35250, 41404, 1480, 19406; SSPI 17806, 18452
- Condition: count > 0 (18456 above threshold sql.login-failures-per-day).
- Refs: NIST-800-53:SI-4, NIST-800-53:AU-6
- Fix: Per id.
- Confidence: likely - provider names for named instances vary.

### SQL-EXPRESS-SIZE-NEAR-CAP - Express database near its size cap
- Rows: SQL-HLT-027, ESET-HLT-004
- What and why: Express stops accepting data at its cap.
- Severity: high. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: SERVERPROPERTY('EngineEdition') = 4 and SUM(size)/128 per database from sys.master_files
- Condition: data above 8 GB.
- Refs: NIST-800-53:SC-5
- Fix: Upgrade edition or archive.
- Confidence: verified.

### SQL-FILE-GROWTH-LIMIT - File cannot grow or is near its maximum
- Rows: SQL-HLT-006, SQL-HLT-007
- What and why: Stuck files stop writes.
- Severity: high. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT DB_NAME(database_id), name, size, max_size, growth FROM sys.master_files
- Condition: growth = 0 or size >= 90 % of max_size.
- Refs: NIST-800-53:SC-5
- Fix: Raise limits.
- Confidence: verified.

### SQL-FILE-PERCENT-GROWTH - Percent growth or badly sized increments
- Rows: SQL-CFG-010, SQL-CFG-011
- What and why: Percent growth gets huge.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.master_files is_percent_growth, growth
- Condition: is_percent_growth = 1, or increment outside 64 MB-1 GB (data) / 64 MB-8 GB (log).
- Refs: NIST-800-53:CM-6
- Fix: Fixed-size growth.
- Confidence: verified.

### SQL-FILES-ON-SYSTEM-DRIVE - Database files on the system drive
- Rows: SQL-CFG-007, SQL-CFG-008, SQL-CFG-030
- What and why: A full system drive stops the OS.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.master_files physical_name and SERVERPROPERTY default paths
- Condition: name starts with the system drive letter (threshold sql.system-drive).
- Refs: NIST-800-53:SC-5
- Fix: Move.
- Confidence: verified.

### SQL-IMPERSONATE-GRANT - IMPERSONATE grants on logins
- Rows: SQL-IAM-007
- What and why: IMPERSONATE can give another login's rights.
- Severity: medium. Lens: security. Category: IAM
- File: rules\sql-server.yaml
- Data: protocol sql: sys.server_permissions class_desc SERVER_PRINCIPAL permission_name IMPERSONATE
- Condition: any grant on a privileged login.
- Refs: NIST-800-53:AC-6
- Fix: Revoke.
- Confidence: verified.

### SQL-INSTANCE-IDLE - Instance with no user sessions
- Rows: SQL-CST-005
- What and why: Idle instances still cost licences.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_exec_sessions where is_user_process = 1 across runs
- Condition: zero sessions across 30 days of runs.
- Refs: NIST-800-53:CM-7
- Fix: Decide.
- Confidence: guess.

### SQL-IO-LATENCY-HIGH - File I/O latency high
- Rows: SQL-HLT-019
- What and why: Latency causes waits.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_io_virtual_file_stats io_stall_read_ms/num_of_reads etc.
- Condition: data files above 20 ms read, log above 5 ms write (cumulative averages).
- Refs: NIST-800-53:SI-4
- Fix: Storage review.
- Confidence: likely.

### SQL-LOG-OVERSIZED - Log larger than data
- Rows: SQL-CFG-033
- What and why: Oversized logs hide runaway transactions.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.master_files sum by type per database
- Condition: log size above data size.
- Refs: NIST-800-53:SC-5
- Fix: Review recovery.
- Confidence: verified.

### SQL-LOG-WITH-DATA-VOLUME - Log and data on one volume
- Rows: SQL-CFG-009
- What and why: Resilience and performance.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.master_files physical_name volume prefix
- Condition: same volume for busy databases.
- Refs: NIST-800-53:CP-2
- Fix: Separate.
- Confidence: verified.

### SQL-LOGIN-BROAD-AD-GROUP - Broad directory group has a login
- Rows: SQL-IAM-004
- What and why: All domain users can connect.
- Severity: high. Lens: security. Category: IAM
- File: rules\sql-server.yaml
- Data: protocol sql: sys.server_principals type G names matching Domain Users, Authenticated Users, Everyone, Domain Computers
- Condition: any.
- Refs: NIST-800-53:AC-3, NIST-800-53:AC-6
- Fix: Drop.
- Confidence: verified.

### SQL-LOGSHIPPING-LATE - Log shipping behind
- Rows: SQL-AVL-006
- What and why: Late shipping breaks recovery points.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\sql-server.yaml
- Data: protocol sql: msdb.dbo.log_shipping_monitor_primary/secondary
- Condition: backup/copy/restore beyond thresholds.
- Refs: NIST-800-53:CP-10
- Fix: Fix job.
- Confidence: verified.

### SQL-MAX-MEMORY-NO-HEADROOM - Memory limit leaves no room for the OS
- Rows: SCCM-HLT-011, SQL-CFG-001, SQL-CFG-002
- What and why: Unlimited or too high limit starves the OS and other services.
- Severity: high. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.configurations 'max server memory (MB)', 'min server memory (MB)', and physical_memory_kb
- Condition: finding when max is unlimited, or physical minus max < max(4 GB, 10 %), or min >= max.
- Refs: NIST-800-53:SC-5
- Fix: Set limit.
- Confidence: verified.

### SQL-MEMORY-DUMPS - Memory dumps produced
- Rows: SQL-HLT-029
- What and why: Dumps follow crashes.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: SELECT filename, creation_time FROM sys.dm_server_memory_dumps
- Condition: any in 30 days.
- Refs: NIST-800-53:SI-4
- Fix: Open a case.
- Confidence: verified.

### SQL-MEMORY-PRESSURE - Memory pressure counters
- Rows: SQL-HLT-011
- What and why: Low page life expectancy and grants pending.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_os_performance_counters
- Condition: Memory Grants Pending > 0 or PLE below 300 s per 4 GB of buffer pool.
- Refs: NIST-800-53:SI-4
- Fix: Memory review.
- Confidence: likely.

### SQL-MIRRORING-IN-USE - Deprecated mirroring in use
- Rows: SQL-AVL-007
- What and why: Deprecated feature.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\sql-server.yaml
- Data: protocol sql: sys.database_mirroring WHERE mirroring_guid IS NOT NULL
- Condition: any or state not synchronized.
- Refs: NIST-800-53:SA-22
- Fix: Move to availability groups.
- Confidence: verified.

### SQL-MSDB-LARGE - msdb large
- Rows: SQL-HYG-009
- What and why: History bloat.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\sql-server.yaml
- Data: protocol sql: size of msdb from sys.master_files
- Condition: above 2 GB.
- Refs: NIST-800-53:SC-5
- Fix: Clean history.
- Confidence: verified.

### SQL-PLAN-CACHE-SINGLE-USE - Plan cache full of single-use plans
- Rows: SQL-HLT-025
- What and why: Wastes memory.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_exec_cached_plans usecounts = 1 share
- Condition: above 20 % and ad hoc optimisation off.
- Refs: NIST-800-53:SI-4
- Fix: Enable the option.
- Confidence: verified.

### SQL-PRIVILEGE-CHANGES-RECENT - Login and role changes in the default trace
- Rows: SQL-MON-016
- What and why: Weekly review of privilege changes.
- Severity: info. Lens: security. Category: MON
- File: rules\sql-server.yaml
- Data: protocol sql: sys.fn_trace_gettable events 102-111
- Condition: any in 7 days.
- Refs: NIST-800-53:AC-2(4)
- Fix: Match to tickets.
- Confidence: likely.

### SQL-PROTOCOLS-UNNEEDED - Unneeded protocols enabled or instance visible
- Rows: SQL-AUT-018, SQL-AUT-020
- What and why: Named pipes and discovery widen exposure.
- Severity: low. Lens: security. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_server_registry SuperSocketNetLib values
- Condition: Np enabled or HideInstance 0 on production.
- Refs: NIST-800-53:CM-7
- Fix: Disable.
- Confidence: verified.

### SQL-PUBLIC-XP-EXECUTE - Public can run file-system extended procedures
- Rows: SQL-AUT-024
- What and why: Coercion and file probing.
- Severity: medium. Lens: security. Category: AUT
- File: rules\sql-server.yaml
- Data: protocol sql in master: sys.database_permissions for public on xp_dirtree, xp_fileexist, xp_subdirs, xp_regread, xp_instance_regread, xp_availablemedia
- Condition: any granted.
- Refs: NIST-800-53:AC-6
- Fix: Revoke.
- Confidence: verified.

### SQL-REPLICATION-AGENT-FAILING - Replication agent failing or late
- Rows: SQL-AVL-008
- What and why: Replicas diverge.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\sql-server.yaml
- Data: protocol sql on the distributor: distribution.dbo.MSreplication_monitordata
- Condition: status error or latency over 5 min.
- Refs: NIST-800-53:CP-10
- Fix: Restart.
- Confidence: guess.

### SQL-RESTARTED-RECENTLY - Instance restarted recently
- Rows: SQL-HLT-028
- What and why: Unplanned restarts.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sqlserver_start_time FROM sys.dm_os_sys_info
- Condition: within 7 days outside the window.
- Refs: NIST-800-53:SI-4
- Fix: Find cause.
- Confidence: verified.

### SQL-SESSION-SYSADMIN-APP - Application connected as sysadmin
- Rows: SQL-IAM-019
- What and why: Applications must not hold sysadmin.
- Severity: high. Lens: security. Category: IAM
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_exec_sessions joined to sysadmin membership
- Condition: non-service program names with sysadmin logins.
- Refs: NIST-800-53:AC-6
- Fix: Give least privilege.
- Confidence: likely.

### SQL-SSRS-VERSION-OLD - Report server version out of support
- Rows: SQL-LCM-009
- What and why: Old versions miss fixes.
- Severity: medium. Lens: maintenance. Category: LCM
- File: rules\sql-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<RS instance>\Setup Version
- Condition: below threshold sql.ssrs-min-version.
- Refs: NIST-800-53:SI-2
- Fix: Update.
- Confidence: guess.

### SQL-STARTUP-PARAMETERS-UNEXPECTED - Unexpected startup parameters
- Rows: SQL-CFG-027
- What and why: Trace flags and paths.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_server_registry SQLArg values
- Condition: values other than -d -e -l and documented -T.
- Refs: NIST-800-53:CM-6
- Fix: Remove.
- Confidence: verified.

### SQL-TABLE-LARGE - Very large table in the site database
- Rows: SCCM-HLT-013
- What and why: Growth hides purge failures.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_db_partition_stats reserved pages for the top tables of a named database
- Condition: table above 20 GB.
- Refs: NIST-800-53:SC-5
- Fix: Purge.
- Confidence: likely.

### SQL-TEMPDB-SPACE-HIGH - tempdb nearly full
- Rows: SQL-HLT-010
- What and why: tempdb exhaustion stops queries.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_db_file_space_usage in tempdb
- Condition: above 80 % used or version store growing.
- Refs: NIST-800-53:SC-5
- Fix: Find consumers.
- Confidence: likely.

### SQL-TLS-CERT-NOT-CONFIGURED - No TLS certificate configured
- Rows: SQL-PKI-002
- What and why: Self-generated certificates cannot be trusted.
- Severity: low. Lens: security. Category: PKI
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_server_registry Certificate value
- Condition: empty.
- Refs: NIST-800-53:SC-17
- Fix: Configure.
- Confidence: verified.

### SQL-TRANSACTION-OPEN-LONG - Long-open transaction
- Rows: SQL-HLT-017
- What and why: Blocks log truncation.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_tran_database_transactions
- Condition: open longer than 1 hour.
- Refs: NIST-800-53:SC-5
- Fix: Find session.
- Confidence: verified.

### SQL-VLF-HIGH - Many virtual log files
- Rows: SQL-HLT-022
- What and why: Slows recovery.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: COUNT(*) FROM sys.dm_db_log_info(DB_ID()) per database
- Condition: above 1000.
- Refs: NIST-800-53:SC-5
- Fix: Resize log.
- Confidence: guess - per-database.

### SQL-VOLUME-ALLOCATION-UNIT - Allocation unit not 64 KB
- Rows: SQL-CFG-024
- What and why: Performance.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\sql-server.yaml
- Data: protocol cim root/cimv2 SELECT Name, BlockSize FROM Win32_Volume for volumes holding database files
- Condition: BlockSize not 65536.
- Refs: NIST-800-53:CM-6
- Fix: Reformat in planned window.
- Confidence: verified.

### SQL-WORKER-THREADS-EXHAUSTED - Worker thread starvation
- Rows: SQL-HLT-015
- What and why: Queries queue.
- Severity: high. Lens: maintenance. Category: HLT
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_os_schedulers work_queue_count, active_workers_count; max_workers_count
- Condition: work_queue_count > 0 or active workers above 80 % of max.
- Refs: NIST-800-53:SC-5
- Fix: Investigate blocking.
- Confidence: verified.

### SQL-XE-SYSTEM-HEALTH-STOPPED - system_health session not running
- Rows: SQL-MON-014
- What and why: Diagnostics lost.
- Severity: low. Lens: maintenance. Category: MON
- File: rules\sql-server.yaml
- Data: protocol sql: sys.dm_xe_sessions
- Condition: system_health absent.
- Refs: NIST-800-53:SI-4
- Fix: Start.
- Confidence: verified.

### TLS-MS-ENDPOINT-INTERCEPTED - Microsoft endpoint presents an inspection certificate
- Rows: WINCLIENT-MON-011, WSS-CFG-001
- What and why: Microsoft recommends not intercepting its required endpoints; a leaf signed by the inspection authority instead of Microsoft's chain shows the bypass list is incomplete.
- Severity: medium. Lens: both. Category: CFG
- File: rules\certificates.yaml
- Data: protocol tls handshake from the scanner to the host:port list in threshold tls.ms-required-endpoints (sourced from Microsoft's published endpoint list); fields issuer, subject; per target
- Condition: finding when the issuer does not match threshold tls.ms-expected-issuer-pattern.
- Refs: NIST-800-53:SC-8, CIS-Controls-v8:3.10
- Fix: Add the host to the inspection bypass list.
- Confidence: likely - works only when the scanner sits behind the same inspection path as users.

### WINSRV-AD-SITE-MISSING - Server reports no AD site
- Rows: WINSRV-AVL-007, HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DynamicSiteName
- What and why: A member that cannot name its AD site picks domain controllers at random, often across the WAN.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT ClientSiteName, DcSiteName, DomainControllerName FROM Win32_NTDomain; per-host; key host
- Condition: finding when ClientSiteName is empty; second rule when DcSiteName differs from ClientSiteName.
- Refs: NIST-800-53:SC-22, NIST-800-53:CM-6
- Fix: Declare the subnet in Sites and Services (see DC-EVT-NETLOGON-NO-CLIENT-SITE).
- Confidence: verified - Win32_NTDomain properties documented.

### WINSRV-AGENT-WATCHED-RUNNING - Watch-listed agent service present on a server
- Rows: WINSRV-HYG-010, SCCM-IAM-022, SCCM-CST-005, LANSWEEPER-HLT-003, KN-aws-replication-agent-on-site-server
- What and why: Agents that should exist only on named hosts (replication agents, retired management agents) show where a product was installed without a decision.
- Severity: medium. Lens: security. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Name, DisplayName, PathName, State FROM Win32_Service; per-host; key {host}|{Name}
- Condition: finding when Name or DisplayName matches threshold windows-server.watched-agent-pattern and the host is not in windows-server.watched-agent-allowed-hosts.
- Refs: NIST-800-53:CM-7, NIST-800-53:CM-8
- Fix: Remove the agent or add the host to the allow list with an owner.
- Confidence: verified - same query shape as the workstation watch-list rule.

### WINSRV-BIOS-OLD - Firmware older than the policy age
- Rows: WINSRV-LCM-025
- What and why: Old firmware on physical servers misses security and stability fixes.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT SMBIOSBIOSVersion, ReleaseDate, Manufacturer FROM Win32_BIOS plus Win32_ComputerSystem.HypervisorPresent; per-host
- Condition: finding when HypervisorPresent is false and ReleaseDate is older than threshold windows-server.bios-max-age-days (default 730).
- Refs: NIST-800-53:SI-2
- Fix: Plan a firmware update through the vendor tool.
- Confidence: likely.

### WINSRV-BITLOCKER-OS-OFF - Server volume with sensitive data not encrypted
- Rows: WINSRV-CFG-031
- What and why: On-premise servers holding personal data should encrypt volumes where the datastore does not.
- Severity: medium. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2/Security/MicrosoftVolumeEncryption, SELECT DriveLetter, ProtectionStatus, VolumeType FROM Win32_EncryptableVolume; per-host
- Condition: finding when ProtectionStatus is 0 on a host listed in threshold windows-server.encrypt-required-hosts.
- Refs: NIST-800-53:SC-28, CIS-Controls-v8:3.6
- Fix: Enable BitLocker with directory escrow.
- Confidence: likely.

### WINSRV-CLONED-IDENTITY - Cloned machine identity
- Rows: WINSRV-HYG-019
- What and why: Servers cloned without generalisation share an update client ID and cause patch reporting errors.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate value SusClientId; store group by value; estate-wide
- Condition: finding for every host whose value occurs on another host.
- Refs: NIST-800-53:CM-8
- Fix: Reset the update identity on the clone.
- Confidence: guess.

### WINSRV-CLUSTER-UNHEALTHY - Failover cluster node or resource not up
- Rows: WINSRV-AVL-014
- What and why: A down node or offline resource erodes redundancy before users notice.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\windows-server.yaml
- Data: protocol cim, root/MSCluster, SELECT Name, State FROM MSCluster_Node and SELECT Name, State, OwnerNode FROM MSCluster_Resource; hosts with the cluster feature; per-host
- Condition: finding when a node State is not 0 (Up) or a resource State is not 2 (Online).
- Refs: NIST-800-53:CP-2, NIST-800-53:CP-10
- Fix: Bring the node or resource online and read the cluster log.
- Confidence: likely - namespace requires the cluster WMI provider.

### WINSRV-CPU-QUEUE-HIGH - Processor queue longer than the core count allows
- Rows: WINSRV-HLT-016
- What and why: A sustained run queue per core shows CPU starvation even when average load looks fine.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT ProcessorQueueLength FROM Win32_PerfFormattedData_PerfOS_System plus Win32_ComputerSystem.NumberOfLogicalProcessors; per-host
- Condition: finding when queue length exceeds 2 x logical processors (one sample).
- Refs: NIST-800-53:SI-4
- Fix: Find the busy process or add cores.
- Confidence: likely - single sample.

### WINSRV-CRASHDUMP-CONFIG - Crash dump settings cannot capture a useful dump
- Rows: WINSRV-HLT-014
- What and why: Without a dump setting and free space on the dump volume, a crash leaves nothing to diagnose.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Control\CrashControl values CrashDumpEnabled, DumpFile, AutoReboot; per-host
- Condition: finding when CrashDumpEnabled is 0 or 1 (complete dumps need RAM-size space), or AutoReboot is 0.
- Refs: NIST-800-53:CP-2
- Fix: Set automatic memory dump.
- Confidence: verified - registry values documented.

### WINSRV-CREDGUARD-OFF - Credential Guard not running on a server that supports it
- Rows: WINSRV-AUT-039
- What and why: Credential Guard isolates secrets from memory-reading attacks.
- Severity: medium. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/DeviceGuard, SELECT VirtualizationBasedSecurityStatus, SecurityServicesRunning FROM Win32_DeviceGuard; per-host
- Condition: finding when SecurityServicesRunning does not contain 1, on hosts not in threshold windows-server.credguard-exempt.
- Refs: NIST-800-53:SC-28, MITRE-ATTACK:T1003.001
- Fix: Enable VBS and Credential Guard by policy.
- Confidence: verified - same query as WS-CREDGUARD-OFF.

### WINSRV-DEFENDER-ASR-MISSING - Attack surface reduction rules not set
- Rows: WINSRV-AUT-052
- What and why: ASR rules block common credential-theft and script-abuse behaviour.
- Severity: low. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/Defender, SELECT AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference; per-host
- Condition: finding when the LSASS credential-stealing rule id (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2) is absent or its action is not block (1).
- Refs: NIST-800-53:SI-3, MITRE-ATTACK:T1003.001
- Fix: Deploy the rule set in audit, then block.
- Confidence: verified - property names documented.

### WINSRV-DEFENDER-MAPS-OFF - Cloud-delivered protection off on a server
- Rows: WINSRV-MON-007
- What and why: Cloud lookups catch new malware before signatures do.
- Severity: low. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/Defender, SELECT MAPSReporting, SubmitSamplesConsent FROM MSFT_MpPreference; per-host
- Condition: finding when MAPSReporting is 0 while Defender is the active antivirus.
- Refs: NIST-800-53:SI-3
- Fix: Enable cloud protection by policy.
- Confidence: verified.

### WINSRV-DEFENDER-PLATFORM-OLD - Defender platform or engine out of the supported window
- Rows: WINSRV-LCM-013
- What and why: Old platform versions stop receiving fixes.
- Severity: medium. Lens: maintenance. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/Defender, SELECT AMProductVersion, AMEngineVersion, AMRunningMode FROM MSFT_MpComputerStatus; per-host
- Condition: finding when AMProductVersion is below threshold windows-server.defender-platform-min.
- Refs: NIST-800-53:SI-3(2), NIST-800-53:SI-2
- Fix: Update platform through the update channel.
- Confidence: verified.

### WINSRV-DEFENDER-SCAN-OLD - No scan for too long
- Rows: WINSRV-MON-011
- What and why: Without a recent quick scan, dormant malware may sit unnoticed.
- Severity: low. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/Defender, SELECT QuickScanAge, FullScanAge FROM MSFT_MpComputerStatus; per-host
- Condition: finding when QuickScanAge exceeds 7 days (65535 means never).
- Refs: NIST-800-53:SI-3
- Fix: Check scan schedule policy.
- Confidence: verified.

### WINSRV-DEP-POLICY-WEAK - Data execution prevention not enforced for all programs by policy
- Rows: WINSRV-CFG-028
- What and why: DEP limits memory-corruption exploits.
- Severity: low. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT DataExecutionPrevention_SupportPolicy FROM Win32_OperatingSystem; per-host
- Condition: finding when the policy is 0 (AlwaysOff) or 1 is accepted: finding only for 0 and 2 under threshold windows-server.dep-min (default 3 = OptOut).
- Refs: NIST-800-53:SI-16
- Fix: Set DEP to OptOut or AlwaysOn.
- Confidence: verified.

### WINSRV-DISK-LATENCY-HIGH - Disk latency above the limit
- Rows: WINSRV-HLT-006, FILESRV-HLT-006
- What and why: Latency shows storage trouble before errors do.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Name, AvgDisksecPerRead, AvgDisksecPerWrite, CurrentDiskQueueLength FROM Win32_PerfFormattedData_PerfDisk_LogicalDisk WHERE Name <> '_Total'; per-host; key {host}|{Name}
- Condition: finding when read or write latency exceeds 0.020 s or queue length exceeds 2 (one sample; sustained averaging is perf-sampling).
- Refs: NIST-800-53:SI-4
- Fix: Locate the busy process or move the workload.
- Confidence: likely - single sample is noisy.

### WINSRV-DISK-OFFLINE-READONLY - Disk offline or read-only
- Rows: WINSRV-HLT-005, FILESRV-HLT-005
- What and why: A disk that is offline or read-only takes its volumes out of service without a health alarm.
- Severity: high. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/Storage, SELECT Number, FriendlyName, IsOffline, IsReadOnly, OfflineReason FROM MSFT_Disk; per-host
- Condition: finding when IsOffline or IsReadOnly is true.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-10
- Fix: Bring the disk online after checking why it left.
- Confidence: verified.

### WINSRV-DNS-NOT-DOMAIN-CONTROLLER - DNS client list not made of domain controllers
- Rows: WINSRV-CFG-008
- What and why: Members should resolve through at least two DCs; anything else breaks AD locator records.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE; store compare with DC addresses from AD (dNSHostName resolved at collection); per-host
- Condition: finding when fewer than 2 entries or any entry not in the DC address set.
- Refs: NIST-800-53:SC-20, NIST-800-53:CM-6
- Fix: Set the DNS client list by policy or DHCP option.
- Confidence: likely.

### WINSRV-DNS-REGISTRATION-OFF - Dynamic DNS registration disabled on the primary adapter
- Rows: WINSRV-CFG-010
- What and why: A server that does not register its name will be unreachable by name after an address change.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/StandardCimv2, SELECT InterfaceAlias, RegisterThisConnectionsAddress FROM MSFT_DnsClient; per-host
- Condition: finding when RegisterThisConnectionsAddress is false on a connected adapter.
- Refs: NIST-800-53:SC-20
- Fix: Enable registration.
- Confidence: verified.

### WINSRV-DNS-SUFFIX - Primary DNS suffix or search list outside the internal domains
- Rows: WINSRV-CFG-009, HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain, HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NV Domain, HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SearchList
- What and why: A wrong suffix or an external search domain sends internal short-name lookups outside.
- Severity: low. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters values Domain, NV Domain, SearchList; per-host
- Condition: finding when Domain differs from threshold windows-server.primary-dns-suffix or SearchList has an entry outside threshold windows-server.dns-search-allowed.
- Refs: NIST-800-53:SC-20
- Fix: Correct the suffix policy.
- Confidence: verified.

### WINSRV-DRIVER-AGE-OLD - Network or storage driver older than policy
- Rows: WINSRV-LCM-022, WINSRV-LCM-024, FILESRV-LCM-008
- What and why: Old drivers carry unfixed bugs, especially in virtual NIC and NVMe drivers.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT DeviceName, DriverVersion, DriverDate, DeviceClass FROM Win32_PnPSignedDriver WHERE DeviceClass = 'NET' OR DeviceClass = 'SCSIADAPTER' OR DeviceClass = 'HDC'; per-host; key {host}|{DeviceName}
- Condition: finding when DriverDate is older than threshold windows-server.driver-max-age-days (default 1095).
- Refs: NIST-800-53:SI-2
- Fix: Update the driver package.
- Confidence: likely - the DMTF date format needs conversion.

### WINSRV-EDGE-OLD - Browser on a server far behind
- Rows: WINSRV-LCM-028
- What and why: Browsers on servers are rare and rarely updated.
- Severity: low. Lens: security. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge value DisplayVersion; per-host
- Condition: finding when the major version is below threshold windows-server.edge-min-major.
- Refs: NIST-800-53:SI-2
- Fix: Update or remove the browser.
- Confidence: guess - key name to confirm.

### WINSRV-EVENT-FORWARDING-MISSING - Server events are not leaving the server
- Rows: WINSRV-MON-030, SCCM-MON-010, FILESRV-MON-010, APP-BASELINE-LOG-006, KN-no-central-server-event-log-collection
- What and why: Local logs roll over or are cleared; forwarding keeps evidence.
- Severity: medium. Lens: security. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager (subkey values) and cim Win32_Service for a collector agent named in threshold windows-server.log-agent-pattern; per-host
- Condition: finding when neither the subscription manager value exists nor the agent service is running.
- Refs: NIST-800-53:AU-6, NIST-800-53:AU-9(2), CIS-Controls-v8:8.9
- Fix: Enable forwarding or the agent.
- Confidence: likely.

### WINSRV-EVT-APP-LOG-FLOOD - One provider fills the Application log within a day
- Rows: WINSRV-LOG-033
- What and why: A flooding source hides everything else and shortens log history.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog log Application, days 1, max 2000; group by provider; per-host
- Condition: finding when the log holds more than threshold windows-server.app-flood-events (default 2000) events in a day or one provider exceeds half of them.
- Refs: NIST-800-53:AU-4
- Fix: Fix or silence the noisy source.
- Confidence: likely - same as the workstation rule.

### WINSRV-EVT-BUILTIN-ADMIN-LOGON - Built-in Administrator signed in on a server
- Rows: WINSRV-IAM-026
- What and why: Use of the shared built-in account cannot be tied to a person.
- Severity: medium. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol eventlog log Security, ids [4624, 4648], days 7, max 500; fields TargetUserSid; per-host
- Condition: finding when TargetUserSid ends with -500.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.4
- Fix: Use personal accounts; vault the built-in one.
- Confidence: verified.

### WINSRV-EVT-CODE-INTEGRITY - Code integrity refused a binary
- Rows: WINSRV-LOG-023
- What and why: Refusals show blocked security agents or tampered files.
- Severity: low. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol eventlog log Microsoft-Windows-CodeIntegrity/Operational, ids [3033, 3063, 3077, 3089], days 7; per-host
- Condition: count > 0.
- Refs: NIST-800-53:SI-7
- Fix: Check the named file and signer.
- Confidence: verified.

### WINSRV-EVT-DEFENDER-CONFIG-CHANGE - Defender settings changed or protection disabled
- Rows: WINSRV-MON-009
- What and why: Exclusion changes and disabled protection are classic attacker steps.
- Severity: high. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol eventlog log Microsoft-Windows-Windows Defender/Operational, ids [5007, 5001, 5010, 5012], days 7; fields NewValue; per-host
- Condition: finding for 5001, 5010, 5012, or 5007 with an exclusion key in the new value.
- Refs: NIST-800-53:SI-4, MITRE-ATTACK:T1562.001
- Fix: Match to a policy push or investigate.
- Confidence: verified.

### WINSRV-EVT-DNS-CLIENT - DNS client timeouts and registration failures
- Rows: WINSRV-LOG-017
- What and why: Name resolution trouble shows first in the DNS client events.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog log System, ids [1014, 8015, 8016, 8018, 8019, 8020], days 7; per-host
- Condition: count > 10 per day for 1014, any for the others.
- Refs: NIST-800-53:SC-20
- Fix: Check resolvers and the zone's update settings.
- Confidence: verified.

### WINSRV-EVT-GP-SILENT - Computer policy has not completed for a day
- Rows: WINSRV-CFG-001
- What and why: A host that stops processing policy drifts from its baseline silently.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol eventlog log Microsoft-Windows-GroupPolicy/Operational, ids [8000, 8001], days 1; per-host
- Condition: count none.
- Refs: NIST-800-53:CM-6
- Fix: Run a policy refresh and read the failing extension.
- Confidence: likely.

### WINSRV-EVT-IIS-WAS - Application pool crashes or rapid-fail trips
- Rows: APP-BASELINE-HLT-013
- What and why: Repeated worker crashes mean an application is unstable.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\windows-server.yaml
- Data: protocol eventlog log System, provider WAS, ids [5002, 5009, 5010, 5011, 5013, 5117], days 7; per-host
- Condition: count > 2 per pool (grouped by param1) in 7 days.
- Refs: NIST-800-53:SI-4
- Fix: Find the failing application; review rapid-fail settings.
- Confidence: verified.

### WINSRV-EVT-INTERACTIVE-NON-ADMIN - Non-admin interactive sign-ins on a server
- Rows: WINSRV-HYG-014
- What and why: Servers should be used by administrators and session-host users only.
- Severity: low. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol eventlog log Security, id 4624, LogonType 2/10, days 30, max 500; store join with admin group members; per-host
- Condition: finding when the account is not in threshold windows-server.interactive-allowed-groups.
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-17
- Fix: Remove the access or document it.
- Confidence: guess.

### WINSRV-EVT-LOCAL-ACCOUNT-CHANGE - Local account or admin group change
- Rows: WINSRV-MON-027
- What and why: New local accounts and admin group changes are persistence signs.
- Severity: medium. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol eventlog log Security, ids [4720, 4722, 4724, 4732, 4733, 4738], days 7; per-host
- Condition: any; severity high when the group is Administrators.
- Refs: NIST-800-53:AC-2(4), MITRE-ATTACK:T1136.001
- Fix: Match to a change record.
- Confidence: verified.

### WINSRV-EVT-LOGON-FAILURES - Authentication failure volume on a host
- Rows: WINSRV-MON-034, APP-BASELINE-LOG-007
- What and why: Bursts of failures show password guessing or a stale credential.
- Severity: medium. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol eventlog log Security, ids [4625, 4740], days 1, max 500; per-host
- Condition: count > threshold windows-server.logon-failures-per-day (default 200).
- Refs: NIST-800-53:AC-7, MITRE-ATTACK:T1110
- Fix: Find the source address and block or fix it.
- Confidence: verified.

### WINSRV-EVT-MDE-CONNECTIVITY - Defender for Endpoint cannot reach its cloud
- Rows: WINSRV-MON-003
- What and why: A sensor that cannot connect is blind.
- Severity: medium. Lens: maintenance. Category: MON
- File: rules\windows-server.yaml
- Data: protocol eventlog log Microsoft-Windows-SENSE/Operational, ids [5, 405], days 1; per-host
- Condition: count > 12 per hour.
- Refs: NIST-800-53:SI-4
- Fix: Fix proxy or inspection bypass for the sensor URLs.
- Confidence: verified.

### WINSRV-EVT-PERSISTENCE - Service or scheduled task installed
- Rows: WINSRV-MON-026
- What and why: New services and tasks are the usual persistence form.
- Severity: medium. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol eventlog log System provider Service Control Manager id 7045 and log Security ids [4697, 4698, 4702], days 7; per-host
- Condition: any; key {host}|{id}|{recordId}.
- Refs: NIST-800-53:CM-3, MITRE-ATTACK:T1543.003, MITRE-ATTACK:T1053.005
- Fix: Match to a deployment.
- Confidence: verified.

### WINSRV-EVT-POWERSHELL-START - PowerShell host started
- Rows: DC-055
- What and why: Who starts shells on sensitive hosts is useful evidence; informational.
- Severity: info. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol eventlog log Microsoft-Windows-PowerShell/Operational, ids [40961, 53504], days 7; per-host
- Condition: any.
- Refs: NIST-800-53:AU-12
- Fix: Review unusual starters.
- Confidence: likely.

### WINSRV-EVT-RDS-LICENSING - Remote Desktop licensing errors
- Rows: WINSRV-LOG-034
- What and why: Licensing errors lock users out of session hosts.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog logs Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin and System, ids [1057, 1058, 1067, 1128, 1130], days 7; per-host
- Condition: any.
- Refs: NIST-800-53:SI-4
- Fix: Check licence server and mode.
- Confidence: verified.

### WINSRV-EVT-RESTART-INITIATOR - Who restarted the server
- Rows: WINSRV-LOG-003, SCCM-AVL-015
- What and why: Restarts by an interactive user outside the maintenance window are change control failures.
- Severity: info. Lens: maintenance. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog log System provider User32 ids [1074, 1076], days 30; fields process, user, reason; per-host
- Condition: finding when the initiator is not in threshold windows-server.restart-allowed-initiators or the hour is outside the window.
- Refs: NIST-800-53:CM-3, NIST-800-53:AU-6
- Fix: Use the patch window.
- Confidence: verified.

### WINSRV-EVT-SECURITY-LOG-FULL - Security log wrapped or auto-archived
- Rows: WINSRV-LOG-031
- What and why: Lost security events cannot be recovered.
- Severity: medium. Lens: security. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog log Security, ids [1104, 1105], days 30; per-host
- Condition: any 1104 or more than 30 events of 1105.
- Refs: NIST-800-53:AU-4, NIST-800-53:AU-5
- Fix: Enlarge the log or forward events.
- Confidence: verified. Server-wide form of DC-EVT-SECURITY-LOG-FULL.

### WINSRV-EVT-TIER0-LOGON - Tier-0 account signed in on a member server
- Rows: WINSRV-IAM-025
- What and why: Domain admin credentials on member servers are exposed to theft there.
- Severity: high. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol eventlog log Security, id 4624, LogonType 2/10/11, days 7, max 500; fields TargetUserSid; per-host
- Condition: TargetUserSid in the set threshold windows-server.tier0-sids.
- Refs: NIST-800-53:AC-6(5), MITRE-ATTACK:T1078.002
- Fix: Use a tier-1 account.
- Confidence: likely.

### WINSRV-EVT-VSS - Volume shadow copy or VSS errors
- Rows: WINSRV-LOG-025, FILESRV-LOG-008, FILESRV-LOG-009
- What and why: Failed shadow copies mean backups are inconsistent or previous versions vanish.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog log Application provider VSS ids [8193, 12289, 12292, 12293, 13] and log System provider volsnap ids [25, 35, 36], days 30; per-host
- Condition: any.
- Refs: NIST-800-53:CP-9
- Fix: Check free space and writers.
- Confidence: verified.

### WINSRV-EVT-WHEA - Hardware errors reported by the platform
- Rows: WINSRV-LOG-014
- What and why: Corrected errors predict failing memory and CPUs.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol eventlog log System provider Microsoft-Windows-WHEA-Logger ids [17, 18, 19, 47], days 30; per-host
- Condition: any fatal (18); count > 10 corrected.
- Refs: NIST-800-53:SI-4
- Fix: Run vendor diagnostics.
- Confidence: verified.

### WINSRV-EVT-WSUS-HEALTH - WSUS health events
- Rows: SCCM-LOG-011
- What and why: WSUS health events precede sync and download failures.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog log Application provider Windows Server Update Services ids [12002, 12012, 12022, 12032, 12042, 12052, 12072], days 7; per-host
- Condition: any.
- Refs: NIST-800-53:SI-2
- Fix: Run the cleanup wizard; check database and pool.
- Confidence: verified.

### WINSRV-GPO-DC-POLICY-APPLIED - Domain controller policy applied to a member server
- Rows: WINSRV-CFG-003
- What and why: The DC policy grants rights and settings meant only for DCs.
- Severity: high. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/rsop/computer, SELECT name, enabled FROM RSOP_GPO WHERE guidName = '{6AC1786C-016F-11D2-945F-00C04fB984F9}'; per-host (non-DC servers)
- Condition: any row.
- Refs: NIST-800-53:CM-6, NIST-800-53:AC-6
- Fix: Unlink it from non-DC OUs.
- Confidence: verified - same as the workstation rule.

### WINSRV-GPO-LIST-MISMATCH - Applied policies differ from the ones linked
- Rows: WINSRV-CFG-002
- What and why: A policy that is linked but not applied (or the reverse) points to filtering or replication faults.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol store; registry subkeys of HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List per host joined to the gPLink chain of the host's OU; per-host
- Condition: finding when a permitted enabled link is missing from the applied list.
- Refs: NIST-800-53:CM-6
- Fix: Check security filtering and replication.
- Confidence: guess.

### WINSRV-GPO-REQUIRED-NOT-APPLIED - Required hardening policy not applied
- Rows: WINSRV-CFG-004
- What and why: A hardening policy that is not in effect gives false assurance.
- Severity: medium. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/rsop/computer, SELECT guidName, enabled, accessDenied FROM RSOP_GPO; per-host
- Condition: finding when no row has a GUID listed in threshold windows-server.required-gpo-guids.
- Refs: NIST-800-53:CM-6, NIST-800-53:CM-2
- Fix: Link to the host's OU or fix filtering.
- Confidence: likely.

### WINSRV-IIS-APPPOOL-STOPPED - Application pool stopped
- Rows: APP-BASELINE-HLT-004
- What and why: A stopped pool takes its site down.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\windows-server.yaml
- Data: protocol cim, root/WebAdministration, SELECT Name, State FROM ApplicationPool (or the IIS config registry); hosts with the web role; per-host
- Condition: finding when State is not 'Started' (1) on an enabled pool.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-2
- Fix: Start the pool and read the WAS events.
- Confidence: likely - provider needs the IIS management scripting tools.

### WINSRV-IIS-INSTALLED - Web server role on a server not meant to host sites
- Rows: WINSRV-HYG-012
- What and why: Unused IIS adds exposure.
- Severity: low. Lens: security. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Name, State FROM Win32_Service WHERE Name = 'W3SVC'; per-host
- Condition: finding when present on a host outside threshold windows-server.web-hosts.
- Refs: NIST-800-53:CM-7
- Fix: Remove the role.
- Confidence: verified.

### WINSRV-LOCAL-ACCOUNT-EXTRA - Enabled local account beyond the built-ins
- Rows: WINSRV-IAM-006
- What and why: Extra local accounts are credential sprawl.
- Severity: medium. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Name, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE; per-host
- Condition: finding for an enabled account whose SID is not -500 or -501 and name not in threshold windows-server.local-accounts-allowed.
- Refs: NIST-800-53:AC-2, NIST-800-53:IA-2
- Fix: Remove or document.
- Confidence: verified.

### WINSRV-LOCAL-ACCOUNT-UNUSED - Enabled local account unused for 35 days
- Rows: WINSRV-IAM-010
- What and why: Unused accounts are free footholds.
- Severity: low. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Name, LastLogon FROM Win32_NetworkLoginProfile; per-host
- Condition: finding when LastLogon is older than 35 days for an enabled account other than the managed administrator.
- Refs: NIST-800-53:AC-2(3)
- Fix: Disable it.
- Confidence: guess - class coverage of local profiles to confirm.

### WINSRV-LOCALADMIN-ORPHAN - Disabled, deleted or unresolved member of local Administrators
- Rows: WINSRV-IAM-003
- What and why: Members whose directory account is gone can be recreated by anyone.
- Severity: medium. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol store; Win32_GroupUser members of Administrators per host joined to AD user state; estate-wide
- Condition: finding when the SID does not resolve or the account is disabled.
- Refs: NIST-800-53:AC-2(3)
- Fix: Remove the member.
- Confidence: likely.

### WINSRV-LOCALGROUP-PRIVILEGED-MEMBERS - Members in other privileged local groups
- Rows: WINSRV-IAM-013, FILESRV-IAM-024
- What and why: Backup Operators, Power Users, Remote Management Users and similar groups hold powerful rights and are often forgotten.
- Severity: medium. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT GroupComponent, PartComponent FROM Win32_GroupUser WHERE GroupComponent = "Win32_Group.Domain='{HOST}',Name='<group>'" per group name in threshold windows-server.privileged-local-groups; per-host
- Condition: any member not in the allowed list.
- Refs: NIST-800-53:AC-6, CIS-Controls-v8:5.4
- Fix: Empty the group or document the members.
- Confidence: guess - group names are localised; use well-known SIDs where possible.

### WINSRV-NET-PROFILE-NOT-DOMAIN - Network category not DomainAuthenticated
- Rows: WINSRV-AVL-017
- What and why: A server profile in Public or Private applies the wrong firewall set.
- Severity: low. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/StandardCimv2, SELECT InterfaceAlias, NetworkCategory FROM MSFT_NetConnectionProfile; per-host
- Condition: finding when NetworkCategory is not 2 (DomainAuthenticated) on a connected adapter.
- Refs: NIST-800-53:SC-7
- Fix: Fix name resolution to a DC so domain detection works.
- Confidence: verified.

### WINSRV-NIC-DHCP-ENABLED - Server address obtained by DHCP
- Rows: WINSRV-CFG-011
- What and why: Servers on dynamic addresses without reservation may change address.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Description, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE; per-host
- Condition: finding when DHCPEnabled is true on a host not in threshold windows-server.dhcp-allowed.
- Refs: NIST-800-53:CM-6
- Fix: Set static or a reservation.
- Confidence: verified.

### WINSRV-NIC-ERRORS - Network adapter errors or discards
- Rows: WINSRV-HLT-023
- What and why: Errors and discards show cabling, driver or congestion trouble.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Name, PacketsReceivedErrors, PacketsOutboundErrors, PacketsReceivedDiscarded, OutputQueueLength FROM Win32_PerfFormattedData_Tcpip_NetworkInterface; per-host
- Condition: finding when errors > 0 or queue length > 2.
- Refs: NIST-800-53:SI-4
- Fix: Check the link and driver.
- Confidence: likely.

### WINSRV-NIC-LINK-SLOW - Server link below policy speed
- Rows: WINSRV-HLT-024
- What and why: A link negotiated down hurts throughput.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/StandardCimv2, SELECT Name, LinkSpeed, FullDuplex, MediaConnectState FROM MSFT_NetAdapter WHERE Virtual = FALSE; per-host
- Condition: finding when LinkSpeed below 1 Gbps or FullDuplex false on a connected adapter.
- Refs: NIST-800-53:SC-5
- Fix: Check the port and cable.
- Confidence: verified.

### WINSRV-POOL-NONPAGED-HIGH - Nonpaged pool large
- Rows: WINSRV-HLT-010
- What and why: A big nonpaged pool points at a driver leak.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT PoolNonpagedBytes FROM Win32_PerfFormattedData_PerfOS_Memory; per-host
- Condition: finding when above threshold windows-server.nonpaged-pool-max-bytes (default 1 GiB).
- Refs: NIST-800-53:SI-4
- Fix: Identify the leaking driver.
- Confidence: verified. Growth over uptime is run-to-run-diff.

### WINSRV-POWER-PLAN-NOT-HIGH - Active power plan is not high performance
- Rows: WINSRV-CFG-016, SQL-CFG-023
- What and why: Balanced plans throttle latency-sensitive servers.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2/power, SELECT ElementName, IsActive FROM Win32_PowerPlan WHERE IsActive = TRUE; physical or database hosts; per-host
- Condition: finding when ElementName is not threshold windows-server.power-plan (default High performance).
- Refs: NIST-800-53:CM-6
- Fix: Set the plan by policy.
- Confidence: verified.

### WINSRV-PROFILES-STALE - Profiles of disabled or deleted users
- Rows: WINSRV-HYG-011
- What and why: Leftover profiles hold personal data and waste space.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT SID, LocalPath, LastUseTime FROM Win32_UserProfile WHERE Special = FALSE AND Loaded = FALSE; store join with AD account state; per-host
- Condition: finding when the SID is deleted/disabled in AD or LastUseTime is older than 180 days.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:MP-6
- Fix: Remove the profile.
- Confidence: likely.

### WINSRV-RDP-DISCONNECTED-SESSION - Disconnected Remote Desktop sessions
- Rows: WINSRV-IAM-027
- What and why: Idle disconnected admin sessions keep tokens alive.
- Severity: low. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2/TerminalServices, SELECT UserName, ConnectionState FROM Win32_TSSession; per-host
- Condition: finding when ConnectionState is disconnected (4) for a privileged user.
- Refs: NIST-800-53:AC-12
- Fix: Log off idle sessions by policy.
- Confidence: guess - disconnect time is not exposed.

### WINSRV-RDS-CAL-LOW - Remote Desktop client licences nearly used up
- Rows: WINSRV-CST-006
- What and why: Exhausted client licences block sign-ins.
- Severity: medium. Lens: maintenance. Category: CST
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT ProductVersion, TypeAndModel, TotalLicenses, IssuedLicenses, ExpirationDate FROM Win32_TSLicenseKeyPack; licence servers; per-host
- Condition: finding when available < 10 % of total or ExpirationDate passed.
- Refs: NIST-800-53:SA-4
- Fix: Add licences.
- Confidence: verified.

### WINSRV-RDS-LICENSING-CONFIG - RDS licensing mode or server not configured
- Rows: WINSRV-CFG-018, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core\LicensingMode, HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\LicensingMode, HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\LicenseServers
- What and why: Session hosts without a licence server run in grace period.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2/TerminalServices, SELECT LicensingType, LicensingName FROM Win32_TerminalServiceSetting; plus registry HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services LicenseServers; session hosts; per-host
- Condition: finding when LicensingType is 0/5 or no licence server value exists.
- Refs: NIST-800-53:SA-4
- Fix: Set mode and server by policy.
- Confidence: likely - grace days need a method call.

### WINSRV-REG-DOTNET-FRAMEWORK-OLD - .NET Framework 4 below 4.8
- Rows: WINSRV-LCM-014
- What and why: Older 4.x releases are out of support.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full value Release; per-host
- Condition: finding when Release < 528040.
- Refs: NIST-800-53:SI-2
- Fix: Install 4.8.
- Confidence: verified.

### WINSRV-REG-IPV6-DISABLED-COMPONENTS - IPv6 components disabled outside the supported value
- Rows: WINSRV-CFG-013, HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents
- What and why: Partial IPv6 disablement breaks Windows features.
- Severity: info. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters value DisabledComponents; per-host
- Condition: finding when present and not 0 or 0x20.
- Refs: NIST-800-53:CM-6
- Fix: Remove or set 0x20.
- Confidence: verified.

### WINSRV-REG-MDNS-WPAD-ON - Multicast DNS or WPAD auto-discovery allowed
- Rows: WINSRV-AUT-022, HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad
- What and why: Both enable name-spoofing attacks.
- Severity: low. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters EnableMDNS and HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp DisableWpad; per-host
- Condition: finding when EnableMDNS is not 0 or DisableWpad is not 1.
- Refs: NIST-800-53:SC-20, MITRE-ATTACK:T1557.001
- Fix: Set both by policy.
- Confidence: verified.

### WINSRV-REG-MY-STORE-COUNT - Personal certificate store bloated
- Rows: WINSRV-PKI-005, FILESRV-PKI-004
- What and why: Hundreds of certificates indicate failing enrolment loops.
- Severity: low. Lens: maintenance. Category: PKI
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\SystemCertificates\My\Certificates subkeys (one row per thumbprint); count per host
- Condition: count > threshold windows-server.my-store-max (default 50).
- Refs: NIST-800-53:SC-17
- Fix: Clean expired certificates and fix the enrolment loop.
- Confidence: verified.

### WINSRV-REG-PERSISTENCE-KEYS - Autostart and LSA extension values changed from defaults
- Rows: WINSRV-MON-029, DC-046, HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages, HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages, HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs, HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs, HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
- What and why: AppInit DLLs, image-file debuggers, shell, userinit and LSA package lists are classic persistence points.
- Severity: high. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit), ...\Windows (AppInit_DLLs, LoadAppInit_DLLs), HKLM\SYSTEM\CurrentControlSet\Control\Lsa (Security Packages, Authentication Packages, Notification Packages); subkeys of Image File Execution Options with a Debugger value; per-host
- Condition: finding when a value differs from the default set held in threshold windows-server.persistence-defaults.
- Refs: NIST-800-53:SI-4, MITRE-ATTACK:T1547, MITRE-ATTACK:T1546.012
- Fix: Investigate the change.
- Confidence: likely.

### WINSRV-REG-ROOT-AUTOUPDATE-OFF - Automatic root certificate update disabled
- Rows: WINSRV-PKI-008, HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot\DisableRootAutoUpdate, HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate\DisableRootAutoUpdate
- What and why: Disabling it freezes the trust list.
- Severity: low. Lens: security. Category: PKI
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot value DisableRootAutoUpdate; per-host
- Condition: finding when 1 (unless threshold windows-server.root-update-managed is true).
- Refs: NIST-800-53:SC-17
- Fix: Enable updates or document an internal distribution.
- Confidence: verified.

### WINSRV-REG-ROOT-STORE-UNKNOWN - Trusted root not on the allowed list
- Rows: WINSRV-PKI-007, FILESRV-PKI-003
- What and why: An extra root can issue trusted certificates for any name.
- Severity: high. Lens: security. Category: PKI
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates subkeys (names are thumbprints); per-host
- Condition: finding for each thumbprint not in threshold windows-server.root-thumbprints-allowed (Microsoft program list plus internal roots).
- Refs: NIST-800-53:SC-17, MITRE-ATTACK:T1553.004
- Fix: Remove or document the root.
- Confidence: likely - the allow list is large; use a generated list.

### WINSRV-REG-SHUTDOWN-TRACKER-OFF - Shutdown reason tracker off
- Rows: WINSRV-CFG-033, HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability\ShutdownReasonOn, HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability\ShutdownReasonUI
- What and why: Reason prompts keep restart history meaningful.
- Severity: info. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability ShutdownReasonOn; per-host
- Condition: finding when not 1.
- Refs: NIST-800-53:AU-12, NIST-800-53:CM-3
- Fix: Enable by policy.
- Confidence: verified.

### WINSRV-REG-TIME-SOURCE - Time source type not domain hierarchy
- Rows: WINSRV-CFG-007, HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type, HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\NtpServer, HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\MaxPosPhaseCorrection, HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\MaxNegPhaseCorrection, HKLM\SOFTWARE\Policies\Microsoft\W32Time\Parameters\Type, HKLM\SOFTWARE\Policies\Microsoft\W32Time\Parameters\NtpServer
- What and why: Members should follow the domain; a manual source drifts away from DCs.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters values Type, NtpServer and the policy path HKLM\SOFTWARE\Policies\Microsoft\W32Time\Parameters; per-host
- Condition: finding when Type is not NT5DS on a non-DC.
- Refs: NIST-800-53:AU-8
- Fix: Reset to the domain hierarchy.
- Confidence: verified.

### WINSRV-REG-WINDOWS-POWERSHELL-OLD - Windows PowerShell below 5.1
- Rows: WINSRV-LCM-019
- What and why: Old engines lack security logging features.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine value PowerShellVersion; per-host
- Condition: finding when below 5.1.
- Refs: NIST-800-53:SI-2
- Fix: Install WMF 5.1.
- Confidence: verified.

### WINSRV-REG-WSUS-DUAL-SCAN - Update source and dual-scan settings conflict
- Rows: WINSRV-LCM-008, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableDualScan, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetPolicyDrivenUpdateSourceForQualityUpdates, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer
- What and why: A host scanning both WSUS and the internet reports inconsistent compliance.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate (WUServer, DisableDualScan, SetPolicyDrivenUpdateSourceForQualityUpdates) and ...\AU UseWUServer; per-host
- Condition: finding when WUServer is set but UseWUServer is not 1, or DisableDualScan is not 1 on a co-managed host.
- Refs: NIST-800-53:CM-6, NIST-800-53:SI-2
- Fix: Align the policy.
- Confidence: verified.

### WINSRV-RESOURCES-BELOW-MINIMUM - Server below OS minimum memory or cores
- Rows: WINSRV-HLT-033
- What and why: Hosts under the OS minimum run unstable.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT TotalPhysicalMemory, NumberOfLogicalProcessors FROM Win32_ComputerSystem; per-host
- Condition: finding when memory < 4 GB or cores < 2 (2 GB for Server Core).
- Refs: NIST-800-53:SC-5
- Fix: Resize.
- Confidence: verified.

### WINSRV-ROUTE-MULTIPLE-DEFAULT - More than one default route
- Rows: WINSRV-CFG-015
- What and why: Multiple default routes cause asymmetric traffic.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/StandardCimv2, SELECT InterfaceAlias, RouteMetric FROM MSFT_NetRoute WHERE DestinationPrefix = '0.0.0.0/0'; per-host
- Condition: count > 1 per host.
- Refs: NIST-800-53:SC-7
- Fix: Remove the surplus or document metrics.
- Confidence: verified.

### WINSRV-RSOP-AUDIT-POLICY - Advanced audit policy below the baseline
- Rows: WINSRV-MON-014, WINSRV-MON-015, WINSRV-MON-016, WINSRV-MON-017, WINSRV-MON-018, WINSRV-MON-019, WINSRV-MON-020, FILESRV-MON-001, APP-BASELINE-LOG-010, AD-MON-001, PKI-MON-002
- What and why: Without the right categories audited, incident evidence is missing.
- Severity: medium. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol cim, root/rsop/computer, SELECT Category, Success, Failure FROM RSOP_AuditPolicy; per-host; subcategory states need secedit-auditpol
- Condition: finding when a category in threshold windows-server.audit-required lacks success or failure auditing.
- Refs: NIST-800-53:AU-2, NIST-800-53:AU-12, CIS-Controls-v8:8.2
- Fix: Apply the audit baseline.
- Confidence: likely - class exposes categories, not all subcategories.

### WINSRV-RSOP-USER-RIGHTS - User rights differ from the baseline
- Rows: WINSRV-IAM-014, WINSRV-IAM-015, WINSRV-IAM-016, WINSRV-IAM-017, WINSRV-IAM-018, WINSRV-IAM-019, WINSRV-IAM-020, WINSRV-IAM-021, WINSRV-IAM-022, WINSRV-IAM-023, WINSRV-IAM-024, AD-IAM-014, AD-IAM-037, AD-IAM-038, AD-IAM-039, AD-IAM-040, AD-IAM-041, GPO-017
- What and why: Logon rights and debug/driver/backup privileges define who can take over a host.
- Severity: high. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol cim, root/rsop/computer, SELECT UserRight, AccountList, precedence FROM RSOP_UserPrivilegeRight WHERE precedence = 1; per-host; key {host}|{UserRight}
- Condition: finding when AccountList for a right in threshold windows-server.user-rights-expected contains an account outside the expected list (for SeDenyNetworkLogonRight: missing local accounts group).
- Refs: NIST-800-53:AC-6, CIS-Controls-v8:5.4
- Fix: Fix the policy that grants the extra right.
- Confidence: likely - SIDs need well-known macros.

### WINSRV-SECURITY-LOG-HISTORY-SHORT - Security log keeps under 30 days
- Rows: WINSRV-LOG-030
- What and why: Short retention loses evidence.
- Severity: medium. Lens: security. Category: LOG
- File: rules\windows-server.yaml
- Data: protocol eventlog log Security, days 30, max 1 (oldest-first order) ; per-host
- Condition: finding when the oldest returned event is younger than 29 days.
- Refs: NIST-800-53:AU-11, CIS-Controls-v8:8.10
- Fix: Enlarge the log or forward.
- Confidence: guess - needs ordering by oldest.

### WINSRV-SHADOW-STORAGE-LARGE - Shadow storage consumes the system drive
- Rows: WINSRV-HLT-027
- What and why: Unbounded shadow storage fills C:.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Volume, DiffVolume, MaxSpace, UsedSpace FROM Win32_ShadowStorage; per-host
- Condition: finding when the volume is the system drive and MaxSpace is unlimited or > 10 % of its capacity.
- Refs: NIST-800-53:SC-5
- Fix: Cap it.
- Confidence: verified.

### WINSRV-SHARE-NONADMIN - Non-administrative share on a server
- Rows: WINSRV-IAM-041, FILESRV-CFG-001
- What and why: Every share is an access path that needs an owner.
- Severity: low. Lens: security. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/SMB, SELECT Name, Path, Description FROM MSFT_SmbShare WHERE Special = FALSE; per-host; key {host}|{Name}
- Condition: finding when Name not in threshold windows-server.shares-allowed.
- Refs: NIST-800-53:CM-7, NIST-800-53:CM-8
- Fix: Document or remove.
- Confidence: verified.

### WINSRV-SNMP-DEFAULT-COMMUNITY - SNMP service with a default community
- Rows: WINSRV-AUT-048, HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\EnableAuthenticationTraps
- What and why: Default communities expose configuration.
- Severity: medium. Lens: security. Category: AUT
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities (value names) and cim Win32_Service Name = 'SNMP'; per-host
- Condition: finding when a value name is public or private (names other than those two are never emitted).
- Refs: NIST-800-53:CM-7, NIST-800-53:IA-5
- Fix: Remove the service or the default names.
- Confidence: guess - the runner must return value names only.

### WINSRV-SQL-INSTANCE-UNREGISTERED - Database instance found on a host but not scanned
- Rows: WINSRV-HYG-016, SQL-LCM-014, SQL-HYG-001
- What and why: Instances nobody registered escape every SQL rule.
- Severity: medium. Lens: maintenance. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT Name, State FROM Win32_Service WHERE Name = 'MSSQLSERVER' OR Name LIKE 'MSSQL$%'; store join with the SQL integration targets; per-host
- Condition: finding when no SQL target matches the host and instance.
- Refs: NIST-800-53:CM-8
- Fix: Register the instance or retire it.
- Confidence: guess.

### WINSRV-SVC-SEARCH-RUNNING - Windows Search running where not needed
- Rows: WINSRV-CFG-030, FILESRV-CFG-022
- What and why: Indexing wastes IO on servers that do not need it.
- Severity: info. Lens: maintenance. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT State, StartMode FROM Win32_Service WHERE Name = 'WSearch'; per-host
- Condition: finding when running on a host outside threshold windows-server.search-hosts.
- Refs: NIST-800-53:CM-7
- Fix: Disable.
- Confidence: verified.

### WINSRV-SW-EOL - End-of-support runtime or component installed
- Rows: WINSRV-LCM-015, WINSRV-LCM-016, WINSRV-LCM-017, WINSRV-LCM-018, SQL-LCM-010, APP-BASELINE-LCM-005, ESET-LCM-004, ESET-LCM-005
- What and why: Old runtimes, Java builds and tools stay on servers for years after support ends.
- Severity: medium. Lens: maintenance. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall and Wow6432Node subkeys (DisplayName, DisplayVersion, Publisher) plus HKLM\SOFTWARE\dotnet\Setup\InstalledVersions; per-host
- Condition: finding when DisplayName matches threshold windows-server.eol-software-pattern (rows like Visual C++ 2008, Java 8, .NET Core 3.1, Python 2).
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22, CIS-Controls-v8:2.2
- Fix: Update or remove.
- Confidence: likely - subkey values must be returned by the runner.

### WINSRV-SW-JAVA-ORACLE - Oracle Java build that needs a subscription
- Rows: WINSRV-CST-008
- What and why: Licence exposure and no free updates.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\windows-server.yaml
- Data: protocol registry Uninstall subkeys filtered by Publisher containing Oracle and DisplayName containing Java; per-host
- Condition: finding for each match above the free-terms versions (threshold windows-server.java-free-versions).
- Refs: NIST-800-53:CM-10
- Fix: Move to an open build or subscribe.
- Confidence: guess.

### WINSRV-SW-UNAPPROVED - Software on a server outside the approved set
- Rows: WINSRV-HYG-009, SCCM-CFG-046, APP-BASELINE-CFG-007, ESET-HYG-014
- What and why: Desktop software on servers widens the attack surface.
- Severity: low. Lens: security. Category: HYG
- File: rules\windows-server.yaml
- Data: protocol registry Uninstall subkeys; per-host
- Condition: finding when DisplayName matches threshold windows-server.unapproved-software-pattern.
- Refs: NIST-800-53:CM-7, NIST-800-53:CM-11, CIS-Controls-v8:2.3
- Fix: Uninstall.
- Confidence: likely.

### WINSRV-SYSMON-MISSING - Sysmon not present on listed servers
- Rows: WINSRV-MON-035
- What and why: Where a team relies on Sysmon telemetry, absence is a gap.
- Severity: low. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol cim Win32_Service Name LIKE 'Sysmon%'; per-host
- Condition: count none on hosts in threshold windows-server.sysmon-hosts.
- Refs: NIST-800-53:SI-4
- Fix: Install and configure.
- Confidence: guess.

### WINSRV-TASK-FAILED - Scheduled task failing
- Rows: WINSRV-LOG-007, FILESRV-BCK-006
- What and why: Failed jobs include backups and housekeeping.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/TaskScheduler, SELECT TaskName, TaskPath, LastTaskResult, LastRunTime, NumberOfMissedRuns FROM MSFT_TaskDynamicInfo; per-host
- Condition: finding when LastTaskResult is not in (0, 267009, 267011, 267014) for tasks outside \Microsoft\.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-9
- Fix: Read the task history.
- Confidence: likely.

### WINSRV-TASK-LOGON-RIGHT-DENIED - Task fails because its account lacks the logon right
- Rows: WINSRV-LOG-008, KN-batch-logon-right-removed-estatewide
- What and why: A tightened rights policy silently stops tasks.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, same class; LastTaskResult in (2147943726, 2147943712, 2147942405)
- Condition: any.
- Refs: NIST-800-53:AC-6, NIST-800-53:CM-3
- Fix: Grant the right to the task account or change account.
- Confidence: likely.

### WINSRV-TASK-STORED-PASSWORD - Scheduled task stores a user password
- Rows: WINSRV-IAM-031, DC-023
- What and why: Stored passwords sit in the task store and age unnoticed.
- Severity: medium. Lens: security. Category: IAM
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/TaskScheduler, SELECT TaskName, TaskPath, Principal FROM MSFT_ScheduledTask; per-host
- Condition: finding when Principal LogonType is 1 (Password) and UserId is not a managed service account.
- Refs: NIST-800-53:IA-5, NIST-800-53:AC-6
- Fix: Move to a managed service account.
- Confidence: likely - embedded object fields.

### WINSRV-TASK-USER-WRITABLE-PATH - Task runs a program from a user-writable path
- Rows: WINSRV-IAM-033
- What and why: A SYSTEM task running a user-writable file is a privilege escalation.
- Severity: high. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/Microsoft/Windows/TaskScheduler, SELECT TaskName, Actions FROM MSFT_ScheduledTask; per-host
- Condition: finding when an action Execute matches (?i)\\Users\\|\\Temp\\|\\ProgramData\\ and the principal is SYSTEM or an administrator.
- Refs: NIST-800-53:AC-6, MITRE-ATTACK:T1053.005
- Fix: Move the binary to a protected path.
- Confidence: likely.

### WINSRV-TCP-CLOSEWAIT-HIGH - Many connections stuck in CLOSE_WAIT
- Rows: WINSRV-HLT-025
- What and why: Stuck closes mean an application leaks sockets.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/StandardCimv2, SELECT OwningProcess, State FROM MSFT_NetTCPConnection WHERE State = 8; per-host
- Condition: count per process > 1000.
- Refs: NIST-800-53:SC-5
- Fix: Restart or fix the application.
- Confidence: guess - rows can be numerous; the runner cap applies.

### WINSRV-TCP-LISTENER-UNEXPECTED - Listener not part of the role
- Rows: WINSRV-AUT-047, APP-BASELINE-CFG-005
- What and why: Unexpected listening ports mark undocumented services.
- Severity: medium. Lens: security. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol cim, root/StandardCimv2, SELECT LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2; per-host; key {host}|{LocalPort}
- Condition: finding when LocalPort is not in the per-role allow list threshold windows-server.listeners-allowed.
- Refs: NIST-800-53:CM-7, CIS-Controls-v8:4.8
- Fix: Document or stop the service.
- Confidence: likely.

### WINSRV-TIMEZONE-UNEXPECTED - Time zone differs from the standard
- Rows: WINSRV-CFG-017
- What and why: Wrong zones skew log correlation.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation TimeZoneKeyName, DynamicDaylightTimeDisabled; per-host
- Condition: finding when TimeZoneKeyName differs from threshold windows-server.timezone.
- Refs: NIST-800-53:AU-8
- Fix: Set the zone.
- Confidence: verified.

### WINSRV-VMGUEST-PRESSURE - Ballooning, swapping or stolen CPU seen from the guest
- Rows: WINSRV-HLT-028, WINSRV-HLT-029
- What and why: Host contention shows in the guest counters.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\windows-server.yaml
- Data: protocol cim, root/cimv2, SELECT MemoryBalloonedMB, MemorySwappedMB FROM Win32_PerfFormattedData_vmGuestLib_VMem and SELECT CpuStolenMs FROM Win32_PerfFormattedData_vmGuestLib_VCPU; per-host (provider present only with hypervisor tools)
- Condition: finding when ballooned or swapped > 0, or stolen time > 5 % of the sample.
- Refs: NIST-800-53:SC-5
- Fix: Reserve memory or move the VM.
- Confidence: guess.

### WINSRV-VMTOOLS-STATE - Guest tools missing or outdated
- Rows: WINSRV-LCM-023
- What and why: Outdated tools lose time sync and driver fixes.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall subkey for the tools product DisplayVersion plus cim Win32_Service VMTools; per-host
- Condition: finding when the service is missing/stopped or DisplayVersion below threshold windows-server.vmtools-min.
- Refs: NIST-800-53:SI-2
- Fix: Update the tools.
- Confidence: likely - the VMW-VM-TOOLS-* rules cover the vCenter view.

### WINSRV-VSS-PROVIDER-UNEXPECTED - Unexpected VSS provider or disabled VSS services
- Rows: WINSRV-BCK-005, FILESRV-BCK-007
- What and why: Third-party providers affect backups; disabled services break snapshots.
- Severity: low. Lens: maintenance. Category: BCK
- File: rules\windows-server.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Services\VSS\Providers subkeys and cim Win32_Service Name IN ('VSS','swprv') StartMode; per-host
- Condition: finding for a provider key not in threshold windows-server.vss-providers-allowed or a service with StartMode Disabled.
- Refs: NIST-800-53:CP-9
- Fix: Restore services; remove unknown providers.
- Confidence: likely.

### WINSRV-WMI-SUBSCRIPTION - Permanent WMI event subscription
- Rows: WINSRV-MON-028
- What and why: Permanent subscriptions are a stealthy persistence form.
- Severity: high. Lens: security. Category: MON
- File: rules\windows-server.yaml
- Data: protocol cim, root/subscription, SELECT * FROM __FilterToConsumerBinding plus consumer classes CommandLineEventConsumer and ActiveScriptEventConsumer; per-host
- Condition: finding for each binding not in threshold windows-server.wmi-subscriptions-allowed.
- Refs: NIST-800-53:SI-4, MITRE-ATTACK:T1546.003
- Fix: Investigate and remove.
- Confidence: verified.

### WS-AGENT-DRIVER-MISSING - Agent driver absent while the agent is installed
- Rows: WSS-HLT-002
- What and why: A security agent without its kernel driver filters nothing though its services run.
- Severity: high. Lens: security. Category: HLT
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT Name, State, StartMode FROM Win32_SystemDriver WHERE Name = '<driver>' per name in threshold workstations.agent-drivers; per-host
- Condition: finding when the driver row is missing or not running on a host where the agent service exists.
- Refs: NIST-800-53:SI-4, NIST-800-53:SI-7
- Fix: Reinstall the agent.
- Confidence: verified.

### WS-AV-NONE-ACTIVE - No active antivirus product
- Rows: ESET-MON-005
- What and why: After a removal or a failed switchover a PC may have no protection at all.
- Severity: critical. Lens: security. Category: HLT
- File: rules\workstations.yaml
- Data: protocol cim, root/SecurityCenter2, SELECT displayName, productState FROM AntiVirusProduct; per-host
- Condition: finding when no row has the real-time-on state bits (productState & 0x1000) set.
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.1
- Fix: Enable the intended product.
- Confidence: verified - state bits documented by Microsoft.

### WS-BATTERY-WEAR - Laptop battery capacity far below design
- Rows: WINCLIENT-HLT-013
- What and why: Worn batteries cause lost work and swelling risk.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\workstations.yaml
- Data: protocol cim, root/wmi, SELECT FullChargedCapacity FROM BatteryFullChargedCapacity and SELECT DesignedCapacity FROM BatteryStaticData; per-host
- Condition: finding when FullChargedCapacity < 50 % of DesignedCapacity.
- Refs: NIST-800-53:CM-8
- Fix: Replace the battery.
- Confidence: likely - needs both classes in one rule (two queries).

### WS-BITLOCKER-METHOD-WEAK - Disk encryption method below policy
- Rows: WINCLIENT-CFG-003
- What and why: Old XTS/CBC choices and hardware encryption weaken the guarantee.
- Severity: low. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2/Security/MicrosoftVolumeEncryption, SELECT DriveLetter, EncryptionMethod FROM Win32_EncryptableVolume; per-host
- Condition: finding when EncryptionMethod is not 6 or 7 (XTS-AES) on a protected volume.
- Refs: NIST-800-53:SC-13, NIST-800-53:SC-28
- Fix: Re-encrypt with the policy method.
- Confidence: verified.

### WS-DEFENDER-CFA-OFF - Controlled folder access off
- Rows: WINCLIENT-AUT-031
- What and why: It blocks ransomware writes to protected folders; the decision should be recorded.
- Severity: low. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/Microsoft/Windows/Defender, SELECT EnableControlledFolderAccess FROM MSFT_MpPreference; per-host
- Condition: finding when 0 and not in threshold workstations.cfa-exempt.
- Refs: NIST-800-53:SI-3
- Fix: Set audit or block.
- Confidence: verified.

### WS-DEFENDER-SCAN-IN-WORK-HOURS - Scheduled scan during working hours
- Rows: WINCLIENT-HLT-019
- What and why: Full scans in office hours slow users down.
- Severity: low. Lens: maintenance. Category: HLT
- File: rules\workstations.yaml
- Data: protocol cim, root/Microsoft/Windows/Defender, SELECT ScanScheduleDay, ScanScheduleTime, ScanAvgCPULoadFactor FROM MSFT_MpPreference; per-host
- Condition: finding when ScanScheduleTime is between 07:00 and 17:00 on weekdays or the CPU factor exceeds 50.
- Refs: NIST-800-53:SI-3
- Fix: Move the schedule.
- Confidence: verified.

### WS-DISK-PREDICT-FAILURE - Drive reports imminent failure
- Rows: WINCLIENT-HLT-003
- What and why: SMART predicted failure leaves days or weeks.
- Severity: high. Lens: maintenance. Category: HLT
- File: rules\workstations.yaml
- Data: protocol cim, root/wmi, SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus; per-host
- Condition: finding when PredictFailure is true.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-9
- Fix: Back up and replace the drive.
- Confidence: verified.

### WS-DNS-NOT-DOMAIN-CONTROLLER - PC resolves through non-domain resolvers
- Rows: WINCLIENT-AVL-010
- What and why: PCs not using DCs for DNS fail locating the domain.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE; store compare with DC addresses; per-host
- Condition: finding when the list has no DC address on a wired or corporate adapter.
- Refs: NIST-800-53:SC-20
- Fix: Fix DHCP option 6.
- Confidence: likely.

### WS-EDITION-NOT-ENTERPRISE - Edition is not the licensed Enterprise edition
- Rows: WINCLIENT-LCM-014
- What and why: Subscription activation should lift Pro to Enterprise.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT OperatingSystemSKU, Caption FROM Win32_OperatingSystem; per-host
- Condition: finding when the SKU is not 4 (Enterprise) or 27 (Enterprise N) on PCs in threshold workstations.enterprise-ous.
- Refs: NIST-800-53:CM-10
- Fix: Trigger subscription activation.
- Confidence: verified.

### WS-ESU-NOT-ACTIVATED - Windows 10 without extended security updates
- Rows: WINCLIENT-LCM-003
- What and why: After end of support Windows 10 gets security fixes only with the extended programme.
- Severity: high. Lens: security. Category: LCM
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT Name, Description, LicenseStatus FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL AND Description LIKE '%ESU%'; per-host
- Condition: finding when the host runs build 19045 or lower and no row has LicenseStatus 1.
- Refs: NIST-800-53:SI-2, NIST-800-53:SA-22
- Fix: Activate the extension or upgrade.
- Confidence: guess - class filter for the add-on is unverified.

### WS-EVENT-FORWARDING-MISSING - PC events are not forwarded
- Rows: WINCLIENT-MON-024
- What and why: PC logs roll over; forwarding or an EDR stream keeps evidence.
- Severity: low. Lens: security. Category: LOG
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager and cim Win32_Service for a collector agent; per-host
- Condition: finding when neither exists and the host is not onboarded to an EDR (WS-REG-MDE-NOT-ONBOARDED).
- Refs: NIST-800-53:AU-6, CIS-Controls-v8:8.9
- Fix: Enable forwarding.
- Confidence: likely.

### WS-EVT-APPLOCKER-AUDIT - Application control audit events
- Rows: ANYDESK-MON-002
- What and why: Audit-mode AppLocker events list what enforcement would block, including banned tools.
- Severity: info. Lens: security. Category: MON
- File: rules\workstations.yaml
- Data: protocol eventlog logs Microsoft-Windows-AppLocker/EXE and DLL and MSI and Script, ids [8003, 8004, 8006, 8007], days 7; per-host
- Condition: any; evidence names the file path.
- Refs: NIST-800-53:CM-7(5)
- Fix: Allow legitimate software; remove the rest.
- Confidence: verified.

### WS-EVT-BITLOCKER-ERRORS - BitLocker management errors
- Rows: WINCLIENT-LOG-018
- What and why: Escrow and policy failures leave drives unprotected or unrecoverable.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\workstations.yaml
- Data: protocol eventlog log Microsoft-Windows-BitLocker/BitLocker Management, ids [846, 851, 853, 854], days 7; per-host
- Condition: any.
- Refs: NIST-800-53:SC-28
- Fix: Read the error code and fix escrow.
- Confidence: verified.

### WS-EVT-CERT-ENROLL - Certificate auto-enrolment errors on the PC
- Rows: WINCLIENT-PKI-005, PKI-LOG-005
- What and why: Failing enrolment leaves machines without network or LDAPS certificates.
- Severity: low. Lens: maintenance. Category: PKI
- File: rules\workstations.yaml
- Data: protocol eventlog log Application provider Microsoft-Windows-CertificateServicesClient-Lifecycle-System / AutoEnrollment ids [6, 13, 82], days 7; per-host
- Condition: count > 0.
- Refs: NIST-800-53:SC-17
- Fix: Fix template permissions or CA reachability.
- Confidence: verified.

### WS-EVT-CODE-INTEGRITY - Code integrity refusals
- Rows: WINCLIENT-LOG-012
- What and why: Refusals reveal blocked agents and tampered files.
- Severity: low. Lens: security. Category: MON
- File: rules\workstations.yaml
- Data: protocol eventlog log Microsoft-Windows-CodeIntegrity/Operational ids [3033, 3063, 3077, 3089], days 7; per-host
- Condition: count > 0.
- Refs: NIST-800-53:SI-7
- Fix: Check the named file.
- Confidence: verified.

### WS-EVT-DEFENDER-CONFIG-CHANGE - Defender settings changed
- Rows: WINCLIENT-MON-007
- What and why: Same as the server form.
- Severity: high. Lens: security. Category: MON
- File: rules\workstations.yaml
- Data: protocol eventlog log Microsoft-Windows-Windows Defender/Operational, ids [5007, 5001, 5010, 5012], days 7; per-host
- Condition: as WINSRV-EVT-DEFENDER-CONFIG-CHANGE.
- Refs: NIST-800-53:SI-4, MITRE-ATTACK:T1562.001
- Fix: Match to policy.
- Confidence: verified.

### WS-EVT-DEFENDER-ERRORS - Defender update or engine failures
- Rows: WINCLIENT-LOG-010
- What and why: Failed updates and remediation failures leave stale protection.
- Severity: medium. Lens: maintenance. Category: LOG
- File: rules\workstations.yaml
- Data: protocol eventlog log Microsoft-Windows-Windows Defender/Operational, ids [1119, 2001, 2003, 2006, 3002, 5008], days 7; per-host
- Condition: any.
- Refs: NIST-800-53:SI-3(2)
- Fix: Check connectivity and the engine.
- Confidence: verified.

### WS-EVT-FOLDER-REDIRECTION - Folder Redirection errors
- Rows: WINCLIENT-BCK-004
- What and why: Redirection errors lose user data access.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\workstations.yaml
- Data: protocol eventlog log Application provider Folder Redirection ids [502, 1006, 1007], days 7; per-host
- Condition: any.
- Refs: NIST-800-53:CP-9
- Fix: Check target share and permissions.
- Confidence: verified.

### WS-EVT-LOCAL-ACCOUNT-CHANGE - Local administrators group changed
- Rows: WINCLIENT-MON-017
- What and why: Admin group additions on a PC need an explanation.
- Severity: medium. Lens: security. Category: MON
- File: rules\workstations.yaml
- Data: protocol eventlog log Security, ids [4732, 4733], days 7; per-host
- Condition: finding when the group is Administrators and the subject is not in threshold workstations.admin-change-allowed.
- Refs: NIST-800-53:AC-2(4)
- Fix: Match to the policy or LAPS action.
- Confidence: verified.

### WS-EVT-MDE-CONNECTIVITY - Defender for Endpoint cannot reach its cloud
- Rows: WINCLIENT-MON-010, WSS-LOG-004
- What and why: See the server rule.
- Severity: medium. Lens: maintenance. Category: MON
- File: rules\workstations.yaml
- Data: protocol eventlog log Microsoft-Windows-SENSE/Operational ids [5, 405], days 1; per-host
- Condition: count > 12 per hour.
- Refs: NIST-800-53:SI-4
- Fix: Fix proxy or bypass.
- Confidence: verified.

### WS-EVT-MDM-ERRORS - Device management policy errors
- Rows: WINCLIENT-LOG-022
- What and why: Policy delivery errors show co-management problems.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\workstations.yaml
- Data: protocol eventlog log Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin, level 2, days 7; per-host
- Condition: count > 5.
- Refs: NIST-800-53:CM-6
- Fix: Read the failing policy area.
- Confidence: verified.

### WS-EVT-SENSENDR-FLOOD - Sensor floods the app-container log
- Rows: WINCLIENT-LOG-011
- What and why: One component can write thousands of events an hour and hide other signals.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\workstations.yaml
- Data: protocol eventlog log Microsoft-Windows-LessPrivilegedAppContainer/Operational, days 1, max 1500; per-host
- Condition: count >= 1000 (cap hit = flood).
- Refs: NIST-800-53:AU-4
- Fix: Update the sensor.
- Confidence: likely.

### WS-EVT-SERVICE-INSTALLED - Service installed repeatedly
- Rows: WSS-HLT-006
- What and why: A service registered at every boot indicates a reinstall loop.
- Severity: low. Lens: maintenance. Category: LOG
- File: rules\workstations.yaml
- Data: protocol eventlog log System provider Service Control Manager id 7045, days 7; fields param1; per-host
- Condition: finding when one service name appears more than twice per host in 7 days.
- Refs: NIST-800-53:SI-4
- Fix: Fix the agent installer.
- Confidence: likely.

### WS-EVT-TIER0-LOGON - Admin account signed in on a workstation
- Rows: WINCLIENT-IAM-008
- What and why: Admin credentials on user PCs leave tier-0 hash material there.
- Severity: high. Lens: security. Category: IAM
- File: rules\workstations.yaml
- Data: protocol eventlog log Security id 4624, LogonType 2/10/11, days 7, max 500; per-host
- Condition: TargetUserName matches threshold workstations.admin-account-pattern (the admin-account naming prefix) or SID in tier-0 set.
- Refs: NIST-800-53:AC-6(5), MITRE-ATTACK:T1078.002
- Fix: Use a PAW.
- Confidence: likely.

### WS-EVT-USB-AUDIT-MISSING - No removable-device audit events
- Rows: WINCLIENT-MON-023
- What and why: Without events, USB policy cannot be proven.
- Severity: low. Lens: security. Category: LOG
- File: rules\workstations.yaml
- Data: protocol eventlog log Security id 6416, days 30, max 1; per-host
- Condition: count none on hosts in threshold workstations.usb-audit-sample.
- Refs: NIST-800-53:AU-12, NIST-800-53:MP-7
- Fix: Enable the Plug and Play audit subcategory.
- Confidence: guess.

### WS-FW-RULE-ANY-INBOUND - Inbound allow rule open to any address on admin ports
- Rows: WINCLIENT-AUT-002
- What and why: Admin ports open to everyone are lateral movement paths.
- Severity: medium. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/StandardCimv2, SELECT Name, Enabled, Direction, Action FROM MSFT_NetFirewallRule WHERE Enabled = 1 AND Direction = 1 AND Action = 2 with MSFT_NetFirewallPortFilter (LocalPort) and MSFT_NetFirewallAddressFilter (RemoteAddress) read as separate queries joined by InstanceID; per-host
- Condition: finding when LocalPort in (445, 135, 3389, 5985, 5986) and RemoteAddress is Any.
- Refs: NIST-800-53:SC-7, CIS-Controls-v8:4.4
- Fix: Scope to management networks.
- Confidence: likely - association join needs support in the runner.

### WS-GPO-UNWANTED-APPLIED - Policy that should not apply to this PC is applied
- Rows: WINCLIENT-CFG-014, WINCLIENT-CFG-015, WINCLIENT-CFG-016
- What and why: Test, legacy and wrongly scoped policies apply when OU placement is wrong.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/rsop/computer, SELECT name, guidName, enabled FROM RSOP_GPO; per-host
- Condition: finding when guidName is in threshold workstations.unwanted-gpo-guids.
- Refs: NIST-800-53:CM-3, NIST-800-53:CM-4
- Fix: Unlink or filter.
- Confidence: likely.

### WS-KERNEL-DMA-OFF - Kernel DMA protection unavailable or off
- Rows: WINCLIENT-CFG-011
- What and why: Protects against DMA attacks over external ports.
- Severity: low. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/Microsoft/Windows/DeviceGuard, SELECT AvailableSecurityProperties, SecurityServicesRunning FROM Win32_DeviceGuard; per-host
- Condition: finding when property 7 is absent on models listed in threshold workstations.dma-capable-models.
- Refs: NIST-800-53:SC-7
- Fix: Enable in firmware.
- Confidence: guess.

### WS-LOCAL-ADMIN-BUILTIN-ENABLED - Built-in administrator enabled outside the managed set
- Rows: WINCLIENT-IAM-012
- What and why: The built-in account should be disabled or password-managed.
- Severity: medium. Lens: security. Category: IAM
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE '%-500'; per-host
- Condition: finding when Disabled is false and the host has no managed-password policy (AD-COMP-LAPS-MISSING).
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.4
- Fix: Disable or manage with LAPS.
- Confidence: verified.

### WS-LOCALGROUP-PRIVILEGED-MEMBERS - Members in privileged local groups
- Rows: WINCLIENT-IAM-016
- What and why: See the server form.
- Severity: medium. Lens: security. Category: IAM
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, Win32_GroupUser for the groups in threshold workstations.privileged-local-groups; per-host
- Condition: any member outside allowed.
- Refs: NIST-800-53:AC-6
- Fix: Empty the group.
- Confidence: guess.

### WS-OFFICE-UPDATE-STATE - Office update channel or build off the plan
- Rows: WINCLIENT-LCM-016, WINCLIENT-LCM-017
- What and why: Machines on unmanaged channels or unsupported builds miss security fixes.
- Severity: medium. Lens: security. Category: LCM
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration values UpdateChannel, VersionToReport, UpdatesEnabled; per-host
- Condition: finding when UpdateChannel differs from threshold workstations.office-channel, UpdatesEnabled is false, or VersionToReport is below threshold workstations.office-min-build.
- Refs: NIST-800-53:SI-2
- Fix: Align the update policy.
- Confidence: verified.

### WS-POWER-SLEEP-BLOCKS-MAINTENANCE - Desktops sleep through the patch window
- Rows: WINCLIENT-CFG-019
- What and why: Sleeping PCs miss deadlines.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\29f6c1db-86da-48c5-9fdb-f2b67b1f44da value ACSettingIndex; per-host
- Condition: finding when ACSettingIndex is a number of seconds below 3600 on desktops.
- Refs: NIST-800-53:SI-2
- Fix: Allow maintenance wake.
- Confidence: guess.

### WS-PROC-USER-WRITABLE-PATH - Process running from a user-writable path
- Rows: WINCLIENT-AUT-024
- What and why: Programs started from AppData or Downloads bypass software control.
- Severity: medium. Lens: security. Category: HYG
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT Name, ExecutablePath FROM Win32_Process WHERE ExecutablePath LIKE '%\\AppData\\%' OR ExecutablePath LIKE '%\\Downloads\\%' OR ExecutablePath LIKE '%\\Temp\\%'; per-host
- Condition: finding when Name is not in threshold workstations.userpath-allowed.
- Refs: NIST-800-53:CM-11, MITRE-ATTACK:T1204
- Fix: Move approved apps to a managed path.
- Confidence: verified.

### WS-REG-AGENT-CONFIG-DRIFT - Agent configuration value differs from the expected
- Rows: GYTPOL-HLT-006, GYTPOL-CFG-007, ANYDESK-HLT-003, ANYDESK-HLT-004, ANYDESK-LOG-001
- What and why: Agents pointing at a wrong tenant or an old server upload nowhere.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry value paths from threshold workstations.agent-config-keys (key names to confirm per product); per-host
- Condition: finding when a value differs from the expected string.
- Refs: NIST-800-53:CM-2
- Fix: Redeploy configuration.
- Confidence: guess - key names unverified.

### WS-REG-CREDENTIAL-PROVIDER-UNEXPECTED - Credential provider from a retired product
- Rows: ESET-AVL-004
- What and why: Third-party credential providers can lock sign-in when their service is gone.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers subkeys (GUID names); per-host
- Condition: finding for each GUID not in threshold workstations.credential-providers-allowed.
- Refs: NIST-800-53:IA-2
- Fix: Remove the provider after removing the product.
- Confidence: likely.

### WS-REG-FAST-STARTUP-ON - Fast startup enabled
- Rows: WINCLIENT-CFG-018
- What and why: Fast startup keeps a hibernation image, so restarts-for-updates never happen on shutdown.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power HiberbootEnabled; per-host
- Condition: finding when 1.
- Refs: NIST-800-53:SI-2
- Fix: Disable by policy.
- Confidence: verified.

### WS-REG-FEATURE-VERSION-PINNED - Feature version pinned by policy
- Rows: WINCLIENT-LCM-008
- What and why: A pin holds PCs on an old release past its end of servicing.
- Severity: medium. Lens: maintenance. Category: LCM
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate values TargetReleaseVersion, TargetReleaseVersionInfo, ProductVersion; per-host
- Condition: finding when TargetReleaseVersion is 1 and the version is on the unsupported list.
- Refs: NIST-800-53:SI-2, NIST-800-53:CM-3
- Fix: Remove or update the pin.
- Confidence: verified.

### WS-REG-LAPS-TWO-MECHANISMS - Legacy and Windows LAPS both configured
- Rows: WINCLIENT-IAM-010, SCCM-AUT-023
- What and why: Two mechanisms fighting over the same account breaks password retrieval.
- Severity: medium. Lens: security. Category: IAM
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd AdmPwdEnabled and HKLM\SOFTWARE\Microsoft\Policies\LAPS BackupDirectory; per-host
- Condition: finding when both are set.
- Refs: NIST-800-53:IA-5
- Fix: Choose one and remove the other.
- Confidence: verified.

### WS-REG-MDNS-WPAD-ON - Multicast DNS or WPAD auto-discovery allowed
- Rows: WINCLIENT-AUT-015
- What and why: See the server form.
- Severity: low. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry as WINSRV-REG-MDNS-WPAD-ON; per-host
- Condition: as the server form.
- Refs: NIST-800-53:SC-20
- Fix: Set by policy.
- Confidence: verified.

### WS-REG-METERED-NETWORK - Wired PC treated as metered
- Rows: SCCM-HLT-030
- What and why: Metered connections stop update and policy downloads.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\DusmSvc\Profiles subkeys with value UserCost; per-host
- Condition: finding when UserCost is 2 on a profile.
- Refs: NIST-800-53:SI-2
- Fix: Reset the profile.
- Confidence: guess - nested subkeys need recursion.

### WS-REG-MY-STORE-COUNT - Personal certificate store large
- Rows: WINCLIENT-PKI-006
- What and why: See the server form.
- Severity: low. Lens: maintenance. Category: PKI
- File: rules\workstations.yaml
- Data: protocol registry subkeys of HKLM\SOFTWARE\Microsoft\SystemCertificates\My\Certificates; per-host
- Condition: count > 20.
- Refs: NIST-800-53:SC-17
- Fix: Clean up.
- Confidence: verified.

### WS-REG-RESIDUE-KEY - Leftovers of a removed product
- Rows: ESET-HYG-007, ESET-HYG-009, ANYDESK-CFG-009
- What and why: Registry keys and tasks of a removed product show an incomplete removal.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\workstations.yaml
- Data: protocol registry keys listed in threshold workstations.residue-keys (for example HKLM\SOFTWARE\<vendor>) and cim MSFT_ScheduledTask by TaskPath; per-host
- Condition: any key or task present.
- Refs: NIST-800-53:CM-7
- Fix: Finish the removal.
- Confidence: likely.

### WS-REG-ROOT-REQUIRED-MISSING - Required inspection root absent
- Rows: WINCLIENT-PKI-002, WSS-PKI-001
- What and why: PCs behind TLS inspection without the root show certificate errors everywhere.
- Severity: medium. Lens: maintenance. Category: PKI
- File: rules\workstations.yaml
- Data: protocol registry subkeys of HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates; per-host
- Condition: finding when the thumbprint in threshold workstations.required-root is absent.
- Refs: NIST-800-53:SC-17
- Fix: Distribute the root.
- Confidence: verified.

### WS-REG-ROOT-STORE-UNKNOWN - Trusted root not on the allowed list
- Rows: WINCLIENT-PKI-001, ESET-PKI-003
- What and why: See the server form; also detects residue after removing an inspection product.
- Severity: high. Lens: security. Category: PKI
- File: rules\workstations.yaml
- Data: protocol registry as WINSRV-REG-ROOT-STORE-UNKNOWN; per-host
- Condition: as the server form.
- Refs: NIST-800-53:SC-17, MITRE-ATTACK:T1553.004
- Fix: Remove.
- Confidence: likely.

### WS-REG-TIME-SOURCE - PC time source not the domain
- Rows: WINCLIENT-CFG-020
- What and why: See the server form.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry W32Time Parameters Type; per-host
- Condition: finding when not NT5DS.
- Refs: NIST-800-53:AU-8
- Fix: Reset.
- Confidence: verified.

### WS-REG-W11-BYPASS - Windows 11 requirement bypass values present
- Rows: WINCLIENT-LCM-010
- What and why: Unsupported installs get no feature updates.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SYSTEM\Setup\LabConfig values BypassTPMCheck, BypassSecureBootCheck, BypassCPUCheck, BypassRAMCheck; per-host
- Condition: any value equal to 1.
- Refs: NIST-800-53:SA-22
- Fix: Replace the hardware.
- Confidence: guess - keys may be removed after setup.

### WS-REG-WSH-ENABLED - Windows Script Host enabled for users
- Rows: WINCLIENT-AUT-040
- What and why: Script hosts run most commodity malware.
- Severity: low. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings value Enabled; per-host
- Condition: finding when absent or 1 on standard-user PCs.
- Refs: NIST-800-53:CM-7, MITRE-ATTACK:T1059.005
- Fix: Disable by policy.
- Confidence: verified.

### WS-REG-WSUS-DUAL-SCAN - Update source conflict
- Rows: WINCLIENT-LCM-032, WINCLIENT-CFG-022
- What and why: See the server form.
- Severity: low. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry as WINSRV-REG-WSUS-DUAL-SCAN; per-host
- Condition: as server form.
- Refs: NIST-800-53:SI-2
- Fix: Align the policy.
- Confidence: verified.

### WS-RSOP-AUDIT-POLICY - Audit categories below the baseline on PCs
- Rows: WINCLIENT-MON-014
- What and why: See the server form.
- Severity: low. Lens: security. Category: MON
- File: rules\workstations.yaml
- Data: protocol cim, root/rsop/computer RSOP_AuditPolicy; per-host
- Condition: as server form with threshold workstations.audit-required.
- Refs: NIST-800-53:AU-2
- Fix: Apply the audit baseline.
- Confidence: likely.

### WS-RSOP-USER-RIGHTS - User rights differ from the baseline on PCs
- Rows: WINCLIENT-IAM-017, WINCLIENT-IAM-018, WINCLIENT-IAM-019, WINCLIENT-IAM-020
- What and why: See the server form.
- Severity: high. Lens: security. Category: IAM
- File: rules\workstations.yaml
- Data: protocol cim, root/rsop/computer RSOP_UserPrivilegeRight; per-host
- Condition: as server form with threshold workstations.user-rights-expected.
- Refs: NIST-800-53:AC-6
- Fix: Fix the granting policy.
- Confidence: likely.

### WS-SCHANNEL-LEGACY-ENABLED - Legacy protocol enabled on the client side
- Rows: WINCLIENT-AUT-016
- What and why: Old protocol clients enable downgrade.
- Severity: low. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol registry SCHANNEL\Protocols\<SSL 2.0|SSL 3.0|TLS 1.0|TLS 1.1>\Client Enabled and DisabledByDefault; per-host
- Condition: finding when Enabled is 1 or DisabledByDefault is 0 explicitly.
- Refs: NIST-800-53:SC-8
- Fix: Remove the override.
- Confidence: verified.

### WS-SVC-APPID-STOPPED - Application Identity service stopped where application control is configured
- Rows: WINCLIENT-AUT-025
- What and why: AppLocker policy has no effect when the service is off.
- Severity: medium. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT State, StartMode FROM Win32_Service WHERE Name = 'AppIDSvc'; per-host
- Condition: finding when not running on hosts that have SrpV2 collection values.
- Refs: NIST-800-53:CM-7(5)
- Fix: Start the service by policy.
- Confidence: guess.

### WS-SVC-IME-MISSING - Intune Management Extension absent on enrolled PC
- Rows: WINCLIENT-LCM-026
- What and why: Without it, Win32 apps and scripts from Intune never run.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT State, StartMode FROM Win32_Service WHERE Name = 'IntuneManagementExtension'; per-host
- Condition: count none on hosts that are enrolled (WSF/Intune join).
- Refs: NIST-800-53:CM-2
- Fix: Reinstall via enrolment.
- Confidence: likely.

### WS-TCP-LISTENER-UNEXPECTED - Agent process listening on a port
- Rows: EPROC-CFG-009
- What and why: Agents should connect out only.
- Severity: low. Lens: security. Category: CFG
- File: rules\workstations.yaml
- Data: protocol cim, root/StandardCimv2, SELECT LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2 joined to Win32_Process by process id; per-host
- Condition: finding when a process matching threshold workstations.outbound-only-agents listens.
- Refs: NIST-800-53:CM-7
- Fix: Raise with the vendor.
- Confidence: likely.

### WS-UNEXPECTED-DRIVER - Driver of a removed product still registered
- Rows: ESET-HYG-006
- What and why: Leftover filter drivers can block networking or storage.
- Severity: medium. Lens: maintenance. Category: HYG
- File: rules\workstations.yaml
- Data: protocol cim, root/cimv2, SELECT Name, State, StartMode FROM Win32_SystemDriver; per-host
- Condition: finding when Name is in threshold workstations.removed-product-drivers.
- Refs: NIST-800-53:CM-7
- Fix: Remove it.
- Confidence: verified.

### WSF-AGENT-HALF-INSTALL - Agent product listed without services (or the reverse)
- Rows: GYTPOL-HLT-004, WSS-HLT-003, WSS-HYG-003, EPROC-HLT-005
- What and why: Broken upgrades leave the product registered but not running.
- Severity: high. Lens: maintenance. Category: HLT
- File: rules\workstations-sccm.yaml
- Data: protocol http (SCCM AdminService) /wmi/SMS_G_System_ADD_REMOVE_PROGRAMS and /wmi/SMS_G_System_SERVICE with $filter on names from threshold workstations-sccm.agent-names; joined by ResourceID
- Condition: finding when exactly one of the two is present.
- Refs: NIST-800-53:SI-4, NIST-800-53:CM-8
- Fix: Reinstall.
- Confidence: likely.

### WSF-BIOS-OLD - BIOS older than the model floor
- Rows: WINCLIENT-LCM-028
- What and why: Firmware advisories hit specific models.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\workstations-sccm.yaml
- Data: protocol http /wmi/SMS_G_System_PC_BIOS (SMBIOSBIOSVersion, ReleaseDate) joined to SMS_G_System_COMPUTER_SYSTEM Model
- Condition: finding when ReleaseDate is older than the floor for the model in threshold workstations-sccm.bios-floor.
- Refs: NIST-800-53:SI-2
- Fix: Update.
- Confidence: guess - floors are tenant data.

### WSF-C-FREE-FOR-UPGRADE - Not enough free space for the feature update
- Rows: WINCLIENT-HLT-002
- What and why: Upgrades need around 20 GB free.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\workstations-sccm.yaml
- Data: protocol http /wmi/SMS_G_System_LOGICAL_DISK (DeviceID C:, FreeSpace) joined to OS build
- Condition: finding when FreeSpace < 20 GB on a Windows 10 PC.
- Refs: NIST-800-53:SI-2
- Fix: Free space.
- Confidence: verified.

### WSF-HARDWARE-AGE - PC older than the replacement age
- Rows: WINCLIENT-HLT-014
- What and why: Age drives failure and support.
- Severity: low. Lens: maintenance. Category: LCM
- File: rules\workstations-sccm.yaml
- Data: protocol http /wmi/SMS_G_System_PC_BIOS ReleaseDate
- Condition: finding when older than threshold workstations-sccm.hardware-max-age-years (default 6).
- Refs: NIST-800-53:SA-22
- Fix: Plan replacement.
- Confidence: verified.

### WSF-NEW-PC-AGENT-DELAY - New PC without the security agent after a day
- Rows: WSS-AVL-004
- What and why: Gaps between first registration and agent install are unprotected windows.
- Severity: medium. Lens: security. Category: AVL
- File: rules\workstations-sccm.yaml
- Data: protocol store; SMS_R_System CreationDate joined to deployment status for the agent application
- Condition: finding when the PC is older than 24 h and has no success.
- Refs: NIST-800-53:CM-3
- Fix: Check boundary and deployment targeting.
- Confidence: guess.

### WSF-SUBNET-NO-BOUNDARY - Client subnet in no boundary
- Rows: WINCLIENT-AVL-003, SCCM-AVL-006, SCCM-AVL-007, WSS-LOG-002
- What and why: Clients on a subnet outside every boundary cannot find content.
- Severity: high. Lens: maintenance. Category: CFG
- File: rules\workstations-sccm.yaml
- Data: protocol store; /wmi/SMS_R_System IPSubnets of active clients joined to /wmi/SMS_Boundary and /wmi/SMS_BoundaryGroup site systems
- Condition: finding for each subnet with active clients and no covering boundary in a group with a site system.
- Refs: NIST-800-53:CM-2
- Fix: Add the boundary.
- Confidence: likely - needs CIDR matching.

### WSF-SW-JAVA-ORACLE - Oracle Java on PCs
- Rows: WINCLIENT-CST-008
- What and why: See the server form.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\workstations-sccm.yaml
- Data: protocol http /wmi/SMS_G_System_ADD_REMOVE_PROGRAMS(_64) filtered by Publisher
- Condition: any match.
- Refs: NIST-800-53:CM-10
- Fix: Replace.
- Confidence: guess.

### WSF-SW-VERSION-OLD - Application version below the floor
- Rows: WINCLIENT-LCM-019, WINCLIENT-LCM-020, WINCLIENT-LCM-021, APP-BASELINE-LCM-014, GYTPOL-LCM-001, WSS-LCM-001, EPROC-LCM-001, ANYDESK-LCM-001, ANYDESK-LCM-002, KN-anydesk-control-deployed-without-pilot
- What and why: Browsers, readers and agents are patched by version.
- Severity: medium. Lens: security. Category: LCM
- File: rules\workstations-sccm.yaml
- Data: protocol http /wmi/SMS_G_System_ADD_REMOVE_PROGRAMS(_64) (DisplayName, Version) with names and floors in threshold workstations-sccm.version-floors
- Condition: finding when a listed product has Version below the floor.
- Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.4
- Fix: Update.
- Confidence: verified.

### WSF-TPM-FIRMWARE-VULNERABLE - TPM firmware on a known-vulnerable list
- Rows: WINCLIENT-LCM-029
- What and why: Some firmware versions weaken keys.
- Severity: medium. Lens: security. Category: LCM
- File: rules\workstations-sccm.yaml
- Data: protocol http /wmi/SMS_G_System_TPM (ManufacturerId, ManufacturerVersion)
- Condition: finding when the pair is in threshold workstations-sccm.tpm-vulnerable.
- Refs: NIST-800-53:SC-12, NIST-800-53:SI-2
- Fix: Update firmware.
- Confidence: likely.

### WSF-UPDATE-SCAN-STALE - Update scan too old or failing
- Rows: WINCLIENT-LCM-007
- What and why: No scan means no compliance data.
- Severity: medium. Lens: maintenance. Category: HLT
- File: rules\workstations-sccm.yaml
- Data: protocol http /wmi/SMS_UpdateScanStatus (ResourceID, LastScanTime, LastErrorCode)
- Condition: finding when LastScanTime older than 7 days or LastErrorCode non-zero.
- Refs: NIST-800-53:SI-2
- Fix: Repair the update agent.
- Confidence: likely.

### XS-ADSYNC-OU-SCOPE-MISMATCH - Sync scope does not match the OU model
- Rows: AD-502
- What and why: Users in OUs that should sync but do not (or leavers' OU that still does) show up as missing or lingering cloud accounts.
- Severity: medium. Lens: both. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; AD user rows (distinguishedName, userAccountControl) joined to Entra user rows (onPremisesSyncEnabled, onPremisesDistinguishedName); estate-wide
- Condition: finding for enabled AD users in OUs listed in threshold xs.sync-in-scope-ous that are absent from Entra, and for users in OUs listed in xs.sync-out-of-scope-ous that are present.
- Refs: NIST-800-53:AC-2, NIST-800-53:AC-2(3)
- Fix: Correct the OU filter or the user placement.
- Confidence: guess - needs an Entra pack that stores the sync flag and DN.

### XS-APP-CONSOLE-HTTP-HARDENING - Console served over plain HTTP or without hardening headers
- Rows: APP-BASELINE-AUT-005, APP-BASELINE-AUT-010
- What and why: Consoles reachable over HTTP, or without strict transport security and framing protection, expose sessions on the wire and to clickjacking.
- Severity: medium. Lens: security. Category: AUT
- File: rules\cross-system.yaml
- Data: protocol http; GET http://<host>/ without following redirects and HEAD https://<host>/; fields status, location, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options or CSP; URLs from a register table; per URL
- Condition: finding when the http variant does not redirect to https, or when the https response lacks strict-transport-security or both framing headers.
- Refs: NIST-800-53:SC-8, CIS-Controls-v8:3.10
- Fix: Add the redirect and the headers at the proxy or site level.
- Confidence: guess - the http runner must expose response headers.

### XS-APP-CONSOLE-URL-DOWN - Registered console URL does not answer
- Rows: APP-BASELINE-HLT-001, LANSWEEPER-HLT-001
- What and why: A register lists each application's console URL; a probe tells when one stops answering or changes redirect target.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\cross-system.yaml
- Data: protocol http; GET with redirects off and a 10-second timeout against URLs held in the registers import; fields status, elapsed; per URL
- Condition: finding when status is not in 200, 301, 302, 401, 403 or the call times out.
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-2
- Fix: Check the service behind the URL.
- Confidence: likely - plain HTTP read.

### XS-APP-VERSION-ON-KEV - Installed product version appears in the known-exploited list
- Rows: APP-BASELINE-LCM-015
- What and why: The public known-exploited catalogue is a free JSON feed; matching it to recorded product versions finds the urgent patches.
- Severity: high. Lens: security. Category: LCM
- File: rules\cross-system.yaml
- Data: protocol http GET of the catalogue JSON; store join with the software inventory rows (publisher/product, version) and register products; estate-wide
- Condition: finding when vendorProject and product match an installed product and the installed version is below the fixed version listed in threshold xs.kev-fixed-versions.
- Refs: NIST-800-53:RA-5, NIST-800-53:SI-2, CIS-Controls-v8:7.4
- Fix: Patch to the fixed version.
- Confidence: guess - the catalogue has no machine-readable version ranges; a curated list is needed.

### XS-BITLOCKER-KEY-NOT-ESCROWED - Encrypted volume whose recovery key is not stored
- Rows: WINSRV-BCK-012, WINCLIENT-BCK-001
- What and why: A volume encrypted without an escrowed recovery key is unrecoverable after a hardware or PIN problem.
- Severity: high. Lens: maintenance. Category: BCK
- File: rules\cross-system.yaml
- Data: protocol store; host rows from Win32_EncryptableVolume (ProtectionStatus, DriveLetter, host) joined to AD msFVE-RecoveryInformation child counts per computer and to Entra BitLocker key records; estate-wide
- Condition: finding for an encrypted OS volume with no escrowed key on either side.
- Refs: NIST-800-53:CP-9, NIST-800-53:SC-12
- Fix: Back up the protector to the directory or Entra ID.
- Confidence: likely - key objects are readable without the key itself (count only).

### XS-DFS-TARGET-SERVER-GONE - Namespace folder target on a server that no longer exists
- Rows: FILESRV-AVL-004
- What and why: A DFS folder target pointing at a disabled or deleted computer gives users timeouts when referrals pick it.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\cross-system.yaml
- Data: protocol store; DFS target rows (root/Microsoft/Windows/DFSN MSFT_DfsNamespaceFolderTarget TargetPath server part) joined to AD computer rows (enabled, lastLogonTimestamp); estate-wide
- Condition: finding when the server is missing, disabled or silent for more than 30 days.
- Refs: NIST-800-53:CM-8, NIST-800-53:CP-2
- Fix: Remove the target or restore the server.
- Confidence: likely.

### XS-DHCP-LEASE-UNKNOWN-HOST - Long-lived lease to a host unknown to the directory
- Rows: DHCP-MON-003
- What and why: Leases whose host names match no computer object are unmanaged or rogue devices.
- Severity: low. Lens: security. Category: HYG
- File: rules\cross-system.yaml
- Data: protocol store; DHCP lease rows (HostName, AddressState, ClientId) joined to AD computer rows by short name; estate-wide
- Condition: finding when an active lease older than threshold xs.lease-min-age-days has no matching computer object.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.2
- Fix: Identify the device or block its lease.
- Confidence: guess - needs lease rows from the DHCP pack.

### XS-DHCP-PARTNER-DRIFT - DHCP partners differ in scopes, options or reservations
- Rows: DHCP-AVL-003, DHCP-CFG-009, DHCP-HYG-004
- What and why: Failover partners that disagree hand out different options after a failover.
- Severity: medium. Lens: maintenance. Category: CFG
- File: rules\cross-system.yaml
- Data: protocol store; scope, option and reservation rows per DHCP server grouped by failover relationship; estate-wide
- Condition: finding when the sets differ between partners.
- Refs: NIST-800-53:CM-2, NIST-800-53:CP-10
- Fix: Replicate the configuration from the primary.
- Confidence: likely.

### XS-DOMAIN-REGISTRATION-EXPIRY - Forest DNS name registration about to lapse
- Rows: AD-015
- What and why: If the public name used for the forest lapses, mail, certificates and sign-in may break.
- Severity: high. Lens: maintenance. Category: LCM
- File: rules\cross-system.yaml
- Data: protocol http GET https://rdap.org/domain/<name> (JSON); fields events[eventAction=expiration].eventDate, entities (registrant role); estate-wide
- Condition: finding when expiry is under threshold xs.domain-min-days (default 90) or the registrant does not match threshold xs.domain-registrant.
- Refs: NIST-800-53:SA-9, CIS-Controls-v8:2.1
- Fix: Renew and register an owner group as contact.
- Confidence: likely - RDAP is a public JSON API; some registries omit entities.

### XS-EVT-VENDOR-INTERACTIVE-LOGON - Supplier account signs in interactively on a managed PC
- Rows: WINCLIENT-IAM-021
- What and why: Supplier staff on municipal PCs should come through the approved path and be rare.
- Severity: medium. Lens: security. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; eventlog rows (Security 4624 types 2, 10, 11: TargetUserName, host, time) joined to members of the vendor group in AD; estate-wide
- Condition: finding for each sign-in by a vendor group member.
- Refs: NIST-800-53:AC-2, NIST-800-53:PS-7
- Fix: Confirm the support need or remove the access.
- Confidence: guess - needs the event rows from every PC rule scan.

### XS-FLEET-WIDE-SIGNAL - Same finding on a large share of hosts in one OU
- Rows: WINCLIENT-LOG-021
- What and why: A rule failing on a quarter of an OU's machines usually has one cause (a policy or a build), not one per host.
- Severity: medium. Lens: maintenance. Category: MON
- File: rules\cross-system.yaml
- Data: protocol store; finding rows grouped by rule id and OU of the host (computer DN); estate-wide
- Condition: finding when failing hosts are >= threshold xs.wide-percent (default 25) of an OU's scanned hosts and >= 5 hosts.
- Refs: NIST-800-53:SI-4
- Fix: Fix the shared cause once.
- Confidence: guess - needs findings grouped by OU in the store.

### XS-LOCALADMIN-ON-MANY-SERVERS - Account that is local administrator on many servers
- Rows: WINSRV-IAM-005
- What and why: Wide local-admin spread makes one stolen credential a fleet compromise.
- Severity: medium. Lens: security. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; Win32_GroupUser member rows of the local Administrators group per server; group by member; estate-wide
- Condition: finding when a non-group member (user account) is admin on more than threshold xs.admin-spread (default 10) servers.
- Refs: NIST-800-53:AC-6(5), CIS-Controls-v8:5.4
- Fix: Replace with group-based tiered access.
- Confidence: likely.

### XS-M365-APPS-UNLICENSED-USER - Office desktop apps installed for a user without the plan
- Rows: WINCLIENT-CST-004, WINCLIENT-CST-005
- What and why: Click-to-Run installs sign in with a user licence; installs whose primary user lacks the desktop-apps plan break at the next activation.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\cross-system.yaml
- Data: protocol store; registry rows HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration ProductReleaseIds joined to the device primary user and the user's assigned plans (Graph licenseDetails); estate-wide
- Condition: finding when ProductReleaseIds names Visio, Project or an apps SKU and the user has no matching service plan.
- Refs: NIST-800-53:CM-10
- Fix: Assign the licence or remove the install.
- Confidence: guess.

### XS-SCCM-SOURCE-HOST-NO-BACKUP - Package source share on a host without backup
- Rows: SCCM-BCK-010
- What and why: Source files are the only copy of what the site distributes; they are not in the site backup.
- Severity: medium. Lens: maintenance. Category: BCK
- File: rules\cross-system.yaml
- Data: protocol store; SMS_PackageBaseclass PkgSourcePath (server part) joined to backup-object rows; estate-wide
- Condition: finding when the source host has no backup object or last success older than 7 days.
- Refs: NIST-800-53:CP-9
- Fix: Add the host to a backup job.
- Confidence: guess.

### XS-SERVICE-ACCOUNT-PASSWORD-OLD - Service or task account with an old password
- Rows: WINSRV-IAM-030, SQL-IAM-025, APP-BASELINE-IAM-009
- What and why: Accounts that run services or tasks rarely get password changes; the age is visible in the directory.
- Severity: medium. Lens: security. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; Win32_Service StartName and MSFT_ScheduledTask principal rows mapped to AD users (pwdLastSet, userAccountControl, objectClass); estate-wide
- Condition: finding when the account is a user (not a managed service account) and pwdLastSet is older than threshold xs.service-pwd-max-days (default 365), or has the never-expires flag.
- Refs: NIST-800-53:IA-5(1), CIS-Controls-v8:5.2
- Fix: Rotate or convert to a group managed service account.
- Confidence: likely.

### XS-SERVICE-ACCOUNT-PRIVILEGED - Service or task runs as a privileged account
- Rows: WINSRV-IAM-029, WINSRV-IAM-032
- What and why: A service identity in a protected group turns any flaw in that service into a directory compromise.
- Severity: high. Lens: security. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; service StartName and task principal rows joined to AD users with adminCount=1 or nested protected-group membership; estate-wide
- Condition: finding for each match.
- Refs: NIST-800-53:AC-6(5), MITRE-ATTACK:T1078
- Fix: Use a least-privilege account.
- Confidence: likely.

### XS-SQL-LINKED-SERVER-DEAD - Linked server points at a dead host
- Rows: SQL-HYG-012
- What and why: Linked servers to retired hosts cause timeouts in jobs that still reference them.
- Severity: low. Lens: maintenance. Category: HYG
- File: rules\cross-system.yaml
- Data: protocol store; sys.servers data_source rows joined to AD computer state; estate-wide
- Condition: finding when the target host is missing or disabled in the directory.
- Refs: NIST-800-53:CM-8
- Fix: Drop the linked server.
- Confidence: likely.

### XS-SQL-LOGIN-ACCOUNT-LEFT - Windows login of a disabled or deleted account
- Rows: SQL-IAM-013
- What and why: Server logins survive the account that owned them and can be reused if the name is recreated.
- Severity: high. Lens: security. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; sys.server_principals type U/G name rows joined to AD sAMAccountName state; estate-wide
- Condition: finding when the AD account is missing or disabled.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:PS-4
- Fix: Drop the login after checking ownership of objects.
- Confidence: likely.

### XS-SQL-REPLICA-DRIFT - Logins or jobs differ between replicas
- Rows: SQL-AVL-012
- What and why: After a failover, missing logins or jobs break the application.
- Severity: medium. Lens: maintenance. Category: AVL
- File: rules\cross-system.yaml
- Data: protocol store; sys.server_principals (name, sid, type) and msdb.dbo.sysjobs (name, enabled) per replica of one availability group; estate-wide
- Condition: finding when the sets differ.
- Refs: NIST-800-53:CP-10, NIST-800-53:CM-2
- Fix: Synchronise logins with matching SIDs and replicate jobs.
- Confidence: likely.

### XS-SQL-SERVICE-ACCOUNT-LOCAL-ADMIN - SQL service account is local administrator of its host
- Rows: SQL-IAM-024
- What and why: A service account with local admin gives SQL injection a path to the host.
- Severity: high. Lens: security. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; sys.dm_server_services service_account joined to local Administrators members of the host; estate-wide
- Condition: finding when the service account (or a group containing it) is an administrator.
- Refs: NIST-800-53:AC-6, CIS-Controls-v8:5.4
- Fix: Remove it from the group.
- Confidence: likely.

### XS-SQL-SERVICE-ACCOUNT-SHARED - Same service account used by several instances
- Rows: SQL-IAM-026
- What and why: Shared service accounts spread one compromise across instances and make rotation risky.
- Severity: low. Lens: security. Category: IAM
- File: rules\cross-system.yaml
- Data: protocol store; service_account values across instances; estate-wide
- Condition: finding when one account runs more than one instance.
- Refs: NIST-800-53:AC-6, NIST-800-53:IA-5
- Fix: Give each instance its own account (or managed service account).
- Confidence: verified.

### XS-SQL-SPN-NOT-REGISTERED - Instance service account lacks its service principal names
- Rows: SQL-AUT-006
- What and why: Without the MSSQLSvc names, clients fall back to NTLM and delegation fails.
- Severity: medium. Lens: security. Category: AUT
- File: rules\cross-system.yaml
- Data: protocol store; service account and port/instance rows joined to AD servicePrincipalName of the account or computer; estate-wide
- Condition: finding when neither MSSQLSvc/<fqdn>:<port> nor the instance-name form exists; duplicates are found by AD-DUPLICATE-IDENTIFIER.
- Refs: NIST-800-53:IA-2, NIST-800-53:SC-23
- Fix: Register the names for the service account.
- Confidence: likely.

### XS-WEB-SPN-NOT-REGISTERED - Web application identity lacks SPNs for the names in use
- Rows: APP-BASELINE-AUT-009
- What and why: Integrated sites need HTTP names registered to the app pool identity or Kerberos falls back to NTLM.
- Severity: low. Lens: security. Category: AUT
- File: rules\cross-system.yaml
- Data: protocol store; application pool identity rows (root/WebAdministration) joined to AD servicePrincipalName; estate-wide
- Condition: finding when a bound host name has no HTTP/<name> on the pool identity.
- Refs: NIST-800-53:IA-2
- Fix: Register the SPNs with setspn-equivalent LDAP writes through change control.
- Confidence: guess.

### XS-WINDOWS-EDITION-VS-LICENCE - Edition does not match the user's licence
- Rows: WINCLIENT-CST-003
- What and why: Users licensed for Enterprise features whose devices run Pro (or the reverse) lose or waste what was paid for.
- Severity: low. Lens: maintenance. Category: CST
- File: rules\cross-system.yaml
- Data: protocol store; Win32_OperatingSystem OperatingSystemSKU per device joined to the primary user's assigned plans; estate-wide
- Condition: finding when plans include the subscription activation plan and the edition is not Enterprise.
- Refs: NIST-800-53:CM-10
- Fix: Trigger the activation or correct the assignment.
- Confidence: guess.

## Checks from the Active Directory and PKI pass (kept, with later rows added)

## Active Directory, domain controllers and AD CS

Ids checked against rules\active-directory.yaml (176 rules after the 2026-10-20 additions), rules\adcs.yaml,
rules\windows-server.yaml and the proposals files; none collides. "DC pack" = a new file
`rules\domain-controllers.yaml` (system `domain-controllers`, integration cim; registry and eventlog rules
share the same targets): targets entity computer, field dNSHostName, where userAccountControl has flag 8192
and lastLogonTimestamp newer than 30 days. Severity ranks below apply to DCs; where a rule is proposed for
windows-server.yaml it runs on every server (DCs included).

### Shared conventions for the DC-EVT-* rules

Every DC-EVT-* entry below is: File domain-controllers.yaml; Data protocol eventlog on each DC with the
`log`, `ids`, `providers` and `days` given; fields host, log, id, provider, level, time plus the event
data; scope per-host; key `{host}|{log}|{id}`; Condition `count: { op: gt, value: 0 }` per host unless the
entry says otherwise (a host whose channel is missing returns no rows and passes - that is the correct
answer for an absent role); kind broken, lens maintenance unless stated; Confidence verified for the
event ids (Microsoft Learn event references for Directory Service, DFS Replication, DNS Server, Netlogon,
KDC and W32Time; links given once per family). Evidence: `"{host}: {count} events {ids} in {days} days"`.
The `days` default is 7; thresholds `dc.evt.<family>-days` let a tenant widen it.

### DC-EVT-DS-ERRORS - Directory Service log carries errors
- All rows depending on this proposal: AD-LOG-001
- Rows: AD-LOG-001
- What and why: any Critical or Error in the Directory Service log is NTDS reporting replication, database, LDAP or topology trouble; it is never noise and is the first place to look before any other DC rule.
- Severity: high. Lens: both. Category: LOG
- Data: eventlog log "Directory Service", no ids, days 7, max 500; Condition count>0 where level le 2. Partial result (cap hit) is reported as partial, never a pass.
- Refs: NIST-800-53:AU-6, NIST-800-53:SI-4
- Fix: group by provider and id, then follow the family rule for that id; add unknown ids to a family.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/troubleshoot/troubleshooting-active-directory-replication-problems

### DC-EVT-DS-KCC - Knowledge Consistency Checker cannot build the topology
- All rows depending on this proposal: AD-LOG-002
- Rows: AD-LOG-002
- What and why: ids 1311, 1865, 1566, 1308 mean the KCC cannot reach or route to a site or DC; the first symptom of a down link or broken DNS between sites.
- Severity: high. Category: AVL
- Data: eventlog log "Directory Service", ids [1311, 1865, 1566, 1308], days 7
- Refs: NIST-800-53:CP-10, NIST-800-53:SI-4
- Fix: fix connectivity and DNS to the DC named in the event; review site links (AD-SITELINK-*); 1128 afterwards confirms recovery.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-1311-ntds-kcc

### DC-EVT-DS-REPL-STALE - Replication partners not reached for a day or longer (1864)
- All rows depending on this proposal: AD-LOG-003
- Rows: AD-LOG-003
- What and why: 1864 lists how many partners have not replicated in 24 h, a week, a month and past the tombstone lifetime; the earliest sign of a DC drifting toward the tombstone cliff.
- Severity: high. Category: AVL
- Data: eventlog log "Directory Service", ids [1864], days 7. Condition: every row (the counters are in the event data; if the runner exposes them as param1..param4, add `where param1 gt 0`).
- Refs: NIST-800-53:CP-10
- Fix: find the partner (needs rootdse-per-dc for msDS-NCReplInboundNeighbors); fix its link or demote it.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-1864-ntds-replication

### DC-EVT-DS-TOMBSTONE - Partner past the tombstone lifetime (2042)
- All rows depending on this proposal: AD-LOG-004
- Rows: AD-LOG-004
- What and why: a partner that has not replicated within the tombstone lifetime is refused; forcing it would re-animate deleted objects. The DC needs lingering-object cleanup or a rebuild.
- Severity: critical. Category: AVL
- Data: eventlog log "Directory Service", ids [2042], days 30
- Refs: NIST-800-53:CP-10
- Fix: remove lingering objects on the source first, then either allow the divergent partner once (and clear the registry override, DC-REG-DIVERGENT-PARTNER-ALLOWED) or demote and re-promote.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-2042-too-long-since-replication

### DC-EVT-DS-LINGERING - Lingering objects detected or re-animated
- All rows depending on this proposal: AD-LOG-005
- Rows: AD-LOG-005
- What and why: 1388 means strict consistency is off and a deleted object came back; 1988 means a source still holds objects this DC deleted; 1946 names them.
- Severity: high. Category: AVL
- Data: eventlog log "Directory Service", ids [1388, 1988, 1946], days 30
- Refs: NIST-800-53:CP-10, NIST-800-53:SI-7
- Fix: enable strict replication consistency everywhere (DC-REG-STRICT-REPL-CONSISTENCY) and remove the lingering objects from the source named in the event.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/lingering-objects-prevent-ad-replication

### DC-EVT-DS-USN-ROLLBACK - USN rollback or replication paused
- All rows depending on this proposal: AD-LOG-006
- Rows: AD-LOG-006
- What and why: 2095/2103 mean a DC was restored from a snapshot or image and froze itself out of replication while still answering clients; 1113/1115 mean inbound or outbound replication was disabled by hand.
- Severity: critical. Category: AVL
- Data: eventlog log "Directory Service", ids [2095, 2103, 1113, 1115], days 90
- Refs: NIST-800-53:CP-10, NIST-800-53:CM-3
- Fix: demote with forced removal and re-promote; never revert a DC snapshot. Re-enable replication if it was paused on purpose and forgotten.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/usn-rollback-virtualized-dc-event-2095

### DC-EVT-DS-REPL-LINK - Replication link or source lookup failures
- All rows depending on this proposal: AD-LOG-007
- Rows: AD-LOG-007
- What and why: 1925/1926 are failed inbound links; 2087/2088 mean the source DC's GUID-based DNS name could not be resolved and the DC fell back (2088) or failed (2087). Almost always DNS client order or a missing _msdcs CNAME.
- Severity: medium. Category: AVL
- Data: eventlog log "Directory Service", ids [1925, 1926, 2087, 2088], days 7
- Refs: NIST-800-53:CP-10, NIST-800-53:SC-20
- Fix: fix the DC's DNS client list (DC-DNS-CLIENT-ORDER) and the _msdcs CNAME of the source; check the RPC path.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-2087-dns-lookup-failure

### DC-EVT-NTDS-DATABASE - Directory database errors (NTDS and ESENT)
- All rows depending on this proposal: AD-LOG-008
- Rows: AD-LOG-008
- What and why: NTDS 467/474/1168/1173/2108 and ESENT 467/474/623 in the Application log mean database corruption, I/O failure or version-store exhaustion - the DC is about to stop or already has.
- Severity: critical. Category: HLT
- Data: two rules sharing the id prefix: (a) eventlog log "Directory Service", ids [467, 474, 1168, 1173, 2108, 1084], days 30; (b) eventlog log Application, providers [ESENT], ids [467, 474, 623], days 30.
- Refs: NIST-800-53:SI-7, NIST-800-53:CP-10
- Fix: check the storage path (WINSRV-EVT-STORAGE) and free space; restore from backup or demote and re-promote; for 623 raise the version store in a planned change.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-1173-ntds-general

### DC-EVT-LDAP-UNSIGNED-BINDS - Clients still bind to LDAP without signing
- All rows depending on this proposal: AD-LOG-009
- Rows: AD-LOG-009
- What and why: 2887 is the daily count of unsigned simple and SASL binds; 2889 names each client (with 2889 audit on). These clients break the day LDAP signing is required, so the list is the migration list.
- Severity: medium. Lens: security. Category: AUT
- Data: eventlog log "Directory Service", ids [2886, 2887, 2888, 2889], days 7. Condition count>0 where id in [2887, 2889]; key `{host}|{id}|{recordId}` so each 2889 client is its own finding (client address and account are event data fields).
- Refs: NIST-800-53:SC-8, NIST-800-53:IA-2, MITRE-ATTACK:T1557
- Fix: move each client to LDAPS or signed binds, then require signing in the DC policy (the baseline value LDAPServerIntegrity 2).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server

### DC-EVT-LDAP-CBT - LDAPS clients without a channel binding token
- All rows depending on this proposal: AD-LOG-010
- Rows: AD-LOG-010
- What and why: 3039/3040/3041 audit clients that would fail once channel binding is enforced.
- Severity: low. Lens: security. Category: AUT
- Data: eventlog log "Directory Service", ids [3039, 3040, 3041], days 7
- Refs: NIST-800-53:SC-8, MITRE-ATTACK:T1557
- Fix: fix the clients (TLS inspection in the path is the usual cause), then enforce channel binding (LdapEnforceChannelBinding 2).
- Confidence: verified - https://support.microsoft.com/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a

### DC-EVT-LDAPS-CERT - LDAP over SSL unavailable or certificate rejected
- All rows depending on this proposal: AD-LOG-011
- Rows: AD-LOG-011
- What and why: 1216/1220/1221 mean the DC could not start LDAPS or rejected its own certificate; directory-sync tools and appliances then fail or fall back silently.
- Severity: medium. Category: PKI
- Data: eventlog log "Directory Service", ids [1216, 1220, 1221], days 30
- Refs: NIST-800-53:SC-17, NIST-800-53:SC-8
- Fix: re-enrol the DC certificate (the DC-CERT-* rules say what is wrong with it).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-1220-ldap-over-ssl

### DC-EVT-DFSR-STATE - SYSVOL replication stopped or waiting for a manual resume
- All rows depending on this proposal: AD-LOG-012
- Rows: AD-LOG-012
- What and why: 2213 (dirty shutdown recovery paused), 2104/4012 (replication stopped, or offline longer than MaxOfflineTimeInDays) and 4612/4614 without a following 4604 mean this DC hands out stale policy.
- Severity: high. Category: AVL
- Data: eventlog log "DFS Replication", ids [2212, 2213, 2214, 2104, 4012, 4612, 4614, 4604], days 30. Condition count>0 where id in [2213, 2104, 4012] (4612/4614 vs 4604 pairing needs run-to-run state; report them as info).
- Refs: NIST-800-53:CP-10
- Fix: resume replication (WMI ResumeReplication) or perform a non-authoritative SYSVOL restore; raise MaxOfflineTimeInDays (DC-REG-DFSR-PARAMETERS) if 4012 recurs.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/dfsr-event-2213-auto-recovery

### DC-EVT-DFSR-CONNECTION - DFSR partner connection failures
- All rows depending on this proposal: AD-LOG-013
- Rows: AD-LOG-013
- What and why: 5002/5008/5014 are failed or lost connections to a SYSVOL partner; a burst maps a WAN or VPN outage, a steady stream maps a firewall rule.
- Severity: medium. Category: AVL
- Data: eventlog log "DFS Replication", ids [5002, 5008, 5014, 5004], days 7. Condition count gt 5 (threshold `dc.dfsr-connection-events-max`) where id ne 5004.
- Refs: NIST-800-53:CP-10, NIST-800-53:SC-7
- Fix: check the RPC path (135 plus the DFSR dynamic port) to the partner and correlate with link outages.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/dfs-replication-events

### DC-EVT-DFSR-STAGING - SYSVOL staging quota pressure
- All rows depending on this proposal: AD-LOG-014
- Rows: AD-LOG-014
- What and why: 4202/4204 (staging high-water mark) and 4206/4208 (files too large for staging) slow or block SYSVOL convergence.
- Severity: low. Category: HLT
- Data: eventlog log "DFS Replication", ids [4202, 4204, 4206, 4208], days 30. Condition count>0 where id in [4206, 4208], or count gt 3 where id eq 4202.
- Refs: NIST-800-53:CP-10
- Fix: raise the SYSVOL staging quota (AD-DFSR-SYSVOL-STAGING-SMALL shows the current value).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/dfsr-staging-folder-conflict-and-deleted-folder

### DC-EVT-DNS-AD-INTEGRATION - DNS service cannot load or write its AD-integrated zones
- All rows depending on this proposal: AD-LOG-015
- Rows: AD-LOG-015
- What and why: 4000/4004/4007/4011/4013/4015/4016 mean the DNS service could not read or write the directory; the cause is the DC's own DNS client order or a replication problem, and clients see intermittent resolution failures.
- Severity: medium. Category: AVL
- Data: eventlog log "DNS Server", ids [4000, 4004, 4007, 4011, 4013, 4015, 4016], days 7. Condition count gt 2 (the boot minute can produce a few).
- Refs: NIST-800-53:SC-20, NIST-800-53:CP-10
- Fix: point the DC at a partner DC first and loopback second (DC-DNS-CLIENT-ORDER); fix replication.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/event-id-4013-dns-server-cannot-load-ad-integrated-zones

### DC-EVT-DNS-ERRORS - Other DNS Server service errors
- All rows depending on this proposal: AD-LOG-016
- Rows: AD-LOG-016
- What and why: socket binding failures (408), expired secondary zones (6527), forwarder loops (7062), malformed packets (5504) and zone transfer faults (6004/6525) show up to clients as flaky resolution.
- Severity: medium. Category: AVL
- Data: eventlog log "DNS Server", ids [408, 6527, 7062, 5504, 6004, 6525], days 7; a second rule DC-EVT-DNS-ERRORS-ANY with no ids and count>0 where level le 2.
- Refs: NIST-800-53:SC-20
- Fix: per id; forwarders and listening addresses are DC-DNS-FORWARDERS and DC-DNS-SERVER-HARDENING.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc735711(v=ws.10)

### DC-EVT-NETLOGON-SECURE-CHANNEL - Clients fail to set up a secure channel
- All rows depending on this proposal: AD-LOG-017
- Rows: AD-LOG-017
- What and why: 5719 (no DC reachable at boot), 5722/5723 (client with a wrong or missing machine password) and 5805 name computers whose domain membership is broken; many distinct names mean a subnet or DNS problem rather than one machine.
- Severity: medium. Category: AUT
- Data: eventlog log System, providers [NETLOGON], ids [5719, 5722, 5723, 5805], days 7. Condition count gt 5 (threshold `dc.netlogon-client-failures-max`) where id ne 5719; the computer name is in the event data for the evidence.
- Refs: NIST-800-53:IA-3, NIST-800-53:SI-4
- Fix: repair the secure channel or rejoin the named computers; declare missing subnets (DC-EVT-NETLOGON-NO-CLIENT-SITE).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/netlogon-event-id-5719-or-group-policy-event-1129

### DC-EVT-NETLOGON-NO-CLIENT-SITE - Clients from undeclared subnets
- All rows depending on this proposal: AD-LOG-018
- Rows: AD-LOG-018
- What and why: 5807 means clients authenticated from addresses that belong to no AD site, so they pick a random DC - across the WAN if that is where the lucky DC is. The per-client list is only in netlogon.log (smb-file-read).
- Severity: medium. Category: CFG
- Data: eventlog log System, providers [NETLOGON], ids [5807], days 7
- Refs: NIST-800-53:CM-6, PINGCASTLE:S-DC-SubnetMissing
- Fix: add the missing subnets to Sites and Services.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-5807-netlogon

### DC-EVT-NETLOGON-DNS-REGISTRATION - DC cannot register its locator records
- All rows depending on this proposal: AD-LOG-019
- Rows: AD-LOG-019
- What and why: 5774/5781 mean the DC's SRV or A records are not being registered; the DC slowly disappears from the locator.
- Severity: high. Category: AVL
- Data: eventlog log System, providers [NETLOGON], ids [5774, 5781], days 7. Condition count gt 2.
- Refs: NIST-800-53:SC-20
- Fix: check the zone's dynamic update setting (DC-DNS-ZONE-INSECURE-UPDATE shows the mode) and the DC's DNS client list.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/event-id-5774-netlogon-dns-registration

### DC-EVT-NETLOGON-DC-CHANNEL - Domain controllers fail to authenticate each other
- All rows depending on this proposal: AD-LOG-020
- Rows: AD-LOG-020
- What and why: 3210/5721 between DCs mean clock skew, a KDC problem or replication latency on a machine password change.
- Severity: medium. Category: AUT
- Data: eventlog log System, providers [NETLOGON], ids [3210, 5721], days 7
- Refs: NIST-800-53:IA-3
- Fix: fix time (DC-EVT-TIME, WINSRV-CLOCK-SKEW) and replication; then reset the DC's secure channel.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-id-3210-netlogon

### DC-EVT-NETLOGON-ZEROLOGON - Netlogon secure channel enforcement events
- All rows depending on this proposal: AD-LOG-021
- Rows: AD-LOG-021
- What and why: 5827/5828 are denied vulnerable connections, 5829 are allowed ones during the transition, 5830/5831 are allow-listed devices. Any 5829-5831 means a device still uses the broken protocol and someone has exempted it.
- Severity: high. Lens: security. Category: AUT
- Data: eventlog log System, providers [NETLOGON], ids [5827, 5828, 5829, 5830, 5831], days 30. Condition count>0 where id in [5829, 5830, 5831]; 5827/5828 reported as info by a second rule.
- Refs: NIST-800-53:IA-3, NIST-800-53:SI-2, MITRE-ATTACK:T1210
- Fix: update or replace the device; remove the allow-list entry (DC-REG-NETLOGON-HARDENING-RELAXED reads it).
- Confidence: verified - https://support.microsoft.com/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e

### DC-EVT-NETLOGON-RPC-SEAL - Clients still sign instead of seal, or use RC4, on the secure channel
- All rows depending on this proposal: AD-LOG-022
- Rows: AD-LOG-022
- What and why: 5838-5841 name clients that break once RPC sealing is enforced (KB5021130).
- Severity: medium. Lens: security. Category: AUT
- Data: eventlog log System, providers [NETLOGON], ids [5838, 5839, 5840, 5841], days 30
- Refs: NIST-800-53:SC-8, MS-KB:5021130
- Fix: fix the named clients, then remove any RequireSeal override.
- Confidence: verified - https://support.microsoft.com/topic/kb5021130-how-to-manage-the-netlogon-protocol-changes-related-to-cve-2022-38023-46ea3067-3989-4d40-963c-680fd9e8ee25

### DC-EVT-KDC-KEYS - KDC cannot find a suitable key or sees duplicate SPNs
- All rows depending on this proposal: AD-LOG-023
- Rows: AD-LOG-023
- What and why: 11 is a duplicate SPN (Kerberos to that service fails), 14/16/27 mean an account has no key of the requested type (forces RC4 or fails), 42 means krbtgt lacks AES keys.
- Severity: medium. Lens: both. Category: AUT
- Data: eventlog log System, providers [Microsoft-Windows-Kerberos-Key-Distribution-Center], ids [11, 14, 16, 27, 42], days 7. Severity high for 11 and 42 via a severity map on id.
- Refs: NIST-800-53:SC-13, MS-KB:5021131
- Fix: remove the duplicate SPN (AD-DUPLICATE-IDENTIFIER lists them); reset the account password to generate AES keys.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/windows-security/kdc-event-id-16-27-des-encryption-disabled

### DC-EVT-KDC-CERT - KDC certificate missing or unusable
- All rows depending on this proposal: AD-LOG-024
- Rows: AD-LOG-024
- What and why: KDC 19/20/21/29 and Security-Kerberos 19 mean the DC has no usable KDC Authentication certificate, so smart-card and certificate sign-ins fail on it.
- Severity: medium. Category: PKI
- Data: two rules: eventlog log System, providers [Microsoft-Windows-Kerberos-Key-Distribution-Center], ids [19, 20, 21, 29], days 7; and providers [Microsoft-Windows-Security-Kerberos], ids [19], days 7.
- Refs: NIST-800-53:IA-5(2), NIST-800-53:SC-17
- Fix: enrol from the Kerberos Authentication template (DC-CERT-NO-KDC-EKU and ADCS-CA-DC-TEMPLATE-NO-KDC-EKU say why it is missing).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/windows-security/event-id-29-kdc-certificate

### DC-EVT-KDC-STRONG-MAPPING - Certificate logons without a strong mapping
- All rows depending on this proposal: AD-LOG-025
- Rows: AD-LOG-025
- What and why: KDC 39/40/41 name certificate sign-ins that work only in compatibility mode and fail under full enforcement of KB5014754.
- Severity: medium. Lens: security. Category: PKI
- Data: eventlog log System, providers [Microsoft-Windows-Kerberos-Key-Distribution-Center], ids [39, 40, 41], days 30
- Refs: NIST-800-53:IA-5(2), MS-KB:5014754, MITRE-ATTACK:T1649
- Fix: reissue the certificates with the SID extension (ADCS-TPL-ESC9) or map them strongly (ADCS-ACCOUNT-WEAK-CERT-MAPPING).
- Confidence: verified - https://support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

### DC-EVT-KDC-PAC - Tickets without the new PAC signatures
- All rows depending on this proposal: AD-LOG-026
- Rows: AD-LOG-026
- What and why: KDC 35-38 mean tickets were issued or accepted without the PAC signatures introduced by KB5020805 - an unpatched DC or client in the mix.
- Severity: medium. Lens: security. Category: AUT
- Data: eventlog log System, providers [Microsoft-Windows-Kerberos-Key-Distribution-Center], ids [35, 36, 37, 38], days 30
- Refs: NIST-800-53:SI-2, MS-KB:5020805
- Fix: patch every DC; check KrbtgtFullPacSignature is not downgraded (DC-REG-KERBEROS-ARMORING-OFF reads it).
- Confidence: verified - https://support.microsoft.com/topic/kb5020805-how-to-manage-kerberos-protocol-changes-related-to-cve-2022-37967-997e9acc-67c5-48e4-9ac6-0a9ec0c0d0e2

### DC-EVT-TIME - Time service cannot reach or trust its source
- All rows depending on this proposal: AD-LOG-027
- Rows: AD-LOG-027, AD-AVL-033
- What and why: W32Time 12/17/24/29/36/47/50/131/134/142/144 mean the DC's clock is free-running or looping; Kerberos stops at five minutes of skew. A second rule, DC-TIME-SYNC-STALE, fires when no 35 or 37 (successful source selection) appeared in 7 days.
- Severity: high. Category: AVL
- Data: eventlog log System, providers [Microsoft-Windows-Time-Service], ids [12, 17, 24, 29, 36, 47, 50, 131, 134, 142, 144], days 7; DC-TIME-SYNC-STALE: same provider, ids [35, 37], days 7, Condition count: none.
- Refs: NIST-800-53:AU-8, NIST-800-53:SC-45
- Fix: fix the hierarchy (DC-TIME-SOURCE); make sure the PDC's external source answers.
- Confidence: verified - https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings

### DC-EVT-SCM-CORE-FAILURES - Core DC service failed to start or crashed
- All rows depending on this proposal: AD-LOG-028
- Rows: AD-LOG-028
- What and why: Service Control Manager 7000/7001/7009/7011/7022/7023/7024/7031/7034 whose param1 names NTDS, DNS, Kdc, Netlogon, DFSR, W32Time or ADWS are an outage or a DC that silently stopped serving.
- Severity: high. Category: AVL
- Data: eventlog log System, providers [Service Control Manager], ids [7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034], days 7. Condition count>0 where param1 matches `(?i)^(Active Directory Domain Services|DNS Server|Kerberos Key Distribution Center|Netlogon|DFS Replication|Windows Time|Active Directory Web Services)$` (display names; threshold `dc.core-service-display-pattern`).
- Refs: NIST-800-53:CP-10, NIST-800-53:SI-4
- Fix: read the service's own log and the Application 1000 crash at the same minute; start the service (DC-SVC-CORE-DOWN shows the current state).
- Confidence: likely - SCM ids are documented; which event data field carries the service name (param1) is from field use.

### DC-EVT-SCM-CORE-STOPPED - Core DC service stopped or its start type changed
- All rows depending on this proposal: AD-LOG-029
- Rows: AD-LOG-029
- What and why: 7036 "stopped" and 7040 (start type changed) for the core services tell who stopped or disabled a DC service and when; outside a documented reboot it is a change nobody approved or an attacker's preparation.
- Severity: medium. Lens: security. Category: MON
- Data: eventlog log System, providers [Service Control Manager], ids [7036, 7040], days 7. Condition count>0 where param1 matches the core-service pattern and (id eq 7040 or param2 matches `stopped`).
- Refs: NIST-800-53:CM-3, NIST-800-53:AU-12, MITRE-ATTACK:T1489
- Fix: correlate with restart events (WINSRV-EVT-UNEXPECTED-SHUTDOWN, User32 1074); restore the start type.
- Confidence: likely - same caveat on param field names.

### DC-EVT-LSA-SAM - DC-side authentication failures and attacks on the built-in Administrator
- All rows depending on this proposal: AD-LOG-032
- Rows: AD-LOG-032
- What and why: LsaSrv 40960/40961 are Kerberos failures seen by the DC itself (skew, SPN, trust); SAM 12294 is repeated bad passwords against the RID-500 account, which cannot lock out - a brute force in progress.
- Severity: medium. Lens: security. Category: MON
- Data: eventlog log System, providers [LsaSrv, Microsoft-Windows-Directory-Services-SAM], ids [40960, 40961, 12294], days 7. Condition count>0 where id eq 12294 (severity high), or count gt 10 where id in [40960, 40961].
- Refs: NIST-800-53:AC-7, NIST-800-53:SI-4, MITRE-ATTACK:T1110
- Fix: find the source in Security 4625/4771 (DC-EVT-AUTH-FAILURES); fix skew for 40960.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/windows-security/event-id-12294-sam-account-lockout

### DC-EVT-SECURITY-LOG-FULL - Security log wrapped or auto-archived
- All rows depending on this proposal: AD-LOG-037
- Rows: AD-LOG-037
- What and why: 1104 (log full) and frequent 1105 (auto-backup) mean security events are lost or scattered before anyone reviews them; with DC-SECURITY-LOG-SMALL it tells whether the size, not the volume, is the problem.
- Severity: medium. Lens: security. Category: LOG
- Data: eventlog log Security, providers [Microsoft-Windows-Eventlog], ids [1104, 1105], days 30. Condition count>0 where id eq 1104, or count gt 30 where id eq 1105.
- Refs: NIST-800-53:AU-4, NIST-800-53:AU-5
- Fix: raise the Security log size (DC-SECURITY-LOG-SMALL) or forward events (DC-EVENT-FORWARDING-MISSING).
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104

### DC-EVT-ADWS - Active Directory Web Services errors
- All rows depending on this proposal: AD-LOG-038
- Rows: AD-LOG-038
- What and why: ADWS errors (1202, 1209 and any Error level) break every RSAT, PowerShell and management-tool read against that DC while LDAP still works - the failure nobody notices until an admin's console hangs.
- Severity: medium. Category: AVL
- Data: eventlog log "Active Directory Web Services", days 7, no ids; Condition count>0 where level le 2. Windows Update client errors (20/25/31) are WINSRV-EVT-WINDOWSUPDATE on every server.
- Refs: NIST-800-53:SI-4
- Fix: restart ADWS after fixing the cause (usually a port 9389 listener conflict or a certificate).
- Confidence: likely - the channel name is standard; ids from Microsoft's ADWS troubleshooting pages.

### DC-EVT-COLLECTION-EMPTY - A DC log that returned no events at all
- All rows depending on this proposal: AD-LOG-040, AD-312
- Rows: AD-LOG-040
- What and why: the old collector once returned zero events from every DC and reported them clean. Keeper marks a failed query unknown, but a working query that returns nothing from the System log in three days is implausible and means the reader cannot see the log (rights, channel access, time window).
- Severity: high. Lens: maintenance. Category: MON
- Data: eventlog log System, days 3, no ids, max 5. Condition count: none per host. A second copy for log "Directory Service".
- Refs: NIST-800-53:AU-6, NIST-800-53:CA-7
- Fix: fix the scan account's Event Log Readers membership and the channel ACL; never treat an empty log as clean.
- Confidence: verified - Keeper semantics (RULES.md: a query that fails is unknown; count none is "should exist").

### DC-EVT-NTDS-GC-MISSING - Daily NTDS garbage-collection report missing
- All rows depending on this proposal: AD-HLT-014
- Rows: AD-HLT-014
- What and why: NTDS logs 1646 once a day with the database's free space. No 1646 for two days means garbage collection is not running (or the log is unreadable); a large free percentage in the event data says the database could be compacted.
- Severity: low. Category: HLT
- Data: eventlog log "Directory Service", ids [1646], days 2. Condition count: none per host. If the runner exposes the free/total MB as event data fields, a second rule can flag free greater than 30 %.
- Refs: NIST-800-53:SI-4
- Fix: check the Directory Service log size and the garbage-collection interval; offline defragment only when space is short.
- Confidence: likely - 1646 is documented; which event data fields the runner names is not.

### DC-EVT-NTDS-IO-LATENCY - Database write or flush took abnormally long
- All rows depending on this proposal: ADX-EVT-001
- Rows: ADX-EVT-001
- What and why: NTDS ISAM 508/509/510/533 mean a write to the directory database or its log took seconds or minutes; replication, authentication and LDAP stall while it waits. It is the early warning of a full, throttled or failing volume under the database.
- Severity: high. Category: HLT
- Data: eventlog log "Directory Service", providers [NTDS ISAM], ids [508, 509, 510, 533], days 7
- Refs: NIST-800-53:SI-4, NIST-800-53:CP-2
- Fix: check latency and free space on the NTDS volume (DC-NTDS-ON-SYSTEM-VOLUME, WINSRV-EVT-STORAGE); move the database off a shared system volume.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/esent-events-508-509-510-533

### DC-EVT-RC4-TICKETS - Service tickets still issued with RC4
- Rows: AD-AUT-011 (supplementary; the account-side rules are AD-USER-KERBEROASTABLE-RC4, AD-USER-NO-AES, AD-COMP-NO-AES)
- What and why: Security 4769 with TicketEncryptionType 0x17 names the services and clients still on RC4; the list is the migration order before RC4 is disabled on the DCs.
- Severity: low. Lens: security. Category: AUT
- Data: eventlog log Security, ids [4769], days 1, max 500. Condition count>0 where TicketEncryptionType eq 0x17; key `{host}|{ServiceName}`. The per-host cap makes the result partial on busy DCs - say so in the evidence.
- Refs: NIST-800-53:SC-13, MS-KB:5021131, MITRE-ATTACK:T1558.003
- Fix: set AES on the account named in ServiceName and reset its password.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769

### DC-EVT-NO-DIRECTORY-CHANGE-AUDIT - No directory-change audit events on a DC
- All rows depending on this proposal: AD-MON-003
- Rows: AD-MON-003
- What and why: with Directory Service Changes auditing and the default SACLs in place, every DC logs 5136 regularly. A DC with none in a week has auditing off or SACLs removed - the record of who changed what is gone. SACL contents themselves need ldap-security-descriptor.
- Severity: medium. Lens: security. Category: MON
- Data: eventlog log Security, ids [5136, 5137, 5141], days 7, max 5. Condition count: none per host.
- Refs: NIST-800-53:AU-2, NIST-800-53:AU-12
- Fix: enable the DS Changes subcategory in the DC audit policy and keep the default SACLs.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136

### DC-EVT-AUDIT-TAMPER - Security log cleared or audit policy changed
- All rows depending on this proposal: AD-MON-006
- Rows: AD-MON-006
- What and why: 1102 is someone clearing the Security log; 4719 is a change to the audit policy. Both are what an intruder does before and after.
- Severity: high. Lens: security. Category: MON
- Data: eventlog log Security, ids [1102, 4719], days 30. Condition each: any; key `{host}|{id}|{recordId}`; evidence names SubjectUserName.
- Refs: NIST-800-53:AU-9, MITRE-ATTACK:T1070.001, MITRE-ATTACK:T1562.002
- Fix: tie each event to a change record; otherwise treat as an incident.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102

### DC-EVT-ACCOUNT-MANAGEMENT - Privileged group and account changes
- All rows depending on this proposal: AD-MON-007
- Rows: AD-MON-007
- What and why: 4728/4732/4756 (and the removals 4729/4733/4757) are group membership changes; 4720/4722/4724/4738/4767 are account creation, enable, password reset, change and unlock. On DCs these are the audit trail of every privilege change; the LDAP-side signal is AD-GROUP-PROTECTED-RECENTLY-CHANGED.
- Severity: info (medium when TargetUserName matches a protected-group pattern). Lens: security. Category: MON
- Data: eventlog log Security, ids [4728, 4729, 4732, 4733, 4756, 4757, 4720, 4722, 4724, 4738, 4767, 5136], days 7, max 500. Condition each: any, key `{host}|{id}|{recordId}`; severity map on TargetUserName matching `(?i)^(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Server Operators|Backup Operators|Print Operators|DnsAdmins|Group Policy Creator Owners)$`.
- Refs: NIST-800-53:AC-2(4), NIST-800-53:AU-12, MITRE-ATTACK:T1098
- Fix: match against change records; investigate anything without one.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4728

### DC-EVT-PERSISTENCE - Service, task or DSRM password set on a DC
- All rows depending on this proposal: AD-MON-008
- Rows: AD-MON-008, AD-BCK-004 (supplementary: 4794)
- What and why: 4697 (service installed), 4698 (task created), 7045 (service installed, System log) and 4794 (DSRM password set) on a DC are rare, high-impact changes; each is either a deployment or persistence.
- Severity: high. Lens: security. Category: MON
- Data: two rules: eventlog log Security, ids [4794, 4697, 4698], days 7; eventlog log System, providers [Service Control Manager], ids [7045], days 7. Condition each: any; key `{host}|{id}|{recordId}`.
- Refs: NIST-800-53:AU-6, MITRE-ATTACK:T1543.003, MITRE-ATTACK:T1053.005
- Fix: tie each to a deployment; remove and investigate the rest.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697

### DC-EVT-DCSYNC - Directory replication requested by a non-DC account
- All rows depending on this proposal: AD-MON-009
- Rows: AD-MON-009
- What and why: Security 4662 with the replication control-access GUIDs (1131f6aa-..., 1131f6ad-...) from a subject that is not a DC machine account or the directory-sync service account is a DCSync attempt - a full credential dump of the domain.
- Severity: critical. Lens: security. Category: MON
- Data: eventlog log Security, ids [4662], days 7, max 500. Condition count>0 where Properties matches `1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2` and SubjectUserName notmatch `\$$` and SubjectUserName notmatch threshold `dc.replication-allowed-accounts-pattern` (default `^(MSOL_|AAD_)`). Note: 4662 needs the DS Access audit subcategory and a SACL on the domain head; 4662 is high-volume, so the cap may truncate - partial is reported.
- Refs: NIST-800-53:AU-6, MITRE-ATTACK:T1003.006
- Fix: treat as an incident: disable the subject account, reset krbtgt twice, review Replicating Directory Changes grants (needs ldap-security-descriptor).
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662

### DC-EVT-LOCKOUTS - Account lockouts with the calling computer
- Rows: AD-MON-011 (supplementary to AD-USER-LOCKOUT-WAVE)
- What and why: 4740 on the PDC emulator names the locked account and the caller computer - the one fact needed to stop a spray or fix a stale credential; the LDAP rule counts lockouts but cannot name the caller.
- Severity: medium. Lens: both. Category: MON
- Data: eventlog log Security, ids [4740], days 1, max 500. Condition count gt 10 (threshold `dc.lockouts-per-day-max`); key `{host}|{TargetUserName}|{recordId}`; evidence includes the caller computer field.
- Refs: NIST-800-53:AC-7, MITRE-ATTACK:T1110.003
- Fix: block or fix the caller; reset the credential it uses.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740

### DC-EVT-NTLMV1-LOGON - NTLMv1 or LM authentication accepted
- All rows depending on this proposal: AD-MON-012
- Rows: AD-MON-012
- What and why: a 4624 whose LmPackageName is "NTLM V1" or "LM" is a logon with a hash that cracks or relays in minutes; the source names the device to fix before LmCompatibilityLevel is raised.
- Severity: medium. Lens: security. Category: AUT
- Data: preferred source: eventlog log Microsoft-Windows-NTLM/Operational, ids [8004, 8003], days 7 (needs NTLM auditing, DC-REG-NTLM-AUDIT-OFF); fallback: log Security, ids [4624], days 1, Condition count>0 where LmPackageName in ["NTLM V1", "LM"] (capped, partial on busy DCs).
- Refs: NIST-800-53:IA-2, MITRE-ATTACK:T1557.001, PINGCASTLE:S-OldNtlm
- Fix: fix the source device, then set LmCompatibilityLevel 5 (WINSRV-GPO-LMCOMPAT-LOW).
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624

### DC-EVT-AUTH-FAILURES - Authentication failure volume on a DC
- All rows depending on this proposal: AD-MON-013
- Rows: AD-MON-013
- What and why: 4771/4768 (Kerberos pre-auth failures), 4776 (NTLM) and 4625 above a daily floor are password spraying or a service with a stale credential; grouping by source is a store follow-up, the per-DC count is the alarm.
- Severity: medium. Lens: security. Category: MON
- Data: eventlog log Security, ids [4771, 4768, 4776, 4625], days 1, max 500. Condition count gt 200 (threshold `dc.auth-failures-per-day-max`) where level ne 0 or Status/FailureCode present (4768 success rows have no failure code); capped result reported as partial.
- Refs: NIST-800-53:AC-7, NIST-800-53:SI-4, MITRE-ATTACK:T1110
- Fix: find the top source address in the events; block or fix it.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771

### DC-EVT-BUILTIN-ADMIN-LOGON - Built-in Administrator signed in on a DC
- Rows: AD-IAM-012 (supplementary to AD-PRIV-BUILTIN-ADMIN-IN-USE)
- What and why: 4624/4768 for the RID-500 account on a DC are work that cannot be attributed to a person; the LDAP rule sees the last logon only, the events show how often and from where.
- Severity: medium. Lens: security. Category: IAM
- Data: eventlog log Security, ids [4768, 4624], days 7, max 500. Condition count>0 where TargetUserName matches threshold `dc.builtin-admin-name-pattern` (default `(?i)^Administrator$`) and TargetUserSid matches `-500$`.
- Refs: NIST-800-53:AC-2, CIS-Controls-v8:5.4
- Fix: use personal admin accounts; vault the built-in one.
- Confidence: verified (event fields documented in the 4624/4768 references above).

### DC-SVC-CORE-DOWN - Core domain controller service stopped or not automatic
- All rows depending on this proposal: AD-HLT-010
- Rows: AD-HLT-010, AD-LOG-035 (NtFrs presence)
- What and why: NTDS, Kdc, Netlogon, DNS, DFSR, W32Time, ADWS, IsmServ and the SMB server underpin logon, policy and replication; one stopped or set to Manual is a broken DC. The NtFrs service still present means SYSVOL never finished migrating.
- Severity: critical (NtFrs present: high). Lens: both. Category: AVL
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT Name, State, StartMode, StartName FROM Win32_Service WHERE Name = 'NTDS' OR Name = 'Kdc' OR Name = 'Netlogon' OR Name = 'DNS' OR Name = 'DFSR' OR Name = 'W32Time' OR Name = 'ADWS' OR Name = 'IsmServ' OR Name = 'LanmanServer' OR Name = 'NtFrs'`; fields Name, State, StartMode, StartName; scope per-host; key `{host}|{Name}`
- Condition: Name eq NtFrs (any state) OR State ne Running OR StartMode ne Auto. Empty result = the DC did not answer = unknown.
- Refs: NIST-800-53:CP-10, NIST-800-53:SI-4
- Fix: read the SCM events (DC-EVT-SCM-CORE-FAILURES), start the service and restore Auto; finish the FRS to DFSR migration (AD-SYSVOL-FRS).
- Confidence: verified - service names from https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack and WINSRV-SVC-CORE-DOWN's query shape.

### DC-THIRD-PARTY-SERVICE - Service on a domain controller that is not part of Windows
- All rows depending on this proposal: AD-HLT-012
- Rows: AD-HLT-012
- What and why: everything on a DC runs at tier 0; a service whose binary lives outside the Windows folder is an agent or product whose owner, update path and need must be known. The expected agents (EDR, backup, management client, monitoring) go in a pattern threshold.
- Severity: medium. Lens: security. Category: HYG
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT Name, DisplayName, PathName, State, StartMode, StartName FROM Win32_Service WHERE NOT PathName LIKE '%\\Windows\\%'` (write the WQL in a block scalar; `\` is literal in WQL LIKE); fields Name, PathName, StartName; scope per-host; key `{host}|{Name}`
- Condition: Name notmatch threshold `dc.approved-service-pattern` (default `^(CcmExec|Sense|MsSense|WinDefend|Ec2Config|AmazonSSMAgent|vmtools|VMTools)$`). Empty = no third-party service = pass.
- Refs: NIST-800-53:CM-7, NIST-800-53:CM-8, CIS-Controls-v8:2.5
- Fix: remove what is not approved; record the owner of the rest in the pattern.
- Confidence: verified - Win32_Service.PathName (https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service); WQL escaping to test.

### DC-SOFTWARE-UNAPPROVED - Installed product on a domain controller outside the approved list
- All rows depending on this proposal: AD-HLT-012
- Rows: AD-HLT-012
- What and why: the uninstall registry lists every installed product without the Win32_Product side effects; on a DC the list should be the OS, the agents and nothing else.
- Severity: medium. Lens: security. Category: HYG
- File: domain-controllers.yaml
- Data: protocol registry, hive HKLM, path `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, subkeys: true (and the Wow6432Node twin); fields host, subkey name and, if the runner returns the subkey's values, DisplayName, Publisher, InstallDate; scope per-host; key `{host}|{subkey}`
- Condition: DisplayName (or the subkey name) notmatch threshold `dc.approved-software-pattern`. Empty = unknown (the key always exists).
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:2.1
- Fix: uninstall unapproved products; add the rest to the pattern with an owner.
- Confidence: likely - the key is standard; whether `subkeys: true` returns each subkey's values or only names needs a check in the registry runner (RULES.md says one row per subkey).

### DC-NTDS-ON-SYSTEM-VOLUME - Directory database or logs on the system volume
- All rows depending on this proposal: AD-HLT-002
- Rows: AD-HLT-002
- What and why: when ntds.dit or its logs share the volume with Windows, a full system drive (updates, logs, dumps) stops the directory. The registry names the paths; the free-space rules (WINSRV-DISK-FREE-*) then cover the volume itself.
- Severity: medium. Category: HLT
- File: domain-controllers.yaml
- Data: protocol registry, hive HKLM, path `SYSTEM\CurrentControlSet\Services\NTDS\Parameters`, values ["DSA Database file", "Database log files path", "DSA Working Directory"]; scope per-host; key host
- Condition: "DSA Database file" matches `(?i)^C:\\Windows\\` or "Database log files path" matches `(?i)^C:\\Windows\\` (threshold `dc.ntds-path-pattern`). Absent values = unknown.
- Refs: NIST-800-53:CP-2, NIST-800-53:SC-5
- Fix: relocate the database and logs to a dedicated volume in a planned DSRM window.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/ad-ds-database-relocation (value names). Note: the registry runner's handling of value names with spaces must be confirmed.

### DC-NTDS-DIT-SIZE - Directory database file is large
- All rows depending on this proposal: AD-HLT-002, AD-HLT-005
- Rows: AD-HLT-002, AD-HLT-005
- What and why: a database larger than the memory available to cache it makes every search hit disk. The engine cannot compare two queries (file size vs RAM), so this rule flags a size above a tenant threshold and the evidence lets the admin compare by eye.
- Severity: low. Category: HLT
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Name = 'C:\\Windows\\NTDS\\ntds.dit'` (path threshold `dc.ntds-dit-path`; a relocated database needs the tenant to set it); fields FileSize; scope per-host; key host
- Condition: FileSize gt 8589934592 (threshold `dc.ntds-dit-max-bytes`). Empty result = the file is elsewhere = unknown, not a pass.
- Refs: NIST-800-53:CP-2
- Fix: add memory to the DC or compact the database offline when free space inside it is large (DC-EVT-NTDS-GC-MISSING).
- Confidence: verified - CIM_DataFile (https://learn.microsoft.com/windows/win32/cimwin32prov/cim-datafile); a direct Name lookup avoids a full file-system scan.

### DC-NIC-CONFIG - Domain controller network adapter configured by DHCP or multihomed
- All rows depending on this proposal: AD-HLT-015
- Rows: AD-HLT-015
- What and why: a DC with a DHCP-assigned address, or with more than one IP-enabled adapter, registers wrong or extra records and confuses the locator; IPv6 state should be the same on every DC.
- Severity: medium. Category: CFG
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT Index, Description, IPEnabled, DHCPEnabled, IPAddress, DNSServerSearchOrder, TcpipNetbiosOptions FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE`; fields DHCPEnabled, IPAddress, Description; scope per-host; key `{host}|{Index}`
- Condition: DHCPEnabled eq true, or (second rule, count) count gt 1 per host where Description notmatch threshold `dc.ignored-adapter-pattern` (VPN and virtual adapters).
- Refs: NIST-800-53:CM-6, NIST-800-53:SC-20
- Fix: set a static address; remove or disable extra adapters.
- Confidence: verified - https://learn.microsoft.com/windows/win32/cimwin32prov/win32-networkadapterconfiguration

### DC-DNS-CLIENT-ORDER - Domain controller DNS client list does not start with a partner DC
- All rows depending on this proposal: AD-AVL-038
- Rows: AD-AVL-038
- What and why: a DC that lists itself first can deadlock at boot (DNS not loaded, AD not started); public resolvers break AD resolution outright. The recommended order is another DC first, loopback second, nothing else.
- Severity: medium. Category: CFG
- File: domain-controllers.yaml
- Data: same query as DC-NIC-CONFIG; field DNSServerSearchOrder (array)
- Condition: DNSServerSearchOrder[0] matches `^127\.|^::1$` (self first) OR any element notmatch threshold `dc.dns-server-pattern` (a regex of the DCs' addresses and loopback; dormant - default `.`). Public resolvers are also WINSRV-DNS-PUBLIC. Array index addressing (`[0]`) is an engine gap if unsupported - then judge "contains loopback and size-lt 2".
- Refs: NIST-800-53:SC-20, NIST-800-53:CM-6
- Fix: set the client list by policy or script on each DC.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/best-practices-for-dns-client-settings

### DC-EXTRA-ROLE - Role installed on a domain controller beyond directory services
- All rows depending on this proposal: AD-HLT-016
- Rows: AD-HLT-016, AD-AUT-026 (role half)
- What and why: file, print, web, remote desktop, certificate, deployment or DHCP roles on a DC add exposure and coercion surface (DFS, VSS agent) to the most valuable server.
- Severity: medium. Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT ID, Name, ParentID FROM Win32_ServerFeature`; fields ID, Name; scope per-host; key `{host}|{ID}`
- Condition: ID in [140 (Web Server), 7 (Print), 18 (RDS), 16 (AD CS), 102 (DHCP), 261 (WDS), 100 (File Services root is fine) with sub-ids for DFS Namespaces 100-series, FS-VSS-Agent] - use the Name field instead: Name matches threshold `dc.forbidden-role-pattern` (default `(?i)^(Web Server|Print and Document Services|Remote Desktop Services|Active Directory Certificate Services|DHCP Server|Windows Deployment Services|DFS Namespaces|File Server VSS Agent Service|Windows Server Update Services)`).
- Refs: NIST-800-53:CM-7, CIS-Controls-v8:4.8, PINGCASTLE:A-DC-Coerce
- Fix: move the role to a member server.
- Confidence: verified - https://learn.microsoft.com/windows/win32/wmisdk/win32-serverfeature (ids vary by OS; match on Name).

### DC-COERCION-SURFACE - Services on a domain controller that can be coerced into authenticating
- All rows depending on this proposal: AD-AUT-026
- Rows: AD-AUT-026
- What and why: the WebClient (WebDAV) service and the Print Spooler on a DC let an attacker force the DC to authenticate to a host of their choice (PetitPotam, PrinterBug), which with AD CS web enrollment becomes domain compromise. RPC filter state is not readable without netsh (winrm-powershell).
- Severity: high. Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'WebClient' OR Name = 'Spooler' OR Name = 'EFS'`; scope per-host; key `{host}|{Name}`
- Condition: Name in [WebClient, Spooler] and (State eq Running or StartMode ne Disabled). Spooler alone is WINSRV-SPOOLER-RUNNING; this rule raises severity on DCs and adds WebClient.
- Refs: MITRE-ATTACK:T1187, NIST-800-53:CM-7, MS-KB:5005413
- Fix: disable WebClient and Spooler on DCs; require EPA on certificate web enrollment.
- Confidence: verified - https://msrc.microsoft.com/update-guide/vulnerability/ADV210003 and KB5005413.

### DC-DFSR-SYSVOL-STATE - SYSVOL replicated folder not in the Normal state
- All rows depending on this proposal: AD-AVL-026
- Rows: AD-AVL-026
- What and why: the DFSR replicated-folder state on a DC says whether SYSVOL is replicating (4 = Normal). Anything else means policy on that DC is frozen.
- Severity: high. Category: AVL
- File: domain-controllers.yaml
- Data: protocol cim, namespace root/microsoftdfs, `SELECT ReplicatedFolderName, ReplicationGroupName, State, LastErrorCode, LastErrorMessageId FROM DfsrReplicatedFolderInfo WHERE ReplicationGroupName = 'Domain System Volume'`; fields State, LastErrorCode; scope per-host; key host
- Condition: State ne 4. Empty result = SYSVOL not on DFSR (FRS) = finding via AD-SYSVOL-FRS; here report count: none as unknown-worthy (a DC must have the folder).
- Refs: NIST-800-53:CP-10
- Fix: per state: 2 initial sync, 3 auto recovery, 5 in error - read DC-EVT-DFSR-STATE events and resume.
- Confidence: verified - https://learn.microsoft.com/previous-versions/windows/desktop/dfsr/dfsrreplicatedfolderinfo

### DC-SYSVOL-NOT-SHARED - SYSVOL or NETLOGON share missing on a domain controller
- All rows depending on this proposal: AD-AVL-027
- Rows: AD-AVL-027
- What and why: without the two shares the DC advertises itself but cannot hand out policy or scripts.
- Severity: critical. Category: AVL
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT Name, Path, Type FROM Win32_Share WHERE Name = 'SYSVOL' OR Name = 'NETLOGON'`; scope per-host; key `{host}|{Name}`
- Condition: count lt 2 per host.
- Refs: NIST-800-53:CP-10
- Fix: check DFSR state (DC-DFSR-SYSVOL-STATE) and SysvolReady (DC-SYSVOLREADY-OFF); non-authoritative restore if needed.
- Confidence: verified - https://learn.microsoft.com/windows/win32/cimwin32prov/win32-share

### DC-SYSVOLREADY-OFF - Netlogon has not been told SYSVOL is ready
- All rows depending on this proposal: AD-AVL-027
- Rows: AD-AVL-027
- What and why: SysvolReady 0 means DFSR never signalled completion; Netlogon keeps the shares closed.
- Severity: high. Category: AVL
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, values [SysvolReady]; key host
- Condition: SysvolReady absent or ne 1.
- Refs: NIST-800-53:CP-10
- Fix: fix DFSR, then set SysvolReady 1 and restart Netlogon as Microsoft documents.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/group-policy/sysvol-netlogon-shares-missing

### DC-REG-STRICT-REPL-CONSISTENCY - Strict replication consistency not enabled on a DC
- All rows depending on this proposal: AD-AVL-018
- Rows: AD-AVL-018
- What and why: without it a DC accepts lingering objects from a partner that was offline too long and re-animates deletions domain-wide.
- Severity: medium. Category: AVL
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\NTDS\Parameters`, values ["Strict Replication Consistency", "Dsa Not Writable", "Allow Replication With Divergent and Corrupt Partner"]; key host (one read serves three rules)
- Condition: "Strict Replication Consistency" absent or ne 1.
- Refs: NIST-800-53:SI-7, NIST-800-53:CP-10
- Fix: set the value to 1 on every DC and create the forest operations marker so new DCs inherit it (AD-FOREST-STRICT-CONSISTENCY-MARKER).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/lingering-objects-prevent-ad-replication

### DC-REG-USN-ROLLBACK-MARKER - Domain controller marked not writable after a USN rollback
- All rows depending on this proposal: AD-AVL-021
- Rows: AD-AVL-021
- What and why: "Dsa Not Writable" is set by NTDS when it detects a restored image; the DC refuses replication but still serves logons - a split brain in waiting.
- Severity: critical. Category: AVL
- Data: same read as DC-REG-STRICT-REPL-CONSISTENCY; Condition: "Dsa Not Writable" exists (any value).
- Refs: NIST-800-53:CP-10
- Fix: demote with forced removal, metadata cleanup, re-promote.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/usn-rollback-virtualized-dc-event-2095

### DC-REG-DIVERGENT-PARTNER-ALLOWED - Replication with divergent partners left enabled
- All rows depending on this proposal: AD-AVL-022
- Rows: AD-AVL-022
- What and why: the override used once to recover from 2042 lets a DC accept data from a partner past the tombstone lifetime; left on, it silently reintroduces deleted objects.
- Severity: high. Category: AVL
- Data: same read; Condition: "Allow Replication With Divergent and Corrupt Partner" eq 1.
- Refs: NIST-800-53:SI-7
- Fix: set it back to 0 after the recovery.
- Confidence: verified (same reference as DC-EVT-DS-TOMBSTONE).

### DC-REG-DFSR-PARAMETERS - DFSR SYSVOL recovery parameters not set as recommended
- All rows depending on this proposal: AD-AVL-040
- Rows: AD-AVL-040
- What and why: StopReplicationOnAutoRecovery 1 (the pre-2012 default) pauses SYSVOL after any dirty shutdown until a human resumes it; MaxOfflineTimeInDays below the tombstone lifetime stops a DC that was off for a while from ever catching up.
- Severity: low. Category: AVL
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\DFSR\Parameters`, values [StopReplicationOnAutoRecovery, MaxOfflineTimeInDays]; key host
- Condition: StopReplicationOnAutoRecovery eq 1, or MaxOfflineTimeInDays lt 60 (threshold `dc.dfsr-max-offline-days-min`; absent = default 60, pass).
- Refs: NIST-800-53:CP-10
- Fix: set StopReplicationOnAutoRecovery 0 and MaxOfflineTimeInDays to the tombstone lifetime.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/dfsr-event-2213-auto-recovery

### DC-TIME-SOURCE - Domain controller time configuration not the expected type
- All rows depending on this proposal: AD-AVL-032
- Rows: AD-AVL-032
- What and why: every DC except the PDC emulator should take time from the domain hierarchy (NT5DS); the PDC should use external NTP servers with the 0x8 client flag. A DC configured NTP against a hypervisor, or NT5DS on the PDC, drifts the whole domain. Which DC is the PDC is a store join (AD-TIME-NO-EXTERNAL-SOURCE).
- Severity: high. Category: AVL
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\W32Time\Parameters`, values [Type, NtpServer]; second read path `SYSTEM\CurrentControlSet\Services\W32Time\Config`, values [AnnounceFlags, MaxPosPhaseCorrection, MaxNegPhaseCorrection]; third read of the policy key `SOFTWARE\Policies\Microsoft\W32Time\Parameters` for evidence; key host
- Condition: Type notin [NT5DS, NTP], or (Type eq NTP and NtpServer matches `(?i)time\.windows\.com|^$`), or AnnounceFlags notin [5, 10] (threshold lists).
- Refs: NIST-800-53:AU-8, NIST-800-53:SC-45
- Fix: configure the PDC with external sources and the others with NT5DS, by the two GPOs Microsoft documents (one WMI-filtered to the PDC).
- Confidence: verified - https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings

### AD-TIME-NO-EXTERNAL-SOURCE - No domain controller, or the wrong one, uses an external time source
- All rows depending on this proposal: AD-AVL-032
- Rows: AD-AVL-032
- What and why: joins the DC-TIME-SOURCE registry rows with the PDC emulator (fSMORoleOwner of the domain head) from the AD scan: the PDC must be the one with Type NTP and an external NtpServer; if no DC has one, the domain free-runs.
- Severity: high. Lens: maintenance. Category: AVL
- File: rules\cross-system.yaml (store) or hybrid of the DC pack
- Data: protocol store; SQL over row_seen for system 'domain-controllers' (attrs.Type, attrs.NtpServer per host) joined to the AD row whose attrs.fSMORoleOwner names the PDC's NTDS Settings DN (match on the DC short name inside the DN); scope estate-wide; key instance
- Condition: the PDC row's Type ne NTP, or no row with Type NTP and a non-empty NtpServer not matching `time\.windows\.com`. No DC rows (pack never scanned) = no result, never a pass.
- Refs: NIST-800-53:AU-8
- Fix: as DC-TIME-SOURCE.
- Confidence: likely - fSMORoleOwner is read by AD-FSMO-DELETED-OWNER-DOMAIN; the join on names is string work in SQL.

### DC-TIME-HYPERVISOR-PROVIDER - Hypervisor time provider enabled on a virtual domain controller
- All rows depending on this proposal: AD-AVL-035
- Rows: AD-AVL-035
- What and why: with the Hyper-V time provider enabled the DC follows the host clock after resume, and the PDC's external source loses the argument; Microsoft's guidance for virtual DCs is to disable it on the PDC and keep one authority.
- Severity: low. Category: AVL
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider`, values [Enabled]; key host
- Condition: Enabled eq 1 (threshold toggle `dc.hypervisor-time-allowed`). Absent key = not Hyper-V = pass.
- Refs: NIST-800-53:AU-8
- Fix: set Enabled 0 on the PDC (and consistently elsewhere); VMware tools timesync is a file read (smb-file-read).
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controllers-hyper-v

### DC-RSOP-TIME-POLICY - Effective policy sets the time type on a domain controller
- All rows depending on this proposal: AD-AVL-036
- Rows: AD-AVL-036
- What and why: the winning GPO value for W32Time Type on each DC shows whether a root-enforced time policy overrides the PDC-specific one; the evidence names the GPO (RSOP carries the GPO id), which is the attribution the registry alone lacks.
- Severity: medium. Category: CFG
- File: domain-controllers.yaml
- Data: protocol cim, namespace root/rsop/computer, `SELECT registryKey, valueName, value, precedence, GPOID FROM RSOP_RegistryPolicySetting WHERE precedence = 1 AND (valueName = 'Type' OR valueName = 'NtpServer')`; scope per-host; key `{host}|{registryKey}|{valueName}`
- Condition: registryKey matches `W32Time` and valueName eq Type and value (base64 of the REG_SZ) decodes to NT5DS on the PDC / NTP elsewhere - the engine cannot decode base64 REG_SZ, so judge presence only: a Type value delivered by policy on every DC with precedence 1 from one GPOID means one GPO wins everywhere (evidence); the registry rule DC-TIME-SOURCE judges the result.
- Refs: NIST-800-53:CM-6
- Fix: scope the time GPOs as Microsoft documents (WMI filter for the PDC, no enforced root link).
- Confidence: likely - RSOP_RegistryPolicySetting is used by WINSRV-GPO-FIREWALL-OFF; the base64 limitation is noted in windows-estate.md.

### DC-DNS-ZONE-NOT-INTEGRATED - Primary DNS zone on a domain controller not stored in the directory
- All rows depending on this proposal: AD-CFG-017
- Rows: AD-CFG-017
- What and why: a file-backed primary zone on one DC is a single point of failure and gets no secure dynamic updates; the same zone set should appear on every DC (a store comparison, DC-DNS-ZONE-SET-DIFFERS, is the follow-up).
- Severity: medium. Category: CFG
- File: domain-controllers.yaml
- Data: protocol cim, namespace root/Microsoft/Windows/DNS, `SELECT ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, IsAutoCreated, ReplicationScope, DynamicUpdate, SecureSecondaries, IsSigned, IsShutdown, IsPaused FROM MSFT_DnsServerZone`; fields as listed; scope per-host; key `{host}|{ZoneName}` (one read serves seven DC-DNS-ZONE-* rules)
- Condition: ZoneType eq Primary and IsDsIntegrated eq false and IsAutoCreated eq false. Empty = DNS role absent = pass (DC without DNS is DC-EXTRA-ROLE's inverse; add a count:none rule DC-DNS-NO-ZONES if every DC must run DNS).
- Refs: NIST-800-53:CP-10, NIST-800-53:SC-20
- Fix: convert the zone to AD-integrated.
- Confidence: verified - https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverzone (MSFT_DnsServerZone properties; the CIM class is what the cmdlet wraps).

### DC-DNS-ZONE-INSECURE-UPDATE - Directory-integrated zone accepts non-secure dynamic updates
- All rows depending on this proposal: AD-CFG-018
- Rows: AD-CFG-018
- What and why: with NonsecureAndSecure any host on the network can overwrite any record - a DC's, a file server's - and redirect traffic.
- Severity: high. Lens: security. Category: AUT
- Data: same query; Condition: IsDsIntegrated eq true and DynamicUpdate ne Secure (and IsReverseLookupZone false or any - reverse zones too).
- Refs: NIST-800-53:SC-20, MITRE-ATTACK:T1557, PINGCASTLE:A-DnsZoneUpdate1
- Fix: set dynamic updates to Secure only.
- Confidence: verified (same reference).

### DC-DNS-ZONE-TRANSFER-OPEN - Zone transfers allowed to any server
- All rows depending on this proposal: AD-CFG-026
- Rows: AD-CFG-026
- Data: same query; Condition: SecureSecondaries eq TransferAnyServer. Severity medium, lens security, category AUT.
- Refs: NIST-800-53:SC-7, NIST-800-53:AC-3
- Fix: set transfers to name servers only or none.
- Confidence: verified.

### DC-DNS-CONDITIONAL-FORWARDER-NOT-INTEGRATED - Conditional forwarder defined on one DC only
- All rows depending on this proposal: AD-CFG-025
- Rows: AD-CFG-025
- Data: same query; Condition: ZoneType eq Forwarder and IsDsIntegrated eq false. Severity low, category CFG. Master reachability needs dns-query.
- Refs: NIST-800-53:CM-6
- Fix: recreate the forwarder as directory-integrated so every DC has it.
- Confidence: verified.

### DC-DNS-NO-SIGNED-ZONE - No DNSSEC-signed zone and no recorded decision
- All rows depending on this proposal: ADX-DNS-002, DNS-021
- Rows: ADX-DNS-002
- Data: same query; Condition: count: none per host where IsSigned eq true. Severity low, lens security, category CFG. Accepting the finding with a reason is the recorded decision.
- Refs: NIST-800-53:SC-20, NIST-800-53:SC-21
- Fix: sign the zones that matter, or accept with the reason.
- Confidence: verified.

### DC-DNS-SCAVENGING-STATE - Scavenging configuration on the DNS servers
- All rows depending on this proposal: AD-CFG-020
- Rows: AD-CFG-020
- What and why: scavenging should run on exactly one server with sane intervals; aging must be on for dynamic zones or stale records pile up. The per-server state is readable; "exactly one" is a store count over the DC rows.
- Severity: medium. Category: HYG
- File: domain-controllers.yaml
- Data: protocol cim, namespace root/Microsoft/Windows/DNS, `SELECT ScavengingState, ScavengingInterval, NoRefreshInterval, RefreshInterval, LastScavengeTime FROM MSFT_DnsServerScavenging`; key host. Store follow-up: count of hosts with ScavengingState true ne 1.
- Condition: ScavengingState true and (ScavengingInterval or RefreshInterval outside 1-14 days - durations arrive as text `7.00:00:00`; a regex `^(0|[0-9]{2,})\.` flags 0 or 15+ days). Per-zone aging (MSFT_DnsServerZoneAging) needs a zone parameter and is a guess.
- Refs: NIST-800-53:CM-6
- Fix: enable scavenging on one DC and aging on the dynamic zones.
- Confidence: likely - singleton class per https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverscavenging; duration formatting through the CIM runner is unverified.

### DC-DNS-FORWARDERS - Forwarders missing or inconsistent on a DNS server
- All rows depending on this proposal: AD-CFG-023
- Rows: AD-CFG-023
- What and why: a DC with no forwarders and root hints disabled resolves nothing outside the forest; different forwarder lists per DC give different answers per client. Reachability of the forwarders needs dns-query.
- Severity: medium. Category: CFG
- File: domain-controllers.yaml
- Data: protocol cim, namespace root/Microsoft/Windows/DNS, `SELECT IPAddress, UseRootHint, Timeout, EnableReordering FROM MSFT_DnsServerForwarder`; key host; store follow-up compares IPAddress lists across hosts.
- Condition: IPAddress empty and UseRootHint eq false; or Timeout gt 5; or any IPAddress element matches threshold `dc.forbidden-forwarder-pattern` (dormant).
- Refs: NIST-800-53:SC-20
- Fix: set the same forwarders on every DC, with an on-premises path for sites that must survive a WAN outage.
- Confidence: likely - singleton class (Get-DnsServerForwarder); IPAddress as an array through the runner is expected but unverified.

### DC-DNS-ROOT-HINTS-MISSING - Root hints missing while root hints are in use
- All rows depending on this proposal: AD-CFG-024
- Rows: AD-CFG-024
- Data: protocol cim, root/Microsoft/Windows/DNS, `SELECT NameServer, IPAddress FROM MSFT_DnsServerRootHint`; key `{host}|{NameServer}`; Condition count lt 13 per host (threshold); pair with DC-DNS-FORWARDERS UseRootHint. Severity low, category CFG.
- Refs: NIST-800-53:SC-20
- Fix: restore the root hints or disable their use.
- Confidence: likely.

### DC-DNS-SERVER-HARDENING - DNS server hardening settings below the recommended values
- All rows depending on this proposal: AD-CFG-027
- Rows: AD-CFG-027
- What and why: four singleton reads, one rule each: recursion open to everyone, response rate limiting off, cache locking below 100 % and a small socket pool are the classic DNS amplification and cache-poisoning exposures.
- Severity: low (RRL/cache locking), medium (open recursion on an internet-facing DC). Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol cim, root/Microsoft/Windows/DNS: (1) `SELECT Enable, SecureResponse FROM MSFT_DnsServerRecursion` - rule DC-DNS-RECURSION-OPEN: Enable true and SecureResponse false; (2) `SELECT Mode, ResponsesPerSec, ErrorsPerSec FROM MSFT_DnsServerResponseRateLimiting` - DC-DNS-RRL-OFF: Mode ne Enable; (3) `SELECT LockingPercent, MaxTtl FROM MSFT_DnsServerCache` - DC-DNS-CACHE-LOCKING-LOW: LockingPercent lt 100; (4) `SELECT SocketPoolSize, ListeningIPAddress, AllIPAddress FROM MSFT_DnsServerSetting` - DC-DNS-SOCKET-POOL-SMALL: SocketPoolSize lt 2500; each key host.
- Refs: NIST-800-53:SC-20, NIST-800-53:SC-5, CIS-Controls-v8:4.1
- Fix: enable RRL, set cache locking 100, socket pool 2500 or more, and let recursion serve internal clients only.
- Confidence: likely - properties mirror the DnsServer cmdlets; singleton enumeration via WQL is expected.

### DC-DNS-GQBL-OFF - Global query block list disabled or missing wpad and isatap
- All rows depending on this proposal: AD-CFG-028
- Rows: AD-CFG-028
- Data: protocol cim, root/Microsoft/Windows/DNS, `SELECT Enable, List FROM MSFT_DnsServerGlobalQueryBlockList`; key host; Condition: Enable eq false, or List notcontains wpad, or List notcontains isatap. Severity high, lens security, category AUT.
- Refs: MITRE-ATTACK:T1557, NIST-800-53:SC-20
- Fix: enable the list with wpad and isatap.
- Confidence: likely.

### DC-DNS-QUERY-LOGGING-OFF - No DNS query logging available on a DNS server
- All rows depending on this proposal: ADX-DNS-003, DNS-025
- Rows: ADX-DNS-003
- What and why: without the analytical channel or debug logging there is no record of lookups to reconstruct beacons or exfiltration after an incident.
- Severity: low. Lens: security. Category: LOG
- File: domain-controllers.yaml
- Data: (1) protocol cim, root/Microsoft/Windows/DNS, `SELECT EnableLogFileRollover, LogFilePath, Queries, Answers, UseSystemEventLog FROM MSFT_DnsServerDiagnostics`; key host; (2) protocol registry, HKLM, path `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNSServer/Analytical`, values [Enabled]; key host.
- Condition: Queries eq false and (Enabled absent or eq 0) - two rules, each with its own read; a tenant disables one if the other source is in use.
- Refs: NIST-800-53:AU-2, NIST-800-53:AU-12
- Fix: enable the analytical log with a size cap or forward DNS logs to the SIEM.
- Confidence: likely - channel key paths with `/` must be accepted by the registry runner (unverified).

### DC-DNS-CACHE-PUBLIC-NAMES - Domain controller resolves many public names for itself
- All rows depending on this proposal: ADX-DCB-008
- Rows: ADX-DCB-008
- What and why: the DC's own resolver cache lists the names its processes looked up; dozens of public names beyond update and CRL endpoints mean browsing or an agent calling home from tier 0.
- Severity: high. Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol cim, namespace root/StandardCimv2, `SELECT Entry, Name, Type, Status FROM MSFT_DNSClientCache`; key `{host}|{Entry}`; scope per-host
- Condition: count gt 25 (threshold `dc.public-cached-names-max`) where Entry notmatch threshold `dc.internal-dns-suffix-pattern` (dormant until set; default matches nothing, so the rule stays silent) and Entry notmatch `(?i)(windowsupdate|microsoft\.com|digicert|msocsp|verisign|akamai)` (threshold `dc.allowed-public-names-pattern`).
- Refs: NIST-800-53:SC-7, NIST-800-53:CM-7
- Fix: block DC egress at the firewall except documented update and CRL endpoints.
- Confidence: verified - https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientcache (MSFT_DNSClientCache in root/StandardCimv2).

### DC-TCP-LISTENER-UNEXPECTED - Listening TCP port on a domain controller outside the directory service set
- All rows depending on this proposal: ADX-DCB-009
- Rows: ADX-DCB-009
- What and why: every extra listener on a DC (a web console, an agent, a forgotten service) is tier-0 attack surface.
- Severity: medium. Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol cim, namespace root/StandardCimv2, `SELECT LocalAddress, LocalPort, OwningProcess, State FROM MSFT_NetTCPConnection WHERE State = 2`; key `{host}|{LocalAddress}|{LocalPort}`
- Condition: LocalAddress notin ["127.0.0.1", "::1"] and LocalPort lt 49152 and LocalPort notin [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 5986, 9389] (threshold `dc.expected-tcp-ports`).
- Refs: NIST-800-53:CM-7, CIS-Controls-v8:4.8
- Fix: identify the owning process; remove or approve it.
- Confidence: verified - https://learn.microsoft.com/powershell/module/nettcpip/get-nettcpconnection (State 2 = Listen).

### DC-SECURITY-LOG-SMALL - Security log on a domain controller too small to hold a week
- All rows depending on this proposal: AD-LOG-037, AD-MON-004
- Rows: AD-MON-004, AD-LOG-037
- What and why: DCs generate the bulk of security events; a Security log under 1 GB wraps in hours and the weekly review misses them. The CIS baseline floor (196 MB) is lower than what a DC needs.
- Severity: medium. Lens: security. Category: LOG
- File: domain-controllers.yaml
- Data: protocol cim, root/cimv2, `SELECT LogfileName, MaxFileSize, NumberOfRecords, OverwritePolicy FROM Win32_NTEventlogFile WHERE LogfileName = 'Security'`; key host
- Condition: MaxFileSize lt 1073741824 (threshold `dc.security-log-min-bytes`).
- Refs: NIST-800-53:AU-4, CIS-Controls-v8:8.3
- Fix: set the Security log size by policy on the DC OU and forward events.
- Confidence: verified - WINSRV-EVENTLOG-SMALL uses the same class.

### DC-EVENT-FORWARDING-MISSING - No event forwarding subscription on a domain controller
- All rows depending on this proposal: AD-MON-005, PKI-MON-003
- Rows: AD-MON-005
- What and why: Windows Event Forwarding subscriptions appear as subkeys under WINEVT\Subscriptions; none, and no collector agent service (WINSRV-SVC-AGENT-STOPPED pattern), means DC security events live only on the DC.
- Severity: high. Lens: security. Category: LOG
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Subscriptions`, subkeys: true; key `{host}|{subkey}`
- Condition: count: none per host (threshold toggle `dc.wef-required`; a tenant that collects through an agent sets it false and relies on the agent-service rule).
- Refs: NIST-800-53:AU-6, NIST-800-53:AU-9
- Fix: configure WEF to the collector or install the SIEM agent on every DC.
- Confidence: verified - https://learn.microsoft.com/windows/win32/wec/setting-up-a-source-initiated-subscription (subscriptions are stored under that key).

### DC-REG-NTLM-AUDIT-OFF - NTLM auditing not enabled on a domain controller
- All rows depending on this proposal: AD-AUT-003
- Rows: AD-AUT-003
- What and why: before NTLM can be restricted, incoming and domain NTLM traffic must be audited; without the audit values the NTLM Operational log stays empty and the migration list never exists.
- Severity: low. Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`, values [AuditReceivingNTLMTraffic, RestrictReceivingNTLMTraffic, RestrictSendingNTLMTraffic, AuditNTLMInDomain, RestrictNTLMInDomain]; key host
- Condition: AuditReceivingNTLMTraffic absent or ne 2, or AuditNTLMInDomain absent or eq 0.
- Refs: NIST-800-53:IA-2, NIST-800-53:AU-2, MITRE-ATTACK:T1557.001
- Fix: enable "Audit incoming NTLM traffic: Enable auditing for all accounts" and "Audit NTLM authentication in this domain: Enable all" on the DC OU.
- Confidence: verified - https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain

### DC-REG-NETLOGON-HARDENING-RELAXED - Netlogon secure channel hardening relaxed by registry
- All rows depending on this proposal: AD-AUT-010, ADX-DCB-011
- Rows: AD-AUT-010, ADX-DCB-011
- What and why: FullSecureChannelProtection 0 reopens the CVE-2020-1472 path; RequireSeal 0 or 1 reopens CVE-2022-38023; a populated vulnerable-channel allow list exempts named devices. All three are transition settings that should be gone.
- Severity: high. Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, values [FullSecureChannelProtection, RequireSeal, RejectMd5Clients, VulnerableChannelAllowList]; key host
- Condition: FullSecureChannelProtection eq 0, or RequireSeal in [0, 1], or VulnerableChannelAllowList notempty.
- Refs: NIST-800-53:SI-2, NIST-800-53:IA-3, MITRE-ATTACK:T1210, MS-KB:5021130
- Fix: remove the overrides after fixing the clients that log 5829-5831 / 5838-5841.
- Confidence: verified - the two Microsoft KB articles linked under DC-EVT-NETLOGON-ZEROLOGON and -RPC-SEAL.

### DC-REG-KERBEROS-ARMORING-OFF - Kerberos armoring not enabled on the KDC, or PAC signature downgraded
- All rows depending on this proposal: AD-AUT-019
- Rows: AD-AUT-019
- What and why: with KDC support for claims, compound authentication and armoring off, clients cannot use FAST and authentication policies cannot be enforced; KrbtgtFullPacSignature below 3 keeps the PAC-forgery downgrade open.
- Severity: low (armoring), high (PAC downgrade). Lens: security. Category: AUT
- File: domain-controllers.yaml (and a WS twin for client RequireFast under `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`)
- Data: protocol registry, HKLM, path `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kdc\Parameters`, values [EnableCbacAndArmor, RequestCompoundId]; second read path `SYSTEM\CurrentControlSet\Services\Kdc`, values [KrbtgtFullPacSignature, ApplyDefaultDomainPolicy]; key host
- Condition: EnableCbacAndArmor absent or eq 0; second rule KrbtgtFullPacSignature exists and lt 3.
- Refs: NIST-800-53:IA-2, MS-KB:5020805, PINGCASTLE:S-KerberosArmoringDC
- Fix: enable "KDC support for claims, compound authentication and Kerberos armoring" on the DC OU; remove the KrbtgtFullPacSignature override.
- Confidence: verified - https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview (armoring policy) and KB5020805.

### DC-REG-DSRM-LOGON-BEHAVIOR - DSRM administrator allowed to log on while the directory runs
- Rows: AD-BCK-004 (supplementary to AD-DC-DSRM-NOT-MANAGED)
- What and why: DsrmAdminLogonBehavior 2 lets the DSRM account sign in to a running DC over the network - a local administrator account on a DC that no domain control touches; 1 allows it when the directory is stopped, 0 (default) never.
- Severity: medium. Lens: security. Category: IAM
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Control\Lsa`, values [DsrmAdminLogonBehavior]; key host
- Condition: DsrmAdminLogonBehavior eq 2 (1 reported low).
- Refs: NIST-800-53:AC-6, MITRE-ATTACK:T1078.003
- Fix: set it to 0 unless a documented recovery procedure needs 1.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-the-dsrm-password

### DC-REG-DNS-PLUGIN-DLL - DNS server loads a plug-in DLL
- All rows depending on this proposal: ADX-DNS-001, DNS-020
- Rows: ADX-DNS-001
- What and why: ServerLevelPluginDll makes dns.exe load an arbitrary DLL as SYSTEM at start; DnsAdmins members can set it remotely, so any value is code execution on a DC.
- Severity: high. Lens: security. Category: AUT
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\DNS\Parameters`, values [ServerLevelPluginDll]; key host
- Condition: ServerLevelPluginDll exists.
- Refs: MITRE-ATTACK:T1574.002, NIST-800-53:CM-7
- Fix: treat as an incident; remove the value in a planned change, restart DNS, empty DnsAdmins (AD-GROUP-DNSADMINS-SIZE).
- Confidence: verified - https://learn.microsoft.com/windows-server/networking/dns/dns-top (the value is documented in the DNS registry reference).

### DC-REG-DNS-AVOID-REGISTER - Domain controller excludes generic locator records
- All rows depending on this proposal: AD-CFG-033
- Rows: AD-CFG-033
- What and why: DnsAvoidRegisterRecords lists the SRV records a DC does not register; used on remote or cloud DCs so clients do not pick them at random. An info rule so the decision is visible, not forgotten.
- Severity: info. Category: CFG
- File: domain-controllers.yaml
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, values [DnsAvoidRegisterRecords] and the policy twin `SOFTWARE\Policies\Microsoft\Netlogon\Parameters`; key host
- Condition: DnsAvoidRegisterRecords notempty (each: any, info).
- Refs: NIST-800-53:CM-6
- Fix: none; confirm the exclusion matches the site design.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/networking/optimize-dc-location-global-catalog

### AD-FOREST-STRICT-CONSISTENCY-MARKER - Forest operations marker for strict replication consistency missing
- All rows depending on this proposal: AD-AVL-018
- Rows: AD-AVL-018
- What and why: the operations GUID object under CN=ForestUpdates makes every newly promoted DC start with strict consistency on; without it each new DC must be set by hand.
- Severity: low. Category: AVL
- File: active-directory.yaml
- Data: protocol ldap, base `CN=Operations,CN=ForestUpdates,{CONFIGDN}`, scope onelevel, filter `(cn=94fdebc6-8eeb-4640-80de-ec52b9ca17fa)`, attributes [cn, whenCreated]; key cn
- Condition: count: none.
- Refs: NIST-800-53:SI-7
- Fix: create the marker as Microsoft documents (repadmin /regkey +strict, or create the container object).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/lingering-objects-prevent-ad-replication (the GUID is named there).

### AD-SITELINK-BRIDGING-OFF - Site link bridging disabled without bridge objects
- All rows depending on this proposal: AD-AVL-012
- Rows: AD-AVL-012
- What and why: with "bridge all site links" off and no siteLinkBridge objects, sites that are not directly linked cannot replicate; a leftover from an old hub-and-spoke design.
- Severity: medium. Category: AVL
- File: active-directory.yaml
- Data: protocol ldap, base `CN=IP,CN=Inter-Site Transports,CN=Sites,{CONFIGDN}`, scope base, filter `(objectClass=interSiteTransport)`, attributes [cn, options]; key cn; second query for bridge objects: base same, scope onelevel, filter `(objectClass=siteLinkBridge)`, attributes [cn, siteLinkList]
- Condition: options has flag 2 (bridging disabled); the bridge-object count is evidence only (two queries cannot be joined in one rule).
- Refs: NIST-800-53:CP-10
- Fix: re-enable bridging or create bridges that cover every link.
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/a-options (interSiteTransport options bit 0x2 = NTDSTRANSPORT_OPT_BRIDGES_REQUIRED).

### AD-SITE-ISTG-DELETED - Site's inter-site topology generator is a deleted domain controller
- All rows depending on this proposal: AD-AVL-012
- Rows: AD-AVL-012
- What and why: interSiteTopologyGenerator on NTDS Site Settings names the DC that builds the site's inter-site connections; a deleted DC there means no new inter-site connections until the KCC fails over (which can take hours or never on an old setting).
- Severity: medium. Category: AVL
- File: active-directory.yaml
- Data: protocol ldap, base `CN=Sites,{CONFIGDN}`, scope subtree, filter `(objectClass=nTDSSiteSettings)`, attributes [cn, interSiteTopologyGenerator, options, whenChanged]; key distinguishedName
- Condition: interSiteTopologyGenerator matches `(\\0A|\n)DEL:`.
- Refs: NIST-800-53:CP-10
- Fix: metadata cleanup of the dead DC; the ISTG moves on the next KCC run.
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/a-intersitetopologygenerator

### AD-SITE-DC-COUNT-LOW - Site with fewer domain controllers than required
- All rows depending on this proposal: AD-AVL-014
- Rows: AD-AVL-014, AD-CFG-015
- What and why: a site with one DC loses local logon when it reboots; a site with none but with subnets serves clients across the WAN. Counting per site is a group-by, so this is a store rule over the server objects collected by AD-SITE-SERVER-ORPHAN.
- Severity: medium (one DC), high (none with subnets). Lens: maintenance. Category: AVL
- File: rules\cross-system.yaml (store)
- Data: protocol store; SQL: sites from row_seen where system 'active-directory' and entity_type 'site' (the AD-SITE-NO-SUBNET query) left-joined to server rows (entity_type matching the AD-SITE-SERVER-ORPHAN rows) on the site DN extracted from the server's distinguishedName (`substr` after `CN=Servers,`); columns site, dc_count, has_subnets; key site
- Condition: dc_count lt 2 (threshold `ad.site-min-dcs`); severity high when dc_count eq 0 and has_subnets. No AD run = no rows.
- Refs: NIST-800-53:CP-2, NIST-800-53:CP-10
- Fix: add a DC, or rely on automatic site coverage from a nearby site and record it.
- Confidence: likely - entity_type names of the site and server rows must be read from the rule file.

### AD-DFSR-SYSVOL-STAGING-SMALL - SYSVOL staging quota below the recommended size
- All rows depending on this proposal: AD-AVL-031
- Rows: AD-AVL-031
- What and why: the DFSR subscription object for SYSVOL holds the staging and conflict quotas; the 4 GB default is too small for large policy sets and shows up as DC-EVT-DFSR-STAGING events.
- Severity: low. Category: HLT
- File: active-directory.yaml
- Data: protocol ldap, base domain, filter `(&(objectClass=msDFSR-Subscription)(cn=SYSVOL Subscription))`, attributes [cn, msDFSR-StagingSizeInMb, msDFSR-ConflictSizeInMb, msDFSR-RootPath, msDFSR-Enabled]; key distinguishedName
- Condition: msDFSR-StagingSizeInMb lt 4096 (threshold `ad.sysvol-staging-min-mb`), or msDFSR-Enabled eq FALSE.
- Refs: NIST-800-53:CP-10
- Fix: raise the staging quota on every DC's subscription object.
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/a-msdfsr-stagingsizeinmb

### AD-DC-SPN-INCOMPLETE - Domain controller account missing a required service principal name
- All rows depending on this proposal: AD-AVL-039
- Rows: AD-AVL-039
- What and why: a DC needs HOST/, ldap/, GC/ and the E3514235-4B06-11D1-AB04-00C04FC2DCD2/<NTDS GUID> replication SPN; a missing one breaks Kerberos to that DC for the matching service while NTLM quietly takes over.
- Severity: medium. Category: AUT
- File: active-directory.yaml
- Data: protocol ldap, filter `(&{COMPUTER}(|{UAC:8192}{UAC:67108864}))`, attributes [sAMAccountName, dNSHostName, servicePrincipalName, msDS-GenerationId, userAccountControl]; key sAMAccountName (one query serves AD-DC-NO-GENERATION-ID)
- Condition: servicePrincipalName notcontains a value matching `^ldap/` or `^GC/` or `^HOST/` or `^E3514235-4B06-11D1-AB04-00C04FC2DCD2/` - four `notmatch` conditions in an `any`.
- Refs: NIST-800-53:IA-3
- Fix: re-register the SPNs (restart Netlogon or set them by hand); check for duplicates (AD-DUPLICATE-IDENTIFIER).
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/spn-registration-dc

### AD-DC-NO-GENERATION-ID - Virtual domain controller without a generation identifier
- All rows depending on this proposal: AD-AVL-039, AD-BCK-008
- Rows: AD-AVL-039, AD-BCK-008
- What and why: msDS-GenerationId is written by a hypervisor that supports VM-Generation ID; its absence on a DC means either a physical DC (fine) or a virtual one without the safeguard against snapshot rollback.
- Severity: info. Category: CFG
- Data: same query as AD-DC-SPN-INCOMPLETE; Condition: msDS-GenerationId absent (each: any, info). The tenant accepts physical DCs.
- Refs: NIST-800-53:CP-9
- Fix: host virtual DCs on a hypervisor with VM-Generation ID; back up with an application-aware tool, never snapshots alone.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controller-architecture

### AD-FOREST-DSH-OTHER - dSHeuristics allows clear-text password operations or non-unique names
- Rows: AD-CFG-001
- What and why: character 13 set to 1 lets passwords be changed over an unencrypted LDAP connection; character 21 set to 1 turns off UPN and SPN uniqueness enforcement. The existing DSH rules cover characters 7, 16, 28 and the AdminSDEx mask.
- Severity: medium. Lens: security. Category: AUT
- File: active-directory.yaml
- Data: same query as AD-FOREST-DSH-ANONYMOUS-LDAP (CN=Directory Service,CN=Windows NT,CN=Services,{CONFIGDN}, attribute dSHeuristics)
- Condition: dSHeuristics matches `^.{12}1` (character 13 = 1) or `^.{20}1` (character 21 = 1).
- Refs: NIST-800-53:IA-5, NIST-800-53:SC-8
- Fix: set the characters back to 0.
- Confidence: verified - https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5

### AD-SCHEMA-COMPUTER-POSS-SUPERIOR - Schema class lets users create computer objects under it
- All rows depending on this proposal: AD-CFG-003
- Rows: AD-CFG-003
- What and why: a class whose possible superiors include computer, beyond the default containers, lets a user who can create that class also create a computer beneath it - a machine-account-quota bypass (CVE-2021-34470 was Exchange's ms-Exch-Storage-Group).
- Severity: low. Lens: security. Category: AUT
- File: active-directory.yaml
- Data: protocol ldap, base schema, scope onelevel, filter `(&(objectClass=classSchema)(|(possSuperiors=computer)(systemPossSuperiors=computer)))`, attributes [lDAPDisplayName, possSuperiors, systemPossSuperiors]; key lDAPDisplayName
- Condition: lDAPDisplayName notin [container, organizationalUnit, domainDNS, computer] (the default superiors are classes that may *contain* computers - invert: the query returns classes that are allowed *to be the parent* of computer; flag those not in the default list).
- Refs: NIST-800-53:AC-6, PINGCASTLE:S-ADRegistrationSchema
- Fix: remove computer from the class's possSuperiors (schema change) or patch the product that added it.
- Confidence: likely - attribute semantics verified (https://learn.microsoft.com/windows/win32/adschema/a-posssuperiors); the exact default list is from PingCastle's rule description.

### AD-SCHEMA-EXTENSIONS-PRESENT - Schema extensions in the forest (inventory)
- All rows depending on this proposal: AD-LCM-008
- Rows: AD-LCM-008
- What and why: Exchange, Configuration Manager, legacy LAPS, Windows LAPS and directory-sync anchors each extend the schema and leave rights behind; an info rule listing the markers keeps the ownership question visible.
- Severity: info. Category: HYG
- File: active-directory.yaml
- Data: protocol ldap, base schema, scope onelevel, filter `(|(cn=ms-Exch-Schema-Version-Pt)(cn=ms-Mcs-AdmPwd)(cn=ms-LAPS-Password)(cn=ms-DS-Consistency-Guid)(cn=ms-SMS-Site-Code))`, attributes [cn, rangeUpper, whenCreated]; key cn
- Condition: each: any (info; evidence shows rangeUpper for the Exchange marker).
- Refs: NIST-800-53:CM-8
- Fix: record an owner per extension; remove orphaned rights groups.
- Confidence: likely - marker names from Microsoft docs; ms-SMS-Site-Code is the Configuration Manager schema marker (guess on the exact cn).

### AD-OU-EMPTY - Organizational unit with no objects
- All rows depending on this proposal: AD-CFG-009
- Rows: AD-CFG-009
- Data: protocol store; SQL counting row_seen entities (users, computers, groups, OUs) whose distinguishedName ends with `,<OU DN>` per OU row (entity_type from the AD-OU-BLOCK-INHERITANCE query), with the OU's whenCreated; key ou_dn
- Condition: child_count eq 0 and whenCreated older than 90 days (threshold `ad.empty-ou-min-age-days`). Severity low, category HYG, lens maintenance.
- Refs: NIST-800-53:CM-8
- Fix: delete the OU or document its purpose.
- Confidence: likely - the OU query must request whenCreated; the AD pack's object inventory must be in row_seen (it is for users and computers; groups and OUs depend on the rules that read them).

### AD-OU-DEPTH - Organizational unit nested deeper than the design allows
- All rows depending on this proposal: AD-CFG-009
- Rows: AD-CFG-009
- Data: protocol ldap, filter `(objectClass=organizationalUnit)`, attributes [ou, whenCreated, gPLink, gPOptions]; key distinguishedName; Condition: distinguishedName matches `^(OU=[^,]+,){6,}` (threshold pattern `ad.ou-max-depth-pattern`). Severity low, category HYG.
- Refs: NIST-800-53:CM-8
- Fix: flatten the OU tree.
- Confidence: verified (DN syntax).

### AD-OU-GPO-CHAIN - Organizational unit receives no policy, or too many
- All rows depending on this proposal: AD-CFG-012, AD-CFG-053
- Rows: AD-CFG-012, AD-CFG-053
- What and why: an OU with users or computers and no GPO in its effective chain runs on defaults; an OU with more than fifteen effective GPOs is slow to process and impossible to reason about. The chain is a walk up the DN honouring gPOptions block and gPLink enforced flags - a store rule with a recursive CTE.
- Severity: low (none), low (many). Category: CFG
- File: rules\cross-system.yaml (store)
- Data: protocol store; SQL over the OU rows (gPLink, gPOptions, distinguishedName) and the domain head row (gPLink): recursive CTE building parent chain per OU, splitting gPLink on `][`, counting links whose option bit 1 is clear, plus enforced links from above a block; joined to child object counts as in AD-OU-EMPTY; key ou_dn
- Condition: effective_gpos eq 0 and child_count gt 0; second rule effective_gpos gt 15 (threshold `ad.ou-max-effective-gpos`).
- Refs: NIST-800-53:CM-6
- Fix: link the baseline GPOs higher, or consolidate.
- Confidence: likely - gPLink format verified (MS-GPOL 2.2.2); SQL string handling to be tested.

### AD-SUBNET-OVERLAP - Subnets assigned to different sites overlap
- All rows depending on this proposal: AD-CFG-016
- Rows: AD-CFG-016
- Data: protocol store; SQL over the subnet rows of AD-SITE-SUBNET-NO-SITE (cn = CIDR, siteObject): IPv4 only, split the address into octets with instr/substr, compute the integer and mask in SQL, self-join on range containment where the sites differ; key `{a}|{b}`. Severity low, category CFG.
- Refs: NIST-800-53:CM-6
- Fix: remove or re-cut the overlapping subnet.
- Confidence: guess - expressible in SQLite but long; worth it only if subnets are many.

### AD-GPO-UNLINKED - GPO linked nowhere
- All rows depending on this proposal: AD-CFG-034
- Rows: AD-CFG-034
- Data: protocol store; SQL: GPO rows (cn, displayName, whenChanged from the AD-GPO-* query) where cn does not appear in any gPLink of OU rows, the domain head row, or site rows; key cn. Condition: whenChanged older than 90 days. Severity low, category HYG.
- Refs: NIST-800-53:CM-8
- Fix: back up and delete, or link it.
- Confidence: likely - requires that OU, domain-head and site queries all request gPLink (the OU and site rules do; the domain-head query carries gPLink).

### AD-GPO-STALE - Linked GPO not changed for more than three years
- All rows depending on this proposal: ADX-GPO-004, GPO-034
- Rows: ADX-GPO-004
- Data: protocol ldap, base `CN=Policies,CN=System,{DOMAINDN}`, onelevel, `(objectClass=groupPolicyContainer)`, attributes [cn, displayName, whenChanged, versionNumber, flags]; key cn (the Q-GPO query); Condition: whenChanged older than 1095 days (threshold `ad.gpo-max-age-days`). "Linked" is left to AD-GPO-UNLINKED; a GPO that is both old and unlinked appears in both. Severity low, category HYG, lens maintenance.
- Refs: NIST-800-53:CM-3
- Fix: review with the owner: keep (touch the comment to record the review), merge or retire.
- Confidence: verified.

### AD-GPO-WMI-FILTER-MISSING - GPO references a WMI filter that does not exist
- All rows depending on this proposal: AD-CFG-044
- Rows: AD-CFG-044
- Data: protocol store; SQL: GPO rows with gPCWQLFilter (the Q-GPO query must add gPCWQLFilter) anti-joined to msWMI-Som rows (new ldap query: base `CN=SOM,CN=WMIPolicy,CN=System,{DOMAINDN}`, onelevel, `(objectClass=msWMI-Som)`, attributes [msWMI-ID, msWMI-Name, msWMI-Parm2]); key cn. Condition: referenced filter id not found. Severity medium, category CFG (a GPO with a missing filter does not apply at all).
- Refs: NIST-800-53:CM-6
- Fix: recreate the filter or clear the reference.
- Confidence: verified - https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/ (gPCWQLFilter format `[<domain>;<guid>;0]`).

### AD-GPO-SOFTWARE-INSTALL-ASSIGNED - Group Policy software installation packages still assigned
- All rows depending on this proposal: AD-CFG-049
- Rows: AD-CFG-049
- Data: protocol ldap, base `CN=Policies,CN=System,{DOMAINDN}`, subtree, filter `(objectClass=packageRegistration)`, attributes [displayName, msiFileList, packageFlags, versionNumberHi, whenChanged]; key distinguishedName; Condition: each: any (info; low when msiFileList points to a UNC - the share may be gone, unverifiable without smb). Severity low, category LCM.
- Refs: NIST-800-53:CM-7
- Fix: move software deployment to the management tool; remove the packages.
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/c-packageregistration

### AD-GPO-NAME-LEGACY-PRODUCT - GPO named after a retired product
- All rows depending on this proposal: KN-gpo-forefront-eol-linked, GPO-032
- Rows: KN-gpo-forefront-eol-linked
- Data: Q-GPO query; Condition: displayName matches threshold `ad.legacy-gpo-name-pattern` (default `(?i)forefront|fcs|symantec|mcafee|windows 7|xp` - tune per tenant). Severity low, category HYG.
- Refs: NIST-800-53:CM-7
- Fix: unlink and delete after a backup.
- Confidence: verified.

### AD-GPO-TEST-LINKED-TO-PROD - Test GPO linked to a production container
- All rows depending on this proposal: KN-gpo-hardening-pc-test-on-prod-ous, GPO-033
- Rows: KN-gpo-hardening-pc-test-on-prod-ous
- Data: protocol store; SQL: GPO rows whose displayName matches threshold `ad.test-gpo-name-pattern` (default `(?i)test|pilot|poc`) joined to OU and domain rows whose gPLink contains the GPO cn and whose DN does not match `ad.test-ou-pattern` (default `(?i)OU=[^,]*(test|pilot)`); key `{gpo}|{ou}`. Severity medium, category CFG.
- Refs: NIST-800-53:CM-3
- Fix: unlink the test policy from production OUs.
- Confidence: likely.

### AD-GPO-ROOT-LINKED-MANY - Many GPOs linked at the domain root
- All rows depending on this proposal: KN-gpo-disable-ps-cmd-root
- Rows: KN-gpo-disable-ps-cmd-root
- Data: Q-DOM query (gPLink on the domain head); Condition: gPLink matches `(\[LDAP://[^\]]+\]){6,}` (threshold pattern for the count, default 5) - every root-linked GPO applies to every object, including DCs and admin workstations; a lockdown GPO at the root is the usual way administrators lock themselves out. Severity low, category CFG; evidence lists the links.
- Refs: NIST-800-53:CM-6
- Fix: move narrow-purpose GPOs to the OUs they are meant for.
- Confidence: verified (gPLink format).

### AD-GROUP-GPCO-MEMBERS - Group Policy Creator Owners has members
- All rows depending on this proposal: AD-IAM-007
- Rows: AD-IAM-007
- Data: protocol ldap, filter `(&{USER}{ENABLED}(memberOf:1.2.840.113556.1.4.1941:=CN=Group Policy Creator Owners,CN=Users,{DOMAINDN}))`, attributes [sAMAccountName, displayName]; key sAMAccountName; Condition: count gt 0 (threshold `ad.gpco-max`). Members can create GPOs that apply wherever they are linked and own them afterwards. Severity low, category IAM.
- Refs: NIST-800-53:AC-6(5)
- Fix: empty the group; delegate GPO creation by OU.
- Confidence: verified (same pattern as AD-GROUP-DNSADMINS-SIZE).

### AD-GROUP-RODC-ALLOWED-NOT-EMPTY - Allowed RODC Password Replication Group has members
- All rows depending on this proposal: AD-IAM-030
- Rows: AD-IAM-030
- Data: protocol ldap, filter `(objectSid=S-1-5-21-*-571)` is not expressible; use `(&(objectClass=group)(cn=Allowed RODC Password Replication Group))`, attributes [cn, member]; key cn; Condition: member notempty. Any member's password may be cached on every RODC. Severity low (medium when RODCs exist - AD-RODC-REVEAL-BROAD covers the per-RODC view), category IAM.
- Refs: NIST-800-53:AC-6, MITRE-ATTACK:T1003
- Fix: empty the group; use per-RODC allowed groups.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/rodc/password-replication-policy

### AD-GROUP-EXCHANGE-PRIVILEGED - Exchange permission groups still populated
- All rows depending on this proposal: AD-IAM-043
- Rows: AD-IAM-043
- Data: protocol ldap, filter `(&(objectClass=group)(|(cn=Exchange Trusted Subsystem)(cn=Exchange Windows Permissions)(cn=Organization Management)(cn=Exchange Servers)))`, attributes [cn, member, whenChanged]; key cn; Condition: member notempty (after Exchange is gone) - a tenant with Exchange on-premises accepts it. The groups' WriteDacl on the domain head needs ldap-security-descriptor. Severity high, lens security, category IAM.
- Refs: NIST-800-53:AC-6(5), MITRE-ATTACK:T1098
- Fix: after decommissioning Exchange, remove the groups' rights and members; with Exchange, apply the split-permissions model.
- Confidence: verified - https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions

### AD-USER-SYNC-ACCOUNT-MULTIPLE - More than one directory-synchronisation service account, or an idle one
- All rows depending on this proposal: AD-IAM-023, AD-129
- Rows: AD-IAM-023
- Data: protocol ldap, filter `(&{USER}(|(sAMAccountName=MSOL_*)(sAMAccountName=AAD_*)(description=*Entra Connect*)(description=*Azure AD Connect*)))`, attributes [sAMAccountName, description, userAccountControl, lastLogonTimestamp, pwdLastSet, whenCreated]; key sAMAccountName; two rules: count gt 1 where userAccountControl noflag 2 (several enabled sync accounts = a retired sync server kept its DCSync rights); each: enabled and lastLogonTimestamp older than 2 days (the sync runs every 30 minutes). Severity high, lens security, category IAM.
- Refs: NIST-800-53:AC-2, NIST-800-53:AC-6, MITRE-ATTACK:T1003.006
- Fix: remove the accounts of decommissioned sync servers (their replication rights with them).
- Confidence: verified - account naming from https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions

### AD-USER-SPN-NO-PSO - Service account without a fine-grained password policy
- All rows depending on this proposal: AD-IAM-035
- Rows: AD-IAM-035
- Data: protocol ldap, filter `(&{USER}{ENABLED}(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))`, attributes [sAMAccountName, msDS-ResultantPSO, pwdLastSet]; key sAMAccountName; Condition: msDS-ResultantPSO absent. The constructed attribute names the PSO that wins for the account (directly or through a group). Severity medium, lens security, category IAM.
- Refs: NIST-800-53:IA-5(1), PINGCASTLE:A-NoServicePolicy
- Fix: create a PSO with a long minimum length for service accounts and apply it through a group (AD-PSO-MIN-LENGTH judges the length).
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/a-msds-resultantpso (constructed attributes are returned when requested by name in a search).

### AD-DOM-LOCKOUT-DURATION-SHORT - Lockout duration or observation window shorter than recommended
- Rows: AD-IAM-034
- Data: the N9 domain-head query (lockoutDuration, lockOutObservationWindow arrive as days through the duration conversion); Condition: lockoutDuration lt 0.0104 (15 minutes in days) and ne "never"-style 0, or lockOutObservationWindow lt 0.0104. Severity low, category IAM.
- Refs: NIST-800-53:AC-7, CIS-Controls-v8:4.1
- Fix: set 15 minutes or more for both.
- Confidence: likely - depends on the engine's duration conversion producing fractional days.

### AD-COMP-PRIMARY-GROUP - Computer with a non-default primary group
- Rows: AD-IAM-032
- Data: protocol ldap, filter `(&{COMPUTER}(!(primaryGroupID=515))(!(primaryGroupID=516))(!(primaryGroupID=521)))`, attributes [sAMAccountName, primaryGroupID]; key sAMAccountName; each: any. Severity low, category IAM.
- Refs: PINGCASTLE:S-PrimaryGroup
- Fix: reset to Domain Computers (515); DCs use 516, RODCs 521.
- Confidence: verified.

### AD-DELEGATION-TARGET-UNRESOLVED - Delegation to a service principal name nobody holds
- All rows depending on this proposal: AD-IAM-019
- Rows: AD-IAM-019
- Data: protocol store; SQL: explode msDS-AllowedToDelegateTo arrays (json_each over the attribute in row_seen of the AD-USER-PROTOCOL-TRANSITION / AD-COMP-* rows) and anti-join against all servicePrincipalName values in row_seen; key `{account}|{spn}`; Condition: no holder. Severity low (hygiene) - the account was given rights to a service that no longer exists, or to a service whose SPN moved. Category IAM.
- Refs: PINGCASTLE:P-UnkownDelegation, NIST-800-53:AC-6
- Fix: remove the stale target.
- Confidence: likely - needs the computer inventory query to request servicePrincipalName (it does) and users (AD-USER-KERBEROASTABLE does).

### AD-DUPLICATE-IDENTIFIER - Service principal name, UPN or mail address used by more than one object
- All rows depending on this proposal: AD-AUT-016, AD-HYG-012
- Rows: AD-AUT-016, AD-HYG-012
- Data: protocol store; SQL: union of (account, value, kind) over servicePrincipalName, userPrincipalName and proxyAddresses/mail from user and computer rows in row_seen of the newest AD run, GROUP BY value HAVING COUNT(DISTINCT account) gt 1; key `{kind}|{value}`. Severity medium (SPN: Kerberos to the service fails; UPN/mail: wrong account signs in or receives mail), category HYG.
- Refs: NIST-800-53:IA-4
- Fix: remove the duplicate from the wrong object.
- Confidence: likely - the user inventory query must add userPrincipalName (it has it), servicePrincipalName (it has it) and mail/proxyAddresses (mail is on the privileged query only - add to the inventory attributes).

### AD-KEYCRED-ON-SENSITIVE-OBJECT - Key credential link on a privileged user, server or domain controller
- All rows depending on this proposal: AD-IAM-052
- Rows: AD-IAM-052
- Data: protocol ldap, two queries: `(&{USER}{ENABLED}(adminCount=1)(msDS-KeyCredentialLink=*))` and `(&{COMPUTER}{ENABLED}(msDS-KeyCredentialLink=*)(|(operatingSystem=*Server*)(userAccountControl:1.2.840.113556.1.4.803:=8192)))`, attributes [sAMAccountName, whenChanged]; key sAMAccountName; each: any. A key credential is a password-less logon credential; on a DC or server object it is the Shadow Credentials persistence technique unless Windows Hello or device trust put it there. Severity high, lens security, category AUT. The key count and dates are inside the DN-binary value (ldap-binary-attribute).
- Refs: MITRE-ATTACK:T1556.005, NIST-800-53:IA-5
- Fix: clear the attribute unless a documented key-trust deployment owns it; find the writer (5136).
- Confidence: verified - presence filter works without reading the value; https://learn.microsoft.com/windows/win32/adschema/a-msds-keycredentiallink

### AD-OBJECT-DESCRIPTION-SECRET - Password-like text in a description, info or comment field
- All rows depending on this proposal: AD-HYG-013
- Rows: AD-HYG-013
- Data: protocol ldap, filter `(&(|(objectClass=user)(objectClass=computer))(|(description=*pass*)(description=*pwd*)(description=*pw:*)(info=*pass*)(comment=*pass*)))`, attributes [sAMAccountName, description, info, comment]; key sAMAccountName; Condition: any of the three matches `(?i)(password|passwd|pwd|pw)\s*[:=]\s*\S` (threshold `ad.secret-text-pattern`). Every authenticated user reads these attributes. Severity medium, lens security, category IAM.
- Refs: NIST-800-53:IA-5(7), MITRE-ATTACK:T1552
- Fix: clear the text and rotate the credential.
- Confidence: verified.

### AD-OBJECT-NAME-NONSTANDARD - Object name outside the naming standard
- All rows depending on this proposal: WINSRV-HYG-006, WINCLIENT-HYG-005, AD-HYG-016
- Rows: AD-HYG-016
- Data: Q-USER / Q-COMP / group queries; Condition: sAMAccountName notmatch threshold `ad.user-name-pattern` / `ad.computer-name-pattern` / `ad.group-name-pattern` (defaults `.` = dormant). Severity info, category HYG.
- Refs: NIST-800-53:CM-8
- Fix: rename or record the exception.
- Confidence: verified.

### AD-PRIV-NAMING-PATTERN - Privileged account that does not follow the administrator naming pattern
- All rows depending on this proposal: ADX-TIER-001, KN-local-admin-group-91-members
- Rows: ADX-TIER-001, KN-local-admin-group-91-members
- Data: protocol ldap, filter `(&{USER}{ENABLED}(|(adminCount=1)(memberOf:1.2.840.113556.1.4.1941:={ADMIN-GROUP-DN})))` - the second branch is per tenant: threshold `ad.local-admin-group-dns` cannot be a filter macro today, so ship the adminCount=1 form and let the tenant copy the rule with its delegated local-admin groups; attributes [sAMAccountName, displayName, objectSid, servicePrincipalName]; key sAMAccountName; Condition: sAMAccountName notmatch threshold `ad.admin-account-pattern` (default `^(adm|su|a)[-_.]`) and objectSid notmatch `-500$` and servicePrincipalName empty. A shared or daily-use account in an admin group cannot be attributed and is exposed to mail and browsing. Severity medium, lens security, category IAM.
- Refs: NIST-800-53:AC-6(2), CIS-Controls-v8:5.4
- Fix: give each administrator a personal admin account; move service accounts out of admin groups.
- Confidence: verified (attributes); the pattern default is a guess the tenant sets.

### AD-PRIV-PAIRED-ACCOUNT-DISABLED - Administrator account whose daily account is disabled or gone
- All rows depending on this proposal: ADX-TIER-001, KN-privileged-account-of-leaver-activity, AD-135
- Rows: ADX-TIER-001, KN-privileged-account-of-leaver-activity
- Data: protocol store; SQL: admin accounts (sAMAccountName matching `ad.admin-account-pattern`) joined to user rows on the name with the prefix removed (threshold `ad.admin-account-prefix-regex`, default `^(adm|su|a)[-_.]`); columns admin, daily, daily_enabled; key admin; Condition: daily missing or (daily_uac & 2) = 2 while the admin account is enabled. The leaver kept an administrator account. Severity high, lens security, category IAM.
- Refs: NIST-800-53:AC-2(3), NIST-800-53:PS-4, CIS-Controls-v8:5.3
- Fix: disable the admin account with the daily one as part of the leaver process.
- Confidence: likely - string pairing in SQL; the prefix convention is per tenant.

### AD-PRIV-NO-AUTHN-SILO - Privileged account outside an authentication policy silo
- All rows depending on this proposal: ADX-FOR-001, AD-107
- Rows: ADX-FOR-001
- Data: protocol ldap, filter `(&{USER}{ENABLED}(adminCount=1)(!(msDS-AssignedAuthNPolicySilo=*))(!(servicePrincipalName=*)))`, attributes [sAMAccountName, displayName]; key sAMAccountName; each: any. Second rule AD-FOREST-NO-AUTHN-POLICY: base `CN=AuthN Policy Configuration,CN=Services,{CONFIGDN}`, subtree, `(objectClass=msDS-AuthNPolicySilo)`, count: none (info - the feature is unused). A silo limits where tier-0 credentials can obtain tickets, which closes the lateral-movement path that Protected Users leaves open. Severity medium (low until a silo exists), lens security, category IAM.
- Refs: NIST-800-53:AC-6, NIST-800-53:AC-3, MITRE-ATTACK:T1550
- Fix: design a tier-0 silo (armoring first), assign the accounts, audit, then enforce.
- Confidence: verified - https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos

### AD-GROUP-NESTING-CYCLE - Circular or excessively deep group nesting
- All rows depending on this proposal: AD-HYG-008
- Rows: AD-HYG-008
- Data: protocol store; SQL recursive CTE over group rows (distinguishedName, member array via json_each) from the newest AD run; detect a path that returns to its start (cycle) and depth gt 5; key group_dn. Requires an AD query that collects every group with member (AD-GROUP-EMPTY reads groups; confirm it requests member). Severity low, category HYG.
- Refs: NIST-800-53:AC-2
- Fix: break the cycle; flatten.
- Confidence: likely.

### AD-USER-TOKEN-BLOAT - User whose effective group count approaches the token limit
- All rows depending on this proposal: AD-HYG-009
- Rows: AD-HYG-009
- Data: protocol store; same recursive CTE walking memberOf upward from each enabled user (memberOf is requested by the inventory query), counting distinct groups plus sIDHistory entries; key account; Condition: effective_groups gt 900 (threshold `ad.token-groups-max`). Severity medium, category HYG (logon and Kerberos failures past ~1015 SIDs).
- Refs: NIST-800-53:AC-6
- Fix: remove stale memberships; raise MaxTokenSize by policy as a stopgap.
- Confidence: likely - memberOf does not include primary group or domain-local groups from other domains; the count is a floor.

### AD-BACKUP-SIGNATURE-OLD - No directory backup recorded for a naming context
- All rows depending on this proposal: AD-BCK-001
- Rows: AD-BCK-001, KN-ad-backup-unproven
- What and why: a system-state backup writes dSASignature on each partition head; its replication metadata carries the time and the DC that was backed up. No write within the window means no AD-aware backup exists, whatever the backup console says.
- Severity: high. Lens: both. Category: BCK
- File: active-directory.yaml (collection) and rules\cross-system.yaml (judgement)
- Data: protocol ldap, base domain (and config), scope base, filter `(objectClass=*)`, attributes [msDS-ReplAttributeMetaData]; key distinguishedName - the attribute is constructed and returns one XML string per attribute. Store rule: `json_extract` the array, pick the element containing `<pszAttributeName>dSASignature</pszAttributeName>`, `substr` the `<ftimeLastOriginatingChange>` value, `julianday` it; columns nc, backed_up_at, by_dc; key nc.
- Condition: backed_up_at older than 1 day (threshold `ad.backup-max-age-days`), or absent. Also judge the config partition (`base: config`).
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2
- Fix: schedule a system-state backup on at least two DCs in different sites; "two DCs" needs history the store does not keep (run-to-run-diff).
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/a-msds-replattributemetadata ; dSASignature semantics in the forest recovery guide.

### AD-GPO-BACKUP-STALE - Group Policy backup missing or older than a week
- Rows: AD-BCK-007
- Data: protocol file, path `gpo-backup\manifest.xml` (the Backup-GPO manifest written into Keeper's imports folder by the backup job), format xml, items `//BackupInst`, key `GPODisplayName`; fields BackupTime; Condition: count: none, or every BackupTime older than 7 days; a store follow-up compares the count with the GPO rows. Severity medium, category BCK.
- Refs: NIST-800-53:CP-9
- Fix: schedule the GPO backup to write into imports\gpo-backup.
- Confidence: likely - manifest.xml element names from the GPMC backup format (BackupInst, GPODisplayName, BackupTime).

### AD-ATTESTATION-OVERDUE - Required attestation missing or older than its period
- All rows depending on this proposal: AD-HYG-015, PKI-BCK-002, PKI-BCK-005, PKI-BCK-007, PKI-HYG-001
- Rows: AD-BCK-006, AD-HYG-015
- What and why: a forest recovery test and an AD design review are not system facts; Keeper's attestation register records that a person did them. The rule turns "no record within 12 months" into a finding instead of a forgotten paragraph.
- Severity: medium. Lens: maintenance. Category: BCK
- File: rules\registers.yaml or cross-system.yaml (store)
- Data: protocol store; SQL over `latest_attestation` (type, attested_at, by) for types in ('forest-recovery-test', 'ad-design-review') (threshold list `ad.required-attestations`); key type
- Condition: no row for the type, or attested_at older than 365 days.
- Refs: NIST-800-53:CP-4, NIST-800-53:PL-2
- Fix: run the test or review, then `keeper attest <type>`.
- Confidence: likely - the attestation register's column names must be read from the store schema.

### ADCS-TRUSTED-CA-OBJECTS - Certification authority objects published in the forest (inventory)
- All rows depending on this proposal: AD-PKI-010, PKI-CFG-018
- Rows: AD-PKI-010
- Data: protocol ldap, base `CN=Public Key Services,CN=Services,{CONFIGDN}`, subtree, filter `(|(objectClass=certificationAuthority)(objectClass=pKIEnrollmentService))`, attributes [cn, objectClass, whenCreated, whenChanged]; key distinguishedName; Condition: cn notmatch threshold `adcs.expected-ca-pattern` (default `.` = dormant; evidence lists the objects under Certification Authorities, AIA, NTAuthCertificates and Enrollment Services). Certificate contents are binary (ldap-binary-attribute). Severity medium, lens security, category PKI.
- Refs: NIST-800-53:SC-17, MITRE-ATTACK:T1649
- Fix: remove CA objects of decommissioned or unknown CAs (and from NTAuth).
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/c-certificationauthority

### ADCS-CA-KEY-PROVIDER - Certification authority key held by a provider whose secret lives on the CA host
- All rows depending on this proposal: ADX-PKI-001, PKI-LCM-005, PKI-PKI-002
- Rows: ADX-PKI-001
- Data: protocol registry on CA hosts (targets: computers whose dNSHostName matches the pKIEnrollmentService dNSHostName rows - a store-derived target list, or a threshold pattern `adcs.ca-host-pattern` until targets can be derived), HKLM, path `SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`, subkeys: true to find the CA name, then path `...\Configuration\<CA>\CSP`, values [Provider, ProviderType, HashAlgorithm]; key host. Condition: Provider matches `(?i)yubi` (threshold `adcs.weak-key-provider-pattern`), or Provider matches `Microsoft Software Key Storage Provider` reported info. Severity low, lens security, category PKI (ESC12).
- Refs: MITRE-ATTACK:T1649, NIST-800-53:SC-12
- Fix: document the HSM authentication design; restrict local administrators of the CA host.
- Confidence: verified - the CSP key is documented in the AD CS registry reference; two-step subkey discovery is an engine gap (the CA name must be a threshold).

### XS-USER-UPN-SUFFIX-UNVERIFIED - On-premises UPN suffix not verified in the cloud directory
- All rows depending on this proposal: AD-CFG-006
- Rows: AD-CFG-006
- Data: protocol store; SQL: distinct UPN suffix of enabled AD users (substr after '@') anti-joined to Entra verified domains (needs an Entra query of `/domains` with isVerified - add to entra.yaml as an info rule so its rows land in row_seen); columns suffix, users; key suffix. Condition: not verified (users signing in with it get a .onmicrosoft.com UPN). Severity medium, category IAM, lens both.
- Refs: NIST-800-53:IA-4
- Fix: verify the domain in Entra or change the users' UPN suffix.
- Confidence: likely - depends on adding the /domains collection to the Entra pack.

### WINSRV-VOLUME-FREE-LOW - Volume (including mount points) below the free-space floor
- All rows depending on this proposal: WINSRV-HLT-002, AD-HLT-003
- Rows: AD-HLT-003
- Data: protocol cim, root/cimv2, `SELECT Name, Label, Capacity, FreeSpace, FileSystem, DriveType FROM Win32_Volume WHERE DriveType = 3`; key `{host}|{Name}`; Condition: Capacity gt 21474836480 and FreeSpace lt 15 % of Capacity - a percentage of two fields is not expressible; use FreeSpace lt 10737418240 (threshold `windows-server.volume-free-bytes-min`) and the percent rule stays with Win32_LogicalDisk. Severity high, category HLT. File windows-server.yaml.
- Refs: NIST-800-53:SC-5
- Fix: free or extend the volume.
- Confidence: verified - https://learn.microsoft.com/windows/win32/wmisdk/win32-volume (Name is the mount path for mount points).

### WINSRV-CPU-HIGH - Processor saturated at scan time
- All rows depending on this proposal: WINSRV-HLT-015, FILESRV-HLT-010, AD-HLT-006
- Rows: AD-HLT-006
- Data: protocol cim, root/cimv2, `SELECT Name, PercentProcessorTime, PercentPrivilegedTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name = '_Total'`; key host; Condition: PercentProcessorTime gt 85 (threshold). One sample per scan; a sustained average needs perf-sampling. Severity low, category HLT. File windows-server.yaml (WS twin optional).
- Refs: NIST-800-53:SI-4
- Fix: find the consumer; right-size.
- Confidence: verified (formatted counter class; same family as WINSRV-COMMIT-HIGH).

### WINSRV-EVT-SCHANNEL - TLS negotiation failures
- All rows depending on this proposal: WINSRV-LOG-021, AD-LOG-034
- Rows: AD-LOG-034
- Data: protocol eventlog, log System, providers [Schannel], ids [36871, 36874, 36887, 36888], days 7; key `{host}|{id}`; count gt 10 (threshold). Severity low, category PKI. File windows-server.yaml.
- Refs: NIST-800-53:SC-8
- Fix: identify the peer; fix its protocol or the certificate.
- Confidence: verified - https://learn.microsoft.com/troubleshoot/windows-server/windows-security/schannel-events

### WINSRV-EVT-APP-ERRORS - Application log errors by source
- All rows depending on this proposal: WINSRV-LOG-009, APP-BASELINE-LOG-001, AD-LOG-036, DC-059
- Rows: AD-LOG-036
- Data: protocol eventlog, log Application, days 7, no ids, max 500; key `{host}|{provider}|{id}`; count gt 0 where level le 2 and provider notmatch threshold `windows-server.app-error-ignore-pattern`. Severity low, category HLT. File windows-server.yaml (WS twin WS-EVT-ERROR-SOURCE-FLOOD).
- Refs: NIST-800-53:AU-6
- Fix: per signature.
- Confidence: verified.

### WINSRV-SCHANNEL-LEGACY-ENABLED - TLS 1.0 or 1.1 still enabled server-side
- All rows depending on this proposal: WINSRV-AUT-024, AD-AUT-021, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\DisabledByDefault, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\DisabledByDefault, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\DisabledByDefault, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\DisabledByDefault, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\DisabledByDefault, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\DisabledByDefault, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\DisabledByDefault
- Rows: AD-AUT-021, KN-tls10-11-enabled
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server`, values [Enabled, DisabledByDefault]; same for `TLS 1.1\Server`; key host. Condition: Enabled absent or ne 0 (on Windows Server 2022 and earlier the absent value means enabled; on 2025 the OS default is off - gate the rule with WINSRV-OS build via a copy per target set, or accept that 2025 hosts show as info). The tls protocol only shows what was negotiated, so a server that offers TLS 1.2 passes DC-CERT-LEGACY-PROTOCOL while still accepting 1.0. Severity medium, lens security, category PKI. File windows-server.yaml (WS twin optional).
- Refs: NIST-800-53:SC-8, NIST-800-53:SC-13, RFC-8996
- Fix: disable TLS 1.0/1.1 by policy after checking Schannel events for old clients.
- Confidence: verified - https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings

### WINSRV-SCHANNEL-WEAK-CIPHER-ENABLED - Weak cipher explicitly enabled
- All rows depending on this proposal: WINSRV-AUT-026, AD-AUT-022, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168\Enabled, HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL\Enabled, HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions
- Rows: AD-AUT-022
- Data: protocol registry, HKLM, paths `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128`, `...\Ciphers\DES 56/56`, `...\Ciphers\Triple DES 168`, `...\Ciphers\NULL`, values [Enabled]; key host (value names with `/` in the key path must be accepted by the runner). Condition: Enabled exists and ne 0 (absent = OS default, which still includes RC4 on older servers - report info). Severity medium, lens security, category PKI.
- Refs: NIST-800-53:SC-13, RFC-7465
- Fix: disable the suites by policy (cipher suite order).
- Confidence: verified (same reference).

### WINSRV-HARDENED-PATHS-MISSING - UNC hardening for SYSVOL and NETLOGON not configured
- All rows depending on this proposal: AD-AUT-022
- Rows: AD-AUT-022
- Data: protocol registry, HKLM, path `SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths` (all values); key host. Condition: key absent, or no value whose name matches `\\\\\*\\SYSVOL` with text containing `RequireMutualAuthentication=1` and `RequireIntegrity=1` - value names contain backslashes, which the baseline importer refuses, and a condition on a field named `\\*\SYSVOL` is an engine gap; interim: `exists` eq false on the key (coarse). Severity high, lens security, category AUT. File windows-server.yaml and workstations.yaml.
- Refs: NIST-800-53:SC-8, MS-KB:3000483, PINGCASTLE:A-HardenedPaths
- Fix: configure Hardened UNC Paths for \\*\SYSVOL and \\*\NETLOGON by policy.
- Confidence: verified - https://support.microsoft.com/kb/3000483; the field-name limitation is an engine gap to record.

### WINSRV-NETCEASE-MISSING - SMB session enumeration not restricted
- All rows depending on this proposal: AD-AUT-024
- Rows: AD-AUT-024
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity`, values [SrvsvcSessionInfo]; key host. Condition: SrvsvcSessionInfo absent (the default descriptor is not stored; a stored value means it was customised - presence is the only readable signal; the binary content cannot be judged). Severity low, lens security, category AUT.
- Refs: MITRE-ATTACK:T1049, NIST-800-53:AC-6, PINGCASTLE:A-NoNetSessionHardening
- Fix: apply the NetCease descriptor by policy preference.
- Confidence: guess - presence-as-hardened is an inference.

### WINSRV-FW-RULE-ANY-INBOUND - Enabled inbound allow rule open to any program and port
- All rows depending on this proposal: WINSRV-AUT-003, SCCM-IAM-024
- Rows: AD-AUT-027
- Data: protocol cim, namespace root/StandardCimv2, `SELECT InstanceID, DisplayName, Enabled, Direction, Action, Profiles FROM MSFT_NetFirewallRule WHERE Enabled = 1 AND Direction = 1 AND Action = 2`; key `{host}|{InstanceID}`; port and program filters live in associated classes (MSFT_NetProtocolPortFilter, MSFT_NetApplicationFilter) that a single WQL cannot join - so flag rules whose DisplayName matches threshold `windows-server.firewall-broad-rule-pattern` (default `(?i)^(allow all|any)`), and count the enabled inbound allow rules per host as info. Severity low, category AUT.
- Refs: NIST-800-53:SC-7
- Fix: remove broad allow rules.
- Confidence: likely - class verified (https://learn.microsoft.com/powershell/module/netsecurity/get-netfirewallrule); the join limitation is real.

### WINSRV-AUTOENROLL-OFF - Certificate auto-enrolment not enabled
- All rows depending on this proposal: PKI-CFG-020
- Rows: AD-PKI-002
- Data: protocol registry, HKLM, path `SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment`, values [AEPolicy]; key host. Condition: AEPolicy absent or flag 1 (disabled) or lacks flags 2 and 4 (renew expired, update pending). A DC without auto-enrolment lets its KDC certificate lapse. Severity medium, category PKI. File windows-server.yaml (DC severity high via the DC pack).
- Refs: NIST-800-53:SC-17
- Fix: enable "Certificate Services Client - Auto-Enrollment" with renew and update by policy.
- Confidence: verified - https://learn.microsoft.com/windows-server/networking/core-network-guide/cncg/server-certs/configure-server-certificate-autoenrollment (AEPolicy 7 = enabled with renew and update).

### WINSRV-LSA-PACKAGES-NONDEFAULT - Non-default security or authentication package registered in LSA
- All rows depending on this proposal: ADX-DCB-004
- Rows: ADX-DCB-004
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Control\Lsa`, values ["Security Packages", "Authentication Packages", "Notification Packages"]; second read `...\Lsa\OSConfig`, values ["Security Packages"]; key host. Condition: any element of the multi-string notmatch threshold `windows-server.lsa-package-pattern` (default `^(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|""|scecli|rassfm|msv1_0\.dll)$`). A custom SSP in LSASS sees every password. Severity high, lens security, category AUT. File windows-server.yaml (the DC pack copies it with critical).
- Refs: MITRE-ATTACK:T1547.005, NIST-800-53:CM-7
- Fix: identify the product; remove unknown packages in a controlled change and investigate.
- Confidence: verified - https://learn.microsoft.com/windows/win32/secauthn/registering-ssps (multi-string handling by the registry runner to confirm).

### WS-DEFENDER-ASR-MISSING - Attack surface reduction rules not configured
- All rows depending on this proposal: WINCLIENT-AUT-027, AD-CFG-050
- Rows: AD-CFG-050
- Data: protocol cim, root/Microsoft/Windows/Defender, `SELECT AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference`; key host; Condition: AttackSurfaceReductionRules_Ids size-lt 10 (threshold `workstations.asr-rules-min`), or absent. The effective state regardless of whether GPO or MDM set it. Severity medium, lens security, category AUT. File workstations.yaml (WINSRV twin optional).
- Refs: NIST-800-53:SI-3, CIS-Controls-v8:10.5, PINGCASTLE:S-DefenderASR, MITRE-ATTACK:T1059
- Fix: deploy the recommended ASR rules in block mode.
- Confidence: verified - https://learn.microsoft.com/powershell/module/defender/get-mppreference

### WS-SCRIPT-ASSOCIATION-NOT-REDIRECTED - Script file types still open with the script host
- All rows depending on this proposal: AD-CFG-052
- Rows: AD-CFG-052
- Data: protocol registry, HKLM, paths `SOFTWARE\Classes\VBSFile\Shell\Open\Command`, `...\JSFile\...`, `...\JSEFile\...`, `...\VBEFile\...`, `...\WSFFile\...`, `...\htafile\...`; values [""] (the default value - whether the runner can name it is a guess); key host. Condition: the default value matches `(?i)wscript|cscript|mshta` (not redirected to notepad). Severity low, lens security, category AUT. File workstations.yaml.
- Refs: MITRE-ATTACK:T1059.005, PINGCASTLE:S-FolderOptions, NIST-800-53:CM-7
- Fix: redirect the associations to notepad by policy or enforce AppLocker script rules.
- Confidence: guess - default-value addressing in the registry runner is unverified.


## AD CS hosts, CA events, templates and the certificate estate

Two new rule files are proposed here. `rules\adcs-hosts.yaml` (system `adcs-hosts`, integration cim; registry
and eventlog rules share its targets): targets are the CA hosts. The CA hosts are the dNSHostName values
of the pKIEnrollmentService objects the adcs pack reads, but a per-host file cannot take its targets from
another system's rows today (engine gap, see the protocols section), so the file ships with
`targets.where: { field: dNSHostName, op: match, value: '.', threshold: adcs.ca-host-pattern }` and the
tenant sets the pattern. The CA's configuration subkey name is also per tenant: every ADCS-HOST-* registry
read below uses `path: SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{CA}` where `{CA}` is the
threshold `adcs.ca-name` (a second engine gap: a registry path cannot carry a threshold today; until it
can, the tenant copies the rules with the name typed in). Rows whose values live directly under
`...\CertSvc\Configuration` (Active, DBDirectory and friends) need no CA name.

Conventions for the ADCS-EVT-* rules: protocol eventlog, log Security on each CA host, provider
Microsoft-Windows-Security-Auditing; scope per-host; key `{host}|{id}|{recordId}`; kind broken unless
stated; the CA audit filter (ADCS-HOST-AUDIT-FILTER) and the "Audit Certification Services" subcategory
must be on, otherwise these logs are empty - ADCS-EVT-NO-AUDIT-EVENTS turns that silence into a finding.
Event ids are documented at https://learn.microsoft.com/windows-server/identity/ad-cs/manage/audit-certification-services
(confidence verified for every ADCS-EVT entry unless noted).

### ADCS-HOST-CERTSVC-DOWN - Certification authority service stopped or not automatic
- All rows depending on this proposal: PKI-HLT-002
- Rows: PKI-HLT-002
- What and why: with CertSvc down nothing enrols or renews; auto-enrolment on every member fails silently until certificates lapse.
- Severity: critical. Lens: both. Category: AVL
- File: adcs-hosts.yaml
- Data: protocol cim, root/cimv2, `SELECT Name, State, StartMode, StartName FROM Win32_Service WHERE Name = 'CertSvc' OR Name = 'W3SVC' OR Name = 'WAS' OR Name = 'OcspSvc'`; key `{host}|{Name}`; scope per-host
- Condition: Name eq CertSvc and (State ne Running or StartMode ne Auto); W3SVC/WAS rows are evidence (needed only when the host serves HTTP CDP/AIA or web enrolment). Empty result = CertSvc not installed on a host the tenant listed = finding (count: none second rule).
- Refs: NIST-800-53:CP-2, NIST-800-53:SC-17
- Fix: start the service; read ADCS-EVT-SERVICE-STOPS for who stopped it.
- Confidence: verified (service names from the AD CS role).

### ADCS-HOST-DB-ON-SYSTEM-VOLUME - CA database or logs on the system volume
- Rows: PKI-HLT-004 (supplementary)
- Data: protocol registry, HKLM, path `SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`, values [DBDirectory, DBLogDirectory, DBSystemDirectory, DBTempDirectory, Active]; key host
- Condition: DBDirectory or DBLogDirectory matches `(?i)^C:\\Windows\\` (threshold `adcs.db-path-pattern`); info on a small CA, medium when the host also carries other roles. Severity low. Category HLT.
- Refs: NIST-800-53:CP-2
- Fix: move the database and logs to a dedicated volume (certutil -dbdir in a planned change).
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-cs/manage/backup-and-restore (registry values).

### ADCS-HOST-DB-LARGE - CA database file large
- All rows depending on this proposal: PKI-HLT-005
- Rows: PKI-HLT-005
- Data: protocol cim, root/cimv2, `SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Drive = 'C:' AND Path = '\\Windows\\System32\\CertLog\\' AND Extension = 'edb'` (Drive and Path are keyed properties; the LIKE form `Name LIKE 'C:\\Windows\\System32\\CertLog\\%.edb'` also works); key `{host}|{Name}`; threshold path `adcs.certlog-path`
- Condition: FileSize gt 10737418240 (threshold `adcs.db-max-bytes`). Trend needs run-to-run-diff. Severity low. Category HLT.
- Refs: NIST-800-53:CP-2
- Fix: remove expired certificates and failed requests from the database (certutil -deleterow in a planned change) and compact it.
- Confidence: verified - https://learn.microsoft.com/windows/win32/cimwin32prov/cim-datafile (Drive, Path, Extension properties).

### ADCS-HOST-DB-LOGS-PILING - CA transaction logs are not being truncated
- All rows depending on this proposal: PKI-HLT-006
- Rows: PKI-HLT-006
- Data: protocol cim, `SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Drive = 'C:' AND Path = '\\Windows\\System32\\CertLog\\' AND Extension = 'log'`; key `{host}|{Name}`
- Condition: count gt 100 per host (threshold `adcs.db-logs-max`) - the logs truncate only after a CA-aware backup. Severity medium. Category BCK.
- Refs: NIST-800-53:CP-9
- Fix: run a CA-aware backup (certutil -backupdb or the backup product's AD CS-aware job).
- Confidence: verified.

### ADCS-EVT-BACKUP-MISSING - No CA database backup recorded
- All rows depending on this proposal: PKI-HLT-006, PKI-BCK-001
- Rows: PKI-HLT-006, PKI-BCK-001
- Data: eventlog log Security, ids [4876, 4877], days 2 (threshold `adcs.backup-max-age-days`), max 5; Condition: count: none per host. 4876 = backup started, 4877 = backup completed (4877 absent with 4876 present = failed backup, a second rule).
- Severity: high. Lens: both. Category: BCK
- Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2
- Fix: schedule a CA-aware backup; confirm the backup product uses the AD CS writer.
- Confidence: verified.

### ADCS-EVT-ISSUANCE-BURST - Unusual issuance volume on the CA
- All rows depending on this proposal: PKI-HLT-007
- Rows: PKI-HLT-007
- Data: eventlog log Security, ids [4887], days 1, max 500; Condition: count gt 200 (threshold `adcs.issuance-per-day-max`) per host; evidence samples the CertificateTemplate and Requester event data fields. A per-template, per-requester breakdown is a store follow-up (GROUP BY over the collected rows).
- Severity: medium. Category: HLT
- Refs: NIST-800-53:SC-17, NIST-800-53:SI-4
- Fix: find the template and requester behind the burst; a template whose renewal period is shorter than its validity re-enrols endlessly.
- Confidence: verified (4887 carries Requester, Attributes, CertificateTemplate).

### ADCS-EVT-REQUESTS-DENIED - Denied certificate requests
- All rows depending on this proposal: PKI-HLT-008
- Rows: PKI-HLT-008
- Data: eventlog log Security, ids [4888], days 7; Condition: count gt 20 (threshold `adcs.denied-per-week-max`) per host, or any 4888 whose CertificateTemplate matches threshold `adcs.privileged-template-pattern`. Severity medium. Category MON.
- Refs: NIST-800-53:SI-4
- Fix: read the denial reason; a privileged template denied from an unexpected requester is reconnaissance.
- Confidence: verified.

### ADCS-HOST-IIS-CERTSRV - Web enrolment and CDP virtual directories on the CA host
- All rows depending on this proposal: PKI-HLT-010
- Rows: PKI-HLT-010
- Data: protocol cim, namespace root/WebAdministration, `SELECT Name, PhysicalPath, ApplicationPool, Path FROM VirtualDirectory` and `SELECT Name, Id, ServerAutoStart FROM Site`; key `{host}|{Path}`; the IIS WMI provider must be installed on the host (a feature, not default).
- Condition: a VirtualDirectory whose Path matches `(?i)/CertSrv` exists (info - web enrolment present; its HTTPS and EPA settings need smb-file-read) and the CertEnroll directory's PhysicalPath does not match threshold `adcs.certenroll-path` (CRLs published somewhere else than IIS serves). Severity medium. Category CFG.
- Refs: NIST-800-53:SC-17
- Fix: align the CDP publication path with the IIS virtual directory; remove web enrolment if unused.
- Confidence: likely - https://learn.microsoft.com/previous-versions/iis/wmi-provider/ (VirtualDirectory class); provider availability is per host.

### ADCS-HOST-CA-KEY-INDEXES - CA certificate renewals and key indexes (inventory)
- All rows depending on this proposal: PKI-LCM-002
- Rows: PKI-LCM-002
- Data: protocol registry, HKLM, path `...\Configuration\{CA}`, values [CACertHash, CAType, CommonName, CAServerName, DSConfigDN]; key host
- Condition: CACertHash size-gt 1 (info: the CA was renewed; every earlier key index still needs a current CRL). Severity info. Category PKI.
- Refs: NIST-800-53:SC-17
- Fix: none; confirm old-index CRLs are published (other:crl-fetch).
- Confidence: verified - CACertHash is a multi-string of thumbprints (AD CS registry reference).

### ADCS-TPL-SUPERSEDED-PUBLISHED - Superseded template still published
- All rows depending on this proposal: PKI-LCM-007
- Rows: PKI-LCM-007
- Data: protocol store; SQL: template rows (cn, msPKI-Supersede-Templates - add to the Q-TPL attributes) exploded with json_each, joined to enrollment-service rows whose certificateTemplates contains the superseded name; key `{ca}|{template}`
- Condition: any match. Severity low. Category HYG. Lens maintenance.
- Refs: NIST-800-53:CM-7
- Fix: unpublish the superseded template once its certificates are renewed.
- Confidence: verified - https://learn.microsoft.com/windows/win32/adschema/a-mspki-supersede-templates

### ADCS-EVT-CA-ERRORS - Certification authority errors in the Application log
- All rows depending on this proposal: PKI-LOG-001
- Rows: PKI-LOG-001
- Data: eventlog log Application, providers [Microsoft-Windows-CertificationAuthority], days 7, max 200; Condition: count>0 where level le 3; key `{host}|{id}`. Severity high. Category LOG.
- Refs: NIST-800-53:AU-6
- Fix: per id (CRL publication, database, policy module); the message names the failing URL or file.
- Confidence: verified (provider name).

### ADCS-EVT-CRL-PUBLISH - CRL not published within its period
- All rows depending on this proposal: PKI-LOG-002
- Rows: PKI-LOG-002
- Data: eventlog log Security, ids [4872], days 7 (threshold `adcs.crl-publish-max-days`, set to the base CRL period), max 10; Condition: count: none per host. A second rule over Application CertificationAuthority ids [66, 70, 74] (CRL publication failures) count>0.
- Severity: high. Category: PKI
- Refs: NIST-800-53:SC-17, RFC-5280
- Fix: publish the CRL by hand, then fix the publication URL or the DFS/IIS path.
- Confidence: verified for 4872; the Application ids are likely (from the AD CS event reference).

### ADCS-EVT-SERVICE-STOPS - Certification authority service stopped or started
- All rows depending on this proposal: PKI-LOG-003
- Rows: PKI-LOG-003
- Data: eventlog log Security, ids [4880, 4881, 4875], days 30 (4880 started, 4881 stopped, 4875 shut down); plus log System, providers [Service Control Manager], ids [7031, 7034, 7036], days 30, where param1 matches `(?i)Active Directory Certificate Services`; key `{host}|{id}|{recordId}`; each: any (info; 7031/7034 medium).
- Severity: medium. Category: AVL
- Refs: NIST-800-53:AU-6, NIST-800-53:CM-3
- Fix: match stops to patch windows; a crash (7031/7034) needs the Application error at the same minute.
- Confidence: verified.

### WINSRV-EVT-CERT-ENROLL - Certificate auto-enrolment failures on a server
- All rows depending on this proposal: WINSRV-LOG-022, PKI-LOG-004
- Rows: PKI-LOG-004 (WS twin WS-EVT-CERT-ENROLL for PKI-LOG-005)
- Data: eventlog log Application, providers [Microsoft-Windows-CertificateServicesClient-AutoEnrollment, Microsoft-Windows-CertificateServicesClient-CertEnroll], ids [6, 13, 82, 86], days 7; key `{host}|{provider}|{id}`; count>0. File windows-server.yaml; twin in workstations.yaml with the same spec.
- Severity: medium (low on workstations). Category: PKI
- Refs: NIST-800-53:SC-17
- Fix: 13 = CA unreachable or enrol permission missing, 82/86 = template or request error; fix the template permissions or the CA path.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-cs/manage/troubleshoot-certificate-autoenrollment

### WINSRV-SECURITY-LOG-SMALL - Security log too small for the audit window
- All rows depending on this proposal: PKI-LOG-007
- Rows: PKI-LOG-007 (and WINSRV-LOG-029 in the server fragment)
- Data: protocol cim, root/cimv2, `SELECT LogfileName, MaxFileSize, NumberOfRecords, OverwritePolicy FROM Win32_NTEventlogFile WHERE LogfileName = 'Security'`; key host; Condition: MaxFileSize lt 201326592 (192 MB, the CIS floor; threshold `windows-server.security-log-min-bytes`, raised to 1 GB for CA hosts and DCs via the DC pack's copy). Severity medium. Category LOG. File windows-server.yaml.
- Refs: NIST-800-53:AU-4, CIS-Controls-v8:8.3
- Fix: set the size by policy.
- Confidence: verified.

### ADCS-CA-SINGLE - A single issuing CA
- All rows depending on this proposal: PKI-AVL-001
- Rows: PKI-AVL-001
- Data: Q-CA (adcs.yaml); Condition: count lt 2 (threshold `adcs.min-issuing-cas`). One CA means every enrolment and CRL depends on one host; the finding is accepted with a reason when a tested restore exists. Severity low. Lens maintenance. Category AVL.
- Refs: NIST-800-53:CP-2
- Fix: add a second issuing CA, or record the restore test.
- Confidence: verified.

### ADCS-CDP-CONTAINER-STALE-HOST - CDP container named after a host that no longer exists
- All rows depending on this proposal: PKI-AVL-003, PKI-HYG-008
- Rows: PKI-AVL-003, PKI-HYG-008, PKI-CFG-002 (part)
- Data: protocol ldap, base `CN=CDP,CN=Public Key Services,CN=Services,{CONFIGDN}`, scope onelevel, filter `(objectClass=container)`, attributes [cn, whenCreated, whenChanged]; key cn - the container cn is the CA host's short name; store rule: anti-join cn against enabled AD computer short names (B2 in cross-system.md)
- Condition: no enabled computer with that name. Certificates still carry the old name in their CDP/AIA extensions if the CA was renamed without re-issuing - an outage waiting for the old DNS alias to go. Severity medium. Category PKI.
- Refs: NIST-800-53:SC-17, NIST-800-53:CM-8
- Fix: keep a DNS alias for the old name while certificates reference it; clean the container when they have all expired.
- Confidence: verified - the CDP container structure is documented in the AD CS migration guide.

### ADCS-CA-ON-DOMAIN-CONTROLLER - Enterprise CA hosted on a domain controller
- All rows depending on this proposal: PKI-CFG-001
- Rows: PKI-CFG-001
- Data: protocol store; SQL: enrollment-service rows (dNSHostName from Q-CA) joined to AD computer rows with userAccountControl flag 8192 on the short name; key ca
- Condition: any match. A CA on a DC puts the CA key under every DC administrator and the DC under every CA administrator; a compromise of either is the other. Severity high. Lens security. Category CFG.
- Refs: NIST-800-53:SC-12, NIST-800-53:CM-7, MITRE-ATTACK:T1649
- Fix: migrate the CA to a dedicated tier-0 server (AD CS migration guide).
- Confidence: verified.

### ADCS-HOST-CA-TYPE - CA type and hierarchy position (inventory)
- All rows depending on this proposal: PKI-CFG-001
- Rows: PKI-CFG-001
- Data: registry `...\Configuration\{CA}`, values [CAType]; key host; Condition: CAType eq 0 or 2 (enterprise or standalone root) reported info - a root that is also the issuing CA is a one-tier hierarchy. Severity info. Category CFG.
- Refs: NIST-800-53:SC-17
- Fix: plan a two-tier hierarchy with an offline root.
- Confidence: verified (CAType values: 0 enterprise root, 1 enterprise subordinate, 3 standalone root, 4 standalone subordinate).

### ADCS-CA-NAME-INCONSISTENT - CA name differs between the host and the directory
- All rows depending on this proposal: PKI-CFG-002
- Rows: PKI-CFG-002
- Data: protocol store; SQL: registry rows (CommonName, CAServerName from ADCS-HOST-CA-KEY-INDEXES) joined to enrollment-service rows on the host; key host
- Condition: CommonName (sanitised) ne the enrollment-service cn, or CAServerName ne the host. Severity low. Category HYG.
- Refs: NIST-800-53:CM-8
- Fix: finish the post-migration cleanup.
- Confidence: likely (name sanitisation rules are documented but fiddly).

### ADCS-HOST-VALIDITY-PERIOD - CA issues certificates for longer than allowed
- All rows depending on this proposal: PKI-CFG-003
- Rows: PKI-CFG-003, PKI-LCM-001 (part)
- Data: registry `...\Configuration\{CA}`, values [ValidityPeriod, ValidityPeriodUnits]; key host; Condition: ValidityPeriod eq Years and ValidityPeriodUnits gt 2 (threshold `adcs.max-validity-years`). Severity medium. Lens security. Category PKI.
- Refs: NIST-800-53:SC-17, NIST-SP-800-57-1
- Fix: lower the maximum (certutil -setreg ca\ValidityPeriodUnits) in a planned change.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-cs/manage/ (ValidityPeriod registry).

### ADCS-TPL-PUBLISHED-UNUSED - Published template with no issuance in the window
- All rows depending on this proposal: PKI-CFG-005
- Rows: PKI-CFG-005
- Data: protocol store; SQL: published template names (json_each over certificateTemplates of the Q-CA rows) anti-joined to the CertificateTemplate field of the 4887 rows collected by ADCS-EVT-ISSUANCE-BURST (90-day window - set that rule's days to 90 or add a 90-day collection rule); key template
- Condition: no issuance. A published template nobody uses is attack surface with no owner. Severity low. Category HYG.
- Refs: NIST-800-53:CM-7
- Fix: unpublish, or record the owner and the consumer.
- Confidence: likely (the 4887 template field is the template's OID or name depending on version).

### WINSRV-ROLE-SENSITIVE - Sensitive server role installed
- All rows depending on this proposal: PKI-CFG-006, AD-504
- Rows: PKI-CFG-006
- Data: protocol cim, root/cimv2, `SELECT ID, Name, ParentID FROM Win32_ServerFeature`; key `{host}|{ID}`; Condition: Name matches threshold `windows-server.sensitive-role-pattern` (default `(?i)^(Active Directory Certificate Services|Certification Authority|Certificate Enrollment|Network Device Enrollment|Online Responder|Windows Deployment Services|DHCP Server|Routing|Remote Access|Hyper-V)`). Every hit is an inventory row (info) so the role list is visible; the tenant turns specific roles into findings. File windows-server.yaml. Severity info. Category CFG.
- Refs: NIST-800-53:CM-8, CIS-Controls-v8:4.8
- Fix: none; confirm each role has an owner.
- Confidence: verified (class; role names vary by OS version).

### ADCS-HOST-POLICY-MODULE - Non-default policy module or request disposition
- All rows depending on this proposal: PKI-CFG-007
- Rows: PKI-CFG-007
- Data: registry `...\Configuration\{CA}\PolicyModules`, values [Active]; second read `...\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy`, values [RequestDisposition, EditFlags, DisableExtensionList, EnableRequestExtensionList, EnableEnrolleeRequestExtensionList]; key host (one read serves five ADCS-HOST-* rules)
- Condition: Active ne CertificateAuthority_MicrosoftDefault.Policy, or RequestDisposition ne 1 (issue) and ne 257 (issue with the pending override) - a third-party policy module or "set to pending" everywhere changes who decides issuance. Severity low. Category CFG.
- Refs: NIST-800-53:CM-6
- Fix: document the module; set disposition per template, not CA-wide.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-cs/manage/ (policy module registry).

### ADCS-HOST-ESC6-SAN-FLAG - CA accepts a subject alternative name from any request (ESC6)
- All rows depending on this proposal: PKI-AUT-001
- Rows: PKI-AUT-001
- Data: same read; field EditFlags; Condition: EditFlags has flag 262144 (EDITF_ATTRIBUTESUBJECTALTNAME2). With it, any enrollee of any template can ask for a certificate with an administrator's UPN. Severity critical. Lens security. Category AUT.
- Refs: MITRE-ATTACK:T1649, NIST-800-53:IA-5(2), ADCS:ESC6
- Fix: clear the flag (certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2) and restart CertSvc.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-cs/manage/ (EditFlags) and KB5014754.

### ADCS-HOST-EDITFLAGS-NONDEFAULT - Policy EditFlags differ from the defaults
- All rows depending on this proposal: PKI-AUT-002
- Rows: PKI-AUT-002
- Data: same read; Condition: EditFlags ne 1114446 (0x11014E, the enterprise CA default; threshold `adcs.editflags-default`) and the ESC6 flag not set (that is the rule above). Severity low. Category CFG. Evidence shows the value in hex for decoding.
- Refs: NIST-800-53:CM-6
- Fix: document each extra flag.
- Confidence: likely - the default differs between enterprise and standalone CAs.

### ADCS-HOST-ESC16-SID-EXTENSION-DISABLED - SID security extension disabled CA-wide (ESC16)
- All rows depending on this proposal: PKI-AUT-005
- Rows: PKI-AUT-005
- Data: same read; field DisableExtensionList; Condition: contains `1.3.6.1.4.1.311.25.2`. The CA then omits the SID from every certificate and strong mapping cannot work. Severity high. Lens security. Category AUT.
- Refs: MITRE-ATTACK:T1649, MS-KB:5014754, ADCS:ESC16
- Fix: remove the OID from DisableExtensionList and restart CertSvc.
- Confidence: verified.

### ADCS-HOST-REQUEST-EXTENSIONS - CA honours extra requester-supplied extensions
- All rows depending on this proposal: PKI-CFG-010
- Rows: PKI-CFG-010
- Data: same read; fields EnableRequestExtensionList, EnableEnrolleeRequestExtensionList (multi-string); Condition: any element not in the default list (threshold `adcs.default-request-extensions`, default the two OIDs of a fresh install: `1.3.6.1.4.1.311.21.7`, `2.5.29.17` in the enrollee list, and the SMIME/key-usage set in the request list). Severity medium. Lens security. Category AUT.
- Refs: MITRE-ATTACK:T1649, NIST-800-53:CM-6
- Fix: remove the extra OIDs.
- Confidence: guess - the default lists must be taken from a fresh CA of the same version.

### ADCS-HOST-ESC11-RPC-ENCRYPTION - CA accepts unencrypted RPC requests (ESC11)
- All rows depending on this proposal: PKI-AUT-003
- Rows: PKI-AUT-003
- Data: registry `...\Configuration\{CA}`, values [InterfaceFlags, CRLFlags, AuditFilter, RoleSeparationEnabled, EnrollmentAgentRights, OfficerRights, KRAFlags, KRACertCount, CACertPublicationURLs, CRLPublicationURLs, CRLPeriod, CRLPeriodUnits, CRLDeltaPeriod, CRLDeltaPeriodUnits, CRLOverlapPeriod, CRLOverlapUnits]; key host (one read serves the ADCS-HOST-* rules below)
- Condition: InterfaceFlags lacks flag 512 (IF_ENFORCEENCRYPTICERTREQUEST) or lacks flag 1024 (IF_ENFORCEENCRYPTICERTADMIN). Without them NTLM relay to the RPC interface issues certificates. Severity high. Lens security. Category AUT.
- Refs: MITRE-ATTACK:T1557.001, MITRE-ATTACK:T1649, ADCS:ESC11
- Fix: certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST and restart.
- Confidence: verified - interface flag values from the AD CS registry reference.

### ADCS-HOST-INTERFACEFLAGS-NONDEFAULT - Interface flags differ from the hardened default
- All rows depending on this proposal: PKI-AUT-004
- Rows: PKI-AUT-004
- Data: same read; Condition: InterfaceFlags ne 1601 (0x641; threshold `adcs.interfaceflags-default`). Severity low. Category CFG.
- Refs: NIST-800-53:CM-6
- Fix: document extra flags; restore the lock and no-remote-backup bits.
- Confidence: likely.

### ADCS-HOST-CRLFLAGS - CRL behaviour flags include a revocation-check bypass
- All rows depending on this proposal: PKI-CFG-009
- Rows: PKI-CFG-009
- Data: same read; field CRLFlags; Condition: has flag 16 (CRLF_REVCHECK_IGNORE_OFFLINE) or flag 1024 (CRLF_IGNORE_INVALID_POLICIES) - the CA then issues while its own chain cannot be checked. Severity low. Lens security. Category PKI.
- Refs: NIST-800-53:SC-17
- Fix: clear the bypass once the CDP is reachable from the CA.
- Confidence: verified (CRLFlags bit names in the registry reference).

### ADCS-HOST-AUDIT-FILTER - CA auditing not enabled for every category
- All rows depending on this proposal: PKI-MON-001
- Rows: PKI-MON-001
- Data: same read; field AuditFilter; Condition: AuditFilter absent or ne 127. Without it the ADCS-EVT-* rules see nothing. Severity high. Lens security. Category MON.
- Refs: NIST-800-53:AU-2, NIST-800-53:AU-12
- Fix: certutil -setreg CA\AuditFilter 127 and enable the Audit Certification Services subcategory.
- Confidence: verified.

### ADCS-EVT-NO-AUDIT-EVENTS - CA audit events absent
- All rows depending on this proposal: PKI-MON-002
- Rows: PKI-MON-002
- Data: eventlog log Security, ids [4886, 4887, 4868, 4870, 4872], days 7, max 5; Condition: count: none per host. The subcategory itself is secedit-auditpol. Severity medium. Lens security. Category MON.
- Refs: NIST-800-53:AU-2
- Fix: enable the subcategory (Success and Failure) by policy on the CA host.
- Confidence: verified.

### ADCS-HOST-ROLE-SEPARATION - Role separation not enforced on the CA
- All rows depending on this proposal: PKI-IAM-004
- Rows: PKI-IAM-004
- Data: same read; Condition: RoleSeparationEnabled absent or eq 0 (info when only one administrator group holds both roles - the descriptor needs ca-api). Severity low. Lens security. Category IAM.
- Refs: NIST-800-53:AC-5
- Fix: certutil -setreg CA\RoleSeparationEnabled 1 after splitting the roles.
- Confidence: verified.

### ADCS-HOST-ENROLLMENT-AGENT-UNRESTRICTED - Enrollment agent or officer restrictions not configured
- All rows depending on this proposal: PKI-CFG-019, PKI-IAM-005
- Rows: PKI-CFG-019, PKI-IAM-005
- Data: same read; Condition: EnrollmentAgentRights absent while ADCS-CA-PUBLISHES-CA-OR-AGENT-TEMPLATE fires on the same CA (cross-rule; interim: EnrollmentAgentRights absent = finding at low severity, the tenant accepts it when no agent template is published); OfficerRights absent reported info. The descriptor contents need ca-api. Severity medium. Lens security. Category IAM.
- Refs: MITRE-ATTACK:T1649, ADCS:ESC3, NIST-800-53:AC-6
- Fix: configure enrollment agent restrictions (CA properties, Enrollment Agents tab).
- Confidence: verified (value names from the restricted enrollment agent documentation).

### ADCS-HOST-KRA-STATE - Key archival configured without enough recovery agents
- All rows depending on this proposal: PKI-IAM-008
- Rows: PKI-IAM-008
- Data: same read; fields KRAFlags, KRACertCount; Condition: KRACertCount gt 0 and lt 2 (threshold `adcs.min-kra-certs`). Severity low. Category PKI.
- Refs: NIST-800-53:SC-12(1)
- Fix: add a second KRA certificate with an offline key.
- Confidence: verified.

### ADCS-HOST-PUBLICATION-URLS - CDP or AIA publication list puts a file path first or includes a UNC in certificates
- All rows depending on this proposal: PKI-PKI-005, PKI-PKI-006
- Rows: PKI-PKI-005, PKI-PKI-006
- Data: same read; fields CACertPublicationURLs, CRLPublicationURLs (multi-string, each `<flags>:<url>`); Condition: first element matches `^\d+:(file:|\\\\)` (a file or UNC path first means clients try it before HTTP), or any element matches `^(\d*[2367]|\d*1\d):\\\\` (include-in-certificate flags on a UNC path - flag bit 2 = include in CDP, bit 4 = include in AIA of issued certs). Severity medium. Category PKI.
- Refs: NIST-800-53:SC-17, RFC-5280
- Fix: order HTTP first; never include file or UNC paths in issued certificates.
- Confidence: likely - the flag bit layout is documented; the regex needs testing against real values.

### ADCS-HOST-CRL-PERIODS - CRL periods outside the recommended range
- All rows depending on this proposal: PKI-PKI-007
- Rows: PKI-PKI-007
- Data: same read; Condition: CRLPeriod eq Weeks and CRLPeriodUnits gt 2, or CRLPeriod eq Days and CRLPeriodUnits gt 14 (threshold `adcs.crl-max-days`), or CRLOverlapUnits eq 0 and CRLDeltaPeriodUnits eq 0 (no overlap and no deltas - a missed publication breaks validation at once). Severity medium. Category PKI.
- Refs: NIST-800-53:SC-17, RFC-5280
- Fix: base CRL 1-2 weeks with a 2-3 day overlap, or daily deltas.
- Confidence: verified.

### ADCS-HOST-EXIT-MODULE - Exit module publishes to the directory or mails an unmonitored address
- All rows depending on this proposal: PKI-CFG-008, PKI-MON-008
- Rows: PKI-CFG-008, PKI-MON-008
- Data: registry `...\Configuration\{CA}\ExitModules\CertificateAuthority_MicrosoftDefault.Exit`, values [PublishCertFlags]; subkey `...\SMTP`, values [SMTPServer] and its event subkeys (subkeys: true); key host; Condition: SMTPServer set and no recipient matching threshold `adcs.notification-mailbox-pattern` (dormant until set); PublishCertFlags has flag 1 (publish every certificate to the directory) reported info. Severity low. Category MON.
- Refs: NIST-800-53:IR-6, NIST-800-53:SC-17
- Fix: point notifications at a monitored shared mailbox.
- Confidence: likely.

### ADCS-HOST-NDES-CONFIG - Network Device Enrollment Service with a static challenge or broad templates
- All rows depending on this proposal: PKI-IAM-013
- Rows: PKI-IAM-013
- Data: protocol registry, HKLM, path `SOFTWARE\Microsoft\Cryptography\MSCEP`, values [EncryptionTemplate, SignatureTemplate, GeneralPurposeTemplate]; subkeys `MSCEP\UseSinglePassword` (value UseSinglePassword), `MSCEP\PasswordVDir`, `MSCEP\CAType`; key host; absent key = NDES not installed = pass
- Condition: UseSinglePassword eq 1, or any template value matches threshold `adcs.ndes-forbidden-template-pattern` (default `(?i)^(User|Computer|IPSECIntermediateOffline)$`). Severity high. Lens security. Category IAM.
- Refs: MITRE-ATTACK:T1649, NIST-800-53:IA-5
- Fix: dynamic challenge passwords (or the Intune connector), dedicated NDES templates, a low-privilege service account.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-cs/network-device-enrollment-service-overview (MSCEP registry).

### ADCS-HOST-THIRD-PARTY-SERVICE - Service on the CA host that is not part of Windows
- All rows depending on this proposal: PKI-IAM-015
- Rows: PKI-IAM-015
- Data: same spec as DC-THIRD-PARTY-SERVICE (AD fragment) with targets = CA hosts and threshold `adcs.approved-service-pattern`. Severity medium. Lens security. Category HYG.
- Refs: NIST-800-53:CM-7, CIS-Controls-v8:2.5
- Fix: every agent on a CA host has a tier-0 control plane or is removed.
- Confidence: verified.

### ADCS-GROUP-CERT-PUBLISHERS - Cert Publishers contains members other than CA computer accounts
- All rows depending on this proposal: PKI-IAM-006
- Rows: PKI-IAM-006
- Data: protocol ldap, filter `(&(objectClass=group)(cn=Cert Publishers))`, attributes [cn, member]; key cn; Condition: any member notmatch `^CN=[^,]+\$?,` ... computer DNs are not distinguishable by syntax; use a second query `(&{USER}(memberOf=CN=Cert Publishers,CN=Users,{DOMAINDN}))` count gt 0 (user members) - members of Cert Publishers can write userCertificate on every user. Severity medium. Lens security. Category IAM.
- Refs: NIST-800-53:AC-6, MITRE-ATTACK:T1649
- Fix: keep only the CA computer accounts.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#cert-publishers

### ADCS-EVT-KEY-RECOVERY - Archived private key retrieved or imported
- All rows depending on this proposal: PKI-IAM-009
- Rows: PKI-IAM-009
- Data: eventlog log Security, ids [4883, 4893, 4894], days 90; each: any. Severity medium. Lens security. Category MON.
- Refs: NIST-800-53:AU-6, NIST-800-53:SC-12(1)
- Fix: match each to a ticket.
- Confidence: verified.

### ADCS-EVT-SENSITIVE-ISSUANCE - Certificate issued from a sensitive or manual template
- All rows depending on this proposal: PKI-IAM-010, PKI-MON-011, PKI-HYG-009
- Rows: PKI-IAM-010, PKI-MON-011, PKI-HYG-009
- Data: eventlog log Security, ids [4887], days 7, max 500; Condition: CertificateTemplate matches threshold `adcs.sensitive-template-pattern` (default `(?i)(EnrollmentAgent|CodeSigning|SubCA|KeyRecoveryAgent|SmartcardLogon|WebServer|OfflineRouter|IPSECIntermediateOffline)`); key `{host}|{recordId}`; evidence shows Requester and Subject. Severity medium (high for SubCA/EnrollmentAgent via a severity map on the field). Lens security. Category MON.
- Refs: MITRE-ATTACK:T1649, NIST-800-53:AU-6
- Fix: match each issuance to a ticket; revoke the rest.
- Confidence: verified.

### ADCS-EVT-PRIVILEGED-ISSUANCE - Authentication certificate issued to a privileged account
- All rows depending on this proposal: PKI-IAM-011
- Rows: PKI-IAM-011
- Data: protocol store; SQL: 4887 rows (Requester field, 90-day collection) joined to AD users with adminCount 1 on the sAMAccountName part of Requester; key `{requester}|{recordId}`
- Condition: any match whose CertificateTemplate is an authentication template (name pattern threshold). A certificate is a credential no password reset revokes. Severity high. Lens security. Category IAM. The full view of valid certificates needs ca-api.
- Refs: MITRE-ATTACK:T1649, NIST-800-53:IA-5(2)
- Fix: revoke certificates administrators did not ask for; restrict the templates.
- Confidence: likely.

### ADCS-EVT-SELF-APPROVAL - Pending request approved by its own requester
- All rows depending on this proposal: PKI-IAM-018
- Rows: PKI-IAM-018
- Data: protocol store; SQL: 4889 rows (RequestId, Requester) joined to 4887 rows (RequestId, SubjectUserName = the approver) on host and RequestId where the two names match; key `{host}|{RequestId}`. Severity medium. Lens security. Category IAM.
- Refs: NIST-800-53:AC-5
- Fix: separate the requester and approver roles (role separation).
- Confidence: likely - field names of 4889/4887 event data as the eventlog runner names them must be checked.

### ADCS-EVT-CONFIG-CHANGE - CA security or configuration changed
- All rows depending on this proposal: PKI-MON-004
- Rows: PKI-MON-004
- Data: eventlog log Security, ids [4882, 4885, 4890, 4891, 4892, 4897, 4899, 4900], days 7; each: any; key `{host}|{id}|{recordId}`. Severity high. Lens security. Category MON.
- Refs: NIST-800-53:CM-3, NIST-800-53:AU-12, MITRE-ATTACK:T1649
- Fix: match to a change record; 4882 (security permissions) and 4890 (property changed) without one are an incident.
- Confidence: verified.

### ADCS-EVT-SAN-MISMATCH - Certificate request carried a subject alternative name attribute
- All rows depending on this proposal: PKI-MON-005
- Rows: PKI-MON-005
- Data: eventlog log Security, ids [4886, 4887], days 7, max 500; Condition: Attributes matches `(?i)\bsan:` (a request-supplied SAN - the ESC1/ESC6 signature); key `{host}|{recordId}`; evidence shows Requester and the attribute. Comparing the SAN UPN with the requester is a store follow-up. Severity medium. Lens security. Category MON.
- Refs: MITRE-ATTACK:T1649, NIST-800-53:SI-4
- Fix: revoke the certificate if the SAN names another identity; fix the template (ADCS-TPL-ESC1) or the CA flag (ADCS-HOST-ESC6-SAN-FLAG).
- Confidence: verified (4886/4887 Attributes field).

### ADCS-EVT-NO-REVOCATIONS - No certificate revoked in the window (inventory)
- All rows depending on this proposal: PKI-PKI-011
- Rows: PKI-PKI-011
- Data: eventlog log Security, ids [4870], days 90, max 5; Condition: count: none per host (info: revocation is not part of the leaver process). Severity info. Category HYG.
- Refs: NIST-800-53:IA-5(2)
- Fix: add certificate revocation to the leaver and decommission steps.
- Confidence: verified.

### ADCS-TPL-NO-KEY-ATTESTATION - Device authentication template without TPM attestation
- All rows depending on this proposal: PKI-CFG-014
- Rows: PKI-CFG-014
- Data: Q-TPL; Condition: EKU is an authentication EKU (AEU set), msPKI-Template-Schema-Version ge 4, and msPKI-Private-Key-Flag lacks both 4096 (attest preferred) and 8192 (attest required), and pKIDefaultCSPs (add to Q-TPL) notmatch `Platform Crypto Provider`. Severity low. Lens security. Category PKI.
- Refs: NIST-800-53:IA-5(2), NIST-800-53:SC-12
- Fix: require TPM key attestation on device templates where hardware allows.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation

### ADCS-TPL-SERVER-SUPPLY-SUBJECT - Server certificate template lets the requester name the subject without approval
- All rows depending on this proposal: PKI-CFG-015
- Rows: PKI-CFG-015
- Data: Q-TPL; Condition: pKIExtendedKeyUsage contains 1.3.6.1.5.5.7.3.1, msPKI-Certificate-Name-Flag has flag 1, msPKI-Enrollment-Flag lacks flag 2 (no manager approval) and msPKI-RA-Signature eq 0 or absent. ADCS-TPL-ESC1 covers authentication EKUs; a server template lets anyone who can enrol impersonate any internal web site. The Enroll ACE half needs ldap-security-descriptor. Severity medium. Lens security. Category PKI.
- Refs: MITRE-ATTACK:T1649, NIST-800-53:SC-17
- Fix: require manager approval or restrict enrolment to the server administrators' group.
- Confidence: verified.

### ADCS-TPL-CONFLICT - Replication-conflict or duplicate certificate template objects
- All rows depending on this proposal: PKI-CFG-016
- Rows: PKI-CFG-016
- Data: Q-TPL plus msPKI-Cert-Template-OID; Condition: cn matches `CNF:`; second rule (store) GROUP BY displayName or msPKI-Cert-Template-OID HAVING COUNT > 1. Severity low. Category HYG.
- Refs: NIST-800-53:CM-6
- Fix: delete the conflict copy; merge duplicates.
- Confidence: verified.

### ADCS-TPL-PUBLISH-FLAGS - Auto-enrolled template publishes every certificate to the directory
- All rows depending on this proposal: PKI-CFG-023
- Rows: PKI-CFG-023
- Data: Q-TPL; Condition: msPKI-Enrollment-Flag has flag 32 (auto-enrol) and has flag 8 (publish to DS) and the template is a computer template (EKU lacks e-mail protection and the subject flags lack the e-mail bits) - directory bloat in userCertificate; or a user template with flag 32 and lacking flag 16 (no duplicate check) - re-enrolment piles up. Severity low. Category HYG.
- Refs: NIST-800-53:CM-6
- Fix: adjust the template flags.
- Confidence: verified (flag values from MS-CRTD).

### ADCS-TPL-CODE-SIGNING-OPEN - Code-signing template without approval or with an exportable key
- All rows depending on this proposal: PKI-AUT-015
- Rows: PKI-AUT-015
- Data: Q-TPL; Condition: pKIExtendedKeyUsage contains 1.3.6.1.5.5.7.3.3 and (msPKI-Enrollment-Flag lacks flag 2 or msPKI-Private-Key-Flag has flag 16). A signed binary from this CA passes application control everywhere. Severity high. Lens security. Category PKI.
- Refs: MITRE-ATTACK:T1553.002, NIST-800-53:SI-7(15)
- Fix: require manager approval, non-exportable (hardware) keys, named enrollees.
- Confidence: verified.

### ADCS-TPL-UNPUBLISHED - Custom templates defined but published by no CA
- All rows depending on this proposal: PKI-HYG-003
- Rows: PKI-HYG-003
- Data: protocol store; SQL: template rows whose cn is not in any Q-CA certificateTemplates array and not a default template name (the list used by ADCS-TPL-ESC1's exclusion); key cn; count gt 10 (threshold). Severity low. Category HYG.
- Refs: NIST-800-53:CM-7
- Fix: delete abandoned templates.
- Confidence: verified.

### ADCS-TPL-NAME-SUSPICIOUS - Template named like a copy or a test
- All rows depending on this proposal: PKI-HYG-004
- Rows: PKI-HYG-004
- Data: Q-TPL; Condition: displayName matches `(?i)^copy( \d+)? of |test|temp|old|backup` (threshold). Severity low. Category HYG.
- Refs: NIST-800-53:CM-6
- Fix: rename or delete.
- Confidence: verified.

### DC-REG-CERT-MAPPING-WEAK - Domain controller allows weak certificate mapping (ESC10)
- All rows depending on this proposal: PKI-AUT-007, DC-054
- Rows: PKI-AUT-007
- Data: protocol registry on DCs (domain-controllers.yaml), HKLM, path `SYSTEM\CurrentControlSet\Services\Kdc`, values [StrongCertificateBindingEnforcement]; second read path `SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel`, values [CertificateMappingMethods]; key host
- Condition: StrongCertificateBindingEnforcement exists and ne 2, or CertificateMappingMethods exists and has flag 4 (UPN mapping). Severity high. Lens security. Category AUT.
- Refs: MITRE-ATTACK:T1649, MS-KB:5014754, ADCS:ESC10
- Fix: remove the overrides (full enforcement is the patched default).
- Confidence: verified - KB5014754.

### WINSRV-REG-DCOM-HARDENING-OVERRIDE - DCOM authentication hardening disabled
- All rows depending on this proposal: PKI-AUT-012
- Rows: PKI-AUT-012
- Data: protocol registry, HKLM, path `SOFTWARE\Microsoft\Ole\AppCompat`, values [RequireIntegrityActivationAuthenticationLevel, RaiseActivationAuthenticationLevel]; key host; Condition: RequireIntegrityActivationAuthenticationLevel exists and eq 0. Plus eventlog System ids [10036, 10037, 10038] providers [Microsoft-Windows-DistributedCOM] days 30 count>0 (clients that would break). File windows-server.yaml (WS twin). Severity medium. Lens security. Category AUT.
- Refs: MS-KB:5004442, NIST-800-53:SC-8
- Fix: delete the override; fix the clients named in 10036.
- Confidence: verified - KB5004442.

### WS-GPO-TRUST-ANCHORS - Trust anchors deployed by policy (inventory and unexpected entries)
- All rows depending on this proposal: PKI-AUT-015, PKI-PKI-015
- Rows: PKI-PKI-015, PKI-AUT-015 (TrustedPublisher)
- Data: protocol registry, HKLM, paths `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates`, `...\SystemCertificates\CA\Certificates`, `...\SystemCertificates\TrustedPublisher\Certificates`, `...\SystemCertificates\Disallowed\Certificates`, subkeys: true; key `{host}|{store}|{subkey}` (the subkey name is the thumbprint); Condition: subkey notin threshold `workstations.expected-policy-anchors` (dormant: default accepts all, the inventory is the value). Certificate blobs cannot be decoded (engine gap). File workstations.yaml and windows-server.yaml. Severity medium when an unexpected thumbprint appears. Lens security. Category PKI.
- Refs: NIST-800-53:SC-17, MITRE-ATTACK:T1553.004
- Fix: remove anchors nobody owns; record the rest.
- Confidence: verified - https://learn.microsoft.com/windows-server/identity/ad-fs/deployment/distribute-certificates-to-client-computers-by-using-group-policy

### WS-EVT-CAPI2-FAILURES - Chain or revocation failures on a workstation
- All rows depending on this proposal: PKI-MON-010
- Rows: PKI-MON-010
- Data: eventlog log Microsoft-Windows-CAPI2/Operational, ids [11, 41, 53], days 7; count gt 10 per host (threshold); the channel is disabled by default - a registry read of `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational` value Enabled tells whether silence means health. File workstations.yaml (server twin). Severity low. Category PKI.
- Refs: NIST-800-53:SC-17
- Fix: fix the CDP reachability or the missing intermediate the events name.
- Confidence: verified - CAPI2 diagnostics documentation.

### INTUNE-CERT-CONNECTOR-UNHEALTHY - Intune certificate connector not healthy
- All rows depending on this proposal: PKI-CFG-024
- Rows: PKI-CFG-024
- Data: protocol graph, path /deviceManagement/ndesConnectors, select [id, displayName, state, lastConnectionDateTime, machineName]; key id; Condition: state ne active or lastConnectionDateTime older than 1 day. Absent connectors with SCEP/PKCS profiles assigned (a second query of /deviceManagement/deviceConfigurations filtered on the certificate profile types) = count: none. File intune.yaml. Severity medium. Category AVL.
- Refs: NIST-800-53:SC-17
- Fix: restart or re-register the connector.
- Confidence: likely - https://learn.microsoft.com/graph/api/resources/intune-deviceconfig-ndesconnector

### XS-CERT-NOT-IN-REGISTER - Served certificate missing from the key-date register
- All rows depending on this proposal: APP-BASELINE-PKI-004, PKI-PKI-018
- Rows: PKI-PKI-018
- Data: protocol store; SQL: tls endpoint rows (subject, sans, notAfter, thumbprint from the certificates scan) anti-joined to key_date rows of kind certificate on thumbprint or subject name; key endpoint; Condition: no register entry for a certificate expiring within 180 days. File cross-system.yaml. Severity low. Lens maintenance. Category CST.
- Refs: NIST-800-53:CM-8, NIST-800-53:SC-17
- Fix: add the certificate to the register with an owner and the renewal path.
- Confidence: likely (key_date column names from the store schema).

### SCCM-SITE-SYSTEM-SSL-STATE - Site system roles without HTTPS (inventory)
- All rows depending on this proposal: PKI-PKI-025
- Rows: PKI-PKI-025
- Data: protocol http, path /wmi/SMS_SCI_SysResUse, $select NetworkOSPath, RoleName, SslState, SiteCode; key `{NetworkOSPath}|{RoleName}`; Condition: RoleName in [SMS Management Point, SMS Distribution Point, SMS Software Update Point] and SslState eq 0 (HTTP). File sccm.yaml. Severity low (medium for the management point). Lens security. Category PKI.
- Refs: NIST-800-53:SC-8
- Fix: enable HTTPS or enhanced HTTP on the roles.
- Confidence: likely - SMS_SCI_SysResUse.SslState is documented in the SDK; the lazy-property behaviour of the AdminService is a known caveat.

