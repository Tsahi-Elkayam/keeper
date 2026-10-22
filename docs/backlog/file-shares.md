# Backlog - file shares (SMB share and NTFS permissions)

Legacy `checks-FILESRV.csv` rows that `rules/file-shares.yaml` cannot express yet, one line each: the
check (by CheckId), what it needs, and the reason. The pack reads only what the `smb` runner returns -
the share list and, per disk share, its share-level ACL - so it covers the open/weak/hidden/misplaced
*share* checks. Everything that needs another protocol, folder-tree enumeration, run-to-run history, a
join across reads, or a human is below.

Source: `filesrv` = the legacy file-server catalogue (`_archive\_health-20261020\Keeper\catalog\checks-FILESRV.csv`).
The `(Restored1)` duplicates were ignored.

## Needs the NTFS runner to enumerate a folder tree - the smb ntfs read takes one literal path

`read: ntfs` reads the ACL of one path given as `share\folder`; it does not recurse a share, and a
generic rule cannot name a tenant's folders (the path is a query field, not a condition threshold). A
tenant copy with explicit paths could express these; the generic pack cannot.

- FILESRV-IAM-005 - share root still inherits the default volume ACL (BUILTIN\Users create/append, CREATOR OWNER Full). Needs each share root's NTFS ACL and AreAccessRulesProtected.
- FILESRV-IAM-006 - broad principals with Write/Modify/Full on departmental folders. Needs folder-tree enumeration to depth 3.
- FILESRV-IAM-007 - permissions granted directly to individual users. Needs per-folder ACE enumeration and a per-identity count.
- FILESRV-IAM-008 - orphaned SIDs (deleted accounts) in ACLs. Expressible per path as `account absent` on an explicit ACE, but needs the folder tree and a path per rule.
- FILESRV-IAM-010 - explicit Deny ACEs. Per-path expressible (`type eq deny`) but needs the folder tree.
- FILESRV-IAM-011 - broken-inheritance map (protected folders) per share. Needs AreAccessRulesProtected per folder, which the runner does not return, and the tree.
- FILESRV-IAM-012 - folders owned by individuals. Needs the owner per folder across the tree (owner is returned, enumeration is not).
- FILESRV-IAM-016 - empty groups granted on folders. Needs the tree plus an LDAP member count.
- FILESRV-IAM-022 - sensitive folders scoped to named groups. Needs folder enumeration and a sensitivity classification.
- FILESRV-IAM-027 - explicit-ACE sprawl on share roots. Needs each share root's NTFS ACL and an explicit-ACE count.
- FILESRV-IAM-028 - Domain Computers or machine accounts with rights on data folders. Needs the tree and SID-class resolution.
- FILESRV-MON-002 - audit entries (SACLs) on sensitive folders. The runner reads the DACL and owner, not the SACL.
- FILESRV-MON-005 - canary folder with alerting SACL. Needs SACL plus a tenant canary name and the folder tree.

## Needs a join across two reads or with the directory - one query cannot do it

- FILESRV-IAM-003 - share ACL wider than the NTFS root ACL. Needs the share ACL and the root NTFS ACL in one comparison.
- FILESRV-IAM-004 - share ACL narrower than NTFS (in-the-group-but-denied). Needs the NTFS granting groups and the share ACL joined, plus group nesting.
- FILESRV-IAM-009 - foreign-domain SIDs in ACLs. Needs the domain SID (LDAP) to tell a foreign SID from a local one.
- FILESRV-IAM-013 - disabled or departed accounts still holding rights. Needs each ACE SID resolved against AD (enabled, last logon).
- FILESRV-IAM-014 - service/shared accounts with rights on data. Needs ACE-to-AD resolution and account classification.
- FILESRV-IAM-015 / -017 - granting-group nesting/size, and managedBy/description. LDAP group reads (directory pack).
- FILESRV-IAM-018 / -019 - home-folder model (each user only on their own folder) and leaver home folders. Needs folder enumeration joined with AD user names/state.
- FILESRV-IAM-020 - roaming profile / redirection share ACLs match the Microsoft model. Needs folder enumeration and a baseline ACL compare.
- FILESRV-IAM-021 - installer share writable by non-administrators. The share-level part is near FILESHARE-SHARE-BROAD-CHANGE; identifying "installer" shares and their NTFS write grants needs content and folder reads.
- FILESRV-IAM-026 - access review per share within 183 days. Obligation/attestation record plus run-to-run group deltas.
- FILESRV-HYG-007 - data owner per departmental folder. LDAP managedBy plus attestation.

## Needs the cim protocol (MSFT_* / Win32_* classes), not the share list

The share list carries name, type, special, remark, path and the share ACL only - not the SMB server
configuration, share flags (ABE, encryption, caching, limits, description), volumes, services,
performance, DFS, FSRM, dedup or shadow copies. These belong in a cim read (some overlap
`rules/windows-server.yaml`, which already covers SMB1-server, SMB signing and the OS/patch/service side).

- FILESRV-HLT-001..011, -014, -017, -018 - volume free space/health/latency, disk/physical health, SMB request latency, LanmanServer and role services, memory/CPU pressure, sessions, shares whose path is gone, share state. CIM (Win32_Volume/LogicalDisk, MSFT_* storage, perf classes, Win32_Service, MSFT_SmbShare/SmbSession).
- FILESRV-HLT-012, -013 - NTFS compression and cluster size per volume. CIM Win32_Volume.
- FILESRV-CFG-003..005, -007, -008 - admin-share state, ABE, caching mode, concurrent-user limit, description. MSFT_SmbShare fields the smb runner does not return.
- FILESRV-CFG-009..016 - idle disconnect, leasing/oplocks, SMB2 credits, null-session shares/pipes, RestrictNullSessAccess, announcement/hidden, strict name checking, Server service tuning. MSFT_SmbServerConfiguration and the LanmanServer registry.
- FILESRV-CFG-017..022, -023, -024 - FSRM quotas/templates/notifications/reports/classification, indexing, BranchCache, other protocols (NFS/iSCSI/Work Folders/FTP). CIM FSRM/service/feature classes.
- FILESRV-AUT-001, -003, -005, -008, -014, -016 - SMB1 server state, server signing, server-wide encryption posture, SPN target-name validation, SMB-over-QUIC, SMB1 access auditing. MSFT_SmbServerConfiguration (SMB1-server and signing overlap WINSRV-SMB1-SERVER-ON / WINSRV-SMB-SIGNING-NOT-REQUIRED).
- FILESRV-AUT-002, -006 - SMB1 clients connected / dialects in use. MSFT_SmbSession, MSFT_SmbConnection.
- FILESRV-AUT-009, -010, -013, -015 - anonymous restrictions, insecure guest, LmCompatibilityLevel, NetBIOS/LLMNR. Registry/CIM (LmCompat and NetBIOS overlap WINSRV-GPO-LMCOMPAT-LOW / WINSRV-NETBIOS-ON).
- FILESRV-AUT-011 - firewall profiles and SMB rule scope. MSFT_NetFirewall* (overlaps WINSRV-FW-PROFILE-OFF).
- FILESRV-BCK-001..007 - shadow copies (enabled/age/retention/storage/diff area/task) and VSS services. CIM Win32_ShadowCopy/ShadowStorage, scheduled-task and service classes.
- FILESRV-PKI-001..004 - machine certificate, QUIC certificate mapping, trust-store hygiene, cert-store size. Not exposed by the smb runner; needs registry/cert or the tls pack.

## Needs DFS - MSFT_Dfs* / MicrosoftDfs classes

- FILESRV-AVL-003..013 - DFS-N root/folder targets online and not stale, referral settings, namespace mode and delegation; DFS-R folder state, backlog, connections, staging, conflict, schedule, volume database. All CIM DFS classes (plus LDAP for stale-target resolution). FILESRV-IAM-025 (namespace delegation) is the same.

## Needs the eventlog protocol or a time window

- FILESRV-LOG-001..012 - SMBServer Operational/Security/Audit/Connectivity signatures, SMB1 access events (the migration list), srv/Ntfs/disk/volsnap/VSS/DFSR events, and event-log sizes/retention. The eventlog runner (overlaps the windows event packs); per-log metadata (size, oldest record) is a known engine gap.
- FILESRV-MON-003 - ACL/share change events (4670, 5142-5144). Eventlog plus audit policy.
- FILESRV-HYG-009 - shares with no access in 90 days. Eventlog 5140 over a window, or a content LastWriteTime scan.

## Needs run-to-run history or several samples

- FILESRV-HLT-002 - volume growth trend and days-to-full. Needs a linear fit over stored runs.
- FILESRV-HLT-006, -010 - disk latency/queue and sustained CPU. Needs several samples; the runner takes one snapshot.
- FILESRV-HLT-011 - sessions vs an 8-run baseline. Needs stored history.
- FILESRV-CST-002, -004 - over-provisioned volumes "for 3 runs", storage growth forecast. Needs history.

## Needs AWS - the aws runner and other integrations

- FILESRV-AUT-012 - SMB exposure in the file servers' security groups. AWS EC2 DescribeSecurityGroups.
- FILESRV-CST-001, -003, -005 - EBS volume type/IOPS, FSx overlap, orphaned snapshots. AWS EBS/FSx.
- FILESRV-HYG-011 - share-to-platform map (EC2 vs FSx). AWS FSx plus the share list.
- FILESRV-BCK-008..012 - backup agent present, last successful backup, backup scope/immutability, restore test. Backup connectors (Veeam/Rubrik/AWS Backup) and attestation.
- FILESRV-MON-008 - Defender/EDR real-time protection and exclusions covering data volumes. CIM Defender classes (overlaps WINSRV-DEFENDER-*); exclusion-vs-share-path join.
- FILESRV-MON-009, -010 - monitored by PRTG/Dynatrace, central log collection. Monitoring connectors and WEF/agent reads.

## Needs content enumeration (file names, sizes, ages) over the admin share

- FILESRV-HLT-015, -016 - long paths and largest folders. Recursive listing the runner does not do.
- FILESRV-HYG-001..004, -010, -012 - stale data by LastWriteTime, disallowed file types, PST files, duplicates, root clutter/empty folders, personal/health-data identification. Recursive content reads (and FSRM classification/DPO attestation).
- FILESRV-MON-004 - ransomware extension / ransom-note sweep. Recursive content read against a maintained pattern list.
- FILESRV-MON-006 - FSRM file-screen with the anti-ransomware group. CIM FSRM classes.

## LDAP / lifecycle of the server objects

- FILESRV-LCM-001, -002, -003, -007, -008 - OS support end, cumulative-update age, pending reboot, agent/driver versions. Overlaps `rules/windows-server.yaml` (OS/patch) and needs registry/CIM for the rest.
- FILESRV-LCM-004, -005 - SMB1 feature installed, installed file-services roles inventory. CIM Win32_OptionalFeature/ServerFeature (SMB1 feature overlaps WINSRV-FEATURE-UNWANTED).
- FILESRV-LCM-006, -HYG-008 - a legacy storage host still in AD / decommission state. LDAP plus reachability (and it is tenant-specific).
- FILESRV-IAM-023, -024 - local Administrators and Backup/Power/Server Operators on file servers. Overlaps WINSRV-LOCALADMIN-* (CIM/RPC); user-rights need RSOP.
- FILESRV-AUT-007 - Kerberos vs NTLM to the file servers and SPN registration. Eventlog 4624 plus LDAP servicePrincipalName.
- FILESRV-HYG-005 - share/folder naming consistency. Share names in this estate are often Hebrew, so a generic non-ASCII rule would be pure noise; needs a tenant naming rule.

## Process, documentation and attestation only - no read decides them

- FILESRV-CFG-001, -006(doc), -HYG-006 - share inventory / share table in the README. Documentation (the share list feeds it; FILESHARE-SHARE-UNSANCTIONED is the enforceable part).
- FILESRV-AVL-001, -002 - reachability and share-baseline diff. Reachability is coverage (unknown target), not a finding; the baseline diff is FILESHARE-SHARE-UNSANCTIONED plus a stored baseline.
- FILESRV-AVL-014, -015 - continuously-available flag without a cluster, single-server share trees (DR). CIM share flag / DFS-R membership and a DR decision.
- FILESRV-AUT-004 - SMB encryption on sensitive shares. MSFT_SmbShare EncryptData plus a sensitivity list.
- FILESRV-MON-001 - object-access audit subcategories enabled. RSOP audit policy.
