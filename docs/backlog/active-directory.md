# Backlog - Active Directory and AD CS

Checks that `rules/active-directory.yaml` and `rules/adcs.yaml` cannot express yet. One line each:
the check, what it needs, and where it came from.

Source labels: `ldap-rules` = the legacy LDAP rule catalogue, `bindings` / `checks` = the legacy AD
check catalogue (check id), `review` = the legacy AD expert review list (item id), `scripts` = the
legacy AD audit scripts, `field` = a problem seen in a real estate (described generically).

## Engine gaps - the data is in LDAP, the engine cannot use it yet

- Disabled GPO still linked somewhere - needs a join of every container's gPLink with GPC flags (one query per rule today). Source: bindings AD-CFG-036; field (a fully disabled GPO that would grant local admin rights if re-enabled was still linked).
- Unlinked GPOs - needs the same gPLink-to-GPC join. Source: bindings AD-CFG-034; review GPO-001; field (unlinked empty GPOs).
- GPO WMI filter that no longer exists - needs a join of gPCWQLFilter with msWMI-Som objects. Source: bindings AD-CFG-044.
- Template rules only matter for templates a CA publishes - needs a join of pKICertificateTemplate cn with certificateTemplates on pKIEnrollmentService. Source: review PKI-011, PKI-032.
- Delegation targets that point to SPNs no account holds - needs an SPN index join. Source: review AD-116.
- Constrained delegation to cifs/ or host/ on a domain controller - needs a join of msDS-AllowedToDelegateTo hosts with DC dNSHostName values. Source: bindings AD-IAM-017; review AD-114.
- Ghost DC metadata where the computer account survived (server or nTDSDSA objects whose DC is gone but whose computer object still exists), and automatic connections from deleted servers - needs a join of CN=Sites objects with DC computer objects. Server objects without a live reference (AD-SITE-SERVER-ORPHAN) and manual or disabled connections from deleted servers (AD-REPL-CONNECTION-FROM-DELETED) are rules. Source: bindings AD-AVL-025, AD-AVL-009; review AD-017, AD-030.
- Sites without a domain controller, global catalog placement per site, ISTG checks - needs site-to-server joins. Preferred bridgeheads (AD-SITE-BRIDGEHEAD-PREFERRED) and DCs that are not a GC (AD-DC-NOT-GC) are rules. Source: bindings AD-AVL-010..016, AD-CFG-015; review AD-034, SITE-006.
- Fine-grained policy coverage of privileged groups and the longest minimum length across policies - needs a join of msDS-PSOAppliesTo with group DNs and an aggregate (max). Source: bindings AD-IAM-035; review AD-213.
- Duplicate SPNs, UPNs, mail and proxy addresses - needs group-by over all rows. Source: bindings AD-AUT-016, AD-HYG-012; review AD-206, AD-406.
- Number of distinct DC operating-system generations - needs a distinct count. Source: bindings AD-LCM-011; review DC-022.
- Schema version behind the newest DC generation - needs a join of objectVersion with DC operatingSystem values; the absolute floor is AD-SCHEMA-VERSION-OLD. Source: bindings AD-LCM-007; review AD-002.
- Which member of an administrative group changed since the last run - needs run-to-run comparison of membership; AD-GROUP-PROTECTED-RECENTLY-CHANGED gives the "something changed" signal. Source: review AD-100.
- Group nesting cycles and depth, users near the token-size limit - needs graph traversal or tokenGroups (base-scope-only constructed attribute). Source: bindings AD-HYG-008; review AD-404.
- Empty or very deep OUs - needs child counts or depth per OU. Source: bindings AD-CFG-009; review AD-411.
- Foreign security principals from domains that no longer exist - needs SID-to-domain resolution; unused ones are AD-HYG-FSP-UNUSED. Source: bindings AD-HYG-010; review AD-405.
- SID history that carries this domain's own SID - needs the domain SID as a rule value (a macro). Source: review AD-127.
- RID pool consumption - rIDAvailablePool packs two 32-bit counters into one 64-bit value; needs arithmetic. Source: review AD-004; scripts (RID pool read).
- Lockout duration and observation window - the runner converts domain-head durations to whole days, so "lockout duration under 15 minutes" or "observation window too short" cannot be written; minimum ages under one day also read as 0 (AD-DOM-MIN-PASSWORD-AGE-ZERO says so). Maximum and minimum age are rules (AD-DOM-MAX-PASSWORD-AGE, AD-DOM-MIN-PASSWORD-AGE-ZERO). Source: bindings AD-IAM-034; review AD-211, AD-212.
- Fine-grained password policy durations in days - msDS-MaximumPasswordAge, msDS-MinimumPasswordAge, msDS-LockoutDuration and msDS-LockoutObservationWindow are not in the runner's duration list, so AD-PSO-MAX-AGE and AD-PSO-MIN-AGE-ZERO compare raw ticks with no tenant threshold, and the lockout windows have no rule. Needs the four attributes added to the duration list. Source: review AD-213; proposals.
- SID-to-name resolution - resource-based delegation trustees (AD-COMP-RBCD-SET, AD-COMP-RBCD-BROAD-TRUSTEE), sIDHistory, foreign security principals and mS-DS-CreatorSID are shown as SIDs, and "the trustee is a privileged account" cannot be a rule. Needs a SID resolver or a store join on row_seen objectSid. Source: bindings AD-IAM-018; review AD-115.
- Localised directories - rules that name Domain Admins, Enterprise Admins, Schema Admins, Protected Users, DnsAdmins or default GPO containers by English DN return no rows on a localised domain, so count rules pass silently. AD-GROUP-PROTECTED-BROAD-MEMBER and AD-RODC-REVEAL-BROAD match the default names through a pattern threshold (ad.broad-group-member-pattern, ad.rodc-reveal-broad-pattern) a tenant can localise; AD-RODC-NEVER-REVEAL-MISSING is name-free and so cannot see a removed Denied RODC Password Replication Group on its own. Needs a well-known-RID macro (for example {RIDDN:512} or {RIDDN:572}).
- Filter-macro windows are literals - {FT:n} and {GT:n} take a number, so the outer window of AD-USER-LOCKOUT-WAVE (7 days), AD-SCHEMA-RECENT-EXTENSION (90) and ADCS-PKI-OBJECT-RECENTLY-CHANGED (30) caps their tenant thresholds. Needs a {GT:threshold-name} form. Source: proposals.
- A rule that depends on another query's rows - "rolling of expiring NTLM secrets is off" (msDS-ExpirePasswordsOnSmartCardOnlyAccounts on the domain head, PingCastle A-SmartCardPwdRotation) matters only when smart-card-only accounts exist and would fire on every domain without them; AD-USER-SMARTCARD-STATIC-HASH reports the effect per account instead. Needs a condition across two queries. Source: proposals.
- Severity that rises with idle age and stays tunable - a severity map over daysLeft could grade lastLogonTimestamp age, but its range boundaries take no threshold, so the idle-age grading is two rules (AD-USER-NO-DC-LOGON, AD-USER-NO-DC-LOGON-1Y). Needs threshold names on severity ranges. Source: stale-user breakdown.
- Last sign-in anywhere (domain controller or cloud) - the domain-only view over-counts stale users in a hybrid estate; the authoritative idle list needs the AD inventory joined to cloud sign-in activity, which belongs to the hybrid identity pack. Source: field (stale-user count inflated by cloud-only users, new accounts and resource mailbox objects).
- Credentials in description, info or comment fields - a regex rule would store the matched text unredacted in the result value. Needs value masking in results. Source: bindings AD-HYG-013; review AD-407.
- Domain controller or client addresses outside every AD site subnet - LDAP has no computer addresses and the engine has no CIDR math. Source: bindings AD-CFG-013, AD-CFG-016; review SITE-001; field (a client subnet in no site and no SCCM boundary left its computers without content).

## Binary attributes the runner drops

- NTAuth store size, retired or expired CAs in NTAuth, AIA and Certification Authorities containers - cACertificate is DER and is dropped. Source: bindings AD-PKI-010, PKI-CFG-018; review PKI-033, PKI-034.
- CA certificate remaining validity - cACertificate on the enrollment service. Source: review PKI-003.
- CRL validity in the LDAP CDP - certificateRevocationList is DER. Source: bindings PKI-AVL-005, PKI-PKI-008; review PKI-004.
- Template validity and renewal overlap - pKIExpirationPeriod and pKIOverlapPeriod are binary. Source: bindings PKI-CFG-011; review PKI-030.
- Domain controller certificate without the KDC Authentication EKU (per certificate) - DC certificates live in the DC's store; userCertificate on the DC object is DER. The template-level half is ADCS-CA-DC-TEMPLATE-NO-KDC-EKU. Source: field (KDC certificate error on a DC).
- Insecure (nonsecure) dynamic DNS updates and zone transfer settings - dnsProperty on dnsZone objects is binary. Source: bindings AD-CFG-018, AD-CFG-026; scripts; field (zones allowing nonsecure updates).
- Privileged accounts synchronised to the cloud - msDS-ConsistencyGuid is binary and absent when objectGUID is the source anchor. Source: bindings ENTRACONNECT-IAM-014; review AD-500.

## Security descriptors (ACLs) - nTSecurityDescriptor is not decoded

- DCSync rights (Replicating Directory Changes All) held by principals other than DCs and the sync account; replication access-denied questions. Source: review AD-014, AD-129; bindings ENTRACONNECT-IAM-005/006; field (replication access denied on inbound sync to a DC).
- AdminSDHolder ACEs beyond the default - AD-ADMINSDHOLDER-RECENTLY-CHANGED gives the change signal; the entries themselves need the descriptor. Source: bindings AD-IAM-020; review AD-117.
- Dangerous OU ACEs, writers on DC objects, LAPS password readers, gPLink writers, computer-create rights, object owners. Source: bindings AD-IAM-025, AD-IAM-026, AD-IAM-042, AD-IAM-044, AD-IAM-045, AD-IAM-051.
- GPO ACLs (read/apply missing, non-admin editors, owner, custom per-user edit rights on root-linked GPOs). Source: bindings AD-CFG-040..043; field (individual users with edit rights on root-linked GPOs).
- OU protection from accidental deletion. Source: bindings AD-CFG-010; review AD-411.
- DNS zone create-child for Authenticated Users. A "no wildcard record in the zone" rule was proposed instead and not written: it fires on nearly every domain, the wildcard has side effects on name resolution, and the zone ACL is the actual control (the zone may also live in ForestDnsZones). Source: review DNS-003; proposals (AD-DNS-NO-WILDCARD).
- Exchange permission groups with WriteDACL on the domain head. Source: review AD-131.
- Certificate template and PKI container write rights (ESC4, ESC5) and template enrollment rights for broad groups; ADCS-PKI-OBJECT-RECENTLY-CHANGED gives the change signal. Source: bindings PKI-CFG-015; review PKI-014, PKI-015, PKI-032.
- Templates that autoenroll but need CA manager approval - whether anyone autoenrolls is the Autoenroll right in the template ACL; the msPKI-Enrollment-Flag autoenrollment bit alone does not say so. Source: proposals (ADCS-TPL-AUTOENROLL-WITH-APPROVAL).

## Secret-listed or unreadable attributes

- Shadow credentials on DCs, servers and privileged users - msDS-KeyCredentialLink is secret-listed and usually unreadable, so a presence filter would pass silently for a standard reader. Source: bindings AD-IAM-052; review AD-136; field (Windows Hello keys on unmanaged computers - the cloud half belongs to the Entra pack).
- Fine-grained password policies are readable by administrators only by default; with a standard reader the PSO rules see no rows. Needs a coverage signal for "container readable but empty" versus "not readable".

## Needs a domain controller registry, service or CIM read (cim or a DC baseline pack)

- LM / NTLMv1 accepted (LmCompatibilityLevel, NoLMHash). Source: review DC-029, DC-030; field (NTLMv1 and LM accepted).
- NTLM audit and restriction, NTLM SSP minimum session security. Source: bindings AD-AUT-003; checks ADX-DCB-001; review DC-031, DC-032.
- LDAP signing and LDAPS channel binding not enforced. Source: review DC-033, DC-034; scripts; field.
- TLS 1.0 and 1.1 enabled, weak cipher suites. Source: bindings AD-AUT-022; review DC-039, DC-041; scripts; field.
- SMBv1 server or client, SMB signing, insecure guest logons on DCs. Source: bindings AD-AUT-009; review DC-026, DC-027, DC-028; field (SMBv1 enabled on a DC).
- Print Spooler running on DCs. Source: review DC-025; field (spooler reachable on several DCs).
- RPC coercion surface (EFSRPC, MS-RPRN, DFSNM, FSRVP). Source: review DC-042.
- Netlogon secure channel protection and RPC sealing (FullSecureChannelProtection, RequireSeal). Source: checks ADX-DCB-011; review DC-037, DC-038.
- Kerberos encryption-type policy and PAC signature enforcement on DCs. Source: bindings AD-AUT-012, AD-AUT-019; review DC-052, DC-053.
- Certificate strong-mapping enforcement (StrongCertificateBindingEnforcement, CertificateMappingMethods). Source: bindings PKI-AUT-007; review DC-054.
- LSA protection, WDigest, custom LSA packages. Source: checks ADX-DCB-002..004; review DC-044..046.
- RDP NLA and security layer, WinRM Basic/CredSSP/unencrypted, PowerShell logging on DCs. Source: checks ADX-DCB-005..007; review DC-047..049.
- LLMNR, NetBIOS and mDNS on DCs; firewall profiles; unexpected listeners; internet egress. Source: bindings AD-AUT-023, AD-AUT-027; checks ADX-DCB-008, ADX-DCB-009; review DC-043, DC-050, DC-051, DC-056.
- DC-only settings (Server Operators may schedule tasks, refuse machine password changes). Source: checks ADX-DCB-010; review DC-057.
- DSRM logon behaviour. Source: bindings AD-BCK-004.
- Strict replication consistency, divergent-partner override, USN rollback marker. Source: bindings AD-AVL-021; review AD-026..028.
- DC disk, memory, CPU, pagefile, uptime, pending reboot, core services, third-party software, extra roles, EDR state. Source: bindings AD-HLT-*; review DC-001..016; field (a DC not rebooted for months).
- DC patch level and missing updates - operatingSystemVersion has no update revision. Source: bindings AD-LCM-003; review DC-018, DC-019; field (clients without recent cumulative updates).
- Legacy components (PowerShell 2.0, SMB1 feature, Telnet). Source: bindings AD-LCM-005; review DC-021.
- Time hierarchy, NTP sources, clock skew per DC. Source: bindings AD-AVL-032, AD-AVL-037; review AD-052.
- DNS server checks (ServerLevelPluginDll, forwarders, root hints, scavenging, cache hardening, global query block list, query logging, SOA answers, DNSSEC decision). Source: checks ADX-DNS-001..004; bindings AD-CFG-017..033.
- DFSR SYSVOL state, staging, content parity, MaxOfflineTimeInDays. Source: bindings AD-AVL-030, AD-AVL-031, AD-AVL-040; review AD-046.
- Virtual DC safeguards (msDS-GenerationId cannot tell physical from virtual). Source: bindings AD-BCK-008; review BK-007.
- AD CS CA-side flags - EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6), CA officer/manager rights (ESC7), RPC encryption enforcement (ESC11), disabled SID extension (ESC16), enrollment-agent restrictions (ESC3), HSM provider (ESC12). Source: checks ADX-PKI-001; review PKI-013.
- AD CS classic web enrollment (/certsrv) over HTTP - not in LDAP; only certificate enrollment web service URLs are (ADCS-CA-ENROLLMENT-OVER-HTTP). Source: review PKI-018; field (web enrollment served over HTTP).
- CA host health, database size, backup age, validity period, role services. Source: bindings PKI-HLT-*, PKI-BCK-001, PKI-CFG-003, PKI-CFG-006; review PKI-001, PKI-035.

## Needs event logs (eventlog pack)

- Directory Service, DFSR, DNS, KDC, NETLOGON, time, storage, Schannel, LSA, Group Policy and security-audit event families. Source: bindings AD-LOG-001..040, AD-MON-006..013; checks ADX-EVT-001; field (database write errors on a DC, NETLOGON 5719 on many clients, KDC certificate errors, Kerberos KRB_AP_ERR_MODIFIED on servers).
- RC4 service tickets actually issued (4769). Source: bindings AD-AUT-011.
- Audit policy, security log retention and forwarding. Source: bindings AD-MON-002, AD-MON-004, AD-MON-005.
- Template issuance, denied and pending requests, CA change events, SAN mismatches. Source: bindings PKI-CFG-005, PKI-HLT-008, PKI-HLT-009, PKI-MON-004/005/011.

## Needs SYSVOL or NETLOGON content (a SYSVOL reader)

- Local Administrators membership pushed by GPO (Restricted Groups, Group Policy Preferences Groups.xml) or by logon scripts - including broad groups such as Domain Users and SIDs that no longer resolve. The LDAP-visible halves are AD-USER-LOGON-SCRIPT, AD-GPO-GPP-LOCAL-GROUPS and AD-GPO-SCRIPTS (which GPOs to read). Source: field (logon script adding groups to local Administrators; a GPO adding Domain Users to local Administrators).
- Stored passwords (cpassword) in preference items - AD-GPO-GPP-CPASSWORD-CAPABLE lists the GPOs whose extensions can hold one; finding the value needs the XML. Source: proposals.
- Zero-filled or corrupt registry.pol and gpt.ini files (a zeroed gpt.ini stops all computer policy processing for the OUs it is linked to). Source: bindings AD-CFG-039; field.
- GPO AD version versus SYSVOL version, orphaned SYSVOL folders, empty linked GPOs. Source: bindings AD-CFG-035, AD-CFG-037, AD-CFG-038; review GPO-002, GPO-004.
- GPO settings - user rights granted to broad groups (log on locally, act as part of the OS, debug), signing disabled, firewall off, UAC off, AlwaysInstallElevated, Kerberos policy in the domain policy, logon rights on the DC OU, deny-logon GPOs for tier 0, ASR and script-engine hardening, LAPS policy coverage, baseline drift. Source: bindings AD-IAM-014, AD-IAM-036, AD-IAM-038, AD-CFG-045..053; checks ADX-GPO-001..003; field (log-on-locally to all users linked enforced at the root; DC policy rights stripping service privileges on workstations).
- Setting collisions and duplicate GPOs. Source: bindings AD-CFG-045, AD-CFG-046; field.
- GPOs and logon scripts that reference servers that no longer exist (UNC paths in registry.pol, scripts, scheduled tasks, drive maps). Source: field (root-linked GPOs pointing at decommissioned servers).
- GPOs for retired products still linked. Source: field (end-of-life anti-malware policies still linked).
- Credentials in NETLOGON and GPO scripts. Source: bindings AD-IAM-048.
- SYSVOL folder ACLs. Source: checks ADX-SYSV-001.
- GPO backup age. Source: bindings AD-BCK-007.

## Other sources or not a rule

- AD-aware backup age per naming context (dSASignature in msDS-ReplAttributeMetaData XML) - needs XML parsing of constructed metadata. Source: bindings AD-BCK-001; review BK-001; scripts.
- Replication health per DC (isSynchronized, pending operations, inbound/outbound neighbour failures, latency, partitions without inbound partners) - needs per-DC RootDSE and msDS-NCRepl*Neighbors XML. Source: bindings AD-AVL-001, AD-AVL-005, AD-AVL-007, AD-AVL-008, AD-AVL-020; review AD-020..025; field (inbound replication refused to one DC).
- FSMO holders reachable and placement - deleted holders are covered (AD-FSMO-DELETED-OWNER-*); liveness needs a network probe. Source: bindings AD-AVL-003, AD-AVL-004; review AD-035.
- SRV records and DC locator coverage. Source: bindings AD-AVL-002, AD-CFG-032.
- Backup product jobs and forest recovery rehearsal - attestation, not LDAP. Source: bindings AD-BCK-002, AD-BCK-003, AD-BCK-006.
- UPN suffixes versus verified cloud domains, sync scope per OU - cross-system (hybrid identity pack). Source: bindings AD-CFG-006, ENTRACONNECT-CFG-003; review AD-013, AD-502.
- Cloud-side identity problems (several authenticator registrations, personal recovery e-mail, cloud-only resource account whose password expired) - belong to the Entra pack. Source: field.
- Computers without BitLocker recovery information in AD - recovery data is in child msFVE-RecoveryInformation objects (secret attributes) and needs a parent-child join. Source: field (OS drive not protected on a workstation).
- Naming standards, personal admin accounts, leaver admin accounts, tenant-specific admin groups - organisation-specific; a tenant can add them in settings\rules. Source: bindings AD-HYG-016; checks ADX-TIER-001; review AD-135, AD-137, AD-142, AD-410.
- Legacy known-issue re-checks - organisation-specific, not ported. Source: bindings KN-*.
- Domain controller below an estate OS floor - not written as its own rule: AD-COMP-OS-SERVER-2012, AD-COMP-OS-SERVER-2016 and AD-COMP-OS-LEGACY already report every active DC older than 2019 and AD-DC-STALE the inactive ones, so a default floor would only repeat them; an estate floor above 2019 is a tenant rule. Source: proposals (AD-DC-OS-OLD).
- "No zones visible in DomainDnsZones" guard - no rule reads that partition (the legacy-storage rule reads the domain partition), and the guard would fire wherever DNS is not AD-integrated. Source: proposals (AD-DNS-NO-ZONES-VISIBLE).
