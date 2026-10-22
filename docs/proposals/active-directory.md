# Proposals - Active Directory and AD CS

Checks proposed for `rules/active-directory.yaml` and `rules/adcs.yaml`, written as specs for whoever
turns them into rules. Nothing here has been added to a rule file. Every proposal was checked against
the 112 AD and 13 AD CS rules that exist so it does not repeat one of them, and against the backlog so
items the current engine can now express become proposals.

Conventions used below:

- **Existing queries** are named after the rule that already carries them; a proposal that says
  "reuses Q-USER" must keep that rule's filter, attribute list and key byte-for-byte so the engine
  serves both from one fetch.
  - Q-USER - the user inventory (AD-USER-NO-DC-LOGON): filter `(&{USER}(!{UAC:2048}))`, attributes
    sAMAccountName, userPrincipalName, objectSid, userAccountControl, lastLogonTimestamp, pwdLastSet,
    whenCreated, accountExpires, msExchRecipientTypeDetails, servicePrincipalName, givenName, sn; key
    sAMAccountName.
  - Q-COMP - the computer inventory (AD-COMP-STALE): filter `(&{COMPUTER}{ENABLED})`, attributes
    sAMAccountName, dNSHostName, operatingSystem, operatingSystemVersion, lastLogonTimestamp,
    userAccountControl, pwdLastSet, whenCreated, adminCount, servicePrincipalName,
    msDS-SupportedEncryptionTypes, msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity,
    ms-Mcs-AdmPwdExpirationTime, msLAPS-PasswordExpirationTime; key sAMAccountName.
  - Q-DOM - the domain head (AD-DOM-MACHINE-ACCOUNT-QUOTA): base scope, `(objectClass=domainDNS)`,
    attributes name, minPwdLength, pwdHistoryLength, pwdProperties, lockoutThreshold,
    ms-DS-MachineAccountQuota, msDS-Behavior-Version, gPLink; key distinguishedName.
  - Q-PSO - fine-grained policies (AD-PSO-MIN-LENGTH): base `CN=Password Settings Container,CN=System,{DOMAINDN}`,
    onelevel, `(objectClass=msDS-PasswordSettings)`, attributes cn, msDS-PasswordSettingsPrecedence,
    msDS-MinimumPasswordLength, msDS-PasswordHistoryLength, msDS-PasswordComplexityEnabled,
    msDS-PasswordReversibleEncryptionEnabled, msDS-LockoutThreshold, msDS-PSOAppliesTo; key cn.
  - Q-TRUST - trusts (AD-TRUST-REVIEW): `(objectClass=trustedDomain)`, attributes cn, trustPartner,
    flatName, trustDirection, trustType, trustAttributes, msDS-SupportedEncryptionTypes, whenCreated,
    whenChanged; key cn.
  - Q-GPO - policy containers (AD-GPO-ALL-DISABLED): base `CN=Policies,CN=System,{DOMAINDN}`, onelevel,
    `(objectClass=groupPolicyContainer)`, attributes cn, displayName, flags, versionNumber,
    gPCFileSysPath; key cn.
  - Q-PART - the partitions container (AD-FOREST-FUNCTIONAL-LEVEL): base `CN=Partitions,{CONFIGDN}`,
    base scope, `(objectClass=crossRefContainer)`, attributes cn, msDS-Behavior-Version,
    msDS-EnabledFeature; key distinguishedName.
  - Q-TPL - certificate templates (ADCS-TPL-ESC1): base
    `CN=Certificate Templates,CN=Public Key Services,CN=Services,{CONFIGDN}`, onelevel,
    `(objectClass=pKICertificateTemplate)`, attributes cn, displayName, msPKI-Certificate-Name-Flag,
    msPKI-Enrollment-Flag, msPKI-RA-Signature, pKIExtendedKeyUsage, msPKI-Certificate-Application-Policy,
    msPKI-Template-Schema-Version, msPKI-Minimal-Key-Size, msPKI-Private-Key-Flag,
    msPKI-RA-Application-Policies; key cn.
  - Q-CA - enrollment services (ADCS-CA-PUBLISHES-CA-OR-AGENT-TEMPLATE): base
    `CN=Enrollment Services,CN=Public Key Services,CN=Services,{CONFIGDN}`, onelevel,
    `(objectClass=pKIEnrollmentService)`, attributes cn, dNSHostName, certificateTemplates,
    msPKI-Enrollment-Servers; key cn.
- **New queries** are numbered N1.. and shared between the proposals that name them.
- Protocol is `ldap` throughout; base is the domain partition unless stated.
- Confidence: **verified** = the attribute and its values are documented on Microsoft Learn at the link
  given; **likely** = documented, but the exact value or behaviour the condition depends on is from
  experience, not a doc sentence; **guess** = named from memory, confirm before use.
- Thresholds (`threshold.<name>`) are proposed defaults; a tenant tunes them.
- Group names in DNs (Domain Admins, Denied RODC Password Replication Group) assume the English default
  names, as the existing rules do. Where a proposal uses `adminCount=1` on group objects instead, it is
  localisation-free - SDProp marks every protected group, nested groups included.

AEU in "EKU" lists means the authentication EKU set the existing ADCS rules use: client authentication
1.3.6.1.5.5.7.3.2, PKINIT client 1.3.6.1.5.2.3.4, smart card logon 1.3.6.1.4.1.311.20.2.2, any purpose
2.5.29.37.0, matched on pKIExtendedKeyUsage or msPKI-Certificate-Application-Policy.

---

## Priority 1 - privilege and credential exposure (critical / high)

### AD-COMP-RBCD-BROAD-TRUSTEE
- **Catches**: a member computer whose resource-based constrained delegation descriptor allows a broad principal (Everyone, Authenticated Users, Users, Domain Users, Domain Computers, Domain Guests). Anyone in the domain can then obtain a service ticket to that host as any user - local administrator on it in one step.
- **Severity**: critical. Category AUT, entity computer, lens security.
- **Data**: reuses Q-COMP. The engine now returns `msDS-AllowedToActOnBehalfOfOtherIdentity` as the array of allowed SIDs.
- **Condition**: any element of msDS-AllowedToActOnBehalfOfOtherIdentity matches `^(S-1-1-0|S-1-5-7|S-1-5-11|S-1-5-32-545)$|-(513|514|515)$`.
- **Refs**: MITRE-ATTACK:T1558, NIST-800-53:AC-6, NIST-800-53:AC-3.
- **Fix**: clear the attribute or restrict it to the one service account that needs to delegate; find out who wrote it (the object's owner or a creator through the machine-account quota can).
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity ; well-known SIDs https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- Closes backlog "Who holds resource-based delegation rights" (presence only) - the trustee list is now readable; names are not resolved (engine gap below).

### AD-GROUP-PROTECTED-BROAD-MEMBER
- **Catches**: a protected group that is not a builtin group (Domain Admins, Enterprise Admins, Schema Admins, Key Admins, DnsAdmins-style custom groups nested in them) with Everyone, Authenticated Users, Domain Users, Domain Computers or Domain Guests as a direct member. AD-GROUP-BUILTIN-BROAD-MEMBER covers the builtin groups only.
- **Severity**: critical. Category IAM, entity group.
- **Data**: new query **N1** - filter `(&(objectClass=group)(adminCount=1))`, attributes cn, member, memberOf, whenChanged, objectSid, groupType, isCriticalSystemObject; key distinguishedName, name cn. (Shared by five proposals.)
- **Condition**: groupType lacks bit 1 (BUILTIN_LOCAL, so builtin groups are left to the existing rule) AND any member matches `^CN=(S-1-1-0|S-1-5-7|S-1-5-11|S-1-5-2|S-1-5-4),CN=ForeignSecurityPrincipals,|^CN=(Domain Users|Domain Computers|Domain Guests),CN=Users,`.
- **Refs**: NIST-800-53:AC-6(5), CIS-Controls-v8:5.4, MITRE-ATTACK:T1078.002.
- **Fix**: remove the broad principal; grant the specific accounts that need the right. Treat as an incident if nobody recognises the change.
- **Confidence**: verified - adminCount https://learn.microsoft.com/en-us/windows/win32/adschema/a-admincount ; groupType bits https://learn.microsoft.com/en-us/windows/win32/adschema/a-grouptype ; SDProp marks nested groups https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory

### AD-GROUP-PROTECTED-FOREIGN-MEMBER
- **Catches**: a protected group whose direct member is a foreign security principal from another domain or forest (S-1-5-21-... under CN=ForeignSecurityPrincipals). Administrative rights here then depend on the other directory's hygiene, and the member is invisible to this domain's user reviews.
- **Severity**: high. Category IAM, entity group.
- **Data**: reuses N1 (all protected groups, builtin included - Administrators is the usual place).
- **Condition**: any member matches `^CN=S-1-5-21-[0-9-]+,CN=ForeignSecurityPrincipals,`.
- **Refs**: NIST-800-53:AC-20, NIST-800-53:AC-6(5), MITRE-ATTACK:T1482.
- **Fix**: replace with an account in this domain, or document the cross-trust administrator and review it with the trust (AD-TRUST-REVIEW).
- **Confidence**: verified - foreign security principals https://learn.microsoft.com/en-us/windows/win32/adschema/c-foreignsecurityprincipal

### AD-GROUP-CUSTOM-NESTED-IN-PROTECTED
- **Catches**: a group the organisation created (not a critical system object) that carries adminCount=1 and is itself a member of other groups - a custom group nested inside a protected group. Whoever manages the custom group's membership is a domain administrator in practice, and reviews of Domain Admins show the group name, not the people.
- **Severity**: medium. Category IAM, entity group.
- **Data**: reuses N1.
- **Condition**: isCriticalSystemObject absent or not TRUE AND memberOf not empty.
- **Refs**: NIST-800-53:AC-6(5), NIST-800-53:AC-6(7), CIS-Controls-v8:5.4, PingCastle:P-AdminNum.
- **Fix**: flatten membership - put the accounts directly in the protected group, or keep the nested group but manage it with the same controls as the protected group (owner, review, no delegated writers).
- **Confidence**: verified - isCriticalSystemObject https://learn.microsoft.com/en-us/windows/win32/adschema/a-iscriticalsystemobject ; PingCastle rule id is a guess.

### AD-ADMINSDHOLDER-RECENTLY-CHANGED
- **Catches**: CN=AdminSDHolder,CN=System modified in the last 30 days. Its ACL is copied by SDProp onto every protected account and group, so an edit here is the classic way to plant a permanent backdoor on all administrators; SDProp itself never writes the object, so whenChanged moves only when someone edits it (installers such as Exchange do - confirm).
- **Severity**: high. Category MON, entity domain, kind misconfigured, refresh 1d.
- **Data**: new query **N2** - base `CN=AdminSDHolder,CN=System,{DOMAINDN}`, scope base, filter `(objectClass=container)`, attributes cn, whenChanged, whenCreated; key distinguishedName.
- **Condition**: whenChanged newer than 30 days (threshold `ad.adminsdholder-change-days`).
- **Refs**: NIST-800-53:AC-6, NIST-800-53:AU-12, MITRE-ATTACK:T1098, PingCastle:P-AdminSDHolder (guess).
- **Fix**: compare the current ACL with the documented default; remove any ACE nobody can account for and find the writer in the security log (event 5136 on the object). Partially covers backlog "AdminSDHolder ACEs beyond the default" - the ACL itself still needs descriptor decoding.
- **Confidence**: likely - the object and SDProp are documented (https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory); "SDProp does not touch whenChanged on AdminSDHolder" is from experience.

### AD-COMP-PASSWORD-NOT-REQUIRED
- **Catches**: an enabled computer account with PASSWD_NOTREQD (bit 32). The account may have an empty password, so anyone can authenticate as that computer - and a computer identity is enough for resource-based delegation and many service ACLs. AD-USER-PASSWORD-NOT-REQUIRED covers users only.
- **Severity**: high. Category IAM, entity computer.
- **Data**: reuses Q-COMP.
- **Condition**: userAccountControl has bit 32.
- **Refs**: NIST-800-53:IA-5, PingCastle:S-PwdNotRequired, MITRE-ATTACK:T1078.
- **Fix**: clear the flag and reset the machine password (`Reset-ComputerMachinePassword` on the host, or re-join); find the tool or script that creates accounts this way (pre-staging with the "pre-Windows 2000 computer" option sets a known password too).
- **Confidence**: verified - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

### AD-GPO-DEFAULT-POLICY-COMPUTER-DISABLED
- **Catches**: the Default Domain Policy or Default Domain Controllers Policy with its computer settings disabled (flags bit 2). Password, lockout and Kerberos policy are computer settings of the root-linked policy; DC user rights and audit come from the DC policy. Disabled, the domain silently runs on built-in defaults.
- **Severity**: high. Category CFG, entity gpo, refresh 7d.
- **Data**: reuses Q-GPO.
- **Condition**: cn in [`{31B2F340-016D-11D2-945F-00C04FB984F9}`, `{6AC1786C-016F-11D2-945F-00C04FB984F9}`] AND flags has bit 2.
- **Refs**: NIST-800-53:CM-6, NIST-800-53:AC-7, CIS-Controls-v8:4.1.
- **Fix**: re-enable the computer half (or confirm another root-linked GPO carries the password policy and the DC OU has a baseline, then document why the default is disabled).
- **Confidence**: verified - flags https://learn.microsoft.com/en-us/windows/win32/adschema/a-flags ; GPO flag values and the two well-known GUIDs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/ (section 2.2.4 and 3.2.1)

### AD-DC-OS-OLD
- **Catches**: a domain controller whose operating system is below the estate's floor (default: anything that is not Windows Server 2019, 2022 or 2025). DCs are the trust anchor; an old DC caps the functional level, keeps old Kerberos and NTLM defaults, and is often the one that misses patches. The existing OS rules grade every computer the same; a DC deserves its own line.
- **Severity**: high. Category LCM, entity computer, lens both.
- **Data**: reuses Q-COMP.
- **Condition**: userAccountControl has 8192 or 67108864 AND operatingSystem does not match `Server (2019|2022|2025)` (regex threshold `ad.dc-os-pattern`).
- **Refs**: NIST-800-53:SA-22, NIST-800-53:SI-2, CIS-Controls-v8:2.2.
- **Fix**: promote replacement DCs on a current release, move FSMO roles, demote the old ones, then raise the functional level (AD-DOM-FUNCTIONAL-LEVEL).
- **Confidence**: verified - operatingSystem https://learn.microsoft.com/en-us/windows/win32/adschema/a-operatingsystem ; UAC bits as above.

### ADCS-ACCOUNT-CERT-MAPPING-PRIVILEGED
- **Catches**: a privileged account (adminCount=1) with any explicit certificate mapping in altSecurityIdentities. The mapping is a second credential for an administrator that no password reset, MFA or Protected Users membership touches; whoever can write the attribute, or obtain a certificate that satisfies the mapping, is an administrator. ADCS-ACCOUNT-WEAK-CERT-MAPPING flags weak mapping forms on any account; this flags any form on privileged ones.
- **Severity**: medium (high when the mapping is a weak form - leave that to the existing rule). Category PKI, entity user. File: adcs.yaml.
- **Data**: new query **N3** - filter `(&{USER}(altSecurityIdentities=*)(adminCount=1))`, attributes sAMAccountName, displayName, altSecurityIdentities, userAccountControl; key sAMAccountName, name displayName.
- **Condition**: every row (`each: any`).
- **Refs**: MITRE-ATTACK:T1649, NIST-800-53:IA-5(2), NIST-800-53:AC-6, ADCS:ESC14.
- **Fix**: remove mappings administrators do not use; keep only strong forms (issuer+serial, SKI, public-key hash) and restrict write access to altSecurityIdentities on protected objects.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-altsecurityidentities ; mapping forms KB5014754 https://support.microsoft.com/kb/5014754

---

## Priority 2 - security hardening and change signals (medium / low)

### AD-PRIV-RECENTLY-CREATED
- **Catches**: an account marked adminCount=1 that was created in the last 30 days - a new administrator, or an attacker's account placed in a protected group.
- **Severity**: medium. Category MON, entity user, refresh 1d.
- **Data**: new query **N4** - filter `(&{USER}(adminCount=1)(whenCreated>={GT:30}))`, attributes sAMAccountName, displayName, whenCreated, userAccountControl, memberOf; key sAMAccountName, name displayName.
- **Condition**: every row.
- **Refs**: NIST-800-53:AC-2(4), NIST-800-53:AC-6(5), MITRE-ATTACK:T1136.002, CIS-Controls-v8:5.1.
- **Fix**: confirm the creation was approved (ticket, owner); otherwise disable, remove from the group, and investigate.
- **Confidence**: verified (whenCreated, adminCount). Note: the 30-day window sits in the filter macro, so it is not tenant-tunable (engine gap).

### AD-GROUP-PROTECTED-RECENTLY-CHANGED
- **Catches**: a protected group object modified in the last 7 days. Membership changes bump whenChanged on the group, so this is the cheapest "Domain Admins changed - was it approved?" signal without run-to-run diffing.
- **Severity**: medium. Category MON, entity group, refresh 1d.
- **Data**: reuses N1.
- **Condition**: whenChanged newer than 7 days (threshold `ad.protected-group-change-days`).
- **Refs**: NIST-800-53:AC-2(4), NIST-800-53:AU-12, CIS-Controls-v8:5.1, MITRE-ATTACK:T1098.
- **Fix**: match the change against change records; the security log (4728/4732/4756) names the member and the actor. Partially covers backlog "Domain Admins membership change since the last run" - which member changed still needs a diff.
- **Confidence**: verified - whenChanged https://learn.microsoft.com/en-us/windows/win32/adschema/a-whenchanged (member writes are replicated changes, so they update it).

### AD-USER-SMARTCARD-STATIC-HASH
- **Catches**: an enabled account with "smart card is required for interactive logon" (bit 262144) whose password has not changed for over a year. The NTLM hash behind such an account is random but never rotates unless the domain rolls it (a 2016-forest-level feature that must be switched on), so a hash stolen once works for years - pass-the-hash against the people who thought they had no password.
- **Severity**: medium. Category AUT, entity user.
- **Data**: reuses Q-USER.
- **Condition**: userAccountControl lacks 2, has 262144, pwdLastSet not 0, pwdLastSet older than 365 days (threshold `ad.smartcard-hash-max-age-days`).
- **Refs**: MITRE-ATTACK:T1550.002, NIST-800-53:IA-5(1), PingCastle:P-SmartCardRequired (guess).
- **Fix**: enable "rolling of expiring NTLM secrets" on the forest (msDS-ExpirePasswordsOnSmartCardOnlyAccounts on the domain head, forest level 2016), or toggle the flag off and on to regenerate the hash.
- **Confidence**: verified - UAC bit as above; rolling feature https://learn.microsoft.com/en-us/windows-server/identity/whats-new-active-directory-domain-services#rolling-public-key-only-users-ntlm-secrets. A companion check "domain head msDS-ExpirePasswordsOnSmartCardOnlyAccounts not TRUE" (add the attribute to a domain-head query) is worth adding - confidence likely.

### AD-USER-PASSWORD-NEVER-SET
- **Catches**: an enabled account created more than 30 days ago whose pwdLastSet is 0 - "must change password at next logon" that never happened. The initial password (set by the helpdesk, often the same for everyone) is still the password.
- **Severity**: medium. Category IAM, entity user.
- **Data**: reuses Q-USER.
- **Condition**: userAccountControl lacks 2, pwdLastSet equals 0, whenCreated older than 30 days (threshold `ad.password-never-set-days`), objectSid does not end in -501.
- **Refs**: NIST-800-53:IA-5, CIS-Controls-v8:5.2.
- **Fix**: if the person never started, disable the account; otherwise set a fresh one-time password and make them change it now.
- **Confidence**: verified - pwdLastSet 0 semantics https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdlastset

### AD-USER-LOCKOUT-WAVE
- **Catches**: more than N enabled accounts locked out in the last 24 hours - the fingerprint of password spraying, or of a service with a stale credential hammering many accounts.
- **Severity**: medium. Category MON, entity user, refresh 1d (6h would be better).
- **Data**: new query **N5** - filter `(&{USER}{ENABLED}(lockoutTime>={FT:1}))`, attributes sAMAccountName, displayName, lockoutTime; key sAMAccountName.
- **Condition**: count greater than 10 (threshold `ad.lockouts-per-day-max`).
- **Refs**: MITRE-ATTACK:T1110.003, NIST-800-53:AC-7, NIST-800-53:SI-4.
- **Fix**: pull the 4740 events from the PDC emulator for the caller computer; block the source; if it is a service, fix its credential.
- **Confidence**: verified - lockoutTime is FILETIME and updates on each lock https://learn.microsoft.com/en-us/windows/win32/adschema/a-lockouttime (note: not cleared when the lockout expires, hence the time window in the filter).

### AD-COMP-RBCD-SET
- **Catches**: any member computer with a non-empty resource-based delegation descriptor, listing the allowed SIDs, so the inventory of "who may impersonate users to this host" is visible. AD-DC-RBCD covers DCs, AD-USER-RBCD users; the broad-trustee case is Priority 1.
- **Severity**: info. Category AUT, entity computer.
- **Data**: reuses Q-COMP.
- **Condition**: userAccountControl lacks 8192 and 67108864 AND msDS-AllowedToActOnBehalfOfOtherIdentity exists (an empty DACL yields no elements and is not reported).
- **Refs**: MITRE-ATTACK:T1558, NIST-800-53:AC-6.
- **Fix**: confirm each trustee is the intended front-end service account; clear everything else.
- **Confidence**: verified (see Priority 1).

### AD-DC-DSRM-NOT-MANAGED
- **Catches**: a writable domain controller seen in the last 30 days with no Windows LAPS expiry attribute. Windows LAPS can rotate the DSRM administrator password on DCs; without it the DSRM password is usually the one typed at promotion, known to whoever promoted the DC and to every backup of it.
- **Severity**: low. Category IAM, entity computer, kind missing.
- **Data**: reuses Q-COMP.
- **Condition**: userAccountControl has 8192 AND lastLogonTimestamp newer than 30 days (threshold `ad.machine-active-days`) AND msLAPS-PasswordExpirationTime absent.
- **Refs**: NIST-800-53:IA-5(1), CIS-Controls-v8:5.2.
- **Fix**: enable Windows LAPS DSRM management by policy on the Domain Controllers OU ("Enable password backup for DSRM accounts").
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory#configure-windows-laps-to-back-up-dsrm-account-passwords (the DSRM password is stored in msLAPS-EncryptedDSRMPassword, secret-listed; the expiry attribute is the readable signal - likely that the same expiry attribute is used).

### AD-DC-MACHINE-PASSWORD-OLD
- **Catches**: a domain controller seen in the last 30 days whose own machine password is older than 90 days. AD-COMP-MACHINE-PASSWORD-STUCK excludes DCs; a DC that stops rotating usually has a broken secure channel to its partner, or "refuse machine password changes" set on the DC OU.
- **Severity**: medium. Category AUT, entity computer, kind broken, lens both.
- **Data**: reuses Q-COMP.
- **Condition**: userAccountControl has 8192 or 67108864 AND lastLogonTimestamp newer than 30 days AND pwdLastSet not 0 AND pwdLastSet older than 90 days (threshold `ad.machine-password-max-age-days`).
- **Refs**: NIST-800-53:IA-5(1).
- **Fix**: `nltest /sc_verify` and the Netlogon log on the DC; check the DC policy for "Domain controller: Refuse machine account password changes" and "Domain member: Disable machine account password changes".
- **Confidence**: verified (pwdLastSet, lastLogonTimestamp).

### AD-GPO-GPP-CPASSWORD-CAPABLE
- **Catches**: a GPO that registers a Group Policy Preferences extension able to store credentials (Local Users and Groups, Drive Maps, Scheduled Tasks, Services, Data Sources). The preference XML may carry a `cpassword`, which every domain user can read and decrypt with the published key (MS14-025). LDAP shows which GPOs to open; the XML itself is a SYSVOL read.
- **Severity**: medium. Category IAM, entity gpo, refresh 7d.
- **Data**: new query **N6** - base `CN=Policies,CN=System,{DOMAINDN}`, onelevel, `(objectClass=groupPolicyContainer)`, attributes cn, displayName, gPCMachineExtensionNames, gPCUserExtensionNames, whenChanged, flags; key cn, name displayName. (Shared by four proposals.)
- **Condition**: gPCMachineExtensionNames or gPCUserExtensionNames matches `17D89FEC-5C44-4972-B12D-241CAEF74509|5794DAFD-BE60-433F-88A2-1A31939AC01F|AADCED64-746C-4633-A97C-D61349046527|91FBB303-0CD5-4055-BF42-E512A681B325|728EE579-943C-4519-9EF7-AB56765798ED`.
- **Refs**: MITRE-ATTACK:T1552.006, NIST-800-53:IA-5(7), MS-KB:2962486.
- **Fix**: search the GPO's folder in SYSVOL for `cpassword`; remove the item, rotate the password it held, and use LAPS or a gMSA instead.
- **Confidence**: verified - extension name attributes https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/ (gPCMachineExtensionNames, section 2.2.4); CSE GUIDs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/ (section 1.9 / 2.2.1 lists the preference CSE GUIDs); MS14-025 https://support.microsoft.com/kb/2962486. Partially covers backlog "Local Administrators membership pushed by GPO" (which GPOs to read).

### AD-GPO-GPP-LOCAL-GROUPS
- **Catches**: a GPO that uses the Local Users and Groups preference extension. These items add accounts and groups (often Domain Users) to local Administrators on every computer in scope; the content is only in SYSVOL, but the list of GPOs that do it is here.
- **Severity**: low. Category IAM, entity gpo, lens security, refresh 7d.
- **Data**: reuses N6.
- **Condition**: either extension list matches `17D89FEC-5C44-4972-B12D-241CAEF74509`.
- **Refs**: NIST-800-53:AC-6(1), CIS-Controls-v8:5.4, MITRE-ATTACK:T1098.
- **Fix**: open Groups.xml under the GPO's Machine\Preferences\Groups folder; remove broad principals from Administrators; prefer Restricted Groups with explicit membership, or LAPS plus no standing local admins.
- **Confidence**: verified (same links).

### AD-GPO-STARTUP-SCRIPTS
- **Catches**: a GPO with the Scripts extension registered - startup/shutdown (SYSTEM) or logon/logoff scripts whose content is not visible over LDAP, a favourite place for leftovers that map dead servers or change local groups.
- **Severity**: low. Category CFG, entity gpo, lens both, refresh 7d.
- **Data**: reuses N6.
- **Condition**: either extension list matches `42B5FAAE-6536-11D2-AE5A-0000F87571E3`.
- **Refs**: NIST-800-53:CM-7, MITRE-ATTACK:T1037.
- **Fix**: review scripts.ini and the script files in the GPO folder; move what is still needed to preferences or management tooling.
- **Confidence**: verified (MS-GPOL scripts extension GUID, https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpscr/).

### AD-TRUST-SELECTIVE-AUTH-OFF
- **Catches**: an outbound or two-way external or forest trust without selective authentication (TRUST_ATTRIBUTE_CROSS_ORGANIZATION, 0x10). Every user of the other domain is then an "Authenticated User" here and reaches whatever that principal can read - most of the directory.
- **Severity**: medium. Category IAM, entity trust, refresh 7d.
- **Data**: reuses Q-TRUST.
- **Condition**: trustDirection in [2, 3] AND trustType in [1, 2] AND trustAttributes lacks 0x20 (within forest) AND trustAttributes lacks 0x10.
- **Refs**: NIST-800-53:AC-20, NIST-800-53:AC-3, MITRE-ATTACK:T1482.
- **Fix**: switch the trust to selective authentication and grant "Allowed to authenticate" on the specific servers the other domain's users need.
- **Confidence**: verified - trustAttributes https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c ; trustDirection https://learn.microsoft.com/en-us/windows/win32/adschema/a-trustdirection

### AD-TRUST-ACCOUNT-PASSWORD-OLD
- **Catches**: an interdomain trust account (UAC 2048, the `<domain>$` account an inbound or two-way trust creates here) whose password is older than 60 days. The trust password is renewed every 30 days by the trusting side; an old one means the other side has been unreachable for weeks or was decommissioned without removing the trust.
- **Severity**: medium. Category AVL, entity trust, kind broken, lens maintenance.
- **Data**: new query **N7** - filter `(&{USER}{UAC:2048})`, attributes sAMAccountName, pwdLastSet, whenCreated, userAccountControl; key sAMAccountName.
- **Condition**: pwdLastSet older than 60 days (threshold `ad.trust-password-max-age-days`).
- **Refs**: NIST-800-53:AC-20, NIST-800-53:CP-10.
- **Fix**: `netdom trust /verify` from both sides; reset the trust or delete it if the partner domain is gone (then the account and the trustedDomain object go too).
- **Confidence**: likely - INTERDOMAIN_TRUST_ACCOUNT bit is documented (UAC link above); the 30-day trust password rotation is documented for the Netlogon secure channel (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ section 3.1.4.9 and the trust password change behaviour) but "pwdLastSet on the trust account reflects it" is from experience.

### AD-RODC-REVEAL-BROAD
- **Catches**: a read-only domain controller allowed to cache the passwords of a broad group (Domain Users, Domain Computers, Authenticated Users, Everyone) or of administrators. An RODC is placed where physical security is weak; a stolen one then yields every cached password.
- **Severity**: medium. Category IAM, entity computer, refresh 7d.
- **Data**: new query **N8** - filter `(&{COMPUTER}{UAC:67108864})`, attributes sAMAccountName, dNSHostName, msDS-RevealOnDemandGroup, msDS-NeverRevealGroup, managedBy; key sAMAccountName, name dNSHostName. (Shared by two proposals.)
- **Condition**: any msDS-RevealOnDemandGroup value matches `^CN=(Domain Users|Domain Computers|Domain Admins|Enterprise Admins|Administrators),|^CN=(S-1-1-0|S-1-5-11),CN=ForeignSecurityPrincipals,`.
- **Refs**: NIST-800-53:AC-6, NIST-800-53:PE-3, MITRE-ATTACK:T1003.
- **Fix**: allow only a site-specific group of the users and computers that actually log on at that location.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-revealondemandgroup

### AD-RODC-NEVER-REVEAL-MISSING
- **Catches**: an RODC whose denied list no longer contains the Denied RODC Password Replication Group or Domain Admins - someone removed the default protection, so administrator secrets may be cached on the RODC.
- **Severity**: medium. Category IAM, entity computer, refresh 7d.
- **Data**: reuses N8.
- **Condition**: msDS-NeverRevealGroup absent OR no value matches `^CN=(Denied RODC Password Replication Group|Domain Admins),`.
- **Refs**: NIST-800-53:AC-6, MITRE-ATTACK:T1003.
- **Fix**: restore the default denied groups (Denied RODC Password Replication Group, Account/Server/Backup Operators, Administrators).
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-neverrevealgroup ; default membership https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/rodc/password-replication-policy

### AD-DOM-MAX-PASSWORD-AGE
- **Catches**: a domain password policy where passwords never expire (maxPwdAge "never") or expire after more than a year. Without breached-password screening and MFA everywhere, a password that never changes outlives every leak. The engine now reads durations as days and the most negative value as "never", which is what kept this out of the pack.
- **Severity**: medium. Category IAM, entity domain, refresh 7d.
- **Data**: new query **N9** - base scope, `(objectClass=domainDNS)`, attributes name, maxPwdAge, minPwdAge, lockoutDuration, lockOutObservationWindow, lockoutThreshold, wellKnownObjects, msDS-ExpirePasswordsOnSmartCardOnlyAccounts; key distinguishedName, name name. (Shared by five proposals. Alternatively extend Q-DOM with these attributes in all nine rules that carry it.)
- **Condition**: maxPwdAge equals "never" OR maxPwdAge greater than 365 (threshold `ad.domain-password-max-age-days`).
- **Refs**: NIST-800-53:IA-5(1), CIS-Controls-v8:5.2, PingCastle:S-PwdNeverExpires (guess for the policy-level id).
- **Fix**: set a maximum age in the root-linked policy; if the organisation follows no-expiry guidance, it must have breached-password screening, MFA and this rule marked as accepted with the reason.
- **Confidence**: verified - maxPwdAge https://learn.microsoft.com/en-us/windows/win32/adschema/a-maxpwdage ; conversion checked in the engine (LdapValues.DurationAttributes). Closes backlog "Maximum password age and lockout duration" for the age half.

### AD-DOM-MIN-PASSWORD-AGE-ZERO
- **Catches**: minimum password age of 0 days: a user can change the password 24 times in a minute and land back on the old one, which makes the history rule meaningless.
- **Severity**: low. Category IAM, entity domain, refresh 7d.
- **Data**: reuses N9.
- **Condition**: minPwdAge equals 0.
- **Refs**: NIST-800-53:IA-5(1).
- **Fix**: set minimum age to 1 day.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-minpwdage

### AD-DOM-LOCKOUT-THRESHOLD-HIGH
- **Catches**: a lockout threshold above 10 bad attempts (AD-DOM-NO-LOCKOUT covers 0). A high threshold gives spraying tools room to try several passwords per account per window without locking anyone.
- **Severity**: low. Category IAM, entity domain, refresh 7d.
- **Data**: reuses Q-DOM.
- **Condition**: lockoutThreshold greater than 10 (threshold `ad.lockout-threshold-max`).
- **Refs**: NIST-800-53:AC-7, CIS-Controls-v8:4.1.
- **Fix**: lower the threshold (5-10) with a short lockout duration.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-lockoutthreshold

### AD-PSO-NO-LOCKOUT
- **Catches**: a fine-grained policy with lockout threshold 0; the accounts it covers (usually administrators or services) can be guessed against without limit while the domain policy locks everyone else.
- **Severity**: medium. Category IAM, entity policy, refresh 7d.
- **Data**: reuses Q-PSO.
- **Condition**: msDS-LockoutThreshold equals 0.
- **Refs**: MITRE-ATTACK:T1110.003, NIST-800-53:AC-7.
- **Fix**: set a threshold on the PSO, or accept it only for service accounts with long random passwords and document it.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-lockoutthreshold

### AD-PSO-HISTORY-SHORT
- **Catches**: a fine-grained policy that remembers fewer than 24 passwords.
- **Severity**: low. Category IAM, entity policy, refresh 7d.
- **Data**: reuses Q-PSO.
- **Condition**: msDS-PasswordHistoryLength less than 24 (threshold `ad.password-history-min`).
- **Refs**: NIST-800-53:IA-5(1).
- **Fix**: raise the history length on the PSO.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-passwordhistorylength

### AD-PSO-MAX-AGE
- **Catches**: a fine-grained policy whose maximum password age is "never" or longer than a year. PSOs usually cover service and administrator accounts, exactly the ones whose passwords should rotate.
- **Severity**: medium. Category IAM, entity policy, refresh 7d.
- **Data**: new query **N10** - base `CN=Password Settings Container,CN=System,{DOMAINDN}`, onelevel, `(objectClass=msDS-PasswordSettings)`, attributes cn, msDS-MaximumPasswordAge, msDS-MinimumPasswordAge, msDS-LockoutDuration, msDS-PSOAppliesTo; key cn. (Or extend Q-PSO with these attributes.)
- **Condition**: msDS-MaximumPasswordAge matches `^-9223372036854775808$` OR is less than -315360000000000 (365 days in negative 100 ns ticks; the runner does not convert msDS-* durations, so the threshold is in ticks - engine gap).
- **Refs**: NIST-800-53:IA-5(1).
- **Fix**: set a maximum age on the PSO; move service accounts to gMSAs.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-maximumpasswordage (negative Int64 of 100 ns intervals; most negative = never).

### AD-PSO-MIN-AGE-ZERO
- **Catches**: a fine-grained policy with minimum age 0 (history can be cycled through).
- **Severity**: low. Category IAM, entity policy, refresh 7d.
- **Data**: reuses N10.
- **Condition**: msDS-MinimumPasswordAge equals 0.
- **Refs**: NIST-800-53:IA-5(1).
- **Fix**: set minimum age to at least 1 day.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-minimumpasswordage

### AD-FOREST-PAM-FEATURE-OFF
- **Catches**: the Privileged Access Management optional feature is not enabled, so time-bound (expiring) group membership is unavailable and every administrative membership is standing.
- **Severity**: low. Category IAM, entity domain, kind missing, refresh 7d.
- **Data**: reuses Q-PART.
- **Condition**: msDS-EnabledFeature absent OR no value matches `^CN=Privileged Access Management Feature,`.
- **Refs**: NIST-800-53:AC-6(5), NIST-800-53:AC-2(2), CIS-Controls-v8:5.4.
- **Fix**: `Enable-ADOptionalFeature 'Privileged Access Management Feature'` at forest level 2016; note it cannot be disabled afterwards. Then use `-MemberTimeToLive` for just-in-time membership.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows-server/identity/whats-new-active-directory-domain-services#privileged-access-management ; feature object name likely (seen as `CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,<config>`).

### AD-DNS-NO-WILDCARD
- **Catches**: no wildcard (`*`) record in any zone of the domain DNS application partition. Authenticated users may create records for names that do not exist, so an attacker registers names that clients look up (WPAD-style, typos, retired hosts) and answers them; a wildcard record is the documented mitigation. If the domain zone replicates forest-wide, this partition is empty of it - see the fix.
- **Severity**: low. Category CFG, entity domain, kind missing, refresh 7d.
- **Data**: new query **N11** - base `DC=DomainDnsZones,{DOMAINDN}`, subtree, filter `(&(objectClass=dnsNode)(dc=\2a))`, attributes dc, name, whenCreated; key distinguishedName.
- **Condition**: count none.
- **Refs**: MITRE-ATTACK:T1557, NIST-800-53:SC-20, NIST-800-53:AC-6.
- **Fix**: add a wildcard A record pointing at an unroutable or sinkhole address in each AD-integrated zone, and add the names clients commonly look up (wpad, isatap) to the global query block list; if the domain zone lives in ForestDnsZones, mark this not applicable and check there (engine gap: base cannot be a threshold).
- **Confidence**: verified - dnsNode class https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ (section 2.3.2.1); `\2a` is the RFC 4515 escape for `*`; wildcard mitigation is widely published (ADIDNS) rather than a Microsoft doc sentence - likely.

### AD-SCHEMA-RECENT-EXTENSION
- **Catches**: attribute or class definitions created in the schema in the last 30 days. Schema extensions are rare, irreversible and need Schema Admins - an unplanned one means either an undocumented product install or a Schema Admins misuse.
- **Severity**: info. Category MON, entity domain, refresh 1d.
- **Data**: new query **N12** - base schema, onelevel, filter `(&(|(objectClass=attributeSchema)(objectClass=classSchema))(whenCreated>={GT:30}))`, attributes lDAPDisplayName, whenCreated, objectClass; key lDAPDisplayName.
- **Condition**: every row.
- **Refs**: NIST-800-53:CM-3, NIST-800-53:AC-6(5).
- **Fix**: match against the change record of the product that extended the schema; empty Schema Admins again (AD-GROUP-SCHEMA-ADMINS-SIZE).
- **Confidence**: verified - attributeSchema/classSchema https://learn.microsoft.com/en-us/windows/win32/adschema/c-attributeschema

### AD-GROUP-ORPHAN-ADMINCOUNT
- **Catches**: a custom group still marked adminCount=1 but no longer a member of any group - it left the protected set, but inheritance stays blocked and the old administrator-only ACL remains, so delegated permissions on its OU never apply. The user-side twin is AD-PRIV-ORPHAN-ADMINCOUNT.
- **Severity**: low. Category IAM, entity group, lens both.
- **Data**: reuses N1.
- **Condition**: isCriticalSystemObject absent or not TRUE AND memberOf absent.
- **Refs**: NIST-800-53:AC-6.
- **Fix**: clear adminCount and re-enable inheritance on the group.
- **Confidence**: verified (adminCount, memberOf).

### AD-USER-DISABLED-WITH-GROUPS
- **Catches**: disabled accounts that still hold group memberships (beyond the admin groups AD-USER-DISABLED-IN-ADMIN-GROUP covers). Re-enabling restores every access at once, and the groups' own reviews count ghosts.
- **Severity**: low. Category IAM, entity user, lens both.
- **Data**: new query **N13** - filter `(&{USER}{UAC:2}(!{UAC:2048}))`, attributes sAMAccountName, displayName, whenChanged, memberOf, objectSid; key sAMAccountName, name displayName. (Shared with AD-USER-DISABLED-LONG.)
- **Condition**: count with where (memberOf not empty AND objectSid does not match `-50[1-3]$`) greater than 0 (threshold `ad.disabled-users-with-groups-max`).
- **Refs**: NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- **Fix**: make "remove all memberships" part of the leaver step; strip memberships from the accounts listed.
- **Confidence**: verified (memberOf, objectSid; RIDs 501-503 are Guest, krbtgt, DefaultAccount).

### ADCS-PKI-OBJECT-RECENTLY-CHANGED
- **Catches**: a certificate template, enrollment service or enterprise OID object changed in the last 7 days. Template edits are how ESC4 is exploited (make a benign template vulnerable, enroll, revert); publication changes on the CA are how ESC1/2/3 templates go live. File: adcs.yaml.
- **Severity**: medium. Category MON, entity policy, refresh 1d.
- **Data**: new query **N14** - base `CN=Public Key Services,CN=Services,{CONFIGDN}`, subtree, filter `(&(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService)(objectClass=msPKI-Enterprise-Oid))(whenChanged>={GT:7}))`, attributes cn, displayName, objectClass, whenChanged, whenCreated; key distinguishedName, name cn.
- **Condition**: every row.
- **Refs**: MITRE-ATTACK:T1649, NIST-800-53:CM-3, NIST-800-53:AU-12, ADCS:ESC4.
- **Fix**: match the change against the PKI change log (CA audit event 4898/4899 for template loads); if nobody made it, treat as an incident and compare the template with its backup.
- **Confidence**: verified - object classes https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ and https://learn.microsoft.com/en-us/windows/win32/adschema/c-pkienrollmentservice

### ADCS-TPL-KEY-ARCHIVAL-AUTH
- **Catches**: an authentication template that requires private-key archival (msPKI-Private-Key-Flag bit 1). The CA then holds a copy of every logon private key it issued; CA or KRA compromise gives usable logon credentials for every holder, and archival is meant for encryption keys only. File: adcs.yaml.
- **Severity**: low. Category PKI, entity policy.
- **Data**: reuses Q-TPL.
- **Condition**: msPKI-Private-Key-Flag has bit 1 AND EKU is an authentication EKU (AEU set).
- **Refs**: MITRE-ATTACK:T1649, NIST-800-53:SC-12.
- **Fix**: clear "archive subject's encryption private key" on logon templates; archive only encryption (EFS, S/MIME) keys.
- **Confidence**: verified - CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667

### ADCS-POP-CA-NONE
- **Catches**: no enterprise CA registered in the configuration partition. Every CA rule then passes without data; either the estate has no AD CS (mark the pack not applicable) or the reader cannot see the container. File: adcs.yaml.
- **Severity**: info. Category MON, entity domain, kind missing, lens maintenance.
- **Data**: reuses Q-CA.
- **Condition**: count none.
- **Refs**: NIST-800-53:CA-7.
- **Fix**: if AD CS exists, check the integration account's read access to CN=Public Key Services; otherwise accept the finding as "no AD CS".
- **Confidence**: verified (pKIEnrollmentService objects are created per enterprise CA).

---

## Priority 3 - hygiene that breaks things (replication, sites, DNS, policy structure)

### AD-SITE-SERVER-DELETED-REFERENCE
- **Catches**: a server object under CN=Sites whose serverReference points at a deleted computer object - a domain controller removed without metadata cleanup. Partners keep trying to replicate with it, the KCC builds topology around it, and DNS still advertises it.
- **Severity**: high. Category AVL, entity computer, kind broken, lens maintenance, refresh 7d.
- **Data**: new query **N15** - base `CN=Sites,{CONFIGDN}`, subtree, `(objectClass=server)`, attributes cn, serverReference, dNSHostName, bridgeheadTransportList, whenChanged; key distinguishedName, name cn. (Shared by three proposals.)
- **Condition**: serverReference matches `(\\0A|\n)DEL:` (same pattern as AD-FSMO-DELETED-OWNER-*).
- **Refs**: NIST-800-53:CP-10, NIST-800-53:CM-8.
- **Fix**: `ntdsutil metadata cleanup` (or delete the server object from Sites and Services), then remove its DNS records and any manual connections.
- **Confidence**: verified - serverReference https://learn.microsoft.com/en-us/windows/win32/adschema/a-serverreference ; metadata cleanup https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/ad-ds-metadata-cleanup. Closes part of backlog "Ghost DC metadata".

### AD-REPL-CONNECTION-FROM-DELETED
- **Catches**: an nTDSConnection whose fromServer points at a deleted NTDS Settings object - a replication link from a DC that no longer exists; the destination logs inbound failures forever.
- **Severity**: high. Category AVL, entity domain, kind broken, lens maintenance, refresh 7d.
- **Data**: new query **N16** - base `CN=Sites,{CONFIGDN}`, subtree, `(objectClass=nTDSConnection)`, attributes cn, fromServer, options, enabledConnection, whenChanged; key distinguishedName. (AD-REPL-CONNECTION-UNMANAGED has a narrower filter; keep it as is.)
- **Condition**: fromServer matches `(\\0A|\n)DEL:`.
- **Refs**: NIST-800-53:CP-10.
- **Fix**: delete the connection object; let the KCC rebuild; finish the metadata cleanup of the missing DC.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-fromserver. Closes "connections from dead servers" in backlog "Ghost DC metadata".

### AD-SITE-SERVER-ORPHAN
- **Catches**: a server object in a site with no serverReference at all - left behind by a demotion that did not finish, or created by hand.
- **Severity**: low. Category HYG, entity computer, lens maintenance, refresh 7d.
- **Data**: reuses N15.
- **Condition**: serverReference absent.
- **Refs**: NIST-800-53:CM-8.
- **Fix**: confirm the object has no NTDS Settings child and delete it.
- **Confidence**: likely - a server object without serverReference is not a DC; whether any legitimate tooling creates such objects is from experience.

### AD-SITE-BRIDGEHEAD-PREFERRED
- **Catches**: a DC designated as preferred bridgehead (bridgeheadTransportList set). When a preferred bridgehead is down the ISTG does not fail over to another DC in that site, so intersite replication for the site stops; a design choice that is usually a forgotten one.
- **Severity**: low. Category AVL, entity computer, lens maintenance, refresh 7d.
- **Data**: reuses N15.
- **Condition**: bridgeheadTransportList exists.
- **Refs**: NIST-800-53:CP-10.
- **Fix**: remove the preferred-bridgehead designation unless the site's firewall design needs it; if it does, designate at least two.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-bridgeheadtransportlist. Closes the bridgehead half of backlog "Sites without a domain controller, GC placement, ISTG and bridgehead".

### AD-SITE-NO-SUBNET
- **Catches**: a site with no subnet associated (siteObjectBL empty) - no client can be placed in it, so its DCs serve nobody locally, or a decommissioned site survived.
- **Severity**: low. Category CFG, entity domain, lens maintenance, refresh 7d.
- **Data**: new query **N17** - base `CN=Sites,{CONFIGDN}`, onelevel, `(&(objectClass=site)(!(siteObjectBL=*)))`, attributes cn, description, gPLink, whenCreated; key cn.
- **Condition**: every row.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: add the site's subnets or delete the site (move its DCs first).
- **Confidence**: verified - siteObjectBL is the back-link of subnet.siteObject https://learn.microsoft.com/en-us/windows/win32/adschema/a-siteobjectbl

### AD-SITELINK-SINGLE-SITE
- **Catches**: a site link with fewer than two sites - it links nothing; typical leftover after a site was removed, and it confuses cost calculations.
- **Severity**: low. Category HYG, entity domain, lens maintenance, refresh 7d.
- **Data**: new query **N18** - base `CN=Inter-Site Transports,CN=Sites,{CONFIGDN}`, subtree, `(objectClass=siteLink)`, attributes cn, cost, replInterval, siteList, options; key distinguishedName, name cn. (Shared by two proposals.)
- **Condition**: siteList absent OR siteList has fewer than 2 elements (size-lt 2; a single value arrives as a scalar and counts as 1).
- **Refs**: NIST-800-53:CM-6.
- **Fix**: delete the link, or add the second site.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-sitelist

### AD-SITELINK-SLOW
- **Catches**: a site link whose replication interval exceeds 180 minutes (default is 180 on DEFAULTIPSITELINK). Password resets, lockouts and group changes take hours to reach the far site.
- **Severity**: low. Category AVL, entity domain, lens maintenance, refresh 7d.
- **Data**: reuses N18.
- **Condition**: replInterval greater than 180 (threshold `ad.sitelink-max-interval-minutes`).
- **Refs**: NIST-800-53:CP-10.
- **Fix**: lower the interval (15 minutes is common on modern links) or enable change notification on the link (options bit 1).
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-replinterval

### AD-DC-NOT-GC
- **Catches**: a domain controller that is not a global catalog (NTDS Settings options bit 1 clear). In a single-domain forest every DC should be a GC; without one, UPN logons and universal-group lookups fail when the GC is down. Multi-domain forests may do this by design - threshold-free, so tune by accepting the finding.
- **Severity**: low. Category AVL, entity computer, lens maintenance, refresh 7d.
- **Data**: new query **N19** - base `CN=Sites,{CONFIGDN}`, subtree, `(objectClass=nTDSDSA)`, attributes cn, options, msDS-HasDomainNCs, whenCreated; key distinguishedName.
- **Condition**: options absent OR options lacks bit 1.
- **Refs**: NIST-800-53:CP-10, NIST-800-53:SC-36.
- **Fix**: tick "Global Catalog" on the NTDS Settings object and wait for the partial replicas to build.
- **Confidence**: verified - NTDSDSA_OPT_IS_GC https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5. Closes the GC-placement half of the backlog item (per-site placement still needs the join).

### AD-DNS-NO-ZONES-VISIBLE
- **Catches**: the domain DNS application partition returns no zones (besides RootDNSServers and TrustAnchors). Either DNS is not AD-integrated here, or the reader cannot see the partition - in both cases every DNS rule passes without looking. The no-data guard for the DNS proposals.
- **Severity**: high. Category MON, entity domain, kind broken, lens maintenance, refresh 7d.
- **Data**: new query **N20** - base `DC=DomainDnsZones,{DOMAINDN}`, subtree, `(&(objectClass=dnsZone)(!(dc=RootDNSServers))(!(dc=..TrustAnchors)))`, attributes dc, whenCreated, whenChanged; key distinguishedName.
- **Condition**: count none.
- **Refs**: NIST-800-53:CA-7.
- **Fix**: confirm the DNS storage scope (`Get-DnsServerZone` ReplicationScope) and the reader's access to the partition.
- **Confidence**: verified - dnsZone objects and partition layout https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ (section 2.3.1); `..TrustAnchors` zone name likely.

### AD-DNS-ZONE-LEGACY-STORAGE
- **Catches**: a DNS zone stored in the domain partition (CN=MicrosoftDNS,CN=System) instead of an application partition - pre-2003 storage that replicates the zone to every DC in the domain, DNS server or not, and cannot be scoped to the forest.
- **Severity**: low. Category CFG, entity domain, lens maintenance, refresh 7d.
- **Data**: new query **N21** - base domain, subtree, `(&(objectClass=dnsZone)(!(dc=RootDNSServers)))`, attributes dc, whenCreated; key distinguishedName. (A subtree search of the domain partition does not descend into the application partitions, so only legacy-stored zones answer.)
- **Condition**: every row.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: change the zone's replication scope to "all DNS servers in the domain" (DomainDnsZones) from DNS Manager.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows-server/networking/dns/deploy/dns-replication-scope (legacy "all domain controllers in the domain" scope)

### AD-OU-BLOCK-INHERITANCE
- **Catches**: an OU with "block policy inheritance" (gPOptions=1). Domain-level baselines - including security settings - stop at that OU unless enforced; the OU's objects get only what is linked there.
- **Severity**: low. Category CFG, entity domain, lens both, refresh 7d.
- **Data**: new query **N22** - filter `(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))(|(gPLink=*)(gPOptions=1)))`, attributes name, gPLink, gPOptions; key distinguishedName, name name. (Shared by two proposals.)
- **Condition**: gPOptions equals 1.
- **Refs**: NIST-800-53:CM-6, CIS-Controls-v8:4.1.
- **Fix**: remove the block, or enforce the baselines that must reach the OU and document the rest.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-gpoptions

### AD-OU-DISABLED-GPO-LINK
- **Catches**: a GPO link whose link options have the disabled bit (`;1]` or `;3]` in gPLink). The GPO looks linked in every tool but does nothing; later someone "fixes" it by enabling the link and deploys years-old settings.
- **Severity**: low. Category HYG, entity domain, lens maintenance, refresh 7d.
- **Data**: reuses N22.
- **Condition**: gPLink matches `;[13]\]`.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: remove the link (and the GPO if unlinked everywhere) or enable it deliberately after review.
- **Confidence**: verified - gPLink format and link options https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/ (section 2.2.2)

### AD-SITE-GPO-LINK
- **Catches**: a GPO linked to a site. Site links apply to every computer in the site across all domains of the forest and are reviewed by almost nobody.
- **Severity**: low. Category CFG, entity domain, lens both, refresh 7d.
- **Data**: new query **N23** - base `CN=Sites,{CONFIGDN}`, onelevel, `(&(objectClass=site)(gPLink=*))`, attributes cn, gPLink, gPOptions; key cn.
- **Condition**: gPLink matches `LDAP://`.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: move the setting to domain or OU links unless the site scope is intended; document it.
- **Confidence**: verified (gPLink on site objects, MS-GPOL section 3.2.5.1.4).

### AD-GPO-RECENTLY-CHANGED
- **Catches**: GPOs changed in the last 7 days - the "what changed this week" list for the policy map, and the first place to look when a wave of workstation problems starts.
- **Severity**: info. Category MON, entity gpo, lens both, refresh 1d.
- **Data**: reuses N6.
- **Condition**: whenChanged newer than 7 days (threshold `ad.gpo-change-days`).
- **Refs**: NIST-800-53:CM-3.
- **Fix**: match each against change records; back up the GPO before and after.
- **Confidence**: verified (whenChanged; the versionNumber also increments).

### AD-DOM-COMPUTERS-CONTAINER-NOT-REDIRECTED
- **Catches**: new computer objects still default to CN=Computers (wellKnownObjects entry for the computers container points at CN=Computers). Every machine joined without an explicit OU lands where no GPO, LAPS policy or delegation reaches; AD-COMP-DEFAULT-CONTAINER counts the result, this names the cause.
- **Severity**: low. Category CFG, entity domain, lens both, refresh 7d.
- **Data**: reuses N9.
- **Condition**: any wellKnownObjects value matches `^B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,`.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: `redircmp "OU=<staging OU>,DC=example,DC=org"` (domain level 2003 or higher).
- **Confidence**: verified - well-known object GUIDs https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5a00c890-6be5-4575-93c4-8bf8be0ca8d8 ; redircmp https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers

### AD-DOM-USERS-CONTAINER-NOT-REDIRECTED
- **Catches**: new user objects still default to CN=Users; legacy tools and scripts that create users without a path put them where no OU policy or delegation applies.
- **Severity**: low. Category CFG, entity domain, lens both, refresh 7d.
- **Data**: reuses N9.
- **Condition**: any wellKnownObjects value matches `^B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,`.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: `redirusr "OU=<staging OU>,DC=example,DC=org"`.
- **Confidence**: verified (same links).

### AD-USER-DEFAULT-CONTAINER
- **Catches**: enabled, person-like user accounts sitting in CN=Users (built-in Administrator and the service-account pattern excluded) - the user-side twin of AD-COMP-DEFAULT-CONTAINER.
- **Severity**: low. Category CFG, entity user, lens maintenance.
- **Data**: new query **N24** - base `CN=Users,{DOMAINDN}`, onelevel, `(&{USER}{ENABLED}(!{UAC:2048}))`, attributes sAMAccountName, userPrincipalName, objectSid, whenCreated; key sAMAccountName, name userPrincipalName.
- **Condition**: count with where (objectSid does not match `-500$` AND sAMAccountName does not match the service-account pattern, threshold `ad.service-account-pattern`) greater than 0 (threshold `ad.default-container-users-max`).
- **Refs**: NIST-800-53:CM-6.
- **Fix**: move the accounts to their OUs and redirect the default container.
- **Confidence**: verified.

### AD-SCHEMA-VERSION-OLD
- **Catches**: schema objectVersion below the floor (default 88 = Windows Server 2019/2022; 2025 is 91). A DC of a newer release cannot be promoted until adprep runs, and newer features' attributes are missing. The backlog asked for "behind the newest DC generation"; an absolute floor is expressible today.
- **Severity**: low. Category LCM, entity domain, lens maintenance, refresh 7d.
- **Data**: new query **N25** - base schema, scope base, `(objectClass=dMD)`, attributes objectVersion, fSMORoleOwner, whenChanged; key distinguishedName.
- **Condition**: objectVersion less than 88 (threshold `ad.min-schema-version`).
- **Refs**: NIST-800-53:CM-2.
- **Fix**: run `adprep /forestprep` from the newest Windows Server media (the promotion wizard does it when run as Schema Admin).
- **Confidence**: verified - version table https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/view-current-schema-version (2019 = 88, 2022 = 88, 2025 = 91 likely).

### AD-KRB-RODC-KRBTGT-ORPHAN
- **Catches**: a `krbtgt_<id>` account whose back-link to its RODC (msDS-KrbTgtLinkBl) is gone - the RODC was removed but its krbtgt account stayed, a credential that nothing uses and that AD-KRB-KRBTGT-PASSWORD-AGE will keep reporting.
- **Severity**: low. Category HYG, entity user, lens maintenance, refresh 7d.
- **Data**: new query **N26** - filter `(&{USER}(sAMAccountName=krbtgt_*))`, attributes sAMAccountName, msDS-KrbTgtLinkBl, pwdLastSet, userAccountControl; key sAMAccountName.
- **Condition**: msDS-KrbTgtLinkBl absent.
- **Refs**: NIST-800-53:CM-8, NIST-800-53:IA-5.
- **Fix**: delete the orphaned krbtgt account after confirming no RODC object references it.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-krbtgtlinkbl

### AD-PSO-NOT-APPLIED
- **Catches**: a fine-grained policy that applies to nobody (msDS-PSOAppliesTo empty) - either the group it targeted was deleted or it was never finished; the accounts it was meant for run on the domain policy.
- **Severity**: low. Category CFG, entity policy, lens maintenance, refresh 7d.
- **Data**: reuses Q-PSO.
- **Condition**: msDS-PSOAppliesTo absent.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: assign the policy to its group, or delete it.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-psoappliesto

### ADCS-TPL-AUTOENROLL-WITH-APPROVAL
- **Catches**: a template with autoenrollment and CA manager approval both set. Every autoenrolling client submits a request that pends until an administrator approves it; nobody does, so the Pending Requests queue grows and the clients never get the certificate. File: adcs.yaml.
- **Severity**: low. Category PKI, entity policy, kind broken, lens maintenance.
- **Data**: reuses Q-TPL.
- **Condition**: msPKI-Enrollment-Flag has bit 32 AND has bit 2.
- **Refs**: NIST-800-53:CM-6.
- **Fix**: decide: approval (then no autoenrollment) or autoenrollment (then subject built from AD and no approval).
- **Confidence**: verified - CT_FLAG_AUTO_ENROLLMENT and CT_FLAG_PEND_ALL_REQUESTS https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-9c3e-1a31f06a8aa0

### ADCS-CA-NO-TEMPLATES
- **Catches**: an enterprise CA that publishes no templates - a dead or forgotten CA that still sits in NTAuth and is trusted for logon by every DC. File: adcs.yaml.
- **Severity**: low. Category PKI, entity domain, lens maintenance.
- **Data**: reuses Q-CA.
- **Condition**: certificateTemplates absent OR empty.
- **Refs**: NIST-800-53:CM-8, NIST-800-53:SC-17.
- **Fix**: decommission the CA properly (revoke, remove from NTAuth and the Enrollment Services container) or publish what it is for.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-certificatetemplates

### AD-USER-UPN-MISSING
- **Catches**: an enabled person-like account with no userPrincipalName (built-in Administrator, Guest, krbtgt and the service pattern excluded). Cloud sync and modern authentication key on the UPN; such accounts sync oddly or not at all and cannot use UPN logon.
- **Severity**: low. Category HYG, entity user, lens both.
- **Data**: reuses Q-USER.
- **Condition**: userAccountControl lacks 2 AND userPrincipalName absent AND objectSid does not match `-50[0-2]$` AND sAMAccountName does not match the service-account pattern (threshold `ad.service-account-pattern`).
- **Refs**: NIST-800-53:IA-4.
- **Fix**: set the UPN to the routable mail-style name used for cloud sign-in.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-userprincipalname

---

## Priority 4 - lifecycle

### AD-USER-EXPIRED-STILL-ENABLED
- **Catches**: an enabled account whose expiry date passed more than 30 days ago. It cannot log on, but it keeps its groups, mailbox links and licences and nobody disables or deletes it; the stale-user rules skip it, so it hides from them.
- **Severity**: low. Category HYG, entity user, lens both.
- **Data**: reuses Q-USER.
- **Condition**: userAccountControl lacks 2 AND accountExpires exists AND accountExpires not 0 AND accountExpires older than 30 days (threshold `ad.expired-account-days`; the max FILETIME reads as "never expires" and does not fire).
- **Refs**: NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- **Fix**: disable the account, strip memberships, and delete after the retention period - or extend the expiry if the contract was renewed.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires ; engine date handling checked (Values.TryDate).

### AD-USER-EXPIRES-SOON
- **Catches**: an enabled account that expires within 14 days - contractors and temporary accounts whose renewal is about to become an outage. A deadline rule: `deadline: accountExpires`, severity rising from info to medium as the date nears.
- **Severity**: by days left - medium at 3 days or less, low at 14, default info. Category LCM, entity user, lens maintenance, kind broken.
- **Data**: reuses Q-USER.
- **Condition**: userAccountControl lacks 2 AND accountExpires exists AND accountExpires not 0 AND NOT (accountExpires until-lt 0) AND accountExpires until-lt 14 (threshold `ad.account-expiry-notice-days`).
- **Refs**: NIST-800-53:AC-2(2).
- **Fix**: confirm with the owner whether to extend; otherwise let it lapse and run the leaver steps on the date.
- **Confidence**: verified (as above).

### AD-USER-DISABLED-LONG
- **Catches**: disabled accounts untouched for more than a year (built-in disabled accounts excluded) - past any retention period, still counted, still restorable with every membership.
- **Severity**: low. Category LCM, entity user, lens maintenance.
- **Data**: reuses N13.
- **Condition**: count with where (whenChanged older than 365 days, threshold `ad.disabled-object-retention-days`, AND objectSid does not match `-50[1-3]$`) greater than 0 (threshold `ad.disabled-users-retained-max`).
- **Refs**: NIST-800-53:AC-2(3), CIS-Controls-v8:5.3.
- **Fix**: delete after the retention period (the Recycle Bin keeps them restorable for the tombstone lifetime).
- **Confidence**: verified (whenChanged).

### AD-COMP-DISABLED-LONG
- **Catches**: disabled computer objects untouched for more than 180 days.
- **Severity**: low. Category LCM, entity computer, lens maintenance.
- **Data**: new query **N27** - filter `(&{COMPUTER}{UAC:2})`, attributes sAMAccountName, dNSHostName, operatingSystem, whenChanged; key sAMAccountName, name dNSHostName.
- **Condition**: count with where (whenChanged older than 180 days, threshold `ad.disabled-object-retention-days`) greater than 0 (threshold `ad.disabled-computers-retained-max`).
- **Refs**: NIST-800-53:CM-8.
- **Fix**: delete them, with their DNS records.
- **Confidence**: verified.

### AD-COMP-LAPS-LEGACY
- **Catches**: an active Windows computer that still has only the legacy LAPS expiry attribute (ms-Mcs-AdmPwdExpirationTime) and no Windows LAPS one. Legacy LAPS is out of support and its password is stored in clear text in the directory; Windows LAPS encrypts it and is built into the OS.
- **Severity**: low. Category LCM, entity computer, lens both.
- **Data**: reuses Q-COMP.
- **Condition**: userAccountControl lacks 8192 and 67108864 AND operatingSystem matches `^Windows` AND lastLogonTimestamp newer than 180 days (threshold `ad.active-computer-days`) AND ms-Mcs-AdmPwdExpirationTime exists AND msLAPS-PasswordExpirationTime absent.
- **Refs**: NIST-800-53:SA-22, NIST-800-53:IA-5(1), MITRE-ATTACK:T1078.003.
- **Fix**: deploy the Windows LAPS policy (with password encryption) and retire the legacy CSE; keep the legacy attributes readable until every computer has rolled.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-legacy

### AD-GMSA-UNUSED
- **Catches**: a (group) managed service account created more than 90 days ago that has never authenticated or has not for 90 days - provisioned for a service that was never deployed or was removed.
- **Severity**: low. Category HYG, entity user, lens maintenance.
- **Data**: new query **N28** - filter `(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))`, attributes sAMAccountName, lastLogonTimestamp, whenCreated, userAccountControl, msDS-ManagedPasswordInterval, servicePrincipalName; key sAMAccountName. (Shared by three proposals; gMSAs are outside Q-USER because their objectCategory is not person.)
- **Condition**: userAccountControl lacks 2 AND whenCreated older than 90 days (threshold `ad.gmsa-unused-days`) AND (lastLogonTimestamp absent OR older than 90 days).
- **Refs**: NIST-800-53:AC-2(3).
- **Fix**: remove the account (`Uninstall-ADServiceAccount` on hosts, then delete).
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-groupmanagedserviceaccount

### AD-GMSA-LONG-INTERVAL
- **Catches**: a gMSA whose password change interval exceeds 30 days.
- **Severity**: low. Category IAM, entity user.
- **Data**: reuses N28.
- **Condition**: msDS-ManagedPasswordInterval greater than 30 (threshold `ad.gmsa-max-interval-days`; absent means the 30-day default and is not reported).
- **Refs**: NIST-800-53:IA-5(1).
- **Fix**: the interval is set at creation; recreate the account with the default interval.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-managedpasswordinterval

### AD-GMSA-NONE
- **Catches**: no managed service accounts exist at all - every service in the domain runs on a human-set password (the Kerberoasting rules list them). A pointer to the fix, not a fault.
- **Severity**: info. Category IAM, entity domain, kind missing, lens both.
- **Data**: reuses N28.
- **Condition**: count none.
- **Refs**: NIST-800-53:IA-5(1), MITRE-ATTACK:T1558.003.
- **Fix**: create the KDS root key and start moving services with SPNs to gMSAs.
- **Confidence**: verified.

### AD-GROUP-NO-OWNER
- **Catches**: security groups with members and no managedBy owner (critical system objects excluded). Access reviews need someone to ask; unowned groups are never reviewed and never deleted.
- **Severity**: low. Category HYG, entity group, lens both.
- **Data**: new query **N29** - filter `(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(!(managedBy=*))(!(isCriticalSystemObject=TRUE))(member=*))`, attributes cn, whenCreated, whenChanged; key distinguishedName, name cn.
- **Condition**: count greater than 0 (threshold `ad.unowned-groups-max`).
- **Refs**: NIST-800-53:AC-2(7), NIST-800-53:AC-6(7), CIS-Controls-v8:6.8.
- **Fix**: assign an owner in managedBy (a person, with "manager can update membership list" only where wanted) and run the first review.
- **Confidence**: verified - https://learn.microsoft.com/en-us/windows/win32/adschema/a-managedby ; the 2147483648 security-group bit per groupType doc.

### AD-HYG-FSP-UNUSED
- **Catches**: foreign security principals from other domains (S-1-5-21-...) that are members of nothing. They were created when a cross-trust principal was added somewhere, outlived that use, and some of them come from domains that no longer exist (the resolution half stays in the backlog).
- **Severity**: low. Category HYG, entity domain, lens maintenance, refresh 7d.
- **Data**: new query **N30** - base `CN=ForeignSecurityPrincipals,{DOMAINDN}`, onelevel, `(&(objectClass=foreignSecurityPrincipal)(!(memberOf=*)))`, attributes cn, whenCreated; key cn.
- **Condition**: count with where (cn matches `^S-1-5-21-`) greater than 0 (threshold `ad.unused-fsp-max`).
- **Refs**: NIST-800-53:CM-8, NIST-800-53:AC-2(3).
- **Fix**: delete the unused FSP objects; those that do not resolve to a name any more are certainly dead.
- **Confidence**: verified (foreignSecurityPrincipal, memberOf).

---

## Backlog items these proposals would close or shrink

- **Who holds resource-based delegation rights** - closed by AD-COMP-RBCD-BROAD-TRUSTEE and AD-COMP-RBCD-SET (SIDs listed; name resolution is an engine gap).
- **Groups with more than 1500 members** - closed by the engine (ranged attributes read in full); no rule needed.
- **Tenant regex settings are not checked at load** - closed by the engine (invalid tenant regex is n/a).
- **Maximum password age and lockout duration** - the age half closed by AD-DOM-MAX-PASSWORD-AGE and AD-DOM-MIN-PASSWORD-AGE-ZERO; lockout duration and observation window still lose their minutes (durations become whole days), so no rule.
- **Fine-grained password policy ages and lockout windows** - AD-PSO-MAX-AGE and AD-PSO-MIN-AGE-ZERO work on raw ticks; the day threshold needs the runner to convert msDS-* durations.
- **Ghost DC metadata** - server objects with a deleted or missing reference and connections from deleted servers closed by AD-SITE-SERVER-DELETED-REFERENCE, AD-SITE-SERVER-ORPHAN, AD-REPL-CONNECTION-FROM-DELETED; nTDSDSA objects without a live DC still need the join.
- **Sites without a DC, GC placement, ISTG and bridgehead** - bridgehead (AD-SITE-BRIDGEHEAD-PREFERRED) and "DC that is not a GC" (AD-DC-NOT-GC) closed; per-site placement still needs the join.
- **Schema version behind the newest DC generation** - the absolute floor (AD-SCHEMA-VERSION-OLD) is expressible; the relative check still needs the join.
- **Domain Admins membership change since the last run** - AD-GROUP-PROTECTED-RECENTLY-CHANGED gives the "something changed" signal; which member needs a diff.
- **AdminSDHolder ACEs beyond the default** - AD-ADMINSDHOLDER-RECENTLY-CHANGED gives the change signal; the ACE list needs descriptor decoding.
- **Local Administrators membership pushed by GPO** - AD-GPO-GPP-LOCAL-GROUPS and AD-GPO-GPP-CPASSWORD-CAPABLE name the GPOs to read; the content needs the SYSVOL reader.
- **Orphaned foreign security principals** - AD-HYG-FSP-UNUSED finds the unused ones; dead-domain resolution still needs SID lookup.

## Engine gaps met while writing these

1. **No field-to-field comparison.** "UPN prefix differs from sAMAccountName", "pwdLastSet equals whenCreated" (pre-staged, never-joined computer with a known default password), "lockoutTime newer than lockoutDuration ago" all need `value: {field}` or a `field-b` operand.
2. **Filter-macro windows are not thresholds.** `{GT:n}` / `{FT:n}` take a literal; the 30-day and 7-day windows in AD-PRIV-RECENTLY-CREATED, AD-SCHEMA-RECENT-EXTENSION, ADCS-PKI-OBJECT-RECENTLY-CHANGED and AD-USER-LOCKOUT-WAVE cannot be tuned per tenant. A `{GT:threshold-name}` form, or a `where` on the row side instead, would fix it.
3. **Query base cannot vary per tenant.** AD-DNS-NO-WILDCARD must pick DomainDnsZones or ForestDnsZones; a base taken from a setting (or a "search every naming context" base) would let one rule serve both.
4. **msDS-* durations stay raw ticks.** msDS-MaximumPasswordAge, msDS-MinimumPasswordAge, msDS-LockoutDuration, msDS-LockoutObservationWindow are not in the runner's duration list, so PSO thresholds are in ticks. Adding them to DurationAttributes is a one-line change.
5. **Durations lose minutes.** lockoutDuration and lockOutObservationWindow become whole days, so "lockout duration under 15 minutes" and "observation window too short" cannot be written.
6. **SID-to-name resolution.** RBCD trustees, sIDHistory, foreign security principals and mS-DS-CreatorSID are SIDs; a `{SID}` resolver (or a store join on row_seen objectSid) would make findings readable and let "trustee is a privileged account" be a rule.
7. **No domain-SID macro.** "sIDHistory carries this domain's own SID" and "RID 500 of this domain" still need `{DOMAINSID}` (the existing rules settle for `-500$`).
8. **No well-known-RID DN macro.** Rules that name Domain Admins or Denied RODC Password Replication Group by English DN pass silently on a localised domain; `{RIDDN:512}` would resolve the DN by SID at run time. Proposals that use `adminCount=1` on group objects avoid the problem.
9. **Count-with-where samples.** When a count rule has a `where`, the evidence sample should list rows that satisfied the `where`, not any rows - confirm the Scanner does this (it appears to sample `matching`).
10. **Constructed attributes.** msDS-UserPasswordExpiryTimeComputed and tokenGroups would let "password expired long ago" and "token size near the limit" be rules; the runner should state which constructed attributes it supports in subtree searches.
