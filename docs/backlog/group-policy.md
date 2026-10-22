# Backlog - Group Policy (SYSVOL content)

Checks `rules/group-policy.yaml` cannot express with the `gpo` runner as coded
(`components/runners/src/Keeper.Runners.Gpo`), one line each with what it needs. The pack judges what
a GPO *sets*; the directory side (flags, links, ACLs, extension lists) is in `rules/active-directory.yaml`.

## Runner notes (what the rules rely on)

- Rows carry the GPO's GUID (`gpo`), `scope` and `_file` - no display name. AD-GPO-* rows give the name for the same GUID.
- Preference rows have no element name (User vs Group, Task vs TaskV2): items are told apart by `_file`, `clsid` or which `Properties` attributes are present.
- A single repeated child is an object, several are an array (`Properties.Members.Member`); rules use `element:`, which handles both.
- GPP registry DWORD values are 8-digit hex text (`00000001`): matched with `^0*1$`, not a number compare.
- Optional fields are guarded with `exists` inside `all`, so rows about other settings pass cleanly instead of being n/a.
- Principals are matched as text (well-known SIDs and English names), not `sid-in`: in a list mixing SIDs and names, `sid-in` is n/a on the names and the whole row becomes unknown. Localised group names are not matched.
- audit.csv subcategory names are matched in English, with or without the "Audit " prefix.

## Needs data the gpo runner does not return

- GPO links, link order, enforcement and block-inheritance per OU: which computers a setting reaches, and which GPO wins a conflict. LDAP gPLink on each OU joined to these rows (a cross-system store rule).
- WMI filters and security filtering: whether a GPO applies at all. LDAP gPCWQLFilter and the GPO's DACL (Apply Group Policy) joined to these rows.
- SYSVOL folder and share ACLs: who can edit a GPO's files, and who can write to a share a SYSTEM task, startup script or file copy runs from. Needs an NTFS/share ACL read of SYSVOL and of each referenced UNC path.
- Startup / shutdown / logon / logoff scripts (scripts.ini, psscripts.ini) and their contents: not a runner part.
- GptTmpl.inf lines without `=` are dropped by the parser: [Service General Setting] (service startup and ACLs), [Registry Keys] and [File Security] cannot be judged.
- Version mismatch between the directory (versionNumber) and SYSVOL (GPT.INI): a join of the LDAP and gpo reads.
- Orphaned SYSVOL folders (no groupPolicyContainer) and containers without a folder: same join.
- A GPO with a non-zero version but no settings in any part: a join across the registry, security, audit and preferences reads.
- Whether a member added to a local or restricted group is a user or a group, enabled, or stale: SID resolution against LDAP.
- Effective (resultant) policy on a host: RSOP, a host-side read.
- "Missing" rules (no GPO sets LSA protection, script block logging, LLMNR off, a deny for local accounts, an audit subcategory) see only Registry.pol / GptTmpl.inf / audit.csv: a setting delivered by a preference registry item, MDM or local policy is not seen, so the tenant may need to accept them. A join with the host-side baseline packs would settle it.
- Whether a GPO that sets a domain-controller-only option (LDAP signing, channel binding, machine account right) is linked to the Domain Controllers OU: needs the links (above).

## Deferred: expressible, but the attribute names or values need a real SYSVOL sample first

- LAPS policy strength (Windows LAPS `Software\Microsoft\Policies\LAPS` BackupDirectory, PasswordLength, PasswordAgeDays, PasswordComplexity, ADPasswordEncryptionEnabled; legacy `AdmPwd`): value semantics differ between the two products and passphrase modes; write after checking a tenant export.
- Defender cloud protection and sample submission values, ASR rule states: value meanings to confirm.
- BitLocker recovery-key backup to AD (`Software\Policies\Microsoft\FVE`): value names to confirm.
- Services.xml recovery actions that run a program, Shortcuts.xml startup shortcuts: attribute names to confirm.
- Immediate tasks vs ordinary tasks: preference rows have no element name; needs a clsid list confirmed against real files.
- Firewall rules pushed by GPO (`WindowsFirewall\FirewallRules` strings) that open admin ports to any source: rule-string parsing to verify against samples.
