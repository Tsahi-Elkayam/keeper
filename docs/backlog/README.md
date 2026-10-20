# Backlog: checks that are not rules yet

Each file lists, per area, the checks Keeper should make but cannot express as a rule today, and why:
a missing protocol or permission, an engine feature, or an API that only exists per object.

| File | Area |
|---|---|
| `active-directory.md` | Active Directory and AD CS |
| `microsoft-cloud.md` | Entra ID, Intune, Microsoft 365 - with the Graph permissions each rule file needs |
| `windows-estate.md` | SCCM, workstations, Windows servers, SQL Server |
| `certificates-registers-imports.md` | TLS certificates, registers, obligations, imported tool reports |
| `infrastructure.md` | VMware, Veeam, PRTG, Dynatrace, Azure, ServiceNow, Wiz - and AWS, which needs a SigV4 integration |

## Engine features most of them wait on

- **Joins in one protocol.** Today only `store` rules join (through `row_seen`): two LDAP queries, or a
  Graph list and a per-object call, cannot be combined in one rule.
- **Comparing two fields of one row** (used vs licensed, free vs total) and arithmetic between fields.
- **Two conditions on the same array element** (the soonest credential, a setting's name and value).
- **Per-object calls** (one request per user, VM or job) and paging styles the HTTP runner does not follow.
- **Registry, event logs and SYSVOL** on Windows hosts: CIM is WQL SELECT only, by design.
- **Severity ranges from a tenant setting.**

Already done since these files were written: `count` with `where` (must-exist rules), per-host
counts, template keys, the `{HOST}` CIM macro, TLS `eku`, LDAP ranged attributes.
