# Rules

A check is a rule. Adding a check means adding a rule to a YAML file - no code.

One file per system type: `rules/<system>.yaml` in the repo for generic rules, and
`settings\rules\*.yaml` in the Keeper home for a tenant's own. A rule carries its own query and the
condition that marks a problem; the engine runs the query through the protocol's runner, applies the
condition, and records results, findings and coverage.

## File

```yaml
schema: keeper.rules/1
system: active-directory          # lower-case id, [a-z0-9-]
name: Active Directory
integration: ldap                 # the integration type this file reads through
defaults:                         # optional; applied to every rule that does not set them
  lens: both
  refresh: 1d
targets:                          # optional; for per-host protocols (cim, sql, tls, eventlog)
  entity: computer                # resolved from the store: entities seen by earlier scans
  where: { field: operatingSystem, op: match, value: "Server" }
  field: dNSHostName
rules:
  - id: AD-USER-PWD-NEVER-EXPIRES
    title: Enabled user accounts whose password never expires
    kind: misconfigured           # broken | misconfigured | missing
    lens: security                # maintenance | security | both
    category: IAM                 # HLT LCM LOG AVL CFG IAM AUT PKI BCK MON HYG CST
    severity: medium              # critical | high | medium | low | info
    entity: user                  # entity type of each row
    why: A password that never expires is valid forever once it leaks.
    fix: Clear "password never expires"; use a gMSA for service accounts.
    refs: [NIST-800-53:IA-5]
    refresh: 1d                   # how often the result goes stale: 30m, 6h, 1d, 7d
    query:
      filter: "(&(objectCategory=person)(objectClass=user))"
      attributes: [sAMAccountName, displayName, userAccountControl]
      key: sAMAccountName         # row field that identifies the entity
      name: displayName           # optional display name
    each:                         # the row FAILS when this is true
      all:
        - { field: userAccountControl, op: flag, value: 65536 }
        - { field: userAccountControl, op: noflag, value: 2 }
    evidence: "{sAMAccountName} - password never expires"
```

Ids are unique across all loaded files. Unknown fields are refused, so a typo fails loudly instead of
silently weakening a check.

## Conditions

A rule has **one** of:

| Form | Meaning | Findings |
|---|---|---|
| `each: <condition>` | Evaluated per row; a row that matches fails | One per failing row (target = row key) |
| `each: any` | Every row the query returns is a problem | One per row |
| `count: { op: gt, value: 5 }` | Compares the number of rows | One for the whole system |
| `count: none` | Returning no rows is the problem ("this should exist") | One for the whole system |
| `count: some` | Returning any rows is the problem | One for the whole system |

A condition is a leaf or a combination:

```yaml
each: { field: pwdLastSet, op: age-gt, value: 365, threshold: ad.passwordMaxAgeDays }
each:
  any:
    - { field: enabled, op: eq, value: false }
    - not: { field: lastSignIn, op: exists }
```

`threshold:` names a tenant setting (`threshold.<name>`) that replaces `value` when it is set.

| Op | Fails when |
|---|---|
| `eq` `ne` | Text equal / not equal, case-insensitive (numbers compare as numbers) |
| `gt` `ge` `lt` `le` | Number comparison |
| `in` `notin` | Value is / is not in the list |
| `contains` `notcontains` | Text or array contains the value |
| `match` `notmatch` | .NET regular expression, case-insensitive, with a timeout |
| `exists` `absent` | Field present / missing or null |
| `empty` `notempty` | Null, empty text or empty array / the opposite |
| `age-gt` `age-lt` | A date older / newer than N days |
| `until-lt` | A date fewer than N days away (or already past) |
| `flag` `noflag` | Integer has / lacks the bit (e.g. `userAccountControl`) |
| `size-gt` `size-lt` `size-eq` | Array length |
| `status` | Verdict words: fail, failed, false, noncompliant fire; pass, ok, true, compliant pass; anything else is unknown |

Fields are paths: `signInActivity.lastSignInDateTime`, and `passwordCredentials[].endDateTime` (any
element). Dates may be ISO 8601, Windows FILETIME or LDAP generalized time.

A missing field gives **n/a** for comparisons and is never a pass by default. A query that fails gives
**unknown** with the reason, never a pass.

## Queries by protocol

| Protocol | Query fields | Notes |
|---|---|---|
| `ldap` | `base` (domain, config, schema or a DN), `scope`, `filter`, `attributes`, `pageSize` | Kerberos/NTLM with signing and sealing. FILETIME and generalized-time attributes become ISO dates, SIDs and GUIDs become text. |
| `graph` | `path`, `version` (v1.0, beta), `select`, `filter`, `expand`, `top`, `consistency` | GET only; follows `@odata.nextLink`. |
| `http` | `path`, `params`, `items`, `paging` (odata, link, offset, none) | GET only; the path is relative to the integration's endpoint. |
| `graphql` | `document`, `variables`, `items`, `paging` | Queries only - a mutation or subscription is refused. |
| `sql` | `database`, `text` | One read-only SELECT/WITH statement, inside a transaction that is rolled back. |
| `cim` | `namespace`, `wql` | Per target host. WQL SELECT only. |
| `tls` | `port` | Per target host. Returns subject, issuer, notAfter, protocol, key size, chain validity. |
| `file` | `path`, `format` (json, xml, csv), `items` | Scanner reports dropped in the Keeper home's `imports\`. The newest matching file wins. |

Every query ends with `key:` and, optionally, `name:` - the row fields that identify the entity.

## Imported scanner results

Scanner reports (PingCastle, Maester, ScubaGear, Prowler) are `file` rules whose rows already are
verdicts. `emit:` maps a row to the scanner's own check id, title and severity:

```yaml
  - id: PINGCASTLE
    title: PingCastle risk rule
    entity: domain
    query: { path: "pingcastle/ad_hc_*.xml", format: xml, items: "//RiskRule", key: RiskId }
    each: any
    emit:
      check: "PC-{RiskId}"
      title: "{Rationale}"
      severity: { field: Points, ranges: [ { min: 50, value: high }, { min: 10, value: medium }, { min: 0, value: low } ] }
```

## What a runner refuses

A rule directs a query with Keeper's credentials, so the runners refuse what a rule must never do:

- **Secret attributes** are never returned, even if named: LAPS passwords (`ms-Mcs-AdmPwd`,
  `msLAPS-Password`, `msLAPS-EncryptedPassword`), `unicodePwd`, `userPassword`,
  `supplementalCredentials`, `msDS-ManagedPassword`. Their expiry times are allowed.
- **Writes**: HTTP is GET only, GraphQL refuses mutations, SQL refuses anything but one SELECT/WITH
  and rolls back, CIM accepts WQL SELECT only, LDAP only searches.
- **Other hosts**: HTTP and Graph paths are relative; a credential only ever goes to its
  integration's endpoint.
- **Other files**: `file` paths stay inside the Keeper home's `imports\` folder.
