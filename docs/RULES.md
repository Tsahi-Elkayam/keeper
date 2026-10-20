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
| `count: { op: lt, value: 1, where: <condition> }` | Counts only the rows the condition holds for: "an enforced MFA policy must exist" | One for the whole system |

For a per-host protocol (`cim`, `sql`, `tls`) a `count` is judged **per host**, and the finding is
about that host: "no update installed in 45 days" is `count: { op: lt, value: 1, where: { field:
InstalledOn, op: age-lt, value: 45 } }` over the host's hotfixes. A host whose query failed is
*unknown* for the rule, never a pass. In `where`, a row the condition cannot judge (a missing field)
is not counted, so an unreadable policy never satisfies a must-exist rule; the evidence says how many
rows could not be judged.

`key:` is a field, or a template when one field is not unique per entity: `key: "{host}|{PartComponent}"`
makes each member of a host's Administrators group its own finding.

A condition is a leaf or a combination:

```yaml
each: { field: pwdLastSet, op: age-gt, value: 365, threshold: ad.passwordMaxAgeDays }
each:
  any:
    - { field: enabled, op: eq, value: false }
    - not: { field: lastSignIn, op: exists }
```

`threshold:` names a tenant setting (`threshold.<name>`) that replaces `value` when it is set.

`value: { field: <other> }` compares with another field of the same row, optionally scaled with
`times` and `plus` - "more than 90% of the seats used" is
`{ field: consumedUnits, op: gt, value: { field: prepaidUnits.enabled, times: 0.9 } }`. A row without
the other field is n/a.

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

Every query has `protocol:`, `key:` (the row field that identifies the entity) and optionally `name:`
(a display name field). The other fields depend on the protocol:

| Protocol | Fields | Rows |
|---|---|---|
| `ldap` | `base`: domain (default), config, schema, root, or a DN (macros allowed). `scope`: subtree (default), onelevel, base. `filter` (required, macros below). `attributes`: list. `pageSize`. | One per entry, plus `distinguishedName`. FILETIME attributes (pwdLastSet, lastLogonTimestamp, accountExpires, LAPS expiry...) become ISO dates; 0 and never-expires stay as they are. whenCreated/whenChanged become ISO. maxPwdAge-style durations become days. objectSid/objectGUID become text. Multi-valued attributes are arrays. |
| `graph` | `path` (required, e.g. /users), `version`: v1.0 (default) or beta, `select`: list, `filter`, `expand`, `top`, `search`, `consistency`: eventual, `items` (default value), `maxPages`. | One per item. |
| `http` | `path` (required, relative to the endpoint's own path), `params`: mapping, `items`: path to the array (default: OData value, or the root), `paging`: auto (default), odata, link, offset, none; `pageSize`, `offsetParam`, `limitParam` (offset paging, defaults sysparm_offset/sysparm_limit), `maxPages`, `headers` (never credentials). | One per item. |
| `graphql` | `document` (required, a query), `path` (default /graphql), `variables`: mapping, `items`: path to the array, `paging`: { cursor, hasNext, variable }, `maxPages`. | One per item. |
| `sql` | `text` (required, one SELECT/WITH), `database` (default master). Per target instance. | One per result row, plus `instance`. |
| `cim` | `wql` (required, one SELECT; `{HOST}` stands for the target's computer name, upper case - e.g. `Win32_Group.Domain='{HOST}',Name='Administrators'`), `namespace` (default root/cimv2). Per target host. Never `Win32_Product`: reading it makes Windows Installer re-check (and repair) every package. | One per instance, plus `host`. Dates are ISO. |
| `eventlog` | `log` (required: System, Application, or a channel such as Microsoft-Windows-GroupPolicy/Operational), `ids` (list), `providers` (list of names), `days` (window, default 7, at most 90), `max` (cap per host, default 500). Filtered on the host. Per target. | One per event: host, log, id, provider, level, recordId, time, plus each named event data field (param1, ServerName, ...). A channel the host does not have returns no rows. Over the cap the result is partial. |
| `registry` | `path` (required: the key, e.g. `SOFTWARE\Policies\Microsoft\Windows\System`), `hive` (HKLM default, or HKU), `values` (list; all values when absent), or `subkeys: true`. Read-only: only StdRegProv's Enum and Get methods are ever called. Per target. | One row per host: host, key, exists, and one field per value; with `subkeys`, one row per subkey. Credentials such as an automatic-logon password come back as "set", never as the value. |
| `tls` | `port` (default 443; a target may also be host:port). Per target. | endpoint, host, port, subject, issuer, notBefore, notAfter, daysLeft, serial, thumbprint, keyAlgorithm, keySize, signatureAlgorithm, protocol, cipherSuite, chainValid, nameMatches, chainErrors, selfSigned, sans, eku (OIDs: 1.3.6.1.5.5.7.3.1 server authentication, 1.3.6.1.5.2.3.5 KDC authentication, ...). |
| `file` | `path` (required, relative to imports\, wildcards in the file name), `format`: json (default), xml, csv; `items`: JSON path (json) or XPath (xml, required); `delimiter` (csv). | One per item, plus `_file` and `_modified`. XML elements become objects: attributes and child elements by name, repeated children as arrays. |
| `store` | `text` (required, one SELECT or WITH; `:now` and `:today` are bound). | One per result row. Readable: the registers (licence, contract, key_date, vendor, initiative, attestation, latest_attestation), the review tables (system, entity, finding, active_finding, override, setting, rule, run, latest_run, coverage, row_seen) and integration_status / integration_test. Never: integration_secret, vault_key, request, schema_version. |

**One request per object** (`http`, `graph`): `for_each` names the list to walk and the field that
goes into the path. The list is fetched first through the same integration, and each row it returns
carries its object as `parent`:

```yaml
    query:
      protocol: graph
      path: /servicePrincipals/{id}/synchronization/jobs
      for_each: { path: /servicePrincipals, select: [id, appDisplayName], field: id, max: 500 }
      key: "{parent.id}|{id}"
```

Only plain ids (letters, digits, `. _ : -`) are put into a path; a failed object makes the result
partial, never a pass. One level only; `max` defaults to 200 (at most 2000).

**Dates relative to the scan** in `http` and `graph` paths, params and filters: `{NOW}`, `{TODAY}`,
`{DAYS_AGO:n}`, `{DAYS_AHEAD:n}` - e.g. `filter: "activityDateTime ge {DAYS_AGO:7}"`.

LDAP filter macros (the earlier LDAP rules use them): `{USER}`, `{COMPUTER}`, `{ENABLED}`, `{UAC:n}`
(bit n set), `{FT:n}` (FILETIME n days ago), `{GT:n}` (generalized time n days ago), `{DOMAINDN}`,
`{CONFIGDN}`, `{SCHEMADN}`, `{ROOTDN}`, `{IFATTR:attribute|clause}` (the clause only if the schema has
the attribute).

## Integration types

A file's `integration:` names the kind of integration it reads through; the tenant binds an instance
(for example two forests are two `ldap` integrations).

| Type | Protocols | For |
|---|---|---|
| `ldap` | ldap | Active Directory, AD CS (configuration partition) |
| `graph` | graph | Entra ID, Intune, Microsoft 365 |
| `azure` | http | Azure Resource Manager |
| `sccm` | http, sql | SCCM AdminService, or the site database read-only |
| `cim` | cim | Windows servers and workstations |
| `sql` | sql | SQL Server instances |
| `tls` | tls | Any TLS endpoint |
| `vcenter`, `veeam`, `prtg`, `dynatrace`, `servicenow` | http | Those products' REST APIs |
| `monday`, `wiz`, `rubrik` | graphql | Those products' GraphQL APIs |
| `files` | file | Reports other tools wrote into imports\ |
| `keeper` | store | Keeper's own registers |
| `http` | http | Any other JSON API |

## Expiry rules

Anything that expires gets a deadline and a severity that rises as the date nears:

```yaml
  - id: TLS-CERT-EXPIRY
    title: Certificate expires soon
    kind: broken
    category: PKI
    entity: endpoint
    severity:
      daysLeft: notAfter
      ranges: [ { max: 0, value: critical }, { max: 14, value: high }, { max: 30, value: medium } ]
      default: low
    deadline: notAfter
    query: { protocol: tls, key: endpoint }
    each: { field: notAfter, op: until-lt, value: 60, threshold: tls.notice-days }
```

`deadline:` names a date field; the finding carries it, and ranking puts deadlines first.

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

## Rules across systems

A `store` rule can read what other scans saw: `row_seen` holds every row of the newest scans, with its
attributes as JSON (`json_extract(attrs, '$.objectSid')`), and `latest_run` names the newest run of
each system. `rules/hybrid-identity.yaml` joins Active Directory and Entra this way: an account is
stale only when neither directory shows a sign-in, because people who use only cloud services never
log on to a domain controller. `keeper run` scans the store's own systems after the others are
loaded, so these rules see the same day's data.

`keeper stale-users` shows the same join as counts per reason - disabled, mailbox objects, expired,
active on-premises, active only in the cloud, new, stale - next to what domain logons alone would say.

## Every problem found is checked everywhere

A problem found on one machine, one account or one sample is written as a rule over every target of
its kind, not as a note about that one: what was seen once is assumed to be widespread until a scan
shows otherwise. Facts about the tenant (names, counts, which host) never go into a rule; the rule
states the condition, the scan finds the instances.

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
