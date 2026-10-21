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
rows could not be judged. And a pass those rows could overturn - "more than 3" with 2 counted and 5
unreadable - is unknown, never a pass.

A count can also be `by: <field>` (one result and finding per value: "more than one admin per site"),
`distinct: <field>` (distinct values, not rows: "more than one OS version") or `percent: true` (the
share of the judged rows that match: "more than 20% of devices unmanaged"; with no row to judge it is
n/a). A partial read can fail a count (it is a floor) but never pass it, and a share of a partial read
is unknown either way.

`deadline:` is a date field of the row, or a date of its own (`deadline: 2026-12-31`, a product's end
of support) given to every finding of the rule.

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

Two conditions on **one element** of an array take `element`: "an assignment that is both to everyone
and required" is not one assignment to everyone and another that is required.

```yaml
each:
  element:
    of: assignments          # the array
    match: any               # any (default): some element fires; all: every element fires
    where: { all: [ { field: target.groupId, op: eq, value: all-users }, { field: intent, op: eq, value: required } ] }
```

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
| `version-lt` `version-le` `version-gt` `version-ge` | Dotted version comparison: 10.0.19045 < 10.0.22621; v and a -suffix are ignored; not a version is n/a |
| `in-cidr` `notin-cidr` | An IPv4/IPv6 address is in / not in one of the networks (a list or comma-separated) |
| `duration-gt` `duration-lt` | A length of time (ISO 8601 such as P90D, or d.hh:mm:ss) longer / shorter than N days |
| `hour-in` `hour-notin` | A time falls in / outside hours of the day on the organisation's clock: `22-6` (22:00 up to 06:00), `12`, or a list. The rule is not configured until `threshold.time-zone` is set (Asia/Jerusalem, or a Windows id) |
| `sid-in` `sid-notin` | A SID is / is not one of a list: names of fixed SIDs (everyone, authenticated-users, anonymous, builtin-administrators, backup-operators, ...), a domain's groups by name or RID in any domain (domain-admins, enterprise-admins, `rid:512`), or literal `S-1-...`; not a SID is n/a |
| `changed` | The field differs from the same entity's in the last clean read, or the entity is new since; arrays compare as sets, text without case. No earlier clean read: n/a |

Fields are paths: `signInActivity.lastSignInDateTime`, and `passwordCredentials[].endDateTime` (any
element). Dates may be ISO 8601, Windows FILETIME, LDAP generalized time, or Unix time (10 digits in
seconds, 13 in milliseconds, `/Date(ms)/`). A date the automatic reading would miss or misread names
its format on the condition: `{ field: Created, op: age-gt, value: 90, format: "dd/MM/yyyy HH:mm" }`,
or `format: ole` (Excel's day numbers), `unix` / `unix-ms` (any year). A custom format must hold the
year (a year-less one would read every date as this year's); for `hour-in` a time alone (`HH:mm`) will
do. A date is read as UTC unless it holds an offset - except for `hour-in`, where a clock time written
without Z or an offset (`2026-10-19 23:30`, an OLE number, a custom format without `z`/`K`) is taken
as the organisation's own clock. Newest or oldest of an array is `element` with `match: all` - "the newest
backup is older than 7 days" is every backup older than 7 days.

**Against the last read.** A rule that uses `changed`, `_new` or `_previous` sees, beside each row, the
same entity in its query's last clean read (of that host, per host): `_new` (true when that read did not
have it), `_previous` (its row then) and `_previous_at`. "A new administrator since the last scan" is
`{ field: _new, op: eq, value: true }`; evidence can say `was {_previous.members}`. With no earlier
clean read, any condition on `_new` or `_previous` is n/a, never a finding about every row; for an
entity that is new, conditions on `_previous` are n/a. Such a finding resolves on the next scan that
sees no change, so give the rule the refresh you want it to stay visible for. A change inside one
element of an array is not a condition: compare the whole field.

**Masked fields.** `mask: [cpassword, pin]` on a rule keeps those values out of everything the scan
writes - the rows it keeps (the value becomes `set`; empty stays empty), results and evidence - for
every rule reading the same query; conditions still read the real value, and a severity may depend on
it. A rule whose conditions read a masked field records no row values in its results; `_previous` is
masked the same way. `changed` on a masked field sees only set and cleared, never one value replaced
by another. The key (each field of a key template), the name, a count's `by` and `distinct` and a
deadline field cannot be masked: they are shown everywhere. Secrets the runners know by name (password, clientSecret,
connectionString...) are masked before any rule sees them.

A missing field gives **n/a** for comparisons and is never a pass by default. A query that fails gives
**unknown** with the reason, never a pass.

## Queries by protocol

Every query has `protocol:`, `key:` (the row field that identifies the entity) and optionally `name:`
(a display name field) and `min_rows:`. The other fields depend on the protocol.

**Too few rows is not a clean answer.** A read that succeeds but returns little looks exactly like a
lost permission, an admin role not activated yet, or a wrong base. So the read is *partial*, which
can neither mark entities gone nor resolve findings, when:
- it returns fewer rows than `min_rows` (per host for per-host protocols). Set it on queries that
  always return something: every user, the domain object, the instance's configuration.
- a read returns less than half of what its last clean read returned (`threshold.scan.row-drop-ratio`,
  default 0.5) - judged per host for per-host protocols. It stays partial, and shows in today's blind
  spots, until three scans in a row over at least two days read as low (`threshold.scan.drop-confirm-scans`,
  `threshold.scan.drop-confirm-days`); a partial for another reason, such as a row cap, starts the count
  again. Then the lower count is accepted, so a real clean-up resolves a few days later. `store` and `file` reads are not
  compared: Keeper's own store and another tool's report cannot lose sight of rows.

A partial read of a `count` rule can still fail (its count is a floor), but never pass. An entity is
gone only when every read that ever returned it - each rule system, query and host - read cleanly
without it in that system's newest scan, so one failed read hides only its own entities. A host the
newest scan no longer reads at all, while it read the query's other hosts, is retired. A per-host key
always names its host (`host|key` when the key does not), so two machines never share an entity.
Rules sharing one query share its strictest `min_rows`. Scans compare with the scans the store has
*loaded* (`keeper run` loads every scan); a slow decline over many scans is not caught.

**A tenant's own list.** A condition whose threshold has no meaningful default - names of the
organisation's agents, its admin groups - takes `required: true`: until the tenant sets it, the rule
is *not configured* (n/a, with the setting to make), never a pass that compared with nothing.

```yaml
- { field: Name, op: match, value: '^$', threshold: workstations.watch-agent-pattern, required: true }
```

| Protocol | Fields | Rows |
|---|---|---|
| `ldap` | `base`: domain (default), config, schema, root, or a DN (macros allowed). `scope`: subtree (default), onelevel, base. `filter` (required, macros below). `attributes`: list. `pageSize`. | One per entry, plus `distinguishedName`. FILETIME attributes (pwdLastSet, lastLogonTimestamp, accountExpires, LAPS expiry...) become ISO dates; 0 and never-expires stay as they are. whenCreated/whenChanged become ISO. maxPwdAge-style durations become days. objectSid/objectGUID become text. Multi-valued attributes are arrays. |
| `graph` | `path` (required, e.g. /users), `version`: v1.0 (default) or beta, `select`: list, `filter`, `expand`, `top`, `search`, `consistency`: eventual, `items` (default value), `maxPages`, `prefer` (a Prefer header; never respond-async), `missing`: empty (a 404 is an answer with no rows). | One per item. |
| `http` | `path` (required, relative to the endpoint's own path), `params`: mapping, `items`: path to the array (default: OData value, or the root), `format`: json (default) or xml (`items` is then an XPath; namespaces are ignored), `method`: get (default) or post with a `body` mapping - post only on the paths the integration type answers as reads (Check Point `/web_api/show-*`, Azure Resource Graph); `paging`: auto (default: @odata.nextLink or ARM nextLink), odata, link, offset, cursor (`cursorField` in the answer, `cursorParam` in the next request), body-offset (`offsetField`/`limitField` in the body), body-cursor (`cursorField` -> `cursorBody`), none; `pageSize`, `offsetParam`, `limitParam` (offset paging, defaults sysparm_offset/sysparm_limit), `maxPages`, `headers` (never credentials), `missing`: empty, `capture_headers`: list (response headers as `_headers.<name>`), `map`: true (an object's keys as rows of `key` and `value`). | One per item. |
| `graphql` | `document` (required, a query), `path` (default /graphql), `variables`: mapping, `items`: path to the array, `paging`: { cursor, hasNext, variable }, `maxPages`. | One per item. |
| `sql` | `text` (required, one SELECT/WITH), `database` (default master). Per target instance. | One per result row, plus `instance`. |
| `cim` | `wql` (required, one SELECT; `{HOST}` stands for the target's computer name, upper case - e.g. `Win32_Group.Domain='{HOST}',Name='Administrators'`), `namespace` (default root/cimv2). Per target host. Never `Win32_Product`: reading it makes Windows Installer re-check (and repair) every package. | One per instance, plus `host`. Dates are ISO. |
| `eventlog` | `log` (required: System, Application, or a channel such as Microsoft-Windows-GroupPolicy/Operational), `ids` (list), `providers` (list of names), `days` (window, default 7, at most 90), `max` (cap per host, default 500). Filtered on the host. Per target. | One per event: host, log, id, provider, level, recordId, time, plus each named event data field (param1, ServerName, ...). A channel the host does not have returns no rows. Over the cap the result is partial. |
| `registry` | `path` (required: the key, e.g. `SOFTWARE\Policies\Microsoft\Windows\System`), `hive` (HKLM default, or HKU), `values` (list; all values when absent), or `subkeys: true`. Read-only: only StdRegProv's Enum and Get methods are ever called. Per target. | One row per host: host, key, exists, and one field per value; with `subkeys`, one row per subkey. Credentials such as an automatic-logon password come back as "set", never as the value. |
| `tls` | `port` (default 443; a target may also be host:port). Per target. | endpoint, host, port, subject, issuer, notBefore, notAfter, daysLeft, serial, thumbprint, keyAlgorithm, keySize, signatureAlgorithm, protocol, cipherSuite, chainValid, nameMatches, chainErrors, selfSigned, sans, eku (OIDs: 1.3.6.1.5.5.7.3.1 server authentication, 1.3.6.1.5.2.3.5 KDC authentication, ...). |
| `file` | `path` (required, relative to imports\, wildcards in the file name), `format`: json (default), xml, csv; `items`: JSON path (json) or XPath (xml, required); `delimiter` (csv). | One per item, plus `_file` and `_modified`. XML elements become objects: attributes and child elements by name, repeated children as arrays. |
| `aws` | `service` (only those Keeper knows: iam, sts, ec2, rds, elasticloadbalancing, autoscaling, cloudformation, sns, monitoring, redshift, elasticache, kms, cloudtrail, config, ssm, ecr, ecs, dynamodb, acm, secretsmanager, logs, codebuild, wafv2, organizations, sso, identitystore, ce, lambda, eks, backup, guardduty, securityhub, inspector2, access-analyzer, s3, route53, cloudfront - a rule never names an API, version or target), `action` (a read: Describe/List/Get/Search/Lookup/BatchGet/Select..., never one that hands over a secret, a credential, content or command text - GetSecretValue, GetParameter, GetObject, GetPasswordData, GetAuthorizationToken, GetFunction, GetCommandInvocation...), `params` (form fields for a query API: `Filter.1.Name: tag:Owner`; the JSON body for a json API; never Action, Version or X-Amz-*), `items` (XPath for XML answers, a path for JSON), `next: { from, to }` (where the answer gives the next token and where the request passes it; known query and json services page by themselves), `path` and `method` (REST APIs: each action at its own method and path only - lambda GetFunctionConfiguration is GET /2015-03-31/functions/{FunctionName}/configuration), `regions` (all - default for regional services -, home, or a list), `accounts` (all, or own), `missing: empty` (with `for_each`: an error that names what is missing - NoSuch..., ...NotFound - is an object without that setting; a bare 404 is a failure), `billed: daily` (Cost Explorer bills each call: required, with a refresh of 1d or more), `maxPages`, `for_each` (one level; each request goes to its object's own account and region). S3: the bucket list (ListBuckets, `path: /`, read once at home) and one bucket's settings in its own region (GetBucketPolicy and the like, `path: /{Name}`, params with that action's subresource: `policy: ""`); never an object. | One per item, plus `_account` (`own` for the integration's own) and `_region`. User data, Lambda and container environments, build variables, session tokens and signed URLs come back as "set"; a CloudTrail event or a Config item's configuration is read as the object it holds, masked the same way. A page that says more follow (any next token or marker, LastEvaluated..., IsTruncated) without a token where the rule reads it is a cut-short read. |
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

Only plain ids (letters, digits, `. _ : -`) are put into a path or a param; a failed object makes the
result partial, never a pass. `max` defaults to 200 (at most 2000). Instead of a list query,
`values: [a, b]` or `threshold: <name>` (the tenant's comma-separated setting) gives the objects.

Two levels at most: the list may itself be per object - sites, each site's lists, each list's items.
Its rows carry their own parent, so `{parent.id}` names the object two levels up. Each level's `max`
caps the rows of the level below it, so requests add up, never multiply:

```yaml
      path: /sites/{parent.id}/lists/{id}/items
      for_each: { path: "/sites/{id}/lists", field: id, for_each: { path: /sites, field: id } }
```

**Dates relative to the scan** in `http` and `graph` paths, params, bodies and filters, and in `graphql`
documents and variables: `{NOW}`, `{TODAY}`, `{DAYS_AGO:n}`, `{DAYS_AHEAD:n}` - e.g.
`filter: "activityDateTime ge {DAYS_AGO:7}"`. The days can be the tenant's: `{DAYS_AGO:threshold.ad.stale-days|90}`.

**Names with dots** in a field path are quoted: `["@odata.type"]`, `value[].["user.company"]`.

LDAP filter macros (the earlier LDAP rules use them): `{USER}`, `{COMPUTER}`, `{ENABLED}`, `{UAC:n}`
(bit n set), `{FT:n}` (FILETIME n days ago), `{GT:n}` (generalized time n days ago), `{DOMAINDN}`,
`{CONFIGDN}`, `{SCHEMADN}`, `{ROOTDN}`, `{IFATTR:attribute|clause}` (the clause only if the schema has
the attribute).

## Integration types

A file's `integration:` names the kind of integration it reads through; the tenant binds an instance
(for example two forests are two `ldap` integrations). Each Microsoft API is its own type: its tokens
are for that API's own resource, and they go to that API's own hosts only. One Entra app can serve all
of them, with the permissions each API needs. A rule may read only with a protocol its integration's
type offers, so a type's guards cannot be walked around through another runner. Power Platform's admin
APIs take the resource `https://service.powerapps.com/` (scope `https://service.powerapps.com//.default`);
if Entra refuses it, the integration's `scopes` option overrides it.

Secrets in URLs are masked like secret fields: a signed URL's `sig=`, `X-Amz-Signature=`, `code=` or
`key=` value becomes `set`, the rest of the URL stays. A request header that would change the method
(`X-HTTP-Method-Override` and the like) is refused, in a rule and in an integration's fixed headers.

| Type | Protocols | For |
|---|---|---|
| `ldap` | ldap | Active Directory, AD CS (configuration partition) |
| `graph` | graph | Entra ID, Intune, Microsoft 365 |
| `azure` | http | Azure Resource Manager (and Resource Graph's KQL as a POST) |
| `power-platform`, `power-apps`, `power-automate`, `power-platform-api` | http | Power Platform admin APIs: environments, DLP policies, apps, connections, flows |
| `dataverse` | http | One Dataverse environment's Web API; its token opens that environment only |
| `power-bi` | http | Power BI admin REST API |
| `defender-endpoint` | http | Defender for Endpoint (api.securitycenter.microsoft.com and its regional hosts): machines, vulnerabilities, advanced hunting (KQL as a POST). Not Defender XDR's own API |
| `cloud-apps` | http | Defender for Cloud Apps: alerts, activities, entities, files, discovered apps (their list POSTs only) |
| `key-vault` | http | One vault's metadata (endpoint `https://<vault>.vault.azure.net`, no path; not Managed HSM): lists, versions, dates, certificate policies. Every page's whole path is checked; the path that returns a secret's value is refused before anything is sent. Give the scanning identity the Key Vault Reader role, which cannot read values either |
| `aws` | aws | AWS: signed here (SigV4, no SDK, no aws.exe). Endpoint = the home region; identity = an access key id (secret `secretAccessKey`); `accounts` + `roleName` read each account through its read-only role (STS AssumeRole, an hour), `regions` the regional reads; `aws-assume-role` assumes `roleArn` first. Give the roles SecurityAudit or ReadOnlyAccess: Keeper only reads, and checks every action against its allow-list. IAM Roles Anywhere is not built yet. Never run against an account yet |
| `exchange-online`, `purview` | http | Exchange Online and Security & Compliance through the REST endpoint their PowerShell module calls (endpoint `.../adminapi/beta/<tenant id>`, exactly; `path: /InvokeCommand`, `body: { CmdletInput: { CmdletName: Get-Mailbox, Parameters: {...} } }`). Get- cmdlets only, the name checked before every page, and never a parameter that makes one do more than read (GetMailboxLog, NotificationEmailAddresses, IncludeCredential); nothing else is sent. Not yet run against a tenant |
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
