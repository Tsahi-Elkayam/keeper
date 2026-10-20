# Keeper

Tells you what to do today. Keeper reviews the systems you run: what is broken, what is configured
wrong, what should be there and isn't, and what is about to expire. It keeps the findings, their
history and your decisions, and each morning it ranks what deserves your time.

Checks are rules in YAML: one file per system type, no code. More checks means more rules.

**Status:** every component is built and unit-tested against synthetic data. **No runner has touched
a live system yet**, so the first real scan of each system is its real test (see *Trying it* below).

## Rule zero: no tenant data in this repo

This repo is meant to be published. Nothing that identifies an organisation goes in it: no domain
names, tenant IDs, hostnames, IP addresses, people's names, counts from a real scan, or collected
output. Examples and tests use `example.com` / `example.org` and the documentation IP ranges
`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`.

A tenant's settings and data live in the **Keeper home**, a private folder outside this repo. The
binaries refuse to start if their settings or data are inside a source tree, beside the binaries,
or readable by other users.

## The daily loop

```
keeper run
  rules load      the rule catalogue
  scan            each system through its integration: read-only, one process per system
  load + qm run   the scans, verified, into the store
  scan (store)    rules over Keeper's own data: registers, obligations, cross-system joins, Keeper's health
  track           findings: new, still open, resolved, reopened, stale; mapped to systems
  rank            today's list within a time budget: deadlines first, then severity, then age
  today           the list, what waits on others, what falls due, what is new, what Keeper cannot see
```

Then you decide (`keeper decide`), hand things off (`keeper push`), and the next run picks it up.

## Trying it

```powershell
.\build.ps1 -Test                                   # build\win-x64\, with the rules
$k = '.\build\win-x64\keeper.exe'
& $k setup --tenant <name>                          # dry run: shows what it would create
& $k setup --tenant <name> --apply                  # private Keeper home + the store

& $k integration types                              # what Keeper can read, and how it signs in
& $k integration add ad --type ldap --auth negotiate --endpoint <your domain> --reason "AD review"
& $k qm run
& $k scan active-directory --test                   # one rule, connection test only
& $k run                                            # the whole loop
& $k today
```

A scan reads; it never changes the system it reads. Keeper writes only its own store, through
`keeper qm`, and every write carries a reason.

## Everyday commands

| Command | What |
|---|---|
| `keeper today` | What to do today (`--format html --out today.html` for a page) |
| `keeper <question>` | Any question: `broken`, `misconfigured`, `missing`, `expiring`, `blind-spots`, `changed --since <date>`, `stale-users`, ... (`keeper query list`) |
| `keeper decide snooze <key> --until 2w` | Out of today's list until then (also `delegate --to`, `clear`, `accept`, `disable`, `threshold`, `undo`, `setting`, `attest`) |
| `keeper system add <ID> --name ..` | The systems findings are grouped, routed and ranked by; `map` claims entities for them |
| `keeper register licence set <id> --expires-on ..` | Licences, contracts, vendors, key dates, initiatives: rules warn before they bite |
| `keeper report security` | `summary`, `security`, `expiring`, `changes --since` |
| `keeper report trends` | Progress per system for management: now against 30 and 90 days ago, fixed vs new, sparklines (`keeper trend --system <ID>` for the daily rows) |
| `keeper report evidence --framework NIST-800-53 --pack` | GRC evidence: per control, each rule's results and the scan that proved them (manifest SHA-256), accepted risks, attestations; `--pack` writes a folder with `SHA256SUMS.txt` an auditor can verify. `keeper controls` shows each control's status |
| `keeper push plan` | Tickets for delegated findings (ServiceNow, monday.com); `apply` asks first |
| `keeper rules explain <id>` | What a rule checks, why, and how to fix it |

Every change needs `--reason "<why>"`; `--now` applies it straight away.

## Binaries

Each verb is its own binary beside `keeper.exe`, so each process holds only the credential it needs:

| Binary | Job |
|---|---|
| `keeper` | The front door: `keeper <verb>` runs `keeper-<verb>`; `setup`, `help` |
| `keeper-run` | The daily loop above |
| `keeper-scan` | One system through one integration; writes a verified run folder |
| `keeper-load`, `keeper-track`, `keeper-rank` | Run folders into the store; findings; today's ranking |
| `keeper-qm` | The queue manager: the only writer of the store |
| `keeper-query` | Questions, read-only |
| `keeper-today`, `keeper-report` | Today's list; reports (text, Markdown, HTML) |
| `keeper-decide`, `keeper-system`, `keeper-register` | Decisions, systems, registers |
| `keeper-integration` | Integrations and their encrypted secrets |
| `keeper-rules` | `validate`, `list`, `explain`, `load` |
| `keeper-push` | Tickets out, ticket state back |
| `keeper-db` | The store: `status`, `init`, `migrate`, `backup` (dry run unless `--apply`) |

## Design rules

- **One job per binary**, composed through files: each stage writes a file, the next verifies it.
- **One writer.** Only `keeper-qm` writes the store; everything else queues a request with a reason,
  applied in a transaction and audited (`keeper writes`).
- **Read-only towards systems.** Runners refuse writes: HTTP is GET only, GraphQL refuses mutations,
  SQL accepts one SELECT and rolls back, CIM accepts WQL SELECT, LDAP only searches. Secret attributes
  (LAPS passwords and the like) are never requested.
- **Secrets are encrypted in the store** (AES-256-GCM, the key protected by Windows DPAPI for the
  user), bound to their integration and endpoint, and never shown. See `docs\SECURITY.md`.
- **No data is not a pass.** A query that fails makes its rules *unknown*, and what Keeper cannot see
  is a section of today's list (`blind-spots`).
- **Seen once, checked everywhere.** A problem found on one machine or account becomes a rule over
  every target of its kind.

## Layout

| Path | What |
|---|---|
| `components\<component>\src` | One folder per library and per binary; `tests\` beside it |
| `components\common`, `contracts`, `store`, `queue`, `query`, `home` | The shared base: arguments, records, SQLite, the queue, questions, the Keeper home |
| `components\rules`, `runners`, `scan` | The rule language, the read-only runners (ldap, graph, http, graphql, sql, cim, tls, file, store), the scanner |
| `components\review`, `rank`, `report`, `push` | Findings and registers, today's ranking, reports, tickets |
| `components\vault`, `integrations` | Encrypted secrets; how Keeper reaches each system |
| `components\keeper` | The composed binaries: `keeper`, `keeper-run`, `keeper-db`, `keeper-qm`, `keeper-query` |
| `rules\` | The generic rule packs, one file per system type |
| `docs\` | `ARCHITECTURE.md`, `RULES.md` (the rule format), `SECURITY.md`, `backlog\` (checks not yet rules, and why) |

## Keeper home

| | |
|---|---|
| Where | `KEEPER_HOME` if set, else `%LOCALAPPDATA%\Keeper` (Windows) / `~/Library/Application Support/Keeper` (macOS) |
| `settings\` | `settings.json` (tenant name and data path only), `denylist.txt`, the tenant's own `rules\*.yaml` and `queries\*.sql` |
| `data\` | `keeper.db`, `spool\`, `runs\`, `builds\`, `imports\` (other tools' reports), `reports\`, `backups\` |

One home per tenant. `keeper setup` creates it readable by you, SYSTEM and Administrators only.

## Build

Needs the .NET 10 SDK; packages restore from nuget.org only (`nuget.config`, with package source mapping).

```powershell
.\build.ps1 -Test                 # leak check, rule validation, tests, publish to build\win-x64\
.\build.ps1 -Runtime osx-arm64    # Apple Silicon -> build\osx-arm64\
```

`build\<runtime>\` is disposable. Builds are framework-dependent: the machine that runs them needs the
.NET 10 runtime. A macOS build made on Windows is unsigned; on the Mac, `codesign --force --sign - <binary>`.

### Leak check

List your tenant's identifiers in `settings\denylist.txt` in the Keeper home, one per line.
`build.ps1` scans the repo for them and stops if any are found. Build before you commit.
