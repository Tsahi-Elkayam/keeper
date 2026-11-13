# Architecture

Keeper tells you what to do today. It is one binary over an engine and four parts - scan, sign-in, rules and
reports - each in its own folder under `src\`. A project stands on its own: its own folder, tests and tables;
none reaches into another's internals.

## Pipeline

```
rules/*.yaml ─┐
              ├─ keeper scan <system> ──> data\runs\<run>\   rows, results, findings, coverage
integrations ─┘                              │
                                    keeper load ──> queue ──> store
                                             │
              keeper scan <store system> ────┘   rules over the store: registers, obligations,
                                    keeper load ──> queue ──> store   cross-system joins, Keeper's health
                                             │
                                    keeper track ──> queue ──> store   lifecycle, history, systems
                                             │
                                    keeper rank  ──> queue ──> store   today's order, one task per check
                                             │
                          keeper today / keeper report / keeper query  (read-only)
                                             │
                                    keeper push ──> trackers (plan is a dry run; apply asks)
```

There is one binary, `keeper`. Each verb is a library in its part's `keeper-<verb>\` folder
(`<Verb>Verb.Run(args)`); `keeper` registers them in `Commands` and runs them in its own process -
nothing is started as a child process. `keeper run` calls the stages in order. A verb that throws
past its own handlers fails alone with an exit code, as a separate process did. People change the
store through `keeper decide`, `system`, `register`, `config` and `integration`, which only queue requests.

Rules over the store (integration type `keeper`) run after the other scans are loaded, so a rule can
join what two systems saw the same day - `hybrid-identity.yaml` joins Active Directory and Entra on
the account's SID through `row_seen`.

The ranker treats the findings of one check as one task: ranked by its worst instance plus its reach,
its time counted once, shown as one line with its number of targets.

## Parts

| Part | Folder | Projects | Job |
|---|---|---|---|
| Engine | `src/engine` | Keeper.Common, Keeper.Contracts, Keeper.Store, Keeper.Queue, Keeper.Query, Keeper.Home | Arguments and exit codes; records that cross a stage (fact, coverage, finding, result, run); SQLite with per-component migrations; the single writer (spool, lock, one transaction and one audit row per request); named read-only questions; the Keeper home |
| | | Keeper.Review + verbs load, track, decide, system, register | The domain: schema, handlers, questions (trends among them), findings lifecycle, decisions, registers |
| | | Keeper.Rank + verb rank | What to do today |
| | | Keeper.Composition, keeper + verbs run, db, qm, query | The one binary: dispatch, setup, help, the daily run |
| Scan | `src/scan` | Keeper.Scan + verbs scan, certs | Runs a system's rules through its runner and writes a run folder |
| | | Keeper.Runners + one project per protocol | Read-only runners: ldap, graph, http, graphql, sql, cim, tls, file, store, host (files, device configuration folders, Docker, CUPS printers and allowlisted commands of this machine, or of each host of an ssh integration), printer (network printers: ports, IPP, Printer-MIB) |
| | | Keeper.Discover + verb discover | Network discovery (`free` and `manual` modes): probes allowed networks via `ProbeGate` and writes `data/imports/discovery/inventory.json` |
| Sign-in | `src/sign-in` | Keeper.Integrations + verbs integration, connect | Endpoints, identities, allowed hosts, Entra and AWS sign-in; the Graph permission map |
| | | Keeper.Vault | AES-256-GCM, data key protected by the OS: DPAPI on Windows, an owner-only `vault.key` file elsewhere |
| | | verb config | The configuration as files, both ways |
| Rules | `src/rules` | Keeper.Rules + verb rules | Rule files: model, loader, validation, condition evaluator |
| Reports | `src/reports` | Keeper.Report + verbs report, today | The daily list, audience reports, trends, the one-page view |
| | | Keeper.Push + verb push | Tickets in ServiceNow / monday |

Tests sit under `tests/<part>/`, one project per library; `tests/testkit` holds the shared fakes and the demo vault.

Each component owns its tables and ships its own migrations (`schema_version` keeps one version per
component). Request kinds are namespaced: `review.override`, `integrations.set-secret`.

## Contracts

Every file a stage writes is JSON Lines - one record per line, a `schema` field naming its type:

| Schema | Written by | Fields |
|---|---|---|
| `keeper.row/1` | scan | source, system, entityType, entityKey, entityName, attrs, observedAt |
| `keeper.result/1` | scan | ruleId, system, entityType, entityKey, state (pass, fail, n-a, unknown), value, operand, why, at |
| `keeper.finding/1` | scan | findingKey, ruleId, checkId, system, entityType, target, kind, category, severity, security, title, evidence, fix, refs, deadline, observedAt |
| `keeper.coverage/1` | scan | source, system, scope (rule, query, target), item, state (ok, partial, failed, not-applicable), reason, count, observedAt |
| `keeper.run/1` (run.json) | scan | runId, source, system, integration, identity, startedAt, finishedAt, status, files with SHA-256 |
| `keeper.inventory/1` (inventory.json) | discover | generatedAt, mode, scanHealth, notes, coverage (sources, summary), assets |
| `keeper.discovery/1` (discovery.yaml) | tenant | mode, scope, targets, exclude, gentle, approve, sources, widen, snmp, rate, staleness, windows, history |

A run folder is written as `<run>.tmp` and renamed when complete. `keeper load` verifies every
file's hash before it submits the run, and the handler verifies them again before applying.

## Security

- **One writer.** Only `keeper qm` writes the store; every write is a request with a reason, applied
  in a transaction with its audit row. Request payloads that point at files carry their hash.
- **Least capability per verb.** Query and report verbs open the store read-only and never
  reference the vault. Only `keeper scan` and `keeper push` decrypt a credential, and only the one
  integration they were called for. This is enforced by code path, not by process: since verbs share
  one process, `keeper run` scans its systems one after another in the same memory, where separate
  binaries used to isolate each credential in its own process.
- **No plaintext secrets at rest.** Secrets are encrypted before they reach the queue; the AAD binds
  each to its integration and endpoint, so a changed endpoint cannot receive the old secret.
- **Static composition.** Handlers, migrations and question packs are compiled into the binary;
  nothing is loaded from a folder at runtime.
- **Runners are read-only by construction** and refuse secret attributes - see RULES.md.
- **Tenant data never in the repo.** The Keeper home is outside every source tree; binaries refuse
  otherwise.
