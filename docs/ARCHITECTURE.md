# Architecture

Keeper tells you what to do today. It is a wrapper around components that each stand on their own:
own folder, project, tests and tables; no component reaches into another's internals.

## Pipeline

```
rules/*.yaml ─┐
              ├─ keeper-scan <system> ──> data\runs\<run>\   rows, results, findings, coverage
integrations ─┘                              │
                                    keeper-load ──> queue ──> store
                                             │
              keeper-scan <store system> ────┘   rules over the store: registers, obligations,
                                    keeper-load ──> queue ──> store   cross-system joins, Keeper's health
                                             │
                                    keeper-track ──> queue ──> store   lifecycle, history, systems
                                             │
                                    keeper-rank  ──> queue ──> store   today's order, one task per check
                                             │
                          keeper-today / keeper-report / keeper-query  (read-only)
                                             │
                                    keeper-push ──> trackers (plan is a dry run; apply asks)
```

`keeper-run` runs the stages in order, each in its own process. `keeper <verb>` dispatches to
`keeper-<verb>` in its own folder. People change the store through `keeper-decide`, `keeper-system`,
`keeper-register` and `keeper-integration`, which only queue requests.

Rules over the store (integration type `keeper`) run after the other scans are loaded, so a rule can
join what two systems saw the same day - `hybrid-identity.yaml` joins Active Directory and Entra on
the account's SID through `row_seen`.

The ranker treats the findings of one check as one task: ranked by its worst instance plus its reach,
its time counted once, shown as one line with its number of targets.

## Components

| Folder | Project(s) | Job |
|---|---|---|
| `components/common` | Keeper.Common | Arguments, exit codes, time format, redaction, JSON Lines |
| `components/contracts` | Keeper.Contracts | Records that cross a process boundary: fact, coverage, finding, result, run |
| `components/store` | Keeper.Store | SQLite: read-only and read-write connections, per-component migrations, backup |
| `components/queue` | Keeper.Queue | The single writer: spool, lock, a transaction and an audit row per request |
| `components/query` | Keeper.Query | Named read-only questions in `.sql` files, bound parameters |
| `components/vault` | Keeper.Vault | AES-256-GCM, data key protected by the OS (DPAPI) |
| `components/integrations` | Keeper.Integrations | Endpoints, identities, encrypted secrets, allowed hosts |
| `components/rules` | Keeper.Rules | Rule files: model, loader, validation, condition evaluator |
| `components/runners` | Keeper.Runners + one project per protocol | Read-only runners: ldap, graph, http, graphql, sql, cim, tls, file, store |
| `components/scan` | Keeper.Scan, keeper-scan, keeper-rules | Runs a system's rules through its runner; writes a run folder; validates rule files |
| `components/review` | Keeper.Review + bins | The domain: schema, handlers, questions, load, track; decide, system, register |
| `components/rank` | Keeper.Rank + bin | What to do today |
| `components/report` | Keeper.Report + bins | The daily list and audience reports |
| `components/push` | Keeper.Push + bin | Tickets in ServiceNow / monday |
| `components/home` | Keeper.Home | The Keeper home: where a tenant's settings and data live |
| `components/keeper` | Keeper.Composition, keeper, keeper-run, keeper-db, keeper-qm, keeper-query | The wrapper: dispatch, setup, the daily run, and the bins composed over every component |

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

A run folder is written as `<run>.tmp` and renamed when complete. `keeper-load` verifies every
file's hash before it submits the run, and the handler verifies them again before applying.

## Security

- **One writer.** Only `keeper-qm` writes the store; every write is a request with a reason, applied
  in a transaction with its audit row. Request payloads that point at files carry their hash.
- **Least capability per binary.** Query and report binaries open the store read-only and never
  reference the vault. Only `keeper-scan` and `keeper-push` decrypt a credential, and only the one
  integration they were started for.
- **No plaintext secrets at rest.** Secrets are encrypted before they reach the queue; the AAD binds
  each to its integration and endpoint, so a changed endpoint cannot receive the old secret.
- **Static composition.** Handlers, migrations and question packs are compiled into the binaries;
  nothing is loaded from a folder at runtime.
- **Runners are read-only by construction** and refuse secret attributes - see RULES.md.
- **Tenant data never in the repo.** The Keeper home is outside every source tree; binaries refuse
  otherwise.
