# Keeper

Tells you what to do today. Keeper reviews the systems you run - what is broken, what is configured
wrong, what should be there and isn't - and keeps the findings, their history and your decisions.

**Status:** scaffold. The store, the queue manager and the query side exist; nothing collects yet.

## Rule zero: no tenant data in this repo

This repo is meant to be published. Nothing that identifies an organisation goes in it:
no domain names, tenant IDs, hostnames, IP addresses, people's names, or collected output.
Examples and tests use `example.com` / `example.org` and the documentation IP ranges
`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`.

A tenant's settings and data live in the **Keeper home**, a folder outside this repo - see below.
The binaries refuse to start if their settings file or data folder is inside a source tree or
beside the binaries themselves.

## Keeper home

| | |
|---|---|
| Where | `KEEPER_HOME` if set, else `%LOCALAPPDATA%\Keeper` (Windows) / `~/Library/Application Support/Keeper` (macOS) |
| `settings\` | `settings.json`, `denylist.txt`, the tenant's own `queries\*.sql` |
| `data\` | `keeper.db`, `spool\`, `runs\`, `backups\` - everything a scan produces |

One home per tenant: set `KEEPER_HOME` to a different folder for each. `--settings <file>` on any
binary points at one settings file for a single run.

## Design rules

- **One job per binary.** Binaries compose through files and pipes, Unix style.
- **One writer.** Only `keeper-qm` writes the store. Everything else submits a request file with a
  reason; each one is applied in a transaction and audited.
- **Readers can't write.** `keeper-query` opens the store read-only, and binds every argument as a parameter.
- **Dry run first.** Anything that changes the store's shape reports what it would do until `--apply`.
- **No data is not a pass.** What Keeper cannot see is a question of its own (`blind-spots`).

## Binaries

| Binary | Job |
|---|---|
| `keeper-db` | The store's lifecycle: `status`, `init`, `migrate`, `backup` |
| `keeper-qm` | The queue manager, the only writer: `status`, `run`, `submit` |
| `keeper-query` | Answers questions, read-only: `list`, then a question by name |

```powershell
.\build\win-x64\keeper-db init --apply
.\build\win-x64\keeper-query list
.\build\win-x64\keeper-query broken --format table
.\build\win-x64\keeper-query changed --since 2026-10-13
.\build\win-x64\keeper-qm submit override --reason "Replaced by the new backup product" --payload disable.json
.\build\win-x64\keeper-qm run
```

## Questions (built in)

| Question | Answers |
|---|---|
| `broken` | What is broken |
| `misconfigured` | What exists but is configured wrong |
| `missing` | What should be there and isn't, including overdue duties |
| `blind-spots` | What Keeper cannot see |
| `changed` | What changed since a date |
| `inventory` | What we have |
| `systems` | Systems, owners and their active findings |
| `expiring` | What falls due soon |
| `decisions` | Decisions in force: overrides, snoozes, hand-offs |
| `writes` | The audit trail of writes |

A tenant adds its own questions as `.sql` files in `settings\queries\` in the Keeper home, with the
same header as the built-ins in `src\Keeper.Query\Queries\`.

## Build

Needs the .NET 10 SDK. Packages restore from nuget.org only (`nuget.config`, with package source mapping).

```powershell
.\build.ps1                       # Windows x64 -> build\win-x64\
.\build.ps1 -Runtime osx-arm64    # Apple Silicon Mac -> build\osx-arm64\
dotnet test
```

`build.ps1` puts the binaries in `build\<runtime>\` - disposable, delete it whenever you like. It
creates the Keeper home's `settings\settings.json` (from the example, on the first build only -
**never overwritten**), `settings\denylist.txt` and `data\`. It stops if the Keeper home is inside
the repo, or if an old-layout `build\settings` / `build\data` is still here.

Builds are framework-dependent: the machine that runs them needs the .NET 10 runtime. A macOS
build made on Windows is unsigned; on the Mac, `codesign --force --sign - <binary>` before first use.

## Leak check

List your tenant's identifiers in `settings\denylist.txt` in the Keeper home, one per line.
`build.ps1` scans the repo for them before every build and stops if any are found. Build before you commit.

## Layout

| Path | What |
|---|---|
| `src\Keeper.Core` | Settings, paths, argument parsing, shared vocabulary |
| `src\Keeper.Store` | SQLite access; the schema is `Migrations\NNN-name.sql` |
| `src\Keeper.Queue` | Spool, request envelope, queue manager, one handler per request kind |
| `src\Keeper.Query` | Named questions (`Queries\*.sql`), runner, output writers |
| `src\keeper-*` | One folder per binary |
| `tests\` | xUnit tests, synthetic data only |
| `config\settings.example.json` | Generic settings template |
