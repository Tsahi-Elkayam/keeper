# Engine: pace, sessions and logon safety

Status: design, 2026-11-13. Branch `engine/pace-and-sessions` (from `engine/flex-cross-os` ecc99ec).

## Why

The first real pilot failed: most systems "did not like the query rate" and
locked the scan out. No run folder or log was kept, so the cause is taken from the code:

1. **A logon per query.** Every runner call opens its own connection and signs in again: a CIM session per
   registry or CIM query, an EventLogSession per event-log query, an LDAP connect + bind per query, SQL with
   pooling switched off, an SSH connect per host query, a new HttpClient (and NTLM handshake) per HTTP query.
2. **Volume.** About 700 distinct registry queries, up to 236 CIM and 78 event-log queries per Windows host
   (`windows-baseline` alone has 716 registry rules) - about a thousand logons per host per scan, eight hosts at a
   time, with no pause. The DC takes ~290 LDAP binds in a row. To Defender for Identity, an IPS, fail2ban or a
   WinRM quota that is a brute force.
3. **Wrong passwords are repeated.** Only `CimSessions` remembers a refused logon. LDAP, event log, SQL, SMB, SSH
   and HTTP present the same refused credential again on the next query - the way an AD account gets locked.
4. **No pace in `scan`.** Discovery has `ProbeGate` (per-host and global limits, a token bucket); the scanner has
   one knob, `--parallel 8`, which is the number of hosts per query.

## What "flexible" means here

The engine adapts to the estate instead of the estate adapting to Keeper:

- how hard a system is read is a setting per integration (a pace profile), not a constant in code;
- the engine slows down by itself when a host pushes back, and stops before it does harm;
- a runner says what it can do (keep a session, merge queries, classify a failure) through optional
  interfaces; the scheduler does the rest, so a new protocol gets pacing and logon safety for free;
- before a scan, `--plan` shows what it will cost each host - with no network traffic.

## Design

### 1. Sessions (runner contract)

New optional interface beside `IRunner`:

```csharp
public interface ISessionRunner : IRunner
{
    /// Runners that share one session per host (registry + cim share a CIM session) return the same key.
    string SessionFamily { get; }
    ValueTask<IRunnerSession> OpenAsync(RunnerContext context, CancellationToken ct);
}
public interface IRunnerSession : IAsyncDisposable
{
    Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken ct);
}
```

The scanner keeps a `SessionPool` for the scan: one session per (family, target) - or per integration for a
runner that is not per-target - opened on first use, reused by every query of that host, closed when the host's
queries are done. A runner without `ISessionRunner` keeps working unchanged (stateless).

Families: `cim` (CimRunner, RegistryRunner), `eventlog`, `ldap` (one bound connection per endpoint), `ssh`
(HostRunner over ssh), `sql` (one connection per server; per-database reads change database on it), `http`
(one HttpClient per integration, so TLS and NTLM are negotiated once). SMB/GPO read UNC paths through the OS,
which already keeps one SMB session per server; they get pacing but no session object.

The pool counts logons (sessions opened) per host; the count goes into the run manifest's notes.

### 2. Failure classification and the logon guard

`RunnerResult` gains `Failure`: `none`, `unreachable`, `refused` (the credential: bad password, locked, expired,
disabled), `denied` (signed in, not allowed here), `throttled`, `timeout`, `error`. Runners set it where they
know; a central `Failures.Classify(Exception)` reads the usual codes (LDAP 49 and its AD sub-codes 52e/775/532/533,
Win32 1326/1909/1330/1331/5, SQL 18456, HTTP 401/403/429/503, SSH authentication exceptions, CIM access-denied).

`LogonGuard` lives for the process, so it spans the systems of one `keeper run`:

- **refused** -> the credential (integration id + identity) is not presented again in this run. Every later query
  through it is failed, not attempted: "not tried: <identity> was refused by <host> (<reason>) - Keeper stops so
  the account is not locked out". One refused logon, not a threshold: AD may lock at 3.
- **denied** -> that host and family are skipped for the rest of the scan (other hosts go on).
- Kerberos errors that depend on the host (no SPN, clock skew) are `denied`, not `refused`.

`CimSessions` keeps its transport choice (wsman then dcom) but its refusal memory moves to the guard.

### 3. Pace (scheduler)

The scan becomes host-major: the planner builds, per target, the list of queries; up to `hosts` targets run at
once; on one host queries run one at a time through its sessions. A query that is not per-target counts against
the integration's endpoint as its host. Results are gathered per query and post-processed exactly as before
(drop guard, last read, coverage, evaluation), so output does not depend on the new order.

`Pacer` is passed to runners in `RunnerContext` (`await context.Pace(ct)` before each network request: an
HTTP request or page, an LDAP page, a registry or CIM call). It enforces a minimum interval per host.

Adaptive back-off per host: a `throttled` or `timeout` answer doubles the host's interval (up to 30 s) and a
clean answer slowly brings it back. After `stopAfter` pressure signals in a row (default 3) the host is
stopped: its remaining queries are failed with "not read: <host> pushed back (3 timeouts) - Keeper stopped to
spare it". Failed, never empty: a stopped host can never retire entities or resolve findings.

Profiles, in the integration option `pace` (or `keeper scan --pace`):

Two rates, because what set off the defences was logons and new connections, not calls on an open session:

| Profile | hosts at once | new sessions/s (whole scan) | requests/s per host | stopAfter |
|---|---|---|---|---|
| gentle (default) | 4 | 1 | 10 | 3 |
| normal | 8 | 4 | 25 | 5 |
| fast | 16 | 16 | 100 | 8 |

Single keys override a profile: `pace.hosts`, `pace.sessionsPerSecond`, `pace.requestsPerSecond`,
`pace.stopAfter`. `--parallel` stays as an alias for `pace.hosts`.

### 4. Query merging

New optional interface `IQueryMerger` on a runner: given the queries of one host, it returns merged queries and,
for each original query, how to cut its rows back out. Rows given back to an original query carry only the fields
it asked for plus its key fields, so masking, evidence, `absent` and keys see exactly what they see today.

- registry (this change): same hive + path + key, plain value reads (not `subkeys`, not `certificates`), same
  `fallback_chain` -> one query with the union of value names (an empty list means all values; it wins). 716
  registry queries sit on 265 paths. The split gives each original query `host`, `key`, `exists` and its own
  values only, and a partial state only when one of *its* values was unreadable, with the reason cut to them.
- cim and ldap (follow-up): same namespace + class + filter / base + scope + filter + controls -> union of
  properties / attributes.

Coverage, drop guard and results stay keyed by the original query id; every original query keeps its own
Distrust pass, min_rows, mask and target list.

### 5. Seeing the cost first

`keeper scan <system> --plan` (no network): per host, the queries before and after merging, the sessions
(logons) it will open and the time it takes at the chosen pace. `keeper run --dry-run` prints the same per
system. `keeper scan --test` reads one rule on one host only (today it reads one rule on every target).

### 6. Smaller fixes that belong to the same problem

- `CimSessions`: a locked, expired or disabled account (and a non-English message) is a refusal, not
  "unreachable", so the probe never presents it again over DCOM; a refusal after the probe is remembered too.
- `IntegrationConnection`: a 429/503/5xx or a timeout at sign-in is transient - not remembered for the whole
  scan as a refusal; any other failure of a sign-in is remembered, not retried by the next query.
- `PerObject` (`for_each`): after 3 children in a row fail with the same 401/403, the rest are not sent.
- SSH: SFTP is opened only when a read needs it; one sign-in per host.
- SNMP printers: a printer that did not answer once is not asked again in the scan; ports are probed a few
  at a time, not all at once.
- Duplicate targets (a host listed twice) are read once.

## Order and invariants the scheduler keeps

From the engine review (2026-11-13): phase 2 (evaluation) needs every host of a query, so the scheduler
buffers `RunnerResult`s per (query, target) and then assembles each query's outcome in the old order - the
query groups in first-appearance order, targets in list order - and runs Distrust, mask, rows, AddLastRead,
coverage exactly as before. A per-target query that was skipped (guard, stopped host) gets a `failed` target
record with its reason: never no record (Tracker would retire the host's entities) and never `partial` (it would
enter the drop-guard history). Non-per-target queries run once, outside the host loops, against the endpoint.

## Engine review findings left for later

From the same review, recorded, not fixed here (each needs its own decision or a rule-pack audit):
B1 an explicit null counts as `absent` (registry writes null for an unreadable value; Graph uses null for unset);
B2 query dedup ignores targets, entity and name; B3 a mask can leak through `name` across rules of one query;
B5 per-host count rules report rule coverage ok despite a failed host; B6 `targets.where` drops hosts it cannot
judge without saying so; B7/B10/B11 store reads without ORDER BY; B8 empty keys collapse; B9 one rule-wide
override satisfies every required setting. (All done: sections 10 and 11.)

### 7. Found while building (2026-11-13)

- **Prove first.** Until one sign-in with a credential was accepted, sign-ins go one at a time across the scan.
- **Denied at sign-in.** A wrong password over DCOM can answer E_ACCESSDENIED: two hosts in a row that deny the
  sign-in, with none accepting, make a refusal. After an accepted sign-in a denial is about the host.
- **Refusals persist.** The lab showed three separate `keeper scan` commands each presenting the refused password
  once - three failures, a locked account. Refusals are kept in the home (`data/state/sign-in-refusals.json`,
  keyed by integration and identity, valid while a hash of identity, endpoint, auth kind and secrets' set-at
  times is unchanged) until the secret is set again or `--retry-sign-in`.

### 8. Independent review fixes (2026-11-13)

- **Proof is a read, not an open.** Event log, HTTP, GPO, AWS and printer sessions open without contacting the
  host, so an open proved nothing: the credential counts as accepted only when a remote read returns data, and
  until then each lane's open *and* first read go through the one-at-a-time gate.
- **Denied while unproven skips the host.** Any "access denied" (open or read) before the credential was accepted
  counts towards a refusal and the rest of that host - every family - is not tried. (Narrowed in section 9.)
- **Refusals are kept the moment they happen** (LogonGuard.OnRefused), not at the end of the scan.
- **A Windows account is one credential** across integrations (EXAMPLE\reader = reader@example.org).
- SEC_E_LOGON_DENIED (0x8009030C) is Refused; an SSH host-key mismatch is not a sign-in denial (nothing was sent).
- A partial read that met a refusal (for_each, SQL databases) carries Failure = Refused to the guard.
- for_each sends its first child alone before going four at a time.
- SFTP that cannot be opened is not retried per query; LDAP binds again once after a drop.
- A runner's own throttle signals slow the host but do not count towards stopping it (one read retried three
  times is one push-back).
- Merged reads keep each member's own host spelling; a blank host list is a failed read; a merge or split that
  throws falls back or fails that query only; registry merge keys keep the path's case.
- Known cost: while a credential is unproven, sign-ins are serial, so unreachable hosts at the head of the list
  each cost their timeout before the first host accepts. `keeper scan --test` proves the credential on one host.

### 9. Second review fixes (2026-11-13)

- **Refusals kept per account.** The file is keyed by the guard's key and the integration, so a Windows account
  refused through ad-main is not presented by a separate `keeper scan` of win-servers. It holds while the refused
  integration's credential is unchanged, and not for an integration whose own secret was set after the refusal.
  `--retry-sign-in` forgets the account's refusals; a proven scan forgets only its own. Writes go through a lock
  file; a home that cannot be written warns instead of aborting the scan.
- **Typed kinds win over message words.** `Failures.Classify` looks for a typed kind through the whole chain
  before reading messages, and an `AuthenticationException` (TLS handshake) is Error, never Refused.
- **Denied is ambiguous only where it can be a wrong password.** `IRunner.DeniedMayBeSignIn` (cim, registry,
  eventlog) and `RunnerResult.SignedIn` (the host answered as the account: StdRegProv return codes). A 403, LDAP
  50 or SQL 229 fails one read; the host is read on. This replaces section 8's "any access denied while unproven".
- **No guard without a held secret.** `LogonGuard.PresentsSecret`: auth none and negotiate are not refused, kept
  or serialized.
- **Proof needs rows or SignedIn.** An empty ok answer (an event log service that is down) is not proof.
- **Proof per integration, refusal per account.** Two integrations with one account name and different passwords
  each prove their own.
- LDAP: a rebind that is refused reports the refusal. CIM: a rule chain's session is opened once per host and
  kept, failure included. SQL: a broken connection is signed in again once per scan; an Azure SQL separate
  connection is paced; a push-back in `databases: all` keeps its kind on the partial result. for_each: a list or
  child that is partial with a refusal stops the children. `Scanner.Merge` is linear; merging keeps each spelling
  of a host as its own read.
- Then fixed (10): a busy sign-in is not sent again for `BusyCooldown` (1 min); a host held at the 30 s
  interval for `Pacer.MaxSlowRequests` (20) requests in a row is stopped, and a runner's next wait on a stopped
  host throws Throttled so a read in flight ends.

### 10. Rate follow-ups (2026-11-13)

- `IntegrationConnection.BusyCooldown`; `Pacer.MaxSlowRequests` and the throwing `HostPace`; the scanner waits on
  the pacer directly (it checks Stopped itself).
- `IntegrationConnection.SignOutAsync`, called by `keeper scan` when the scan ends: vCenter DELETE /api/session,
  session-login POST to the option `logoutPath`. Best effort, 10 s.
- LDAP ranged attributes: reaching the page cap is a failed read, never a silently short list.
- Checked, already right: GPO lists SYSVOL once per scan (GpoSession); a vCenter or session-login token is
  renewed once on a 401 mid-scan (RenewSessionAsync).

### 11. Engine review bugs B1-B11 (2026-11-13)

- B1: a value the registry could not read is named in the row's `_unread`; any condition on it is unknown.
- B2: rules with one query in files with different targets read their own hosts (id~hash for the second list);
  stored rows take entity type and name from a rule judged row by row, not a count rule listed first.
- B3: entity names on rows and findings are read after every mask of the query.
- B5: a per-host count with a failed host is not covered "ok".
- B6: hosts the targets' where cannot judge are a manifest note (not an incomplete list, which would keep every
  finding open in any domain with never-used computer objects).
- B7/B10/B11: host attributes keep the newest read (ORDER BY); overrides most specific first; fixed order of
  the incomplete-list reasons.
- B8: several keyless rows of one read and host get host|(no key: content hash); one keeps its old key.
- B9: a rule override sets only the rule's own threshold (name=value when it has several), never the time zone.

### 12. Third review fixes (2026-11-13)

- **B8 kept old keys.** A key template counts as missing only when none of its placeholders has a value: a
  template with one empty part (`{id}|{param1}`) keeps the keys it always had. The content-hash key is given
  only when two or more keyless rows of one read share a host, and it hashes the row after masking, so a masked
  secret never shapes a key.
- **An operator's slow pace is not a push-back.** The 20-requests-at-30-s stop counts only while the host itself
  pushed the interval up (factor above 1); `requestsPerSecond: 0.01` no longer stops hosts.
- **Clean answers inside one long read speed the host up again.** A for_each child that answers ok decays the
  host's factor without resetting the stop count; a stopped host is listed among the hosts that pushed back.
- **A for_each stopped mid-read keeps what it read.** A child whose pace wait throws (the host was stopped) is
  not sent; the result is partial with the stop's kind, the children already read stay.
- **B2 groups by the effective targets.** Rules whose targets come from the integration share one group whatever
  their spec says; a fixed list is its own group.
- **B9 says what it ignores.** A rule-wide override on a rule with several thresholds that names none of them is
  a run note, not silently dropped.
- **Sign-out never fails a scan.** A sign-out that throws is a warning: the session ends at its idle timeout.
- **A cached token is used during a busy cool-down.** Only a new sign-in waits out `BusyCooldown`.
- **One-time history break (accepted).** B2's per-row rule changes the stored entity type of 21 shipped query
  groups where a count rule used to come first (for example aws `instance` to `trail`, entra `tenant` to
  `conditional-access-policy`). Entities and results are keyed by type, so those entities start a new history
  under the new type on the first scan after upgrade, and the old ones stop being seen.
- Not covered by tests: the LDAP range cap needs a directory server; a registry `_unread` that is not merged runs
  on Windows only. The B6 note shows in every scan of an AD estate with computer objects that never signed in.

## Not in this change

Sharing sessions across the systems of one `keeper run`; scan windows (only at night); reading the account's lockout policy
before scanning; moving integration types from code to data. Recorded as follow-ups.

## Tests

- Scanner: a fake session runner counts opens, calls and timing - one session per host, merged calls, the
  guard stops after one refusal across systems, a stopped host makes its rest failed (not partial, not empty),
  outputs identical to the query-major scanner for the same fake rows.
- Classifier: table tests per protocol code.
- Mergers: registry/cim/ldap merge and split, masks preserved.
- Live: a Samba AD DC in Docker with lockout threshold 3 and a wrong password - locked before, not after;
  logons counted with the right password. sshd in Docker with MaxStartups for the ssh family.
