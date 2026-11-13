# Pace and sign-ins

How hard Keeper reads an estate, and how it keeps a scan from locking accounts or tripping defences.

## Why this exists

The first pilot was locked out: most systems "did not like the query rate".
Keeper then signed in once per query - about a thousand sign-ins per Windows host per scan, eight hosts at a
time - and presented a refused password again on the next query. To Defender for Identity, an IPS, fail2ban,
a WinRM quota or an AD lockout policy that is a password spray. The design is in
`docs/superpowers/specs/2026-11-13-engine-pace-and-sessions-design.md`.

## What a scan does now

- **Host by host.** Up to *hosts* hosts at once; on one host one read at a time.
- **One session per host.** A host's queries share one signed-in session per kind of access: CIM (registry
  and WMI together), event log, LDAP, SQL, SSH, HTTP (one connection pool, so NTLM and TLS are negotiated
  once), AWS, SNMP. A session that cannot be opened is not tried again on that host in that scan. The
  exceptions, each one more sign-in: a rule with its own `fallback_chain` opens one more CIM session per host
  (kept for the scan); an Azure SQL database that cannot be switched to gets its own connection; a SQL
  connection that breaks is signed in again once per scan, never twice.
- **A refused credential stops.** Wrong password, locked, expired or disabled account, an HTTP 401: the
  credential is not presented again - on any host, for the rest of the scan and of `keeper run`, and by later
  `keeper scan` commands too, through any integration that signs in as the same account: the refusal is kept in
  `data/state/sign-in-refusals.json` (no secret in it) until the refused integration's secret is set again or a
  scan runs with `--retry-sign-in` (which forgets every refusal of that account). Another integration of the
  same account whose own secret was set after the refusal tries again. Every read it would have made is failed
  with "not tried: ... so the account is not locked out". One refusal, not a threshold: AD may lock at three.
  A TLS handshake that fails is not a refusal: no credential was sent.
- **Only credentials Keeper holds.** Auth `none` and `negotiate` (the Windows user Keeper runs as) present no
  password Keeper could have wrong: nothing is refused or kept for them, and their sign-ins are not serialized.
- **The first sign-in proves the credential.** Until one sign-in was accepted, hosts sign in one at a time,
  so a wrong password meets one host, not four at once. Over DCOM a wrong password can come back as plain
  "access denied": two hosts in a row that deny the sign-in, with none accepting it, stop the credential too.
  Once a sign-in was accepted, a host that denies it is one where the account lacks the right. "Accepted" means
  a read came back with rows, or the host answered as the account (a registry provider's return code) - some
  kinds of access only sign in on the first read, and an empty answer can hide a read that never happened.
  Before that, a CIM, registry or event log "access denied" stops the rest of that host. Elsewhere "access
  denied" (an HTTP 403, LDAP 50, SQL 229) means the sign-in was accepted and one object is closed: that read
  fails, the rest of the host is read. The cost: while unproven, hosts that do not answer each take their
  timeout in turn, so start with `keeper scan <system> --test`.
- **One Windows account, one credential.** EXAMPLE\reader refused through the ldap integration is not presented
  again through the cim or sql integration either. A proof is per integration: two integrations may hold
  different passwords for one account, so each proves its own before going wide.
- **A host that pushes back is slowed, then left alone.** A timeout, 429, 503, a busy directory, a WinRM
  quota or a reset connection doubles the host's interval (up to 30 s); clean answers bring it back. After
  *stopAfter* push-backs in a row the host is not read again in that scan; its remaining reads are failed
  (never empty), so nothing on it is retired or resolved by a read that did not happen.
- **Merged reads.** Registry rules that read values under the same key are one read (716 baseline rules sit
  on 265 keys); each rule still sees only its own values. Two files that spell a host differently read it
  separately (over the one session), so each keeps its own spelling in its rows.
- **Duplicates.** A host listed twice is read once.

## Profiles

Set per integration with `keeper integration set <id> --option pace=normal`, or for one scan with
`--pace`:

| Profile | hosts at once | new sessions/s (whole scan) | requests/s per host | stop a host after |
|---|---|---|---|---|
| gentle (default) | 4 | 1 | 10 | 3 push-backs |
| normal | 8 | 4 | 25 | 5 |
| fast | 16 | 16 | 100 | 8 |

One number of a profile: `--option pace.hosts=2`, `pace.sessionsPerSecond`, `pace.requestsPerSecond`,
`pace.stopAfter`. `--parallel <n>` is the number of hosts at once for one scan.

## Before a scan

```
keeper scan windows-baseline --plan      # per host: queries, reads after merging, sign-ins, time - nothing is sent
keeper run --dry-run                     # the same for every system the run would scan
keeper scan windows-baseline --test      # one rule on one host: proves the credential with one sign-in
```

## A first run in a new estate

1. `keeper run --dry-run` and read the plan: how many hosts, sign-ins and how long.
2. Ask the estate's owners what watches sign-ins (lockout threshold, Defender for Identity, IPS, fail2ban)
   and tell them the source address and the account Keeper uses.
3. `keeper scan <system> --test` for each integration: one sign-in each. A refusal shows here, once.
4. The first full scan on `gentle`; read the run notes: sessions opened, hosts that pushed back or were
   stopped, refusals. Raise the pace only when nothing pushed back.

## Measured (lab, 2026-11-13)

An sshd that locks an account after three failed sign-ins (pam_faillock), scanned with the sshd, nginx and
docker packs as three separate `keeper scan` commands (8 queries):

| | before | after |
|---|---|---|
| wrong password: failed sign-ins | 4 in the first scan alone - account locked | 1 in all - not locked |
| right password: sign-ins | 16 (two per query: ssh and sftp) | 6 (ssh once per scan, sftp once when files are read) |
| right password: results | 15 rows, 2 findings | the same |

The lab is in `_claude-tmp/2026-11-13-keeper-lab` on the build machine (Dockerfile and `lab.sh`).

## Run notes

Every run's `run.json` notes say the pace used, how many sessions were opened on how many hosts for how
many reads (and how many were merged), every host that pushed back or was stopped, and a refusal.
