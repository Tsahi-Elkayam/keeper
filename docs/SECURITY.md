# Security

Keeper holds two dangerous things: credentials that can read every system it reviews, and a map of
that estate's weaknesses. This page says how each is protected, and what is not protected yet.

## What Keeper may do

- **Read systems, never change them.** Each runner refuses what a rule must never do:
  - HTTP is GET only, with no redirects; plain `http://` needs the integration option `allowHttp`.
  - GraphQL accepts queries, never mutations.
  - SQL accepts one SELECT/WITH, with `Encrypt` mandatory and ReadOnly intent, inside a transaction that is always rolled back.
  - CIM accepts WQL SELECT only and never invokes a method. `{HOST}` takes only a strict computer name.
  - LDAP only searches, with signing and sealing (or TLS). Secret attributes (LAPS passwords,
    `unicodePwd`, `msDS-ManagedPassword`, ...) are refused when a rule is loaded and dropped if returned.
  - `file` reads only inside the Keeper home's `imports\`, with XML external entities off.
  - `store` opens the store read-only and refuses the tables that hold secrets, keys or the write audit.
- **Write only its own store**, and only through `keeper qm`. Every write is a request with a reason
  and the submitting user, applied in a transaction and kept (`keeper writes`).
- **Change nothing in the store's shape without asking.** `keeper db init` / `migrate` and
  `keeper setup` are dry runs unless `--apply`; a migration backs the store up first.
- **Open tickets only when asked.** `keeper push plan` is a dry run; `apply` needs a typed confirmation
  and refuses to run without a console.

## Credentials

- **Not in files.** Settings hold the tenant name and data path only; unknown fields are refused.
  Integrations and their secrets live in the store.
- **Encrypted at rest.** Each secret is AES-256-GCM ciphertext. The data key is protected by Windows
  DPAPI for the current user, or on macOS and Linux by a random key-encryption key in `vault.key` beside
  `settings.json` (created owner-only, mode 0600; Keeper refuses to use it if others can read it). The associated data binds the ciphertext to its integration, secret
  name and endpoint, so a secret cannot be moved to another integration or pointed at another host.
  Changing an integration's endpoint drops its secrets.
- **Entered hidden, never echoed.** `keeper integration set-secret` reads from the console with echo
  off and refuses to run without one. Values never appear in output, logs, questions or reports;
  error messages pass through a redactor.
- **Sent only where they belong.** SaaS integration types have an allow-list of hosts. Requests go to
  paths relative to the integration's own endpoint, and a handler pins every request to that host.
- **Held only by the process that needs it.** Each system is scanned in its own process, which opens
  only its integration's secret.
- **Expiry is tracked.** A secret records when it expires; `KEEPER-SECRET-EXPIRY` warns before it does,
  and `KEEPER-SECRET-NO-EXPIRY` flags one with no date.

## The Keeper home

- Readable by its owner, SYSTEM and Administrators only. `keeper setup` sets it that way, and every
  binary refuses a home others can read (override: `KEEPER_ALLOW_SHARED_HOME=1`, at your own risk).
- Outside any source tree and outside the folder the binaries run from, so a commit or a copied build
  cannot carry tenant data. `build.ps1` also scans the repo for the identifiers in `denylist.txt`.

## Code that runs

- Composed at build time: no plugin folder, no DLL loading at runtime.
- `keeper <verb>` runs only `keeper-<verb>` from its own folder, by a strict name pattern. It never
  looks in PATH or in the current directory.
- Rule files are parsed strictly: unknown fields, YAML anchors and files over 1 MB are refused, and
  regular expressions time out after one second.
- Packages come from nuget.org only. Known high and critical advisories fail the build.

## Not protected yet

- **SSH reads are scoped, pinned and read-only.** An `ssh` integration's endpoint lists where its credential may be
  used (CIDR ranges, host names, `*.suffix`); a rule file cannot point it anywhere else, and a host name never matches
  a range, so DNS is not trusted with a credential. The credential is sent only after the host's key matches a
  fingerprint pinned in the integration's `hostKeys` option (a host may pin several, one per key algorithm); an
  unknown host is refused with the fingerprint to check, a changed key is refused whatever else is set, and
  `acceptAnyHostKey` is an explicit choice that the read then records. Keeper reads over SFTP (open, stat, list - no
  write call) and runs only the fixed command table, each part single-quoted under a fixed environment. Files that
  hold credentials or keys are never opened, also behind a link, and a file that starts with a private key is refused.
- **Kubernetes is read through a short allowlist and a private CA.** The `kubernetes` integration reads named lists
  only - never secrets, config maps, logs, exec, proxy or tokens - and the runner refuses any other path before it
  sends anything. A cluster's private CA is trusted for that integration alone (`caCertificate`): the machine's trust
  store is not widened, the host name must match, and without the CA no token is sent. Pod environment values,
  command arguments and the `last-applied-configuration` annotation (which holds the whole applied manifest, env
  values included) are masked. See `docs/KUBERNETES.md`.
- **The store is not encrypted as a whole.** Findings, evidence and `row_seen` (every attribute of
  every scanned object) are plain SQLite, protected by the folder's access list only. Whole-database
  encryption is deferred.
- **DPAPI and the key file protect against other users and copied stores, not against you.** Anything running
  as the same OS user can unwrap the data key (DPAPI) or read `vault.key`. Run Keeper under an account used for
  nothing else. A store copied or backed up without `vault.key` cannot open its secrets: back the key file up
  separately, and if it is lost, set the secrets again.
- **Rule results are stored as read.** A rule that returned a sensitive attribute (a description
  someone typed a password into) would keep it in the store. No shipped rule reads free-text fields
  for that reason.
- **Binaries are not signed** and there is no reproducible build yet.
- **Nothing has been tested against a live system.** WAM sign-in, CIM, LDAP, SQL and every SaaS
  adapter are unit-tested only.
