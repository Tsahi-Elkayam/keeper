# Backlog - Entra Connect Sync (`rules/entra-connect.yaml`)

`rules/entra-connect.yaml` is the **server-side** pack for the Entra Connect Sync hosts, read over the
`cim` integration's protocols only: `cim` (WQL SELECT), `registry` (StdRegProv Get/Enum, read-only) and
`eventlog`. The **cloud side** of synchronisation is already in `rules/entra.yaml` under `ENTRA-SYNC-*`
and must not be duplicated here (see "Already covered" below).

This file lists the legacy `checks-ENTRACONNECT.csv` checks (CheckId shown) that are **not** rules in
`entra-connect.yaml` yet, one line each, grouped by why. Source: the archived catalogue
`_archive\_health-20261020\Keeper\catalog\checks-ENTRACONNECT.csv`.

## Already covered - do not add here (cloud side is Graph, lives in `rules/entra.yaml`)

The Graph/organization sync-state checks belong to the `graph` integration, so they are in `entra.yaml`,
not in this `cim` file. Adding them here would both duplicate them and never run (wrong integration):

- Directory sync enabled + last-sync recency (`onPremisesSyncEnabled` / `onPremisesLastSyncDateTime`): ENTRA-SYNC-STALE. CheckId HLT-003 (cloud half).
- Password-hash-sync staleness and off: ENTRA-SYNC-PASSWORD-HASH-STALE, ENTRA-SYNC-PASSWORD-HASH-OFF. CheckId HLT-004, CFG-010.
- Per-object provisioning/export errors (`onPremisesProvisioningErrors`): ENTRA-SYNC-PROVISIONING-ERROR, ENTRA-USER-SERVICE-PROVISIONING-ERROR. CheckId LOG-003.
- Soft/hard-match takeover hardening: ENTRA-SYNC-HARD-MATCH-TAKEOVER-OPEN, ENTRA-SYNC-SOFT-MATCH-OPEN. CheckId IAM-013.
- Accidental-delete prevention, retired features, writeback, cloud password policy, sync interval, directory extensions, premium entitlement: ENTRA-SYNC-ACCIDENTAL-DELETE-PREVENTION-WEAK, -RETIRED-FEATURE-ON, -WRITEBACK-ENABLED, -CLOUD-PASSWORD-POLICY-OFF, -INTERVAL-LONG, -DIRECTORY-EXTENSION-SENSITIVE, -NO-PREMIUM-ENTITLEMENT. CheckId CFG-011, LCM-008, CFG-013, AUT-006, CFG-012, CFG-015, CST-001.
- Sync account / sync identity risk: ENTRA-SYNC-ACCOUNT-MULTIPLE, -IDLE, -NO-LOCATION-POLICY, ENTRA-SYNC-AUDIT-SETTINGS-CHANGED-RECENT. CheckId IAM-010, IAM-011, MON-003.
- Synced accounts holding privileged Entra roles, UPN suffix verified, leaver propagation: ENTRA-* over the user inventory / hybrid-identity.yaml store join. CheckId IAM-012, IAM-014, CFG-008, CFG-016.

## Needs the ADSync PowerShell module on the Connect server (no `cim`/`registry`/`eventlog` read)

The sync engine's configuration and run history are exposed only through the ADSync PowerShell cmdlets
on the server; WQL, the registry and the event log cannot reach them. Needs a module-backed runner (a
remote-PowerShell protocol) or a `files` import of the cmdlet output into `imports\entra-connect\`.

- Scheduler state (enabled, suspended, cycle in progress, next cycle, staging/maintenance): Get-ADSyncScheduler. CheckId HLT-002, AVL-003.
- Engine-side last successful export per connector, run-profile results, cycle duration: Get-ADSyncRunProfileResult / Get-ADSyncRunStepResult. CheckId HLT-003 (engine half), HLT-009, LOG-002, LOG-004.
- Connector-space / metaverse object counts and drift: Get-ADSyncConnectorStatistics. CheckId HLT-008.
- Export held by the accidental-delete threshold (`stopped-deletion-threshold-exceeded`): Get-ADSyncRunProfileResult. CheckId LOG-007.
- Automatic-upgrade enabled/suspended: Get-ADSyncAutoUpgrade. CheckId LCM-002.
- Connector inventory, OU/attribute/group filtering, custom/modified sync rules, source anchor, config drift hash: Get-ADSyncConnector / Get-ADSyncRule / Get-ADSyncGlobalSettings. CheckId CFG-002..007, CFG-013.
- Staging server existence, config parity, DC-selection: Get-ADSyncScheduler / Get-ADSyncConnector across hosts. CheckId AVL-001, AVL-002, AVL-005.
- Sign-in method design, Seamless SSO in use, app-based-auth credential: Get-ADSyncGlobalSettings. CheckId CFG-009, AUT-003, PKI-003.

## Needs an engine feature or a different protocol the `cim` integration does not offer

- Bundled-component versions (SQL LocalDB, VC++ runtime, Connect Health agent build) under the Uninstall key: the registry runner returns subkey **names** only, so a per-product DisplayVersion is unreadable, and Win32_Product is banned. CheckId LCM-006, LCM-007 (matches ECSYNC-BUNDLED-COMPONENT-OLD in microsoft-cloud.md).
- Interactive/privileged logons to the server and connector-account logons: the event runner filters by id and provider only; 4624/4672/4768 need event-data conditions (LogonType 2/10, TargetUserName) in the XPath, and are otherwise all network/service noise. CheckId MON-004, IAM-008, IAM-016, MON-007 (matches ECSYNC-LOGON-* in microsoft-cloud.md).
- LocalDB / MSSQL engine errors in the Application log: the provider name is instance-specific (`MSSQL$...`), which the `providers` list cannot enumerate generically. CheckId LOG-008 (the SCM crash half is covered by ECSYNC-SERVICE-CRASH-EVENTS).
- Cumulative-update age: Win32_QuickFixEngineering `InstalledOn` is a free-form string that the cim runner does not reliably normalise to a date, so an `age` condition is unreliable; generic server patch age belongs to the `windows-server` pack. CheckId LCM-005.
- Outbound proxy / TLS inspection: `machine.config`'s `<defaultProxy>` is file **content** (not a registry value the runner parses), and the TLS chain to the cloud endpoints needs an outbound `tls` probe from the server, not a `cim` integration. CheckId AVL-007, PKI-001 (the root-auto-update half is covered by ECSYNC-ROOT-AUTOUPDATE-DISABLED).
- DC/endpoint reachability and WinRM reachability of the server: active TCP probes, not a read. CheckId AVL-004, AVL-006.

## Belongs in another rule file (its data is not on the sync server)

- Connect Health service registration, alerts and notification routing: ARM `Microsoft.ADHybridHealthService` - `rules/azure.yaml`. CheckId MON-001, MON-002, LCM-007 (ARM half).
- AWS principals that can reach the host's disks/console, EC2 backup and VSS consistency: `rules/aws.yaml`. CheckId IAM-015, BCK-001, BCK-002, BCK-003.
- AD DS connector account rights, object hardening, delegated permissions, LDAP signing on the DCs, Seamless SSO object ACL: `rules/active-directory.yaml` (LDAP). CheckId IAM-005, IAM-006, IAM-007, AUT-002, AUT-003 (object half), HYG-002.
- Estate monitoring sensor/alarm on ADSync and last-sync age: `rules/prtg.yaml` / `rules/azure.yaml`. CheckId MON-005.
- Federation residue on verified domains (Golden SAML): `rules/entra.yaml` (`/domains` federation config). CheckId AUT-005.
- Licensing prerequisites and dedicated-server cost: `rules/m365.yaml` (subscribedSkus) and `rules/aws.yaml` (Cost Explorer). CheckId CST-001, CST-002.

## Documentation / attestation checks (no technical read)

- Config export kept off the server, rebuild/staging-switch runbook, DR drill, recovery inputs, documentation currency, forced-cycle frequency: a `files` or `store`/attestation rule, which the `cim` integration cannot run. CheckId BCK-002, BCK-004, BCK-005, BCK-006, HYG-003, HYG-005, LOG-009 (trace content is read as metadata only by ECSYNC-WIZARD-RUN-RECENT, by design).
