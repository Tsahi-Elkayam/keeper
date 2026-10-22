# Backlog - SQL Server

Legacy checks from the health-check catalog (`_archive\_health-20261020\Keeper\catalog\checks-SQL.csv`,
the `(Restored1)` rows ignored) that `rules/sql-server.yaml` cannot express as a rule today, one line
each: the check, why it cannot be a `sql` rule, and its legacy CheckId. The `sql` runner runs one
read-only SELECT/WITH per instance (rolled back), optionally the same SELECT in every database
(`databases: all|user`); it reads system views and DMVs only. Anything that needs the host, the
registry, repeated sampling, another product, or a tenant decision is deferred.

Source label: `rgcheck`/catalog CheckId = the legacy SQL health catalog.

## Needs the host (OS, registry, WMI/CIM, services) - not in T-SQL

These read the Windows host the instance runs on, which the `sql` runner cannot reach; they belong to
the `cim`/`registry` runners against the SQL host, or a future join with the windows-estate pack.

- Engine and Agent service start mode (Automatic) and the other SQL services (Browser, FD, SSRS/SSIS/SSAS) running - `sys.dm_server_services` gives the engine's own start mode, but the feature services and host service state need CIM `Win32_Service`. Source: SQL-HLT-002, SQL-CFG-032, SQL-LCM-008.
- Host operating system supported for the SQL version - needs `Win32_OperatingSystem` on the host. Source: SQL-LCM-007.
- SSRS / Power BI Report Server version and support - version lives in the registry / install folder, not in the engine. Source: SQL-LCM-009.
- Client drivers (SNAC 11, old OLE DB/ODBC) on application servers - a per-server inventory, not a SQL read. Source: SQL-LCM-010.
- tempdb, data and log on separate volumes and off the system drive; 64 KB allocation unit; antivirus exclusions; power plan; instant file initialisation; lock pages in memory - file paths are readable in T-SQL but the volume layout, format, AV and host policy are host facts. Source: SQL-CFG-007, SQL-CFG-008, SQL-CFG-009, SQL-CFG-020, SQL-CFG-021, SQL-CFG-023, SQL-CFG-024, SQL-CFG-025.
- Startup parameters and global trace flags - read from the service command line / registry, not a catalog view. Source: SQL-CFG-026, SQL-CFG-027.
- Service account is not a local administrator on the host; shared across instances; domain password age / gMSA use - `sys.dm_server_services` names the account; the host-side membership and password age need AD/CIM. Partial: SQL-SVC-DOMAIN-USER-ACCOUNT, SQL-SVC-LOCALSYSTEM (account shape only). Source: SQL-IAM-023, SQL-IAM-024, SQL-IAM-025, SQL-IAM-026.
- SPN registration and Kerberos vs NTLM, duplicate SPNs, Extended Protection - SPN state is in AD and the connection's auth scheme over time, not a single read. Source: SQL-AUT-005, SQL-AUT-006, SQL-AUT-028.
- Force Encryption on, legacy TLS disabled, only needed network protocols, Hide Instance, Browser service, static TCP port - these live in the registry (`SuperSocketNetLib`) / SQL Configuration Manager; the engine exposes the listener, not the force-encryption flag. Partial: SQL-CONNECTIONS-UNENCRYPTED (observed sessions), SQL-TCP-DEFAULT-PORT (listener). Source: SQL-AUT-002, SQL-AUT-004, SQL-AUT-018, SQL-AUT-019, SQL-AUT-020, SQL-AUT-021.
- Network exposure of SQL ports - a network-reachability fact, not a host or engine read. Source: SQL-AUT-025.
- SQL-related errors in the Windows Application log (SQLWriter, VSS, MSSQLSERVER) - an event-log read on the host. Source: SQL-LOG-015.

## Config or evidence outside T-SQL (error log, trace files, extended events)

Readable in principle but from the error log, the default trace or an extended-events session, which
the one-SELECT runner cannot stream and parse safely in a rule.

- Error-log errors by severity, login failures (18456), 823/824/825, 833, non-yielding schedulers, memory errors, log-full, AG errors, Agent error log, SPN/SSPI errors - the ring buffer and `sp_readerrorlog` / `xp_readerrorlog` are procedures, not a SELECT; the system_health XE file read is a function with host-path arguments. Partial: SQL-SUSPECT-PAGES (the recorded result of 823/824). Source: SQL-LOG-001..SQL-LOG-011, SQL-LOG-015.
- Error-log file count, size and cycling; Agent job-history retention - some are registry/Agent settings (`NumErrorLogs`), some are msdb sizing read elsewhere. Source: SQL-LOG-012, SQL-LOG-013, SQL-LOG-014.
- Autogrowth events and their duration; blocked-process reports; deadlock counts - default-trace / XE reads (`fn_trace_gettable`, `fn_xe_file_target_read_file`) with host paths. Source: SQL-HLT-021, SQL-HLT-018, SQL-MON-017.
- Login auditing level (registry `AuditLevel`) - noted in SQL-AUDIT-NO-FAILED-LOGIN's own text as not readable here; it is a registry value. Source: SQL-MON-009.
- Database Mail actually delivers - sending or reading the mail queue outcome, not a state read. Source: SQL-MON-008.
- Memory dumps produced by SQL Server - `sys.dm_server_memory_dumps` is a single SELECT and could be a rule, but every row is historical with no clean/benign distinction without the dump; deferred pending a safe age/exclusion design. Source: SQL-HLT-029.

## Needs repeated sampling, stored history, or a trend (not a point-in-time read)

A rule evaluates one scan's rows; these need a delta between two samples or a fit across many runs,
which the runner does not keep. (`changed`/`_previous` compares one prior clean read, not a trend.)

- Memory pressure (PLE, grants pending), CPU utilisation, scheduler/signal waits, top wait types, worker exhaustion, IO latency per file, plan-cache single-use share, connection-count baseline - all deltas of `sys.dm_os_*` / `sys.dm_io_virtual_file_stats` between samples. Partial: SQL-OS-MEMORY-LOW (instantaneous memory state). Source: SQL-HLT-011..SQL-HLT-016, SQL-HLT-019, SQL-HLT-025, SQL-HLT-026.
- Blocking chains over 60 s and long-open transactions - a point-in-time DMV read exists but is meaningful only when sampled repeatedly; a single scan would flag or miss at random. Source: SQL-HLT-016, SQL-HLT-017.
- Capacity / growth runway per volume and per database; database and backup size trend; VLF count growth; statistics staleness and index fragmentation over two runs - a linear fit or multi-run comparison. Partial: SQL-VOLUME-LOW-FREE (current free space). Source: SQL-HLT-009, SQL-HLT-022, SQL-HLT-023, SQL-HLT-024, SQL-BCK-013, SQL-HYG-014.
- Instance restarts and uptime outside a window; jobs running much longer than usual - need the previous value and a window. Partial: SQL-AGENT-JOB-RUNNING-LONG (absolute 12 h). Source: SQL-HLT-028, SQL-MON-005.
- Databases with no activity - needs usage stats accumulated over time. Source: SQL-HYG-003.

## Needs a cross-system or cross-tool join

Keeper joins only through `store` rules over `row_seen`; these need rows another pack collects.

- sysadmin / login mapped to a disabled or deleted AD account (leavers) - join SQL Windows logins to the AD/Entra directory. Partial: SQL-SYSADMIN-USER-ACCOUNT, SQL-WINDOWS-GROUP-LOGIN (shape only). Source: SQL-IAM-013.
- Broad AD groups (large or everyone-type groups) granted SQL access - needs the group's AD membership. Source: SQL-IAM-004.
- Every database mapped to a system and an owner; instance inventory across the estate; estate documented - a CMDB/attestation join. Source: SQL-HYG-001, SQL-HYG-002, SQL-HYG-011.
- Snapshot backups by Veeam / Rubrik / AWS and who owns the log chain; workload covered by a backup product - join to the backup pack. Partial: SQL-BACKUP-LOCAL-DISK, SQL-BACKUP-FULL-NEVER (what the engine recorded). Source: SQL-BCK-010.
- Instances monitored by PRTG / Dynatrace SQL sensors - join to the monitoring pack. Source: SQL-MON-015.
- Linked servers pointing at dead or unsupported targets - needs to resolve and probe the remote. Partial: SQL-LINKED-SERVER-STORED-LOGIN, SQL-LINKED-SERVER-RPC-OUT (local config). Source: SQL-HYG-012.
- Applications connecting as sysadmin or sa - needs the client inventory / connection evidence, not a login read. Partial: SQL-SYSADMIN-SQL-LOGIN. Source: SQL-IAM-019.

## Needs a tenant decision or an attestation (no generic pass)

Expressible only with tenant-supplied values; where a generic shape exists it was written with a
`required` or allow-pattern threshold, otherwise it is deferred to an attestation register.

- Recovery model matches the documented recovery need - the needed model is per database and per policy. Source: SQL-CFG-015.
- Criticality-1 databases without high availability or a tested restore; restore test within 183 days; RPO/RTO recorded; access review of privileged roles within 183 days; migration plan before end of support - all attestation / register facts, not a server state. Source: SQL-AVL-009, SQL-BCK-016, SQL-BCK-017, SQL-IAM-029, SQL-LCM-002.
- Query Store enabled on user databases, indirect checkpoints, min server memory, cost threshold for parallelism, max worker threads / user connections at defaults, backup compression default - readable as single SELECTs but opinionated and noisy without a tenant target; left out of this pass rather than flag healthy instances. Source: SQL-CFG-002, SQL-CFG-004, SQL-CFG-005, SQL-CFG-018, SQL-CFG-019, SQL-CFG-029, SQL-CFG-022.
- Backups encrypted; backup encryption certificate backed up; TDE certificate private keys backed up; service and database master keys backed up; mirroring/AG endpoint certificates - the backup-encryption columns (`key_algorithm`, `encryptor_type`) vary by engine build, "which databases must be encrypted" is a tenant decision, and whether a key's backup exists is not a server fact. Partial: SQL-CERT-EXPIRING (master certificate dates), SQL-DB-TDE-OFF (encryption at rest with a required-pattern). Source: SQL-BCK-009, SQL-PKI-003, SQL-PKI-004, SQL-PKI-005, SQL-PKI-007.
- Enterprise edition without Enterprise features; licensed cores vs used; idle instances still licensed; passive/secondary replica licensing; edition in production (Developer/Evaluation/Express) - licensing facts and usage that need entitlement data. Partial: SQL-EVALUATION-EDITION (Evaluation edition in use). Source: SQL-CST-001, SQL-CST-002, SQL-CST-005, SQL-CST-009, SQL-CST-004.

## Amazon RDS for SQL Server

RDS management-plane facts (engine version and minor-upgrade policy, pending maintenance, Multi-AZ,
automated backups and latest restorable time, snapshot copy and deletion protection, forced TLS, CA,
right-sizing) are read through the AWS RDS API, not a T-SQL connection. They belong to the `aws`
pack once that integration runs. Source: SQL-LCM-011, SQL-LCM-012, SQL-AVL-010, SQL-BCK-018,
SQL-BCK-019, SQL-AUT-026, SQL-PKI-006, SQL-CST-003, SQL-CST-007.

## Thresholds the added rules define

Set as `threshold.<name>` in the Keeper home; the value in the rule applies when it is not set. An
allow pattern defaults to `^$` (matches nothing, so every row is a finding) until the tenant names the
sanctioned entities.

| Threshold | Default | Rule |
|---|---|---|
| sql.fixed-server-role-allow-pattern | `^$` | SQL-FIXED-SERVER-ROLE-MEMBER |
| sql.endpoint-allow-pattern | `^$` | SQL-ENDPOINT-NONSTANDARD |
| sql.os-command-job-allow-pattern | `^$` | SQL-AGENT-JOB-OS-COMMAND |
| sql.maxdop-cores-min | 8 | SQL-CFG-MAXDOP-UNSET |
| sql.min-compat-level | 110 | SQL-DB-COMPAT-LEVEL-OLD |

## To confirm on the first real run

- `databases: all` / `user` reads every online database the login can open; a database it cannot open (and, without VIEW ANY DATABASE, every database it does not own) makes the read partial, so SQL-DB-ORPHANED-USER, SQL-DB-GUEST-ENABLED, SQL-DB-PUBLIC-PERMISSION and SQL-CLR-ASSEMBLY-UNSAFE need a login with VIEW ANY DATABASE and access to each database, or they report less than the whole estate.
- The catalog views these rules read (`sys.database_principals`, `sys.database_permissions`, `sys.assemblies`, `sys.endpoints`, `sys.servers`) are metadata-visibility sensitive: without VIEW ANY DEFINITION the read is partial, not a clean pass.
- `sys.configurations` returns a row for an option only when the build has it, so SQL-CFG-CLR-STRICT-OFF (2017+) and SQL-CFG-CONTAINED-DB-AUTH (2012+) are n/a, not a finding, on older builds.
- SQL-DB-FILE-GROWTH-DISABLED flags `growth = 0`; confirm the estate has no deliberately fixed read-only filegroups before treating it as a fault (they go in a future allow pattern if common).
- SQL-DB-COLLATION-MISMATCH is low by design; vendor databases legitimately ship their own collation, so expect review items rather than faults.
