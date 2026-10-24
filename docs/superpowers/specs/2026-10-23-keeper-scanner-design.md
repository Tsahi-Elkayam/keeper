# Keeper discovery scanner: design and plan

Date: 2026-10-23. Step 1 of the owner's priority order (`2026-10-23-keeper-problem-list.md`).
Pipeline: Opus plans (this file), Sonnet implements one task at a time, Opus reviews each task.
Marked **[verified]** = read in the code; **[guess]** = not checked; **[owner]** = needs the owner.

## 1. Goal, non-goals, done

**Goal.** `keeper discover`: an in-process scanner that reads a targets file, probes machines with
TCP connect and a few UDP protocol probes, names them by their management protocols, and writes an
inventory file with states and history. The inventory reaches the rules engine through the existing
`files` integration, so findings are YAML rules.

**Non-goals.** Raw packets, ICMP, ARP sweeps, OS fingerprinting, probing unknown ports, vulnerability
checks, credential guessing, the certificate product. Nothing that changes a device is ever sent (no
SNMP SET, SMB session or SSH login). Credentialed scans of found machines are step 2.

**Done.** Tasks 1-14 merged and reviewed; credential-free discovery runs on Windows and macOS against
localhost fakes; `keeper scan network` turns the inventory into findings; all acceptance tests pass on
both platforms. Nothing has run on a real network, and the docs say so.

## 2. Architecture

New component `components/discover`:
- `src/Keeper.Discover` library: addresses, targets file, inventory, lifecycle, probe gate, probes,
  sources, classifier, orchestrator (`Discoverer`).
- `src/keeper-discover` verb `DiscoverVerb.Run(args)`, registered in
  `components/keeper/src/keeper/Program.cs` and referenced by `keeper.csproj` [verified: that is
  how `certs` is wired].
- `tests/Keeper.Discover.Tests`.

The verb is named `discover`, not `scan`, because `keeper scan` and `Scanner` already mean "run a
system's rules" [verified: `ScanVerb.cs`, `Scanner.cs`]. The discoverer runs no rules.

Flow, one job per verb, composed through files:

```
settings/discovery.yaml (targets) ─┐
store (read-only: AD computers) ───┼─ keeper discover ──> data/imports/discovery/inventory.json
previous inventory ────────────────┘                          │
                     keeper scan network  (rules/network.yaml, integration files, protocol file)
                                                              │ run folder: rows, results, findings
                                             keeper load ──> keeper qm ──> store (row_seen, entity)
                                                              │
               other packs: targets { entity: network-host, field: address, where ... }
```

- **Store and queue.** `keeper discover` opens the store read-only and queues nothing; `keeper qm`
  stays the only writer [verified: ARCHITECTURE.md, `QueueManager.cs`].
- **Into the rules engine.** The inventory sits under `imports/`, so the existing `FileRunner` reads
  it (path guarded, links refused, 200 MB cap) [verified: `FileRunner.cs`]. `rules/network.yaml`
  (`integration: files`, `query: { protocol: file, path: discovery/inventory.json, items: assets,
  key: id }`, entity `network-host`) gives rows and findings. Rows land in `row_seen`, and
  `StoreInputs.Targets` reads the newest rows of an entity type from any system [verified], so a pack
  can target found machines by type: `where: { field: answered, op: contains, value: ssh }`
  (`contains` works on arrays [verified: RULES.md]).
- **Scanner.cs.** Not used for probing; its idea is: `Distrust` refuses a single low read, the
  discoverer refuses a single bad scan (scan health, section 3). File reads skip the drop check
  [verified: `Scanner.cs` line 91], which suits an inventory that never drops assets.
- **Runners.** TLS facts reuse `TlsRunner.Split`, `TlsRunner.Row`, `CertificateRows.Of` [verified:
  public static]. Probes live in `Keeper.Discover`, not as rule runners: a departure from
  ENGINE-ROADMAP stage 6 (`tcp`, `ssh banner` runners). A later runner can wrap them. **[owner]**
- **Credentials.** New integration type `snmp`: auth `snmp-v3` (identity = user, secrets
  `authPassword`, `privPassword`) and `snmp-v2c` (secret `community`). Its endpoint is the CIDR scope
  the credential may be used in; secrets are bound to the endpoint [verified:
  `IntegrationStore.Binding`], and the gate never sends one outside it.
- **Contracts.** `Schemas.Inventory` (`keeper.inventory/1`) and `Schemas.DiscoveryTargets`
  (`keeper.discovery/1`) in `Records.cs`; the record types stay in `Keeper.Discover`.

**OPEN QUESTION FOR THE OWNER: does the engine scan found machines automatically?**
Recommendation: **review first, then automatic within what the owner approved.** Every found machine
gets the credential-free `network` rules at once. A credentialed pack (CIM, later SSH) reads a found
machine only when a directory lists it (as today) or when it matches an `approve` entry in the
targets file ("WinRM hosts in 192.0.2.0/24 may be read by the `cim` integration"). Why: domain
credentials sent to an unknown host can be captured or relayed (NTLM); guest, partner and BYOD
devices may not be the tenant's to scan; fragile devices. This needs targets from more than one
entity type, which `TargetSpec` cannot express [verified: one `Entity`]: a step 2 engine change.

## 3. Files and states

**Targets file** `settings/discovery.yaml` in the Keeper home (tenant data, never in the repo).
Unknown fields are refused, like rule files.

```yaml
schema: keeper.discovery/1
mode: free                       # free | manual
scope: [192.0.2.0/24, 198.51.100.0/23, "2001:db8:10::/120"]   # free mode: never probe outside
targets:
  - 192.0.2.0/25
  - 198.51.100.10
  - host: printer-01.example.com
exclude:                         # never sent a packet, checked after name resolution
  - { cidr: 192.0.2.250/32, why: "old controller, crashes under scans" }
  - { name: "*.lab.example.com" }
gentle: [198.51.100.64/27]       # one connection at a time, connect only
approve: []                      # step 2: which found machines credentialed packs may read
sources:
  ad: { enabled: true }          # computers from the newest Active Directory scan in the store
  dns: { forward: true, reverse: false }
  snmp-neighbours: { enabled: false, credentials: [snmp-core] }
widen:                           # one mechanism widening another
  from-ad: { ipv4-prefix: 24 }
  from-dns: { ipv4-prefix: 24 }
  from-snmp-neighbours: { ipv4-prefix: 32 }
  max-new-addresses: 4096
snmp: { v3: [snmp-core], v2c: [], allow-cleartext: false }
rate: { connections-per-second: 50, concurrent: 64, per-host: 2, timeout-ms: 1500, retries: 1 }
staleness: { gone-after-scans: 3, gone-after-days: 14 }
windows: [{ days: [sat, sun], from: "20:00", to: "06:00" }]   # the organisation's clock
history: { keep: 20 }
```

Manual mode probes only `targets`; sources and widening are ignored. Free mode refuses to start
without `scope`. Hand-declared known assets go in `targets` (input); the inventory is output only.
Whether the owner also wants to edit the inventory stays open (problem list) **[owner]**.

**Inventory file** `data/imports/discovery/inventory.json`, written to `.tmp` and renamed.

```json
{ "schema": "keeper.inventory/1", "generatedAt": "2026-10-25T21:04:00Z", "mode": "free",
  "scanHealth": "ok", "notes": [],
  "coverage": {
    "sources": [
      { "scope": "source", "item": "targets", "state": "ok", "count": 128, "reason": null },
      { "scope": "source", "item": "ad", "state": "ok", "count": 42, "reason": null },
      { "scope": "source", "item": "dns", "state": "ok", "count": 42, "reason": null },
      { "scope": "widening", "item": "from-ad:/24", "state": "ok", "count": 212, "reason": null }
    ],
    "summary": {
      "totalCandidates": 382, "attempted": 380, "answering": 145, "notAnswering": 12,
      "likelyGone": 3, "unresolved": 1, "excluded": 1, "outOfScope": 0,
      "withManagementProtocol": 138, "widenedAddresses": 212
    }
  },
  "assets": [
    { "id": "ws-0042.example.com", "names": ["ws-0042.example.com"], "addresses": ["192.0.2.42"],
      "sources": [ { "kind": "ad", "firstListed": "2026-10-11T21:00:00Z", "lastListed": "2026-10-25T21:00:00Z" } ],
      "state": "answering", "everAnswered": true, "firstSeen": "2026-10-11T21:02:10Z",
      "lastSeen": "2026-10-25T21:03:41Z", "misses": 0, "missingSince": null, "flaps": 0,
      "kind": "windows", "kindWhy": "smb2 + rpc + winrm",
      "answered": ["rpc", "smb", "winrm"],
      "services": [ { "port": 445, "transport": "tcp", "service": "smb", "state": "open", "rttMs": 3,
                      "detail": { "dialect": "3.1.1", "signingRequired": false } } ],
      "snmp": null, "tls": [],
      "history": [ { "at": "2026-10-25T21:03:41Z", "outcome": "answered", "answered": ["rpc", "smb", "winrm"], "rttMs": 3 } ] } ] }
```

The `id` is the lower-cased name when a source gives one, else `ip:<address>`; an IP-only asset is
merged into a named asset that resolves to it. The store keeps full history (one run per scan); the
file keeps the last `history.keep` entries.

**Discovery and operational coverage.** Every discovery run records its own coverage in
`inventory.json` (`coverage.sources` and `coverage.summary`):
- Which mechanisms (`targets`, `ad`, `dns`, `snmp-neighbours`, `widening`) ran cleanly (`ok`), were
  incomplete/capped (`partial`), failed (`failed`), or were disabled in manual mode (`skipped`).
- How many discovered assets expose a management protocol (`withManagementProtocol`) vs. are opaque
  on the network, feeding Keeper's estate-wide operational coverage (which discovered hosts are deeply
  inspected across health `HLT`, backups `BCK`, monitoring `MON`, lifecycle `LCM`, availability `AVL`,
  and configuration `CFG`, vs. seen only from the network).

**States.** An *attempt* is one scan's verdict (retries inside a scan are not attempts). An asset
*answers* when a TCP port connects or refuses (a refusal proves a host) or an SNMP or LDAP reply
arrives. UDP silence is never a miss.

| State | Meaning | Moves |
|---|---|---|
| `pending` | listed, never attempted | first attempt -> answering / not-answering |
| `answering` | answered in its newest attempt | miss -> not-answering (misses 1, missingSince now) |
| `not-answering` | missed, below the gone threshold | answer -> answering, flaps +1; misses >= gone-after-scans **and** now - missingSince >= gone-after-days -> likely-gone |
| `likely-gone` | stayed silent long enough | answer -> answering, flaps +1. Never deleted |
| `unresolved` | its name has no address | resolves -> pending |
| `excluded` | matches `exclude` | never attempted; recorded with the reason |
| `out-of-scope` | listed by a source, address outside `scope` | never attempted |

Gone needs a count and a time span, as `Distrust` needs `drop-confirm-scans` and
`drop-confirm-days` [verified: `Scanner.cs` 141-148]. **Scan health:** when fewer than half of last
scan's answering assets answer (`health-ratio`, 0.5), the scan is `degraded`: no miss counts and the
notes say why. A scan cut short by its window records no attempt for assets it did not reach.
`--fresh` starts empty, keeps the old file as `inventory.previous.json`, and declares nothing gone.

## 4. Mechanisms and probes, in build order

1. **Targets file:** addresses, ranges, names. IPv6 ranges wider than `/112` are refused.
2. **TCP connect** on the profile's ports (embedded data): 22, 23, 80, 88, 135, 139, 389, 443, 445,
   631, 636, 3268, 3269, 3389, 5985, 5986, 8080, 8443, 9100. Open, refused, filtered or unreachable,
   and the connect time. *Limits:* a host firewall that drops everything looks gone; every connect
   completes a handshake that targets and IDS log; stateful firewalls count the sessions.
3. **Handshake probes, no credentials,** only where the profile says: SSH banner (read, send nothing);
   HTTP `GET /` (no redirects, 64 KB cap: status, `Server`, `WWW-Authenticate`, title); WinRM
   `GET /wsman` (401 or 405 from `Microsoft-HTTPAPI` [guess]); TLS through the `TlsRunner` code; SMB2
   NEGOTIATE (dialect, signing required; no session); LDAP anonymous rootDSE in hand-encoded BER
   (whether `System.DirectoryServices.Protocols` works on macOS is unverified); RPC and Kerberos
   connect only. *Nothing is ever sent on 9100-9107 or 515:* raw print ports print what arrives.
4. **AD source:** `StoreInputs.Targets(new TargetSpec("computer", null, "dNSHostName", []))`, as
   `keeper certs --from-ad` does [verified], without a logon-age filter: stale records are the point.
   When `TargetsIncomplete` [verified] says the list may be short, no asset loses its `ad` source.
5. **DNS:** forward A/AAAA for every name, optional reverse PTR, through `System.Net.Dns` behind an
   `IResolver` (portable, no package). *Limits:* no SRV, no zone transfer (noisy, often alerted); AD's
   `dnsRecord` is binary and not decoded [verified: `dns-zones.yaml` header].
6. **SNMP** (UDP 161), with Lextm.SharpSnmpLib (named by the roadmap). v3 engine discovery needs no
   credential and gives engine ID, boots and time (a device id, and reboots); with a v3 credential,
   GET of the system group. v2c only with `allow-cleartext: true`, warned in the run notes, and only
   configured communities, never a guessed one. v2c without v3 is a finding. Only GET, GETNEXT, GETBULK.
7. **SNMP neighbours:** ARP (`ipNetToPhysicalTable`, `ipNetToMediaTable`) and LLDP addresses from
   routers and switches; also the IPv6 neighbours.
8. **Widening:** each source's addresses widened to its prefix, cut to `scope`, capped by
   `max-new-addresses`, tagged `widened-from`.
9. **Classifier:** embedded `fingerprints.yaml` maps evidence to a kind (windows, domain-controller,
   linux-unix, network-device, printer, hypervisor, unknown) with the reason.

Left out on purpose: ICMP (on Linux, `Ping` may start the `ping` program without raw-socket rights
[guess from memory]); the OS ARP cache (a different call per platform); NTP, RDP negotiation, the RPC
endpoint mapper, SMB1 detection, CDP, DHCP.

## 5. Safety

- **One gate.** Every socket goes through `ProbeGate` over an `IDialer` (`SocketDialer`, or
  `FakeDialer` in tests). At the moment of sending it checks scope, exclusions (after resolution),
  the window, the credential's scope and the rate. Nothing else in `Keeper.Discover` opens a socket.
- **Rate:** a token bucket (connections per second), global and per-host concurrency, `gentle`
  ranges at one connection, connect only. Defaults are guesses until a real network **[real network]**.
- **Always excluded:** unspecified, multicast, broadcast, and the network and broadcast addresses
  of IPv4 ranges wider than `/31`.
- **Windows:** outside one the verb refuses unless `--ignore-window`; when one closes mid-run, no new
  probe starts and the inventory is written as partial.
- **IPv6:** from DNS, AD names, SNMP neighbours and the targets file; never swept. Dual-stack names
  keep both addresses on one asset.
- **Credentials:** from the vault, unattended (no prompts during a scan).

## 6. Risks and conflicts

- **Conflict: portability against the vault.** The vault refuses to run outside Windows [verified:
  `KeyProtectors.Default`], so credentialed SNMP works only on Windows until step 5.
- **"N attempts" is ambiguous** (retries now, or scans?). The design uses scans plus days. **[owner]**
- **Roadmap divergence:** probes in a component, not runners (section 2).
- **`files` is implicit** [verified: `IsImplicit`]: a tenant that never runs discover sees a failed
  `network` read in blind spots every day, as with a missing PingCastle report.
- **One-day lag:** packs resolve targets from rows loaded before today's scans [verified:
  `RunVerb`], as AD to workstations already does.
- **Identity by name or IP** breaks with DHCP churn and multi-address devices (engine-ID merging is
  not in step 1).
- **Probing is visible** and may be reported as an attack; the docs tell tenants to warn their SOC.
- **Not verified:** WinRM's answer to an anonymous GET; SharpSnmpLib's version and licence (MIT, from
  memory); whether SMB2 NEGOTIATE is logged; real devices under these probes.

## 7. Tests

- **Unit:** pure logic (addresses, validation, lifecycle tables, health gate, widening, merging,
  classifier, parsers on canned bytes) with a fake `TimeProvider`.
- **Fake network:** `FakeDialer` maps documentation addresses (192.0.2.0/24, 2001:db8::/32) to
  scripted in-memory peers, so multi-host tests touch no network. Some tests open real loopback
  listeners on ephemeral ports, as `TlsAndLdapTests` does [verified]; the profile is data, so a test
  maps `ssh` to its port. macOS has only `127.0.0.1` by default, hence `FakeDialer` for many hosts.
- **End to end:** a temp Keeper home, manual-mode discover against loopback fakes, then `Scanner`
  over `rules/network.yaml` gives the expected findings.
- **Real network only:** drop against reject, printers and old devices, SNMP v3 on real switches,
  WinRM and SMB answers, DHCP churn, IDS reaction, rate defaults, IPv6 neighbours. First live run:
  a lab with a printer and a switch.

## 8. Task list

Rules for every task: synthetic data only (`example.com`, documentation ranges, loopback); unit
tests beside the component; `dotnet test` green on macOS and Windows; warnings are errors; no `git
stash`, no `docker prune`. Adding a NuGet package needs the owner's yes (task 8).

**Review in every task:** no `Process`, no `Ping`; outside `SocketDialer`, no `Socket`, `TcpClient`,
`UdpClient` or `ConnectAsync` in `Keeper.Discover` (grep for them); no
`[SupportedOSPlatform("windows")]` or Windows-only API in `Keeper.Discover`; nothing written to the
store; no tenant data; refusals throw `ArgumentException` with a clear message, as other verbs do.

**T1. Component and addresses.** Create `components/discover/src/Keeper.Discover/Keeper.Discover.csproj`,
`tests/Keeper.Discover.Tests/`; add both to `Keeper.slnx`. `Addresses.cs`: parse IPv4/IPv6 addresses
and CIDRs, contains, expand with a cap, the always-excluded classes.
*Accept:* `/24` expands to 254 hosts; `/31` and `/32` keep every address; `2001:db8::/64` refuses to
expand; an expansion over the cap throws; multicast and broadcast are flagged.
*Review:* off-by-one errors at the ends of ranges; IPv6 written in canonical form.

**T2. Targets file.** `DiscoveryTargets.cs`, `TargetsLoader.cs` (YamlDotNet), `Schemas.DiscoveryTargets`
in `components/contracts/.../Records.cs`.
*Accept:* the section 3 example loads; an unknown field, free mode without scope, v2c without
`allow-cleartext`, an oversized IPv6 range, a target outside the scope in free mode, and a bad window
all fail with a message naming the field.
*Review:* defaults match section 3; validation runs before any network use.

**T3. Inventory file.** `Inventory.cs`, `InventoryFile.cs`: read, atomic write, schema check,
history cap, `--fresh` keeps `inventory.previous.json`; `Schemas.Inventory`.
*Accept:* round trip is identical; an unknown major schema is refused; a crash before the rename
leaves the old file; the cap holds.
*Review:* the file path goes through `PathGuard` under `imports/`; nothing in it is secret.

**T4. Lifecycle.** `Lifecycle.cs`, a pure function (asset, outcome, scan health, settings, now) that
returns the new asset.
*Accept:* table tests for every move in section 3; a degraded scan changes no misses; gone needs
both the count and the days; `flaps` counts returns; excluded and out-of-scope are never attempted.
*Review:* compare with `Scanner.Distrust` semantics; no move deletes an asset.

**T5. Gate and dialer.** `ProbeGate.cs`, `IDialer.cs`, `SocketDialer.cs` (TCP connect with timeout,
UDP exchange), `tests/.../FakeDialer.cs`, a token bucket on `TimeProvider`.
*Accept:* an excluded or out-of-scope address is never dialed (the FakeDialer log is empty); a name
that resolves into an exclusion is refused; the rate and concurrency caps hold under a fake clock;
refused gives `closed`, a timeout gives `filtered`; window close stops new dials.
*Review:* the gate is the only path to a socket; check-time equals use-time (no TOCTOU between
resolution and connect).

**T6. TCP sweep and profiles.** `Probes/TcpConnect.cs`, embedded `profiles.yaml` (port, service,
probe, `send-nothing`).
*Accept:* loopback open, refused and filtered (FakeDialer) cases; the connect time is recorded;
print ports are marked send-nothing.
*Review:* sockets are disposed; no data is written on a send-nothing port.

**T7. Handshake probes.** `Probes/SshBanner.cs`, `Http.cs`, `WinRm.cs`, `TlsProbe.cs` (reuses
`TlsRunner.Row`), `Smb2Negotiate.cs`, `LdapRootDse.cs`.
*Accept:* each parser passes on canned synthetic bytes and against a loopback fake server; byte and
time caps hold; HTTP never follows a redirect and sends only GET; the SMB probe sends one NEGOTIATE
and closes.
*Review:* no probe sends credentials; malformed answers give `unknown`, never an exception that
escapes; caps on everything read.

**T8. SNMP and the `snmp` integration type.** Needs the owner's yes for Lextm.SharpSnmpLib (check
licence, version, audit; add it to `Directory.Packages.props` and the source mapping in
`nuget.config`). `Probes/Snmp.cs`: v3 discovery, v3 GET, v2c only when allowed. Add the `snmp` type
to `IntegrationTypes.cs`, with secrets in `SecretsFor`.
*Accept:* a loopback UDP fake agent answers discovery and GET; a credential is refused for an
address outside its integration's endpoint scope; v2c disabled sends nothing; the code builds no
SET PDU (a test over the PDU types it can emit); integration tests for the new type.
*Review:* secrets never logged or written to the inventory; usmStats answers are not reported as
"no agent".

**T9. Sources, merge, widening.** `Sources/TargetsSource.cs`, `AdSource.cs` (StoreInputs),
`DnsSource.cs` (`IResolver`), `SnmpNeighbours.cs`, `Widening.cs`, `AssetMerge.cs`.
*Accept:* an in-memory store with synthetic AD computer rows gives AD candidates; an incomplete AD
read keeps old `ad` sources; manual mode uses no source; widening stays inside the scope and under
the cap; an IP-only asset merges into the named asset that resolves to it.
*Review:* the store is opened read-only; widened counts are reported.

**T10. Classifier.** Embedded `fingerprints.yaml`, `Classifier.cs`.
*Accept:* synthetic evidence sets map to each kind with `kindWhy`; no evidence gives `unknown`.
*Review:* the mapping is data; nothing environment-specific in it.

**T11. Discoverer.** `Discoverer.cs`: plan, probe through the gate, scan health, lifecycle,
classify, write.
*Accept (FakeDialer + fake resolver):* a new unlisted host appears as answering; an AD host silent
for 3 scans over 14 days becomes likely-gone with `everAnswered: false`; an outage scan is degraded
and changes nothing; excluded hosts get no dial; cancellation writes a partial inventory.
*Review:* no state change on degraded or cut-short scans; notes explain every refusal.

**T12. Verb.** `components/discover/src/keeper-discover/DiscoverVerb.cs` + csproj; register in
`Program.cs` and `keeper.csproj`. Flags: `--targets`, `--fresh`, `--dry-run` (sources, address count,
time estimate at the configured rate, sends nothing), `--ignore-window`, `--help`.
*Accept:* `--dry-run` dials nothing; a temp-home manual run against loopback writes the inventory;
exit codes follow `ExitCodes` (Ok, NoData on partial, Usage on bad input).
*Review:* the help text states what is sent; the v2c warning is printed.

**T13. Rule pack.** `rules/network.yaml` (entity `network-host`): NET-RECORD-NOTHING-BEHIND,
NET-STOPPED-ANSWERING, NET-UNLISTED-MACHINE, NET-NAME-UNRESOLVED, NET-SNMP-V2C-ONLY, NET-TELNET-OPEN,
NET-SMB-SIGNING-OFF, NET-NO-MANAGEMENT-PROTOCOL, NET-FLAPPING, NET-INVENTORY-OLD (`_modified`).
Extend `ShippedRulesTests` with a synthetic inventory fixture.
*Accept:* `keeper rules validate` passes; the fixture gives exactly the expected findings.
*Review:* the field paths match the T3 model; severities and fixes are reasonable; no tenant terms.

**T14. Docs.** Rows for README (verb table, Trying it), ARCHITECTURE (components table and pipeline),
RULES.md (`network` pack fields), ENGINE-ROADMAP stage 6 (what was built, and where the probes live),
and `docs/DISCOVERY.md` (targets reference, safety, SOC notice, "never run live").
*Review:* the docs match the code; each limit in section 4 is stated.

**T15 (owner decides; not in "done").** `keeper run --discover` as the first stage, and step 2's
targets from several entity types with `approve`.
