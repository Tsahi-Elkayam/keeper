# Network Discovery (`keeper discover`)

`keeper discover` builds and updates a living inventory of the machines and devices on your networks
at `data/imports/discovery/inventory.json` (`keeper.inventory/1`). The `network` rule pack
(`rules/network.yaml`) reads that file through the `files` integration, turning reachability changes,
unlisted machines, missing management protocols, and weak network services into findings while loading
every discovered asset into `row_seen` as a `computer` entity.

## Modes: `free` vs `manual`

Discovery is configured in `settings/discovery.yaml` (`schema: keeper.discovery/1`):

- **`free` mode (autonomous discovery within boundaries):**
  - Requires at least one CIDR in `scope` (refuses to start if `scope` is empty).
  - Pulls known computer hostnames from Active Directory in the store (`sources.ad.enabled: true`),
    resolves forward and reverse DNS (`sources.dns`), walks SNMP ARP/neighbour tables on discovered
    routers and switches (`sources.snmp-neighbours`), and widens around known addresses (`widen`)
    up to `widen.max-new-addresses`, clipped strictly to `scope` minus `exclude`.
- **`manual` mode (explicit targets only):**
  - Ignores external sources (AD, SNMP neighbour tables, and subnet widening) and probes only the
    addresses, CIDRs, and hostnames listed in `targets`, minus `exclude`.

## Example `settings/discovery.yaml`

```yaml
schema: keeper.discovery/1
mode: free

scope:
  - 192.0.2.0/24
  - 198.51.100.0/24

targets:
  - 192.0.2.10
  - sw-core-01.example.com

exclude:
  - cidr: 192.0.2.240/28
    why: lab bench equipment
  - name: "*.ilo.example.com"
    why: out-of-band controllers polled separately

gentle:
  - 198.51.100.128/26

approve:
  - cidr: 192.0.2.0/24
    protocols: [snmp]
    integration: snmp-core

sources:
  ad:
    enabled: true
  dns:
    forward: true
    reverse: true
  snmp-neighbours:
    enabled: true
    credentials: [snmp-core]

widen:
  from-ad: { ipv4-prefix: 24 }
  from-dns: { ipv4-prefix: 24 }
  from-snmp-neighbours: { ipv4-prefix: 24 }
  max-new-addresses: 2048

snmp:
  v3: [snmp-core]
  v2c: []
  allow-cleartext: false

rate:
  connections-per-second: 50
  concurrent: 64
  per-host: 2
  timeout-ms: 1500
  retries: 1

staleness:
  gone-after-scans: 3
  gone-after-days: 14

windows:
  - days: [mon, tue, wed, thu, fri]
    from: "01:00"
    to: "05:00"

history:
  keep: 20
```

## Safety Guarantees (`ProbeGate`)

Every outbound TCP connection and UDP packet passes through `ProbeGate` immediately before dialing:

1. **Always-excluded addresses:** `0.0.0.0/8`, `255.255.255.255/32`, multicast (`224.0.0.0/4`, `ff00::/8`),
   and reserved `240.0.0.0/4` are refused unconditionally.
2. **Configured exclusions & scope:** Any IP or hostname matching `exclude` is marked `excluded` and
   never dialed. In `free` mode, any address outside `scope` is marked `out-of-scope` and never dialed.
3. **Raw print ports & gentle ranges:** Ports `515` (LPD) and `9100..9107` (JetDirect) are hard-coded
   `SendNothing`: Keeper only completes a TCP three-way handshake and closes the socket without sending
   a single byte, preventing garbage pages on printers. Addresses in `gentle` ranges are restricted to
   TCP connect only (no protocol handshakes, no UDP SNMP probes, `per-host: 1`).
4. **Read-only SNMP:** `SnmpProbe` only emits `GetRequest-PDU` (`0xA0`) and `GetNextRequest-PDU` (`0xA1`).
   `SetRequest-PDU` (`0xA3`) is never constructed. SNMPv2c is refused unless `snmp.allow-cleartext: true`
   is set explicitly, and credentials are only sent to addresses within both the integration's CIDR
   endpoint and an `approve` rule.
5. **Outage protection:** If fewer than 50% of previously answering assets answer in a run (when at
   least 4 answered previously), the run's `scanHealth` is marked `degraded` and miss counters are
   frozen so a scanner-side network outage never transitions healthy machines to `likely-gone`.

## Asset Lifecycle & Operational Coverage

Assets in `inventory.json` never disappear silently; each asset moves through explicit states:
`pending` -> `answering` / `not-answering` -> `likely-gone`, or `unresolved` / `excluded` / `out-of-scope`.

In addition to `assets`, `inventory.json` records a `coverage` object:
- `coverage.sources`: whether each discovery source (`targets`, `ad`, `dns`, `snmp-neighbours`) and
  widening rule (`from-ad`, `from-dns`, `from-snmp-neighbours`) succeeded (`ok`), hit its cap or had
  an incomplete upstream read (`partial`), was `skipped`, or `failed`.
- `coverage.summary`: counts of total candidates, attempted probes, answering, not-answering,
  likely-gone, unresolved, excluded, out-of-scope, answering assets exposing at least one management
  protocol (`ssh`, `winrm`, `https`, `snmp`, `ldap`, `rdp`), and widened addresses.

## Commands

| Command | Description |
|---|---|
| `keeper discover --dry-run` | Prints mode, source coverage, candidate and address counts, and estimated time. Sends no probes and writes no files; DNS lookups for named targets are still made |
| `keeper discover` | Runs discovery within the configured scan window and updates `data/imports/discovery/inventory.json` |
| `keeper discover --ignore-window` | Runs discovery now, ignoring `windows` |
| `keeper discover --fresh` | Backs up `inventory.json` to `inventory.previous.json` and resets miss counters |
| `keeper discover --targets <file>` | Uses another `discovery.yaml` instead of `settings/discovery.yaml` |
| `keeper run --discover` | Runs `keeper discover` before `keeper scan` in the daily loop |
