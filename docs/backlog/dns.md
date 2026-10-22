# DNS checks waiting on runner features

The DNS packs (`rules/dns-zones.yaml` over `ldap`, `rules/dns-server.yaml` over `cim`) cover what the
current runners can read. This file lists the checks left out, what each one would read, and the
runner feature it waits on. Names below are placeholders (`example.org`, `mail.example.org`).

## 1. LDAP: decode `dnsRecord` and `dNSProperty`

Both are binary. The LDAP runner drops binary values it does not know (they are not valid text), so
no rule can see record types, record data, timestamps or a zone's stored properties from the
directory. A decoder in `LdapValues` (like the one for `nTSecurityDescriptor`) would turn:

- `dnsRecord` (multi-valued, `DNS_RPC_RECORD`-style layout: DataLength, Type, Version, Rank, Flags,
  Serial, TtlSeconds (big-endian), Reserved, TimeStamp (hours since 1601), Data) into
  `[ { type: A|AAAA|CNAME|NS|SRV|MX|TXT|PTR|SOA|..., ttl, timestamp (ISO, or "static" for 0), data } ]`.
- `dNSProperty` (multi-valued, `DNS_PROPERTY_RECORD`: DataLength, NameLength, Flag, Version, Id, Data)
  into an object keyed by property id name: `allowUpdate` (id 0x02), `secureTime`, `noRefreshInterval`
  (0x10), `refreshInterval` (0x20), `agingState` (0x40), `scavengingServers` (0x11),
  `agingEnabledTime` (0x12), `type` (0x01), `masterServers`, `autoNsServers`, `dcPromoConvert`.

Rules that become possible, per partition (DomainDnsZones, ForestDnsZones, legacy):

| Proposed id | What it would judge |
|---|---|
| DNS-ZONE-LDAP-NONSECURE-UPDATE | `dNSProperty.allowUpdate = 1` on a zone - the directory-side twin of DNS-SRV-ZONE-NONSECURE-UPDATE, readable without WinRM to each server |
| DNS-ZONE-LDAP-AGING-OFF | `agingState = 0` on a zone that allows dynamic update |
| DNS-ZONE-LDAP-NO-SCAVENGER | aging on, but `scavengingServers` names no server that has scavenging enabled (join with the cim pack through the store) |
| DNS-NODE-STATIC-STALE | static records (timestamp 0) pointing at addresses no known computer has (join with AD computers / cim adapter rows) |
| DNS-NODE-DYNAMIC-STALE | dynamic records whose timestamp is older than no-refresh + refresh, i.e. scavengeable but not scavenged |
| DNS-NODE-CNAME-DANGLING-INTERNAL | CNAME targets inside AD zones that do not exist as a node |
| DNS-NODE-NS-UNKNOWN | NS records in internal zones naming hosts that are not DNS servers in the inventory |
| DNS-NODE-WILDCARD-TYPE | which record type the wildcard is (an A wildcard captures more than a MX wildcard) |
| DNS-NODE-DC-SRV-MISSING | `_ldap._tcp.dc._msdcs`, `_kerberos._tcp`, `_ldap._tcp.pdc` SRV sets that lack a domain controller the directory lists (and SRV records for DCs that no longer exist) |
| DNS-NODE-TTL-ZERO | records with TTL 0 or extreme TTLs |

Why not now: guessing the binary layout inside a rule is impossible, and these attributes are not
safe to treat as text.

## 2. LDAP / store: cross-checks needing a join

| Proposed id | Reads | Needs |
|---|---|---|
| DNS-NODE-OWNER-USER | `dnsNode` owner SID joined to AD user rows (a name registered by a user account, the ADIDNS footprint) | a `store` rule over `row_seen` joining the dns-zones rows to the active-directory user rows; belongs in a keeper-integration pack, not in the ldap one |
| DNS-SRV-NO-SCAVENGER-ANYWHERE | `ScavengingInterval` across all DNS servers of a domain: fire only when none scavenges | a store rule across hosts (cim counts are per host); today DNS-SRV-SCAVENGING-OFF fires per server at low severity |
| DNS-SRV-BIND-SECONDARIES | `BindSecondaries = true` on MicrosoftDNS_Server (uncompressed, one-record-per-message transfers for BIND 4) | it is on by default on Windows DNS, so it would fire on every DC; only meaningful once the tenant states that no BIND secondaries exist (a `required: true` setting such as `threshold.dns.no-bind-secondaries`). Written and removed |
| DNS-ZONE-REPLICATION-SCOPE | zones replicated forest-wide that only one domain uses, or in a custom application partition with too few replicas | `msDS-NC-Replica-Locations` of the partition's crossRef joined to zones; doable over ldap later, left out to keep scope |

## 3. CIM: settings outside the legacy WMI provider

`root/MicrosoftDNS` does not expose these. They live in the DNS Server PowerShell provider's CIM classes
(`root/Microsoft/Windows/DNS`, e.g. `DnsServerResponseRateLimiting`, `DnsServerRecursion`,
`DnsServerGlobalQueryBlockList`, `DnsServerCache`, `DnsServerSetting`, `DnsServerDiagnostics`,
`DnsServerQueryResolutionPolicy`). Whether those classes answer a plain WQL `SELECT` (rather than only
the provider's own methods) has not been verified on a server, so no rule reads them yet.

| Proposed id | What it would judge |
|---|---|
| DNS-SRV-RRL-OFF | response rate limiting mode is not Enable on internet-facing servers |
| DNS-SRV-DNSSEC-VALIDATION-OFF | the resolver does not validate DNSSEC answers |
| DNS-SRV-RECURSION-SCOPE | recursion scopes / query resolution policies that recurse for everyone |
| DNS-SRV-VERSION-QUERY | the server answers `version.bind`-style queries |
| DNS-SRV-DIAG-QUERY-LOG | debug log (DnsServerDiagnostics) settings: query logging on with no size cap, or off with no analytic logging either |
| DNS-SRV-CACHE-MAX-TTL | cache max TTL far above the default |

The cache locking percent, socket pool size and global query block list are read from the registry
today (DNS-REG-*), which covers the main hardening without this provider.

## 4. Registry: key names that contain `/`

The registry runner's key-path check accepts letters, digits, space, `_ . ( ) - { }` and backslashes.
Event channel keys contain `/`
(`SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNSServer/Audit`), so two
checks were written and taken out again:

- **DNS-REG-AUDIT-CHANNEL-OFF** - `Enabled = 0` on the DNSServer/Audit channel (zone, record and setting
  changes leave no trace).
- **DNS-REG-ANALYTIC-CHANNEL-OFF** - DNSServer/Analytical not enabled (no query log for investigations).

Allowing `/` inside one path segment (never `..`, never a leading separator) would bring both back.
An alternative is an `eventlog` option that reports a channel's enabled state and size.

## 5. A DNS-protocol runner (public and external DNS hygiene)

None of this is readable through LDAP or CIM: it needs a `dns` protocol that sends standard queries
(UDP, falling back to TCP) to a named resolver or to a zone's authoritative servers, read-only, and
returns one row per answer record. Suggested query fields: `name` (a template, or `for_each` over the
tenant's list of public domains - `threshold.dns.public-domains`, never in the rule), `type`,
`server` (`recursive` default, `authoritative`, or an address), `dnssec: true` (set DO, return AD flag
and RRSIGs). Rows: `name, type, ttl, data, rcode, authoritative, ad, server`. It never sends updates,
NOTIFY or zone transfer requests except where a rule names `type: AXFR` against the tenant's own
servers (see open resolvers below).

| Proposed id | What it would read | Fails when |
|---|---|---|
| DNS-PUB-SPF-MISSING | TXT at each public domain | no `v=spf1` record |
| DNS-PUB-SPF-WEAK | the same | more than one SPF record, `+all` or `?all`, more than 10 DNS-lookup mechanisms after expanding includes |
| DNS-PUB-SPF-NULL-FOR-NONMAIL | TXT at domains the tenant marks as not sending mail | missing `v=spf1 -all` |
| DNS-PUB-DMARC-MISSING | TXT at `_dmarc.example.org` | no `v=DMARC1` record |
| DNS-PUB-DMARC-WEAK | the same | `p=none` past a grace period, `pct` below 100, no `rua` |
| DNS-PUB-DKIM-MISSING | TXT/CNAME at `<selector>._domainkey.example.org` for the tenant's selectors | the selector does not resolve, key shorter than 1024 bits |
| DNS-PUB-MTA-STS | TXT at `_mta-sts.example.org` plus the policy over the `http` runner | record missing, or the policy mode is not `enforce` |
| DNS-PUB-TLSRPT | TXT at `_smtp._tls.example.org` | missing |
| DNS-PUB-CAA-MISSING | CAA at each public domain | no CAA record (any CA may issue) |
| DNS-PUB-DNSSEC-UNSIGNED | DS at the parent, DNSKEY at the zone | no DS/DNSKEY where the tenant expects signing |
| DNS-PUB-DNSSEC-BROKEN | the validating resolver's answer | SERVFAIL with DO set, or RRSIG expiring within N days |
| DNS-PUB-DANGLING-CNAME | CNAME targets of public names, then the target | target is NXDOMAIN or a cloud hostname pattern (storage, app hosting, CDN) that no longer exists - subdomain takeover |
| DNS-PUB-DANGLING-NS | NS delegations of sub-zones | the delegated servers do not answer authoritatively (lame delegation, takeover risk) |
| DNS-PUB-NS-INCONSISTENT | NS at the parent vs NS at the zone's own servers, and SOA serials across them | sets differ, or serials diverge for longer than the refresh |
| DNS-PUB-NS-SINGLE | NS set | fewer than two name servers, or all in one network |
| DNS-PUB-AXFR-OPEN | AXFR to each of the tenant's own authoritative servers | the transfer succeeds from the scanner's address |
| DNS-INT-OPEN-RESOLVER | recursive query for an unrelated public name sent to the tenant's internet-facing DNS addresses | the server recurses for an outside client |
| DNS-INT-SPLIT-LEAK | internal-only names queried on public resolvers | an internal name resolves publicly |
| DNS-PUB-MX-NULL | MX at domains that do not receive mail | no null MX (`0 .`) |

Every public domain list, selector list and "expected to be signed" list is a tenant threshold with
`required: true`; the rules hold no domain names.
