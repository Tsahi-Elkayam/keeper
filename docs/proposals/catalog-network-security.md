# Proposals - network and security products (catalogue port)

Status: proposal only. Nothing here is loaded or run; another model writes the YAML from these specs.
Source: the archived check catalogue (network and security product files) mapped row by row; the
per-row map (which holds tenant detail) lives outside the repo. This document is tenant-free: no
hosts, addresses, names, counts or dates. Where a check needs a tenant-specific list (allowed
registrars, protected roles, approved hosts, camera VLANs) the list is a `threshold.<name>` setting.

Written 2026-10-20 without contacting any tenant system. Vendor documentation could not be fetched
during this pass, so **no entry is marked verified**: `likely` means the path and fields are the
documented, widely used ones from the vendor's public reference as known to the author; `guess`
means the shape must be tried on a real tenant first. A wrong path is `unknown`, never a pass.

Engine facts relied on (from `docs/RULES.md` and the integration code): `http` is GET-only (POST reads
exist only for `graphql`) with none/basic/bearer/api-key/oauth-client-credentials and
`session-login` auth (a POST sign-in on the integration's own endpoint with user and password or key
pair, JSON or form body, the token read from a field of the answer and sent in a configurable header
with an optional prefix; options `loginPath`, `userField`, `passwordField`, `body`, `tokenField`,
`header`, `prefix`, `lifetimeMinutes`, fixed `loginFields.*`), `for_each` (one level), relative dates
`{DAYS_AGO:n}`; `graph`,
`sccm`, `prtg`, `servicenow`, `vcenter` are named http types; `cim`/`registry`/`eventlog` run per
Windows host; `tls` handshakes per target; `file` reads json/xml/csv in `imports\`; `store` SQL
reads Keeper's own rows (row_seen history, registers, attestations). A missing field is n/a, a
failed query is unknown, neither is a pass.

Canonical refs: `NIST-800-53:XX-n`, `CIS-Controls-v8:n.n`, `MITRE-ATTACK:Tnnnn`.

Entry format: **ID** - Catches; Severity (lens); Source; Condition; Refs; Fix; Confidence.
"Rows:" lists the catalogue CheckIds the entry closes. Several rows often share one query - rules
with identical query text share one read.

---

## 1. FortiGate (`rules\fortigate.yaml`, system `fortigate`, integration `http` with auth `bearer` - no new type, see section 17)

All reads are FortiOS REST: `GET /api/v2/monitor/...` (state) and `GET /api/v2/cmdb/...`
(configuration), JSON `results` array (or object), `Authorization: Bearer <token>` of a REST API
administrator with a read-only access profile. Set `items: results`, `paging: none`, `headers:
{ Accept: application/json }`. Paths below are the FortiOS 7.x ones; a 6.4 or 7.0 build may differ
in a few monitor endpoints (first run confirms). Vendor reference: FortiOS REST API reference on the
Fortinet developer portal (login-walled); FortiOS Administration Guide and CIS FortiGate Benchmark
for the settings.

### Priority 1

**FGT-IPSEC-TUNNEL-DOWN** - Catches: a configured IPsec tunnel whose phase 1 or any phase 2
selector is down. Severity: critical (both). Source: GET `/api/v2/monitor/vpn/ipsec`, key `name`;
fields `proxyid[].status`, `incoming_bytes`, `outgoing_bytes`, `creation_time`. Condition:
`proxyid[].status` ne `up` (any element). Refs: NIST-800-53:CP-2, NIST-800-53:SC-7. Fix: compare
proposals and PSK with the peer, enable auto-negotiate, re-key. Confidence: likely. Rows:
FORTIGATE-AVL-001.

**FGT-BGP-NEIGHBOR-DOWN** - Catches: a BGP neighbour not in Established state. Severity: critical.
Source: GET `/api/v2/monitor/router/bgp/neighbors`, key `neighbor_ip`; fields `state`,
`admin_status`, `uptime`, `prefixes received` (name varies). Condition: `state` ne `Established`.
Refs: NIST-800-53:CP-2. Fix: check the tunnel, ASN, timers. Confidence: likely. Rows:
FORTIGATE-AVL-004.

**FGT-BGP-NO-PREFIXES** - Catches: an Established neighbour that delivered zero prefixes (an idle
path). Severity: high. Source: same read. Condition: `state` eq `Established` and the received-prefix
field lt 1. Refs: NIST-800-53:CP-2. Fix: fix route propagation on the peer side or the inbound filter.
Confidence: likely (field name to confirm). Rows: FORTIGATE-AVL-005.

**FGT-BGP-MULTIPATH-OFF** - Catches: ECMP disabled although two tunnels per connection exist.
Severity: high. Source: GET `/api/v2/cmdb/router/bgp`, key `-`; fields `ebgp-multipath`,
`ibgp-multipath`. Condition: `ebgp-multipath` ne `enable`. Refs: NIST-800-53:CP-2. Fix: enable
multipath (and confirm ECMP on the cloud side). Confidence: likely. Rows: FORTIGATE-AVL-006.

**FGT-BGP-NO-OUTBOUND-FILTER** - Catches: a BGP neighbour without an outbound prefix-list or
route-map - the device can leak routes learned from one peer to the other (transit). Severity: high
(security). Source: GET `/api/v2/cmdb/router/bgp`, `items: results[0].neighbor`, key `ip`; fields
`prefix-list-out`, `route-map-out`, `distribute-list-out`. Condition: all three empty. Refs:
NIST-800-53:SC-7, NIST-800-53:CM-6 (RFC 7454). Fix: attach a deny-by-default outbound prefix-list
permitting only the on-premises aggregates. Confidence: likely. Rows: FORTIGATE-CFG-013,
KN-bgp-transit-route-leak.

**FGT-BGP-NO-INBOUND-FILTER** - Catches: a neighbour without an inbound prefix-list or with
maximum-prefix unset or warning-only. Severity: medium. Same read; fields `prefix-list-in`,
`route-map-in`, `maximum-prefix`, `maximum-prefix-warning-only`. Condition: any of `prefix-list-in`
empty and `route-map-in` empty; `maximum-prefix` absent or eq 0; `maximum-prefix-warning-only` eq
`enable`. Refs: NIST-800-53:SC-7. Confidence: likely. Rows: FORTIGATE-CFG-014.

**FGT-BGP-TIMERS-MISMATCH** - Catches: hold or keepalive timers not matching the cloud peer's
documented values. Severity: medium. Same read (global `holdtime-timer`, `keepalive-timer`, and per
neighbour). Condition: effective hold-time ne 30 (threshold `fortigate.bgp-holdtime`) or keepalive ne
10. Refs: NIST-800-53:CP-2. Confidence: likely. Rows: FORTIGATE-CFG-015.

**FGT-BGP-REDISTRIBUTE-UNFILTERED** - Catches: `redistribute connected` or `redistribute static`
enabled without a route-map. Severity: medium. Same read; fields `redistribute.connected.status`,
`.route-map`, `redistribute.static.*`. Condition: status eq `enable` and route-map empty. Refs:
NIST-800-53:SC-7. Confidence: likely. Rows: FORTIGATE-CFG-017.

**FGT-BGP-NEIGHBOR-DEFINITION-DRIFT** - Catches: a neighbour whose `remote-as` or the local `as`
differs from the expected ASNs (thresholds `fortigate.bgp-local-as`, `fortigate.bgp-remote-as`).
Severity: high. Same read. Condition: `remote-as` ne threshold. Refs: NIST-800-53:CM-6. Confidence:
likely. Rows: FORTIGATE-CFG-012.

**FGT-BGP-AUTH-MISSING** - Catches: a neighbour whose `password` is empty where the peer type requires
authentication (threshold: list of neighbour roles). Severity: medium (security). The API returns the
password as a masked marker or empty, never the value. Condition: `password` empty. Refs:
NIST-800-53:SC-8. Confidence: guess (masking behaviour). Rows: FORTIGATE-CFG-018.

**FGT-BGP-ROUTEMAP-DRIFT** - Catches: route-map rules whose `set-aspath` / `set-local-preference` or
the neighbour's `route-map-in`/`-out` names differ from the approved plan (thresholds
`fortigate.routemap.<name>.local-preference`, `.aspath`). Severity: medium. Source: GET
`/api/v2/cmdb/router/route-map`, key `name`, plus the neighbour read. Condition: field ne threshold.
Refs: NIST-800-53:CM-3. Confidence: likely. Rows: FORTIGATE-AVL-007.

**FGT-IPSEC-NO-AUTO-NEGOTIATE** - Catches: a tunnel that never initiates IKE (`auto-negotiate`
disabled or `passive-mode` enabled) on phase 1 or phase 2. Severity: high. Source: GET
`/api/v2/cmdb/vpn.ipsec/phase1-interface` and `/phase2-interface`, key `name`. Condition:
`auto-negotiate` ne `enable` or `passive-mode` eq `enable`. Refs: NIST-800-53:CP-2. Confidence:
likely. Rows: FORTIGATE-AVL-003.

**FGT-IPSEC-DPD-OFF** - Catches: dead peer detection disabled or slower than the peer's replacement
window. Severity: high. Source: phase1 read; fields `dpd`, `dpd-retrycount`, `dpd-retryinterval`.
Condition: `dpd` eq `disable`, or `dpd-retryinterval` gt 10, or `dpd-retrycount` gt 3. Refs:
NIST-800-53:CP-2. Confidence: likely. Rows: FORTIGATE-CFG-034.

**FGT-IPSEC-PHASE1-WEAK** - Catches: IKEv1, a proposal using 3DES/DES/MD5/SHA1, or a DH group below
14. Severity: high (security). Source: phase1 read; fields `ike-version`, `proposal`, `dhgrp`,
`mode`. Condition: `ike-version` ne 2, or `proposal` match `3des|des-|md5|sha1`, or `dhgrp` match
`\b(1|2|5)\b`, or `mode` eq `aggressive`. Refs: NIST-800-53:SC-13, NIST-800-53:SC-8. Fix: align
to AES-256/SHA-256+/DH 14+ with the peer. Confidence: likely. Rows: FORTIGATE-CFG-030,
FORTIGATE-AUT-008, FORTIGATE-AUT-009 (peertype `any` as a sibling condition:
FGT-IPSEC-IKEV1-OR-PEERTYPE-ANY).

**FGT-IPSEC-PHASE2-MISMATCH** - Catches: phase 2 without PFS, a weak proposal, or a key lifetime
above the peer's 3600 s. Severity: high. Source: phase2 read; fields `proposal`, `pfs`, `dhgrp`,
`keylifeseconds`, `replay`. Condition: `pfs` ne `enable`, or `keylifeseconds` gt 3600, or `replay`
ne `enable`, or `proposal` match the weak pattern. Refs: NIST-800-53:SC-13. Confidence: likely.
Rows: FORTIGATE-CFG-031, FORTIGATE-CFG-032 (rekey/fragmentation fields as FGT-IPSEC-REKEY-SETTINGS,
low).

**FGT-IPSEC-ADD-ROUTE-ON** - Catches: a route-based tunnel with `add-route` enabled (static routes
fight BGP). Severity: high. Source: phase1 read; fields `add-route`, `net-device`. Condition:
`add-route` eq `enable`. Refs: NIST-800-53:CM-6. Confidence: likely. Rows: FORTIGATE-CFG-033.

**FGT-IPSEC-PSK-NOT-ROTATED** - Catches: no pre-shared-key change event for a tunnel within the
rotation period. Severity: high (security). Source: GET `/api/v2/monitor/log/event` with
`filter=cfgpath==vpn.ipsec.phase1-interface` and a relative start time of `{DAYS_AGO:365}`
(threshold `fortigate.psk-max-age-days`); the value is never returned. Condition: `count: none`
per tunnel (template key on `cfgobj`). Refs: NIST-800-53:IA-5, NIST-800-53:SC-12. Fix: rotate on
both sides through a secrets channel. Confidence: guess (log filter grammar and retention). Rows:
FORTIGATE-AUT-010.

**FGT-POLICY-ANY-ANY-ANY** - Catches: an enabled accept policy with source all, destination all and
service ALL. Severity: high (security). Source: GET `/api/v2/cmdb/firewall/policy`, key
`policyid`, name `name`; fields `status`, `action`, `srcaddr[].name`, `dstaddr[].name`,
`service[].name`, `srcintf[].name`, `dstintf[].name`, `logtraffic`, `comments`, `utm-status`,
`ips-sensor`, `av-profile`, `nat`. Condition: `status` eq `enable` and `action` eq `accept` and
`srcaddr[].name` contains `all` and `dstaddr[].name` contains `all` and `service[].name` contains
`ALL`. Refs: NIST-800-53:SC-7, NIST-800-53:AC-4, CIS-Controls-v8:4.4. Confidence: likely. Rows:
FORTIGATE-CFG-001. Siblings on the same read: **FGT-POLICY-SERVICE-ALL** (service ALL, medium),
**FGT-POLICY-NOT-LOGGED** (`logtraffic` notin [all, utm], medium; rows CFG-004),
**FGT-DENY-NOT-LOGGED** (action deny and logtraffic eq disable, plus policyid 0; rows LOG-009),
**FGT-TUNNEL-POLICY-NOT-LOGGED** (srcintf or dstintf in the tunnel/SSL VPN interface list threshold
and logtraffic ne all; rows LOG-010), **FGT-POLICY-DISABLED-OLD** (status disable; age needs the
revision log, low; rows CFG-005), **FGT-POLICY-NO-NAME-OR-COMMENT** (name empty or comments empty,
low; rows CFG-006), **FGT-POLICY-INBOUND-NO-VIP-OR-IPS** (srcintf role wan and no VIP destination or
ips-sensor empty, high; rows CFG-008), **FGT-SSLVPN-POLICY-UNSCOPED** (srcintf ssl.root and groups
empty or dstaddr all, high; rows CFG-009), **FGT-TUNNEL-POLICY-NAT-OR-UTM** (tunnel interfaces with
nat enable or utm-status enable where the design says none, medium; rows CFG-010),
**FGT-POLICY-NO-SECURITY-PROFILE** (wan or ssl.root policies with utm-status disable or ips-sensor
empty, medium; rows CFG-043).

**FGT-POLICY-ZERO-HITS** - Catches: an enabled policy with zero hits whose first-used date is older
than 90 days. Severity: low. Source: GET `/api/v2/monitor/firewall/policy`, key `policyid`; fields
`hit_count`, `last_used`, `first_used` (epoch seconds - the engine cannot read epoch, so judge
`hit_count` eq 0 only and leave the age to the first run). Refs: NIST-800-53:CM-7. Confidence:
likely. Rows: FORTIGATE-CFG-003.

**FGT-POLICY-SHADOWED** - Catches: a policy fully contained by an earlier one. Severity: medium.
Source: store rule over the policy rows in `row_seen` (pairwise containment in SQL). Confidence:
guess (engine capacity). Rows: FORTIGATE-CFG-007.

**FGT-LOCAL-IN-POLICY-MISSING** - Catches: no local-in policy restricting IKE, the SSL VPN port and
admin ports by source. Severity: high (security). Source: GET `/api/v2/cmdb/firewall/local-in-policy`,
key `policyid`. Condition: `count: { op: lt, value: 1, where: { field: status, op: eq, value: enable } }`
(refine by service names on the first run). Refs: NIST-800-53:SC-7, NIST-800-53:AC-17. Confidence:
likely. Rows: FORTIGATE-CFG-040.

**FGT-ADMIN-ON-WAN** - Catches: a WAN-role interface with any administrative access protocol in
`allowaccess`. Severity: critical (security). Source: GET `/api/v2/cmdb/system/interface`, key
`name`; fields `role`, `allowaccess`, `status`, `alias`, `description`, `type`. Condition: `role` eq
`wan` and `allowaccess` match `https|ssh|snmp|ping|http|telnet`. Refs: NIST-800-53:AC-17,
NIST-800-53:SC-7, CIS-Controls-v8:4.4. Confidence: likely. Rows: FORTIGATE-CFG-041. Siblings:
**FGT-MGMT-ON-USER-INTERFACE** (non-management roles with https/ssh; rows CFG-028),
**FGT-CLEARTEXT-ADMIN-ENABLED** (allowaccess match `telnet|http\b`; rows AUT-005),
**FGT-INTERFACE-UNLABELLED-OR-UNUSED-UP** (physical interface, status up, no link, alias empty - low;
rows CFG-029), **FGT-UNDERLAY-LINK-DOWN** (interfaces tagged as underlay in a threshold list whose
monitor `link` is false, critical; rows AVL-008).

**FGT-SSLVPN-AUTH-NO-MFA** - Catches: an SSL VPN authentication rule whose `auth` is local or LDAP
without a second factor. Severity: critical (security). Source: GET
`/api/v2/cmdb/vpn.ssl/settings`, `items: results.authentication-rule`, key `id`; fields `auth`,
`groups[].name`, `portal`, `client-cert`; plus GET `/api/v2/cmdb/user/local` (`two-factor`) and
`/api/v2/cmdb/user/radius`, `/user/saml`. Condition: `auth` in [local, ldap] (a RADIUS/SAML rule
is assumed to carry MFA; the first run confirms). Refs: NIST-800-53:IA-2(1), CIS-Controls-v8:6.4,
MITRE-ATTACK:T1133. Fix: front the VPN with SAML + Conditional Access or RADIUS MFA. Confidence:
likely. Rows: FORTIGATE-AUT-001, DUO-CFG-017. Siblings on the settings read:
**FGT-SSLVPN-DEFAULT-PORTAL-OPEN** (`default-portal` not a no-access portal threshold; rows
CFG-038), **FGT-SSLVPN-SOURCE-UNRESTRICTED** (`source-interface` includes non-wan or
`source-address` eq all; rows CFG-036), **FGT-SSLVPN-TLS-WEAK** (`ssl-min-proto-ver` notin
[tls1-2, tls1-3]; rows AUT-002), **FGT-SSLVPN-NO-BRUTEFORCE-LIMIT** (`login-attempt-limit` gt 3 or
`login-block-time` lt 300; rows AUT-003), **FGT-SSLVPN-NO-CLIENT-CERT** (`reqclientcert` eq disable,
medium; rows AUT-004), **FGT-SSLVPN-DTLS-OFF** (`dtls-tunnel` ne enable, low; rows AVL-012).

**FGT-SSLVPN-NO-OS-CHECK** - Catches: a portal without host check or OS check. Severity: medium.
Source: GET `/api/v2/cmdb/vpn.ssl.web/portal`, key `name`; fields `host-check`, `os-check`,
`split-tunneling`, `split-tunneling-routing-address`, `web-mode`, `limit-user-logins`. Condition:
`host-check` eq `none` and `os-check` eq `disable`. Refs: NIST-800-53:CM-7. Confidence: likely.
Rows: FORTIGATE-LCM-008, FORTIGATE-CFG-039. Siblings: **FGT-SSLVPN-FULL-TUNNEL** (`split-tunneling`
eq disable or routing address contains all; rows CFG-037), **FGT-SSLVPN-WEB-MODE-ON** (`web-mode` eq
enable, medium; rows AUT-016), **FGT-SSLVPN-PORTAL-UNREFERENCED** (`q_ref` eq 0, low; rows HYG-009).

**FGT-SSLVPN-LOCAL-USER** - Catches: a local user referenced by a VPN group or rule. Severity: high
(security). Source: GET `/api/v2/cmdb/user/local`, key `name`; fields `type`, `status`, `q_ref`,
`two-factor`, `passwd-time`. Condition: `q_ref` gt 0 and `type` eq `password`. Refs:
NIST-800-53:AC-2(1). Confidence: likely. Rows: FORTIGATE-IAM-008.

**FGT-XS-SSLVPN-GROUP-STALE-MEMBER** - Catches: an AD group bound to a VPN rule that contains disabled
or stale accounts. Severity: medium. Source: store rule joining `user/group` match names (fortigate
rows) with AD group members from the AD scan. Confidence: likely (join via sAMAccountName of the
group's `group-name` match). Rows: FORTIGATE-IAM-009.

**FGT-XS-SSLVPN-SESSION-DISABLED-USER** - Catches: an active SSL VPN session for a user disabled in
AD, or longer than 24 h. Severity: high. Source: GET `/api/v2/monitor/vpn/ssl`, key `index`;
fields `user_name`, `remote_host`, `duration`, `subsessions`; store join with AD users. Condition:
duration gt 86400 or the joined `userAccountControl` has flag 2. Refs: NIST-800-53:AC-2(3),
NIST-800-53:AC-12. Confidence: likely. Rows: FORTIGATE-IAM-010. Sibling: **FGT-SSLVPN-USERS-NEAR-LIMIT**
(`count: { op: gt, value: N }` with threshold `fortigate.sslvpn-max-users` x 0.7; rows HLT-017).

**FGT-ADMIN-NO-MFA** - Catches: an administrator with `two-factor` disabled. Severity: high (security).
Source: GET `/api/v2/cmdb/system/admin`, key `name`; fields `accprofile`, `trusthost1`..`10`,
`two-factor`, `remote-auth`, `wildcard`, `password-expire`, `force-password-change`. Condition:
`two-factor` eq `disable`. Refs: NIST-800-53:IA-2(1), CIS-Controls-v8:6.5. Confidence: likely.
Rows: FORTIGATE-IAM-004. Siblings on the same read: **FGT-ADMIN-NO-TRUSTED-HOSTS** (every trusthost
field eq `0.0.0.0 0.0.0.0` or empty; rows IAM-003), **FGT-DEFAULT-ADMIN-IN-USE** (name eq admin and
status enable; last login via the log read; rows IAM-002), **FGT-ADMIN-SUPERADMIN-MANY**
(`count: { op: gt, value: 3, where: accprofile eq super_admin }`; rows IAM-005),
**FGT-ADMIN-WILDCARD-REMOTE** (`wildcard` eq enable; rows IAM-007), **FGT-ADMIN-INVENTORY** (info list
of every admin; rows IAM-001), **FGT-ADMIN-PASSWORD-OLD** (`password-expire` past or empty with the
policy off; rows AUT-015).

**FGT-APIUSER-BROAD-PROFILE** - Catches: a REST API user with a writable profile or no trusted hosts.
Severity: medium (security). Source: GET `/api/v2/cmdb/system/api-user`, key `name`; fields
`accprofile`, `trusthost[]`, `cors-allow-origin`, `schedule`. Condition: `accprofile` eq
`super_admin` or `trusthost` empty. Refs: NIST-800-53:AC-2, NIST-800-53:IA-5. Confidence: likely.
Rows: FORTIGATE-IAM-006.

**FGT-SNMP-V2C-ENABLED** - Catches: an enabled SNMP v1/v2c community, or a v3 user below auth-priv.
Severity: high (security). Source: GET `/api/v2/cmdb/system.snmp/community` (key `id`; `status`,
`name`, `hosts`) and `/api/v2/cmdb/system.snmp/user` (key `name`; `security-level`, `auth-proto`,
`priv-proto`, `notify-hosts`, `events`). Condition: community `status` eq enable; user
`security-level` ne `auth-priv`. Refs: NIST-800-53:IA-5, CIS-Controls-v8:4.6. Confidence: likely.
Rows: FORTIGATE-IAM-018, FORTIGATE-AUT-007. Siblings: **FGT-SNMP-TRAPS-INCOMPLETE** (`notify-hosts`
empty or `events` lacks `vpn-tun-down`/`bgp-backward-transition`/`ha-switch`; rows MON-005).

**FGT-STRONG-CRYPTO-OFF** - Catches: `strong-crypto` disabled, SSL minimum below TLS 1.2, or SSH
algorithm lists with CBC/SHA-1/group1. Severity: medium (security). Source: GET
`/api/v2/cmdb/system/global`, key `-`; fields `strong-crypto`, `ssl-min-proto-version`,
`admin-https-ssl-versions`, `ssh-kex-algo`, `ssh-enc-algo`, `ssh-mac-algo`, `admin-telnet`,
`admintimeout`, `admin-lockout-threshold`, `admin-lockout-duration`, `admin-sport`,
`pre-login-banner`, `post-login-banner`, `admin-server-cert`, `revision-backup-on-logout`,
`revision-image-auto-backup`, `gui-allow-default-hostname`, `admin-forticloud-sso-login`,
`admin-restrict-local`, `ssl-static-key-ciphers`, `admin-concurrent`. Condition: `strong-crypto` ne
enable, or `ssl-min-proto-version` in [TLSv1, TLSv1-1, SSLv3], or `ssh-enc-algo` match `cbc`, or
`ssh-mac-algo` match `sha1|md5`. Refs: NIST-800-53:SC-13, NIST-800-53:SC-8. Confidence: likely.
Rows: FORTIGATE-CFG-027, FORTIGATE-AUT-006. One `system/global` read feeds the siblings:
**FGT-ADMIN-TLS-WEAK** (`admin-https-ssl-versions` contains tlsv1-0 or tlsv1-1; rows LCM-011),
**FGT-LEGACY-SETTING-ENABLED** (`ssl-static-key-ciphers` eq enable or `admin-telnet` eq enable;
rows LCM-012), **FGT-ADMIN-TIMEOUT-LONG** (`admintimeout` gt 10 or `admin-lockout-threshold` gt 3;
rows CFG-024, IAM-015), **FGT-LOGIN-BANNER-OFF** (either banner eq disable, low; rows CFG-025),
**FGT-REVISION-BACKUP-OFF** (either revision flag eq disable, low; rows BCK-003),
**FGT-GUI-OPTIONS-WEAK** (`admin-forticloud-sso-login` eq enable or `admin-restrict-local` eq
disable, low; rows HYG-013), **FGT-ADMIN-CONCURRENT-SESSIONS** (`admin-concurrent` eq enable, low;
rows IAM-013).

**FGT-PASSWORD-POLICY-OFF** - Catches: password policy disabled, not applied to admin passwords and
IPsec pre-shared keys, or minimum length below 14. Severity: medium (security). Source: GET
`/api/v2/cmdb/system/password-policy`, key `-`; fields `status`, `apply-to`, `minimum-length`,
`expire-status`, `expire-day`. Condition: `status` ne enable, or `apply-to` notcontains
`ipsec-preshared-key`, or `minimum-length` lt 14. Refs: NIST-800-53:IA-5(1), CIS-Controls-v8:5.2.
Confidence: likely. Rows: FORTIGATE-IAM-014.

**FGT-LDAP-CLEARTEXT** - Catches: an LDAP server object without LDAPS/StartTLS or without server
identity check. Severity: high (security). Source: GET `/api/v2/cmdb/user/ldap`, key `name`; fields
`secure`, `ca-cert`, `server-identity-check`, `username`, `type`. Condition: `secure` eq `disable`
or `server-identity-check` ne enable. Refs: NIST-800-53:SC-8, NIST-800-53:IA-5. Confidence: likely.
Rows: FORTIGATE-AUT-012 (bind account rotation is AD-USER-PASSWORD-OLD on `username`).

**FGT-RADIUS-NO-MESSAGE-AUTHENTICATOR** - Catches: a RADIUS server object not requiring
Message-Authenticator, or with a single server. Severity: medium (security). Source: GET
`/api/v2/cmdb/user/radius`, key `name`; fields `server`, `secondary-server`,
`require-message-authenticator`, `auth-type`, `transport-protocol`. Condition:
`require-message-authenticator` ne enable, or `secondary-server` empty
(**FGT-RADIUS-SERVER-SINGLE**, rows DUO-AVL-001). Refs: NIST-800-53:IA-5, NIST-800-53:CP-2.
Confidence: likely (field added in 7.4; older builds return absent = n/a). Rows: FORTIGATE-AUT-011.

**FGT-SAML-MISCONFIGURED** - Catches: a SAML server object whose IdP entity id is not the expected
tenant (threshold `fortigate.saml-idp-entity-pattern`) or whose digest is not SHA-256. Severity:
medium. Source: GET `/api/v2/cmdb/user/saml`, key `name`; fields `idp-entity-id`, `idp-cert`,
`digest-method`, `group-name`. Confidence: likely. Rows: FORTIGATE-AUT-013.
**FGT-XS-SAML-IDP-CERT-STALE** - store join of `idp-cert` expiry (from
`/api/v2/cmdb/vpn.certificate/remote` `valid-to`) with the Entra service principal's active signing
certificate; fails when the thumbprints differ or the local copy expires within 30 days. Severity:
high. Confidence: guess (thumbprint fields). Rows: FORTIGATE-PKI-007.

**FGT-ANTISPOOF-OFF** - Catches: asymmetric routing allowed or anti-replay disabled. Severity: medium.
Source: GET `/api/v2/cmdb/system/settings`, key `-`; fields `asymroute`, `strict-src-check`,
`v4-ecmp-mode`, `gui-*` feature flags. Condition: `asymroute` eq enable. Refs: NIST-800-53:SC-7.
Confidence: likely. Rows: FORTIGATE-AUT-014. Sibling: **FGT-FEATURE-UNUSED-ENABLED** (feature
flags enabled outside the documented list threshold, low; rows HYG-011; DHCP server count via
`/api/v2/cmdb/system/dhcp/server`, explicit proxy via `/api/v2/cmdb/web-proxy/explicit`).

**FGT-NO-TUNNEL-DOWN-TRIGGER** - Catches: no enabled automation trigger for the IPsec tunnel-down
event (and, as **FGT-NO-CRITICAL-EVENT-TRIGGER**, for BGP down, HA failover, conserve mode, CPU; as
**FGT-NO-CONFIG-CHANGE-TRIGGER**, for configuration change). Severity: critical / high / medium.
Source: GET `/api/v2/cmdb/system/automation-trigger`, key `name`; fields `event-type`, `logid[]`,
`trigger-type`; plus `/api/v2/cmdb/system/automation-stitch` (`status`, `trigger`, `actions`).
Condition: `count: { op: lt, value: 1, where: { field: event-type, op: eq, value: event-log } }`
narrowed by the `logid` of the tunnel-down event (threshold `fortigate.logid.tunnel-down`). Refs:
NIST-800-53:SI-4(5), NIST-800-53:IR-6. Confidence: likely (log ids per build). Rows:
FORTIGATE-MON-001, MON-002, MON-016.

**FGT-NO-CENTRAL-LOGGING** - Catches: no enabled syslog or FortiAnalyzer destination. Severity: high.
Source: GET `/api/v2/cmdb/log.syslogd/setting` (and syslogd2..4), `/api/v2/cmdb/log.fortianalyzer/setting`,
key `-`; fields `status`, `server`, `mode`, `enc-algorithm`, `certificate-verification`,
`ssl-min-proto-version`. Condition: every destination `status` ne enable. Refs: NIST-800-53:AU-6(3),
NIST-800-53:AU-4(1), CIS-Controls-v8:8.9. Confidence: likely. Rows: FORTIGATE-MON-003. Siblings:
**FGT-LOG-TRANSPORT-UNVERIFIED** (`enc-algorithm` eq disable or `certificate-verification` eq
disable or syslog `mode` eq udp; rows PKI-008), **FGT-LOG-DELIVERY-FAILED** (GET
`/api/v2/monitor/log/fortianalyzer` connection status ne connected; rows LOG-012),
**FGT-EVENTLOG-SUBTYPE-OFF** (GET `/api/v2/cmdb/log/eventfilter`: `event`, `system`, `vpn`, `user`,
`router`, `ha` any ne enable; rows LOG-001), **FGT-AUDIT-LOGGING-INCOMPLETE** (GET
`/api/v2/cmdb/log/setting`: `user-anonymize` eq enable or `local-in-deny-unicast` eq disable; rows
MON-010), **FGT-LOG-RETENTION-SHORT** (GET `/api/v2/cmdb/log.disk/setting` `maximum-log-age` lt 14;
rows LOG-013).

**FGT-FIRMWARE-UNSUPPORTED** - Catches: a running version below the minimum supported branch/patch
(thresholds `fortigate.min-version`, `fortigate.supported-branches`). Severity: high. Source: GET
`/api/v2/monitor/system/status`, key `-`; fields `version`, `build`, `model`, `serial`, `hostname`.
Condition: `version` notmatch threshold pattern. Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.4.
Confidence: likely. Rows: FORTIGATE-LCM-001. Sibling: **FGT-PSIRT-UNPATCHED** (`version` match a
`fortigate.vulnerable-builds` pattern kept from the vendor's advisories, critical; rows LCM-002;
confidence guess - no stable public JSON feed), **FGT-FIRMWARE-NOT-UPGRADED-LONG** (newest revision
whose comment or version differs is older than 365 days, from GET
`/api/v2/monitor/system/config-revision`; rows LCM-014; guess).

**FGT-SIGNATURES-STALE** - Catches: a licensed signature service whose last update is older than 7
days, or an expiring entitlement. Severity: medium / high. Source: GET
`/api/v2/monitor/license/status`, key `-`; fields per service (`ips`, `antivirus`, `appctrl`,
`forticare`, `web_filtering` ...: `status`, `expires`, `last_update`, `version`). Condition:
`<service>.last_update` age-gt 7 (epoch seconds - engine cannot read epoch; if so use the
`/api/v2/monitor/system/fortiguard/update-info` ISO fields, or mark the row n/a until the engine
reads epoch). Refs: NIST-800-53:SI-3. Confidence: guess (date formats). Rows: FORTIGATE-LCM-005.
Siblings: **FGT-FORTICARE-EXPIRING** (`forticare.expires` until-lt 90, high; rows CST-001),
**FGT-SUBSCRIPTION-EXPIRING-OR-UNUSED** (any service `expires` until-lt 90 while referenced; rows
CST-002), **FGT-FORTIGUARD-UNREACHABLE** (GET `/api/v2/monitor/system/fortiguard/server-info` status
ne reachable; rows HLT-015), **FGT-FORTICLOUD-ACCOUNT-UNEXPECTED** (account field notmatch a
municipal-mailbox pattern threshold; rows IAM-017; guess).

**FGT-HA-STANDALONE** - Catches: HA mode standalone, or peers fewer than two, or checksums differing.
Severity: high. Source: GET `/api/v2/cmdb/system/ha` (key `-`; `mode`, `hbdev`, `monitor`,
`session-pickup`, `session-pickup-connectionless`, `override`), GET `/api/v2/monitor/system/ha-peer`
(key `serial_no`), GET `/api/v2/monitor/system/ha-checksums`. Condition: `mode` eq `standalone`.
Refs: NIST-800-53:CP-2, CIS-Controls-v8:12.x. Confidence: likely. Rows: FORTIGATE-AVL-016.
Siblings: **FGT-HA-CHECKSUM-MISMATCH** (checksums per member differ - store compare; rows LCM-010),
**FGT-HA-SINGLE-HEARTBEAT** (`hbdev` lists one interface or `monitor` empty; rows AVL-017),
**FGT-HA-SESSION-PICKUP-OFF** (`session-pickup` ne enable, low; rows AVL-020), **FGT-HA-EVENT** (log
read subtype ha; rows LOG-008).

**FGT-SENSOR-ALARM** - Catches: a hardware sensor in alarm, or fewer than two power supplies.
Severity: high. Source: GET `/api/v2/monitor/system/sensor-info`, key `name`; fields `value`,
`alarm`, `status`, `type`. Condition: `alarm` eq true. Refs: NIST-800-53:PE-11. Confidence: likely.
Rows: FORTIGATE-HLT-013, FORTIGATE-AVL-021 (PSU count lt 2 as **FGT-SINGLE-PSU**).

**FGT-MEMORY-NEAR-CONSERVE** / **FGT-CPU-HIGH** / **FGT-SESSIONS-NEAR-LIMIT** - Catches: resource
usage above thresholds (`fortigate.cpu-max-pct` 70, `fortigate.mem-max-pct` 72,
`fortigate.sessions-max` per model). Severity: high / high / medium. Source: GET
`/api/v2/monitor/system/resource/usage?scope=global` (one call returns `cpu`, `mem`, `session`,
`setuprate`, `disk` series), `items: results`, key `-`; use the latest sample's `current` value.
Refs: NIST-800-53:SC-5, NIST-800-53:SI-4. Confidence: likely (array shape to confirm). Rows:
FORTIGATE-HLT-001, HLT-002, HLT-004, HLT-005 (ippool via GET `/api/v2/monitor/firewall/ippool`:
`used`/`total` -> **FGT-IPPOOL-NEAR-FULL**), HLT-006 (GET `/api/v2/monitor/log/device/state`
`used` pct gt 80 -> **FGT-LOG-DISK-FULL**).

**FGT-CONSERVE-MODE-EVENT** / **FGT-TUNNEL-FLAP-EVENT** / **FGT-BGP-STATE-CHANGE-EVENT** /
**FGT-SSLVPN-LOGIN-FAILURES-HIGH** / **FGT-SSLVPN-LOGIN-FOREIGN-COUNTRY** / **FGT-ADMIN-LOGIN-FAILED**
/ **FGT-CONFIG-CHANGE-RECENT** / **FGT-REBOOT-RECENT** / **FGT-IKE-NO-RESPONSE** /
**FGT-EVENTLOG-ERROR-SIGNATURE** - one family over the event log: GET
`/api/v2/monitor/log/event` (or `/api/v2/monitor/log/disk/event/...` depending on build) with
`params: { filter: "subtype==vpn", rows: "1000" }` and a start time of `{DAYS_AGO:7}`; key a
template of `logid|date|time|<object>`. Conditions: `logdesc` match `Conserve mode` (high);
`action` in [tunnel-down, negotiate] (high); `subtype` eq router and `msg` match `BGP` (high);
`action` eq ssl-login-fail counted per `remip` gt 20 per run (high); `action` eq ssl-login and
`srccountry` notin threshold list (high); `subtype` eq system and `action` eq login and `status` eq
failed (high); `action` in [Edit, Add, Delete] info list (medium); `msg` match `reboot|restarted`
(medium); `msg` match `no response` on IKE (medium); `level` in [error, critical, alert] grouped by
`logid` (medium). Refs: NIST-800-53:AU-6, NIST-800-53:SI-4, NIST-800-53:AC-7. Confidence: guess
(the monitor log filter grammar and the exact path differ between builds; local disk logging must be
on). Rows: FORTIGATE-HLT-003, HLT-014, LOG-002, LOG-003, LOG-004, LOG-005, LOG-006, LOG-007,
LOG-014, AVL-018.

### Priority 2

**FGT-INTERFACE-ERRORS** / **FGT-INTERFACE-UTILISATION-HIGH** - Source: GET
`/api/v2/monitor/system/interface?include_vlan=true`, key `name`; fields `rx_errors`, `tx_errors`,
`rx_drops`, `tx_drops`, `rx_bytes`, `tx_bytes`, `speed`, `link`, `duplex`. Deltas need a store rule
over two runs; a single run can only flag non-zero error counters (info). Severity: high / medium.
Refs: NIST-800-53:SI-4. Confidence: likely. Rows: FORTIGATE-HLT-007, HLT-008.

**FGT-TUNNEL-ECMP-IMBALANCE** - store rule: for each pair of tunnels of one connection (threshold
list), the busier tunnel's byte delta between two runs over the pair's total gt 0.65. Severity:
high. Rows: FORTIGATE-HLT-010. **FGT-TUNNEL-THROUGHPUT** - info rows of per-tunnel byte deltas (the
cloud-side CloudWatch read is the authoritative ceiling check, see section 2). Rows: HLT-009,
HLT-011 (packets).

**FGT-NPU-OFFLOAD-OFF** - phase1 `npu-offload` ne enable or tunnel policy `auto-asic-offload` ne
enable. Severity: medium. Rows: FORTIGATE-HLT-012.

**FGT-TUNNEL-MSS-NOT-CLAMPED** - interface `tcp-mss` absent or gt 1379 on tunnel interfaces, and
tunnel policies without `tcp-mss-sender`/`-receiver`. Severity: medium. Rows: FORTIGATE-HLT-018.

**FGT-DNS-MISCONFIGURED** - GET `/api/v2/cmdb/system/dns`: `secondary` empty or `protocol`
contains cleartext toward a non-internal server (threshold). Low. Rows: FORTIGATE-HLT-016.
**FGT-DNS-SERVER-ENABLED** - GET `/api/v2/cmdb/system.dns-server` rows exist (`count: some`). Low.
Rows: CFG-042.

**FGT-NTP-MISCONFIGURED** / **FGT-NTP-NOT-SYNCHRONISED** - GET `/api/v2/cmdb/system/ntp`
(`ntpsync` ne enable, fewer than two servers, `authentication` ne enable) and GET
`/api/v2/monitor/system/ntp/status` (`synchronized` ne true or `offset` gt 500 ms). Medium. Rows:
FORTIGATE-CFG-023, MON-012.

**FGT-AUTOUPDATE-OFF** - GET `/api/v2/cmdb/system.autoupdate/schedule` `status` ne enable, or
`/push-update` `status` ne enable. Low. Rows: LCM-006.

**FGT-ALT-PARTITION-OLD** / **FGT-FLASH-CLUTTER** - GET `/api/v2/monitor/system/firmware`:
`partitions[]` with `active` false whose `version` is not the previous production build (threshold),
or image count gt 2. Low / info. Rows: LCM-009, HYG-014.

**FGT-FABRIC-VERSION-MISMATCH** - GET `/api/v2/monitor/system/csf`: member versions differ from
the root (store compare). Low. Rows: LCM-013. **FGT-SDN-CONNECTOR-STATIC-KEY** - GET
`/api/v2/cmdb/system/sdn-connector`: `use-metadata-iam` ne enable and type is a cloud connector.
Medium. Rows: MON-014.

**FGT-LINK-MONITOR-MISSING** - GET `/api/v2/cmdb/system/link-monitor`: `count: none`, or per
underlay interface (threshold list) no monitor with `status` enable. Medium. Rows: AVL-009.
**FGT-WAN-SINGLE-UPLINK** - interfaces with `role` eq wan count lt 2 (`count` over the interface
read with `where`). Medium. Rows: AVL-010.

**FGT-STATIC-ROUTE-UNCOMMENTED** / **FGT-PBR-UNDOCUMENTED** / **FGT-ROUTE-COUNT-CHANGED** /
**FGT-SDWAN-RULE-COVERS-TUNNEL-PREFIX** - GET `/api/v2/cmdb/router/static` (`comment` empty, or
`blackhole` route for the cloud supernets missing - threshold), `/api/v2/cmdb/router/policy`
(`status` enable and `comments` empty), `/api/v2/monitor/router/ipv4` (count vs the previous run in
the store, +-10 %), `/api/v2/cmdb/system/sdwan` (`service[].dst` overlapping the tunnel prefixes
threshold). Medium. Rows: AVL-013, AVL-014, AVL-015, CFG-048.

**FGT-ZONE-INTRAZONE-ALLOW** - GET `/api/v2/cmdb/system/zone`: `intrazone` eq allow. Medium. Rows:
CFG-011. **FGT-SERVICE-WIDE-RANGE** - GET `/api/v2/cmdb/firewall.service/custom`: `tcp-portrange`
or `udp-portrange` spanning more than 100 ports (regex on the range text; exact arithmetic needs
the store). Medium. Rows: CFG-021. **FGT-ADDRESS-UNREFERENCED** / **FGT-VIP-UNREFERENCED** /
**FGT-AUTH-OBJECT-UNREFERENCED** / **FGT-ROUTEMAP-UNREFERENCED** - `q_ref` eq 0 on
`/api/v2/cmdb/firewall/address`, `addrgrp`, `firewall.service/custom`, `firewall.schedule/*`,
`firewall/vip`, `firewall/ippool`, `user/local`, `user/group`, `user/ldap`, `user/radius`,
`vpn.certificate/local`, `router/route-map`. Low. Rows: CFG-020, CFG-022, HYG-001, HYG-002,
CFG-019. **FGT-IPSEC-TUNNEL-UNUSED** - phase1 objects absent from the monitor read or with
`q_ref` eq 0. Medium. Rows: CFG-035.

**FGT-IPS-SENSOR-MONITOR-ONLY** - GET `/api/v2/cmdb/ips/sensor` referenced sensors with
`entries[].action` eq pass on severity high/critical, or `scan-botnet-connections` ne block.
Medium. Rows: CFG-044. **FGT-INSPECTION-FACTORY-CA** - GET
`/api/v2/cmdb/firewall/ssl-ssh-profile`: `ssl.inspect-all` eq deep-inspection and `caname` eq
`Fortinet_CA_SSL`. Medium. Rows: PKI-010.

**FGT-CERT-EXPIRING** / **FGT-CA-CERT-EXPIRING** / **FGT-OCSP-OFF** / **FGT-ACME-NOT-USED** -
GET `/api/v2/monitor/system/available-certificates` (`valid_to` until-lt 30 where `references` gt
0; `is_default` certificates referenced -> **FGT-FACTORY-DEFAULTS-IN-USE**), GET
`/api/v2/cmdb/vpn.certificate/ca` (`valid-to` until-lt 180), GET `/api/v2/cmdb/vpn.certificate/setting`
(`ocsp-status` ne enable and `strict-crl-check` ne enable; low), GET `/api/v2/cmdb/system/acme`
(`count: none` while public certificates are manual; low). Rows: PKI-002, PKI-005, PKI-006, PKI-009,
HYG-008. Served-side certificate checks (PKI-001, PKI-003, PKI-004, AVL-011) are the existing TLS-*
rules with the portal and admin GUI as tls targets.

**FGT-CONFIG-REVISION-UNAPPROVED** / **FGT-REVISION-UNCOMMENTED** - GET
`/api/v2/monitor/system/config-revision`, key `id`; fields `time`, `admin`, `comment`, `version`.
Conditions: `id` gt the approved revision id (threshold `fortigate.approved-revision`) - medium;
`comment` empty within 7 days - low. A text diff is not expressible. Rows: CFG-045, HYG-005.

**FGT-VDOM-INVENTORY** - GET `/api/v2/cmdb/system/vdom`, info rows. Rows: CFG-046.
**FGT-SESSION-TTL-DEFAULT** - GET `/api/v2/cmdb/system/session-ttl` `default` gt 3600. Low. Rows:
CFG-047. **FGT-USB-AUTOINSTALL-ON** - GET `/api/v2/cmdb/system/auto-install` either flag eq enable.
Low. Rows: CFG-026. **FGT-GUEST-GROUP-NO-EXPIRY** - `/api/v2/cmdb/user/group` `group-type` eq guest
and `expire` absent. Low. Rows: IAM-012. **FGT-NETFLOW-OFF** - `/api/v2/cmdb/system/netflow`
collector empty or tunnel interfaces without `netflow-sampler`. Low. Rows: MON-007.
**FGT-SECURITY-RATING-FAILED** - GET `/api/v2/monitor/system/security-rating` emit per failed
check (`emit: check: "FGT-SR-{id}"`, severity by the vendor's severity). Low. Rows: MON-008.
**FGT-OUTBREAK-ALERT-OPEN** - outbreak alert list endpoint (path guess), medium. Rows: MON-009.
**FGT-FORTITOKEN-SHORTAGE** - GET `/api/v2/monitor/user/fortitoken`: available lt admins without
MFA (store). Low. Rows: CST-004. **FGT-NAMING-NONCOMPLIANT** / **FGT-ROUTING-OBJECT-UNCOMMENTED**
- names vs `fortigate.naming-pattern`; phase1 `comments`, neighbour `description`, static `comment`
empty. Low. Rows: HYG-003, HYG-004. **FGT-FORTICLOUD-BACKUP-STATE** - `/api/v2/cmdb/system/fortiguard`
`auto-join-forticloud` (info). Rows: BCK-005.

**FGT-XS-NOT-MONITORED** / **FGT-XS-ALERT-RECIPIENT-LEFT** - store rules: the firewall's hostname
absent from PRTG `device` rows (prtg system); `alertemail/setting` `mailto1..3` and
`automation-action` email recipients joined with Entra users where `accountEnabled` eq 0 or the
address matches no mailbox. Rows: MON-004, MON-006.

Rows needing an integration beyond the fortigate type: BCK-001, BCK-002, BCK-007 (file-share-read
of the backup store), AVL-019, AVL-022, HLT-009, HLT-011, MON-011 (aws, section 2), BCK-006
(obligation, section 16).

## 2. AWS network (`rules\aws-network.yaml`, system `aws-network`, integration `aws` - new named type)

All reads are AWS APIs that need SigV4 request signing, which the generic http type cannot do. The
`aws` type (section 17) signs GET/POST query calls with an access key or an SSO/role session, read
only. Actions named per rule.

**AWSNET-VPN-TUNNEL-DOWN** - EC2 `DescribeVpnConnections`, rows per `VgwTelemetry[]` (key
`VpnConnectionId|OutsideIpAddress`); `Status` ne UP. Critical. Refs: NIST-800-53:CP-2. Rows:
KN-1g-vpn-second-tunnel-down.
**AWSNET-VPN-TUNNEL-NEAR-CEILING** / **AWSNET-VPN-TUNNEL-PPS-HIGH** - CloudWatch `GetMetricData`
`AWS/VPN` `TunnelDataIn`/`TunnelDataOut` (and packet metrics where published) per tunnel, p95 over
7 days vs the per-tunnel ceiling threshold (`aws.vpn-tunnel-ceiling-bps`); high. Rows:
KN-10g-tunnel-at-ceiling, FORTIGATE-HLT-009, HLT-011, NTZ-AVL-001.
**AWSNET-VPN-TUNNEL-DOWNTIME-MINUTES** - CloudWatch `TunnelState` minimum per minute, minutes at 0
and at 1 tunnel per connection; high. Rows: FORTIGATE-AVL-022.
**AWSNET-VPN-NO-TUNNEL-ALARM** - CloudWatch `DescribeAlarms` with no alarm on `TunnelState` for a
connection; high. Rows: KN-no-alarm-on-tunnel-down, FORTIGATE-MON-011.
**AWSNET-VPN-ENDPOINT-REPLACED-DOWNTIME** - Health `DescribeEvents` (VPN endpoint replacement) joined
in the store with tunnel-down events; high. Rows: FORTIGATE-AVL-019.
**AWSNET-TGW-ROUTE-ASYMMETRIC** - EC2 `SearchTransitGatewayRoutes` for the camera prefixes vs the
on-premises BGP preference (store join with FGT route reads); medium. Rows:
KN-dx-vpn-asymmetric-routing.
**AWSNET-DX-SINGLE-LOCATION** - DirectConnect `DescribeConnections` distinct `location` lt 2 among
available connections; high. Rows: KN-dx-no-location-diversity.

Generic AWS rules referenced from other packs (same type, `rules\aws.yaml`, prefix `AWS-`):
**AWS-EC2-INSTANCE-SATURATED** / **AWS-EC2-INSTANCE-OVERSIZED** (CloudWatch `CPUUtilization` p95 gt 70
/ lt 20), **AWS-BACKUP-VOLUME-NO-RECOVERY-POINT** (Backup `ListRecoveryPointsByResource` none within
7 days), **AWS-BACKUP-VAULT-NOT-LOCKED** (`GetBackupVaultLockConfiguration` absent), **AWS-ACM-CERT-UNUSED**
(ACM `ListCertificates` where `InUseBy` empty), **AWS-ROUTE53-HEALTHCHECK-UNHEALTHY**,
**AWS-ROUTE53-DUPLICATE-ZONE**, **AWS-ROUTE53-PRIVATE-ZONE-SHADOWS-PUBLIC**,
**AWS-ROUTE53-WRITE-PRINCIPALS-MANY**, **AWS-ROUTE53-DNSSEC-KSK-UNHEALTHY** (`GetDNSSEC` status ne
SIGNING or KMS key disabled), **AWS-ROUTE53-CHANGE-UNEXPECTED-PRINCIPAL** (CloudTrail `LookupEvents`
`ChangeResourceRecordSets` by a principal outside the operator list), **AWS-ROUTE53-NXDOMAIN-TOP**
(Logs Insights - note the query start is a write-class call; prefer a saved-query export as new-file),
**AWS-ALARM-ACTION-NO-SUBSCRIPTION** (SNS `ListSubscriptions` pending/deleted for alarm topics),
**AWS-INSPECTOR-INSTANCE-NOT-COVERED** (Inspector2 `ListCoverage`), **AWS-SG-CAMERA-SEGMENT-BROAD**,
**AWS-COST-MONTHLY-REPORT** / **AWS-COST-CROSS-AZ-BYTES-HIGH** / **AWS-COST-ROUTE53-UNEXPLAINED** /
**AWS-COST-MARKETPLACE-PAYG-VS-BYOL** / **AWS-EBS-VOLUME-COST-HIGH** (Cost Explorer
`GetCostAndUsage`), **AWS-MARKETPLACE-DUPLICATE-FIREWALL**. Severities medium unless stated.
Confidence: likely for the action names (public AWS API reference); the Prowler import already covers
the posture rows noted as `PROWLER-FAILED` in the map.

## 3. Check Point management and gateways (`rules\checkpoint-management.yaml`, system `checkpoint-management`, integrations `http` with auth `session-login` and a read-only POST mode, plus `snmp` - see section 17)

The Management API is a session-based POST API: `POST /web_api/login` returns `sid`, every command
is `POST /web_api/<command>` with header `X-chkp-sid`, paged with `offset`/`limit` and a `total`
field; `show-*` commands are read-only. The Gaia REST API on each host is the same pattern
(`POST /gaia_api/login`, `POST /gaia_api/show-*`). The sign-in is now covered by `session-login`
(`loginPath` the login command, `tokenField` `sid`, `header` `X-chkp-sid`). What the generic type
still cannot do is the read itself: every `show-*` command is a POST with a JSON body, and `http` is
GET-only. These rows therefore stay "needs an integration" until `http` gains a read-only POST mode
limited to allow-listed command paths (section 17, first entry); the rules below are written against
that mode, one `http` integration per management server or gateway. Gateway counters and cluster state come from the CHECKPOINT-MIB over SNMP v3, a second
new type `snmp`. Vendor reference: the Management API reference published on the vendor's support
site (command names below are from that reference; confidence likely unless noted).

### Priority 1 - rulebase, identities, availability

**CPM-RULE-ANY-ANY-ANY-ACCEPT** - Catches: an enabled access rule with source Any, destination Any,
service Any and action Accept. Severity: critical (security). Source: `show-access-rulebase`
(`name` = each layer from `show-access-layers`, `use-object-dictionary` true,
`details-level` full), key `uid`, name `name`; fields `enabled`, `action.name`, `source[].name`,
`destination[].name`, `service[].name`, `track.type`, `comments`, `meta-info.last-modify-time`,
`hits.value`, `source-negate`, `destination-negate`, `custom-fields`. Condition: `enabled` eq true
and `action.name` eq Accept and all three lists contain Any. Refs: NIST-800-53:SC-7,
NIST-800-53:AC-4, CIS-Controls-v8:4.4. Fix: replace with explicit rules. Rows: CHECKPOINT-CFG-002.
Siblings on the same rulebase read: **CPM-RULE-SERVICE-ANY** (service Any on an Accept rule, high;
CFG-003), **CPM-RULE-INBOUND-FROM-INTERNET** (source Any/Internet object and destination internal,
high; CFG-004), **CPM-RULE-ADMIN-PORTS-FROM-USER-NETWORKS** (service in the admin-protocol list
threshold and source not in the admin-network role list, high; CFG-005, CYMULATE-CFG-002,
EKRAN-CFG-012), **CPM-LAYER-NO-CLEANUP-RULE** / **CPM-LAYER-NO-STEALTH-RULE** (per layer: last rule
not Any/Any/Any Drop with track Log; no early Drop rule whose destination is the gateway objects;
medium; CFG-006, CFG-007), **CPM-RULE-ZERO-HITS** (`hits.value` eq 0 with `show-hits` true and
`hits-settings.from-date` 180 days back, medium; CFG-008), **CPM-RULE-DISABLED-OLD** (`enabled` eq
false and `meta-info.last-modify-time` age-gt 90, low; CFG-010), **CPM-RULE-NO-NAME-OR-OWNER**
(`name` empty or `comments` empty, low; CFG-011), **CPM-RULE-TEMPORARY-EXPIRED** (name/comments
match `temp|test|tmp|until|pilot` and older than 30 days, or a time object past its end, medium;
CFG-012), **CPM-RULE-NEGATED-UNCOMMENTED** (any negate flag true and comments empty, low;
CFG-013), **CPM-RULE-SERVER-EGRESS-ANY** (source in the server-role list, destination Any/Internet,
service Any, high; CFG-014), **CPM-RULE-NOT-LOGGED** (`track.type.name` eq None on Accept, or Drop
without Log, medium; LOG-004), **CPM-RULE-STATIC-SAAS-GROUP** (destination group name match
`office365|microsoft|aws` while updatable objects exist, low; CFG-032), **CPM-RULE-CAMERA-NETWORK-BROAD**
(source in the camera-role list and destination/service beyond the recorder/VMS/NTP/DNS roles, high;
CFG-038), **CPM-CLOUDGUARD-RULE-VPC-ANY** (cloud package: Any between VPC roles, high; CFG-039),
**CPM-RULE-MGMT-PORT-EXPOSED** (destination an internal host object, service a management port,
source outside admin roles - high; PINEAPP-CFG-015, OPSWAT-AUT-004, NEXPOSE-AUT-002),
**CPM-RULE-QUARANTINE-REACH** (source the quarantine VLAN object and destination beyond the
remediation roles, high; PORTNOX-CFG-006), **CPM-RULE-NO-SECTION** (rules without a section
title, low; HYG-001), **CPM-RULE-SHADOWED** (store containment over row_seen, low; CFG-009 - the
`verify-policy` command creates a task and is not read-only).

**CPM-RULE-TARGET-GONE** - Catches: a host object referenced by a rule whose address or name matches
a stale or deleted computer in the directory scan. Severity: medium. Source: `show-hosts`
(`details-level` full, key `uid`; `ipv4-address`, `name`, `nat-settings`) plus `where-used` per
host (fan-out), joined in the store with AD computers (stale per AD-COMP-STALE) by name. Refs:
NIST-800-53:CM-8. Rows: CHECKPOINT-HYG-003, OPSWAT-HYG-007, PINEAPP-HYG-008, PORTNOX-HYG-004.
Siblings on the object reads: **CPM-OBJECT-DUPLICATE** (same `ipv4-address` under two names, or name
is a bare dotted quad, low; CFG-018), **CPM-OBJECT-DEFAULT-NAME** (`show-objects` name match
`^New |_\d+$|^Host|^Network` or comments empty, low; HYG-002), **CPM-OBJECT-NAMING-NONCOMPLIANT**
(name notmatch the `checkpoint.naming-pattern` threshold, low; HYG-006), **CPM-OBJECTS-UNUSED-MANY**
(`show-unused-objects` total gt 5 % of objects, low; CFG-017), **CPM-GROUP-NESTING-DEEP**
(`show-groups` details full: nesting depth gt 3 or a member wider than /16, low; CFG-019),
**CPM-NAT-RULE-ANY-OR-STALE** (`show-nat-rulebase`: original source and destination Any on a manual
rule, or automatic NAT on a host that is stale, medium; CFG-016), **CPM-OBJECT-CREATED-BY-LEAVER**
(`meta-info.creator` joined with disabled directory accounts, low; IAM-015),
**CPM-XS-CAMERA-PREFIX-OBJECT-DRIFT** (`show-networks` in the camera groups vs the cloud route-table
prefixes from the aws scan, medium; HYG-014).

**CPM-ACCESS-ROLE-GROUP-MISSING** - `show-access-roles` details full, key `uid`; the `groups[].dn`
joined in the store with AD groups (exists and has members). Severity: medium. Refs:
NIST-800-53:AC-2. Rows: CHECKPOINT-CFG-015.

**CPM-POLICY-NOT-INSTALLED-LATEST** - Catches: a gateway whose installed access or threat policy
revision is older than the last published session, or a gateway with no package. Severity: high.
Source: `show-gateways-and-servers` (`details-level` full, key `uid`, name `name`; fields `type`,
`version`, `os-name`, `hardware`, `sic-status`, `network-security-blades`, `management-blades`,
`policy.access-policy-installed`, `policy.access-policy-revision`, `policy.threat-policy-installed`)
plus `show-last-published-session`, `show-packages`. Condition: `policy.access-policy-installed` eq
false, or the revision differs from the last published (store compare). Refs: NIST-800-53:CM-3.
Rows: CHECKPOINT-CFG-001. Siblings on the gateway read: **CPM-GATEWAY-SIC-NOT-COMMUNICATING**
(`sic-status` ne communicating, high; HLT-009, PKI-008), **CPM-VERSION-UNSUPPORTED** (`version`
notin the supported list threshold, high; LCM-001), **CPM-APPLIANCE-EOS** (`hardware` in an EOS
list threshold, high; LCM-004 - also record EOS as a key date), **CPM-BLADE-UNUSED-OR-UNLICENSED**
(blade enabled but absent from installed layers / the licence export, medium; LCM-013, CST-007),
**CPM-REMOTE-ACCESS-BLADE-LEGACY** (`vpn` or `mobile-access` blade enabled while the remote-access
product of record is another, medium; LCM-014), **CPM-MGMT-NO-SECONDARY** (`count` of objects with
management blades and secondary role lt 1, high; AVL-005), **CPM-GATEWAY-GHOST** (`sic-status` eq
uninitialized or not communicating for 30 days, low; HYG-005), **CPM-CLUSTER-MEMBERS-DIFFER**
(store compare of version/blades per cluster, high; AVL-003), **CPM-CLOUDGUARD-OBJECT-ORPHAN**
(autoprovisioned objects joined with aws instances: no running instance, high; CFG-041),
**CPM-PACKAGE-ORPHAN** (`show-packages` installation-targets empty, low; HYG-004).

**CPM-GATEWAY-NO-LOGS** - `show-logs` with `new-query: { filter: "origin:<gateway>", time-frame:
last-hour }` per gateway (fan-out over the gateway list); `count: none` fails. Severity: high.
Refs: NIST-800-53:AU-12. Rows: CHECKPOINT-LOG-001. Same mechanism: **CPM-THREAT-EVENT-DETECT-ONLY**
(blade in the threat blades, severity high/critical, action detect, last 7 days; high; LOG-010),
**CPM-CLOUDGUARD-DROP-NEW-SIGNATURE** (origin the cloud gateways, action drop, grouped in the store
and compared with the previous run; medium; LOG-011), **CPM-HTTPS-INSPECTION-FAILURES** (blade HTTPS
Inspection, action bypass/drop; low; LOG-015), **CPM-IDENTITY-ACQUISITION-ERRORS** (blade Identity
Awareness, type identity error; medium; LOG-016), **CPM-CLUSTER-FAILOVER-RECENT** (type control,
message match `cluster|member state changed`, last 7 days; high; AVL-004), **CPM-NO-ALERTS-RECEIVED**
(type alert, last 30 days, `count: none`; low; MON-010), **CPM-LOG-RETENTION-SHORT** (oldest log
entry younger than 90 days; medium; LOG-007), **CPM-VPN-PSK-NOT-ROTATED** (audit log: shared-secret
modification older than 365 days per community; high; AUT-010). Confidence: guess for the
`show-logs` query grammar.

**CPM-CHANGE-NO-DESCRIPTION** / **CPM-CHANGE-NO-TICKET** / **CPM-SESSION-UNPUBLISHED-OLD** /
**CPM-POLICY-INSTALL-FAILED** / **CPM-POLICY-INSTALL-BUSINESS-HOURS** / **CPM-SMARTCONSOLE-BUILD-MISMATCH**
/ **CPM-REVISION-RETENTION-SHORT** - `show-changes` (last 7 days: session name, description,
administrator), `show-sessions` (state, changes, locks, application version, last-login-time),
`show-tasks` (install-policy / verify-policy status and start time), `show-api-versions`.
Conditions: description empty or without a ticket pattern (threshold regex); `changes` gt 0 and
state open older than 24 h; task status failed; install start time inside business hours
(threshold); session application version ne the management build; revisions retained lt 90 days.
Severity: medium / medium / low / high / low / low / low. Refs: NIST-800-53:CM-3, CM-5. Rows:
LOG-006, IAM-009, IAM-008, LOG-008, HYG-012, LCM-009, BCK-004.

**CPM-ADMIN-LOCAL-PASSWORD** - Catches: a human administrator whose authentication method is a local
Check Point or OS password. Severity: high (security). Source: `show-administrators` (details
full), key `uid`, name `name`; fields `authentication-method`, `permissions-profile`,
`expiration-date`, `must-change-password`, `email`. Condition: `authentication-method` in
[check point password, os password] and name notin the break-glass list threshold. Refs:
NIST-800-53:IA-2(1), CIS-Controls-v8:6.5. Rows: CHECKPOINT-IAM-004. Siblings:
**CPM-ADMIN-GENERIC-OR-NO-EXPIRY** (name match `admin|fwadmin|test|temp`, or vendor-pattern name
without expiration-date; high; IAM-001), **CPM-ADMIN-SUPERUSER-MANY** (`count` of
permissions-profile Super User gt 3; medium; IAM-002), **CPM-ADMIN-INACTIVE-OR-LEFT** (no audit
login in 90 days, or the joined directory account disabled; high; IAM-003),
**CPM-BREAKGLASS-MISSING-OR-USED** (`count` of the break-glass name lt 1, or audit logins by it in 90
days without a recorded reason; medium; IAM-005), **CPM-ADMIN-APIKEY-NO-EXPIRY** (method api key and
expiration-date absent or more than 365 days away; medium; IAM-007).

**CPM-TRUSTED-CLIENT-ANY** - `show-trusted-clients`: `type` eq any. High. Rows: CFG-034.
**CPM-API-ACCEPTS-ALL-IPS** - `show-api-settings`: `accepted-api-calls-from` eq "All IP addresses".
Medium. Rows: CFG-033. **CPM-IMPLIED-RULES-BROAD** / **CPM-IMPLIED-RULES-UNLOGGED** /
**CPM-OUT-OF-STATE-ACCEPTED** - `show-global-properties` (firewall section): ICMP/DNS/RIP implied
rules enabled; `log-implied-rules` false; drop-out-of-state-tcp false or a gateway override in
`show-simple-gateway` firewall-settings. Medium / medium / high. Rows: CFG-035, LOG-005, CFG-036.

**CPM-INTERFACE-ANTISPOOFING-OFF** - `show-simple-gateway` / `show-simple-cluster` details full,
`items: interfaces`, key `{parent.name}|{name}`; `anti-spoofing` ne true or
`anti-spoofing-settings.action` ne prevent, or `topology` eq automatic without defined networks.
High. Rows: CFG-020. Same read: **CPM-GATEWAY-LOCAL-LOGGING-OFF** (`logs-settings.save-logs-locally`
false or alert threshold lt 20; medium; LOG-003), **CPM-IDENTITY-SOURCE-SINGLE**
(`identity-awareness-settings` sources lt 2 on gateways with access roles; medium; AVL-014),
**CPM-EDGE-SINGLE-UPLINK** (`isp-redundancy` absent on the perimeter cluster; medium; AVL-006),
**CPM-HTTPS-INSPECTION-CA-EXPIRING** (outbound CA validity until-lt 365 or key lt 2048; high;
PKI-003), **CPM-VPN-DOMAIN-OVERLAP** (vpn-settings domains overlapping across communities - store;
medium; AUT-011), **CPM-THREAT-PROFILE-FAIL-MODE** (https-inspection bypass-under-load as an info
row; AVL-011).

**CPM-VPN-COMMUNITY-WEAK-CRYPTO** - `show-vpn-communities-star` / `-meshed` details full, key
`uid`; `encryption-method` ne ikev2 only, or `encryption-suite` custom with phase 1/2 encryption in
[3des, des], integrity in [md5, sha1], DH group in [1, 2, 5], or `use-pfs` false. High. Refs:
NIST-800-53:SC-13. Rows: AUT-009. Siblings: **CPM-VPN-COMMUNITY-NOT-PERMANENT**
(`permanent-tunnels` off, medium; AVL-007), **CPM-VPN-CERT-EXPIRING** (`show-objects` type
certificate `not-after` until-lt 90 and `show-objects` type certificate-authority CRL settings;
medium; PKI-006), **CPM-SIC-CERT-EXPIRING** (per-gateway certificate `not-after` until-lt 180 from
`show-generic-objects`; high; PKI-002; guess), **CPM-LDAP-ACCOUNT-UNIT-CLEARTEXT**
(`show-generic-objects` class `com.checkpoint.objects.classes.dummy.CpmiLdapAu`: `ldapSsl` false or
port 389; high; AUT-007; guess), **CPM-RADIUS-SERVER-SINGLE-OR-STALE-SECRET** (`show-objects` type
radius-server count lt 2 or the audit log shows no secret change in 365 days; medium; AUT-008),
**CPM-ALERT-RECIPIENT-LEFT** (`show-threat-profile` track alert and the alert mail recipients from
the global properties export joined with Entra users; high; MON-003).

**CPM-THREAT-PROFILE-DETECT-ONLY** - `show-threat-rulebase` per threat layer and `show-threat-profile`
details full, key `uid`; profile `ips-settings.activation-mode` or anti-bot/anti-virus action eq
detect for high/critical, or a gateway with no threat layer. High. Refs: NIST-800-53:SI-3,
NIST-800-53:SI-4. Rows: CFG-025. Siblings: **CPM-IPS-PROFILE-WEAK** (`ips-settings`
`newly-updated-protections` staged for more than 14 days or exclusion by performance impact, medium;
CFG-026), **CPM-THREAT-PROFILE-FILE-TYPES-NARROW** (anti-virus archive scan off or emulation file
types exclude Office/PDF, medium; CFG-028), **CPM-IPS-EXCEPTION-BROAD**
(`show-threat-rule-exception-rulebase`: protected-scope Any and protection Any, or exception older
than 365 days without a comment, medium; CFG-027, HYG-013, NEXPOSE-CFG-016, CYMULATE-CFG-014),
**CPM-APPCONTROL-CATEGORIES-NOT-BLOCKED** (application layer rulebase lacks Block on anonymizer,
malware, phishing, remote-administration categories for user networks, medium; CFG-030),
**CPM-HTTPS-INSPECTION-BYPASS-MISSING** (`show-https-rulebase` lacks bypass rules for the
documented categories/destinations threshold, medium; CFG-023), **CPM-HTTPS-INBOUND-CERT-EXPIRING**
(inbound rule certificate `not-after` until-lt 30, medium; CFG-024), **CPM-IDENTITY-ACCOUNT-PRIVILEGED**
(LDAP AU login DN joined with AD privileged accounts, high; CFG-031), **CPM-ZONES-NOT-USED**
(`show-security-zones` empty or zone-based rule share lt 50 %, low; CFG-037),
**CPM-CLOUDGUARD-CAMERA-PROFILE** (info row of the profile applied to camera-role rules on the cloud
package; CFG-029), **CPM-IPS-UPDATE-STALE** (`show-ips-status` `update-date` age-gt 7 or
`show-ips-update-schedule` disabled, high; LCM-010).

**CPM-GAIA-*** (Gaia REST through the same type, per host): **CPM-GATEWAY-REBOOT-PENDING**
(`show-installer-packages` any package `installed, reboot required`; medium; HLT-010),
**CPM-HOTFIX-TAKE-OLD** (installed take lt the threshold per version; high; LCM-002),
**CPM-GAIA-KERNEL-OLD** (`show-version-all` kernel ne 3.10; medium; LCM-003), **CPM-CPUSE-AGENT-OLD**
(`show-installer-status` agent build lt threshold; low; LCM-005), **CPM-GAIA-DNS-NTP-MISCONFIGURED**
(`show-dns` secondary empty, `show-ntp` fewer than 2 servers or not active, `show-proxy` differing
from design; medium; CFG-022, AUT-005), **CPM-ROUTE-INCONSISTENT** (`show-routes` differing between
cluster members or a cloud prefix with an unexpected next hop - store; medium; CFG-021),
**CPM-GAIA-EXTRA-USERS** (`show-users` beyond admin and named read-only users, or shell /bin/bash on
a non-admin; high; IAM-006), **CPM-GAIA-PASSWORD-POLICY-WEAK** (`show-password-policy` min-length lt
14, history lt 10, lockout off; medium; AUT-001), **CPM-SNMP-V2C-ENABLED** / **CPM-SNMP-TRAPS-OFF**
(`show-snmp` communities present or users below authPriv; traps disabled; high / medium; AUT-004,
MON-002), **CPM-LOGIN-BANNER-MISSING** (`show-message-of-the-day` empty and Mgmt `show-login-message`
empty; low; AUT-014), **CPM-GAIA-BACKUP-STALE** (`show-backups` / `show-snapshots` newest older
than 30 days; high; BCK-002).

**CPM-SNMP-*** (snmp type, CHECKPOINT-MIB, per host or per cluster): **CPM-GATEWAY-NO-POLICY**
(fwModuleState ne Installed or fwInstallTime age-gt 30; critical; HLT-001), **CPM-GATEWAY-CPU-HIGH**
(multiProcTable any core gt 95 or procUsage gt 80; high; HLT-002), **CPM-GATEWAY-MEMORY-LOW**
(memFreeReal / memTotalReal lt 15 %; high; HLT-003), **CPM-GATEWAY-CONNECTIONS-NEAR-LIMIT**
(fwPeakNumConn gt 70 % of the configured limit threshold; high; HLT-004), **CPM-GATEWAY-DISK-FULL**
(multiDiskTable percent gt 80, /var/log gt 70; high; HLT-005), **CPM-INTERFACE-ERRORS** (IF-MIB error
and discard counters with a non-zero delta across runs - store; high; HLT-006),
**CPM-ACCELERATION-OFF** (SecureXL status off; medium; HLT-007), **CPM-HARDWARE-SENSOR-FAILED**
(sensor status ne 0 or PSU down; high; HLT-011), **CPM-LOG-INDEXING-LAG** (ls branch lag gt 5 min;
medium; HLT-012), **CPM-VPN-TUNNEL-DOWN** (tunnel table state ne up for permanent tunnels; high;
HLT-013), **CPM-THREATCLOUD-DISCONNECTED** (teCloudConnectivity not ok or amwUpdateStatus stale;
medium; HLT-020), **CPM-AV-SIGNATURES-STALE** / **CPM-APPCONTROL-DB-STALE** (update status not
up-to-date; medium / low; LCM-011, LCM-012), **CPM-CLUSTER-MEMBER-NOT-ACTIVE-STANDBY** (haState
pattern not exactly one Active - store; critical; AVL-001), **CPM-CLUSTER-PNOTE-PROBLEM**
(haProblemTable status ne ok or sync interface down; high; AVL-002), **CPM-DAEMON-RESTARTS**
(process restart counters delta gt 0; medium; LOG-009). Confidence: likely for the OIDs named in the
catalogue; the snmp type returns one row per table index.

**CPM-CLOUDGUARD-*** (aws type, section 2): **CPM-CLOUDGUARD-TARGET-UNHEALTHY** (ELBv2
`DescribeTargetHealth` any target not healthy or fewer than 2 healthy; critical; HLT-014),
**CPM-CLOUDGUARD-ASG-SINGLE-AZ** (`DescribeAutoScalingGroups` MinSize lt 2 or AZs lt 2, or a GWLB
endpoint missing in an attachment AZ; high; AVL-008), **CPM-CLOUDGUARD-TGW-APPLIANCE-MODE-OFF**
(`DescribeTransitGatewayVpcAttachments` `Options.ApplianceModeSupport` ne enable; high; AVL-009),
**CPM-CLOUDGUARD-CROSS-ZONE-IMBALANCE** (`DescribeLoadBalancerAttributes` cross-zone on while
targets per AZ differ; medium; AVL-010), **CPM-CLOUDGUARD-SG-MGMT-OPEN** (`DescribeSecurityGroups`
22/443/18191/18192 from sources outside the management role, or 6081 from outside the GWLB subnet;
high; CFG-040), **CPM-CLOUDGUARD-AMI-OLD** (`DescribeImages` CreationDate age-gt 180; medium;
LCM-008), **CPM-CLOUDGUARD-IAM-ROLE-BROAD** (`ListAttachedRolePolicies` includes AdministratorAccess
or a `*:*` inline policy; high; IAM-013), **CPM-CLOUDGUARD-STACK-DRIFTED** (`DescribeStacks` drift
status DRIFTED; medium; BCK-006), **CPM-CLOUDGUARD-NO-ALARM** (`DescribeAlarms` none on
UnHealthyHostCount / ASG capacity; high; MON-007).

**CPM-MGMT-PORT-UNREACHABLE** / **CPM-LEGACY-LISTENER-OPEN** / **CPM-SSH-WEAK-ALGORITHMS** - tcp-probe
(expected ports must connect; 21/23/80 must refuse) and ssh-probe (banner, KEX/cipher/MAC lists
without group1/CBC/SHA-1). Medium / medium / high. Rows: HLT-019, AUT-012, AUT-002.
**CPM-MGMT-BACKUP-STALE** / **CPM-LOG-EXPORTER-UNENCRYPTED** / **CPM-SIEM-FEED-STALE** /
**CPM-SIEM-RULES-MISSING** - backup target listing (aws S3 `ListObjectsV2` or file-share-read),
exporter target file (file-share-read), SIEM event count and alert definitions (a SIEM integration,
section 17). Rows: BCK-001, AUT-006, LOG-002, MON-005. **CPM-LICENSE-EXPIRING** - new-file: the
licence export (CSV) in `imports\checkpoint\licenses*.csv`, key the licence line; `expires`
until-lt 90 or a blade enabled without a licence line (store join). High. Rows: CST-001.
**CPM-COMPLIANCE-BLADE-POOR** - new-file: the compliance report export (CSV); `status` eq poor on a
critical best practice. Low. Rows: MON-009. **CPM-XS-GATEWAY-NOT-MONITORED** - store join of the
gateway names with PRTG device rows. High. Rows: MON-001.

## 4. Harmony Endpoint and the Infinity Portal (`rules\harmony-endpoint.yaml`, system `harmony-endpoint`, integration `http` with auth `session-login` and the read-only POST mode of section 17)

The Infinity Portal issues a bearer token from an API key pair (`POST /auth/external` with
`clientId`/`accessKey`), which `session-login` covers (`userField` `clientId`, `passwordField`
`accessKey`, `tokenField` the token field of the answer, `prefix` `Bearer `). Each service is then
reached under the regional portal host. The Harmony Endpoint management API is cloud-hosted and
mostly POST (job creation then polling); the portal's global settings (users, roles, API keys,
notifications, services) are reachable through the same token. As with the management server, the
sign-in is solved and the POST reads are the open gap (section 17, first entry); the rules below
assume that mode and allow only the documented read queries. Also feeds section 5 (Harmony Email) rows.

**CPEP-CLIENT-NOT-REPORTING** - computers whose last connection is older than 7 days while still
enabled (asset computers query, fields `lastConnection`, `lastLogsUpload`, `isEnabled`,
`clientVersion`, blade states). Medium. Rows: CHECKPOINT-HLT-018, LOG-014. Siblings:
**CPEP-CLIENT-BLADE-ERROR** (a blade in error state for more than 7 days, or an unremediated
infection older than 48 h; medium; MON-008), **CPEP-SEATS-VS-INSTALLED** (portal asset seats used
gt licensed, or licensed gt active PCs x 1.15 via a store join with the sccm count; medium;
CST-003).
**CPEP-POLICY-BLADES-DRIFT** / **CPEP-FIREWALL-BLADE-INACTIVE** / **CPEP-UNINSTALL-PASSWORD-OFF** /
**CPEP-EXCLUSION-BROAD** / **CPEP-FIREWALL-POLICY-NO-ADMIN-RULE** - policy export reads: blade
activation per rule vs the design threshold; firewall blade inactive on a computer (joined with the
Windows firewall-off GPO scope in the store); client settings uninstall password disabled; an
exclusion that is a drive root or a wildcard extension; firewall policy lacking an inbound rule for
the admin management ports from the admin network role. Medium / high / medium / medium / medium.
Rows: CFG-042, CFG-043, CFG-044, CFG-045, AVL-013.
**CPEP-PORTAL-LOCAL-ADMIN** / **CPEP-PORTAL-ADMIN-MANY** / **CPEP-PORTAL-APIKEY-OLD** /
**CPEP-PORTAL-ROLE-CHANGE-RECENT** / **CPEP-PORTAL-SUPPORT-ACCESS-ON** /
**CPEP-PORTAL-SESSION-TIMEOUT-LONG** / **CPEP-PORTAL-AUDIT-RETENTION-SHORT** /
**CPEP-PORTAL-NOTIFY-RECIPIENT-LEFT** / **CPEP-PORTAL-TRIAL-SERVICE-ACTIVE** - portal global
settings reads: users with local authentication beyond the break-glass; full-admin count gt 3 or
users joined with disabled Entra accounts; API keys older than 365 days; role changes in 7 days
(info); support access enabled without expiry; session timeout gt 60 min; audit retention lt 365
days; notification recipients joined with Entra users disabled or absent; services in trial or
expired state. Severities high / high / medium / medium / medium / low / low / medium / low. Rows:
CHECKPOINT-IAM-010, IAM-012, MON-011, HARMONY-EMAIL-IAM-001..005, IAM-007, IAM-009, AUT-001, AUT-004,
MON-002, MON-005, HYG-004. Confidence: guess for every portal path (the public developer portal
documents the token step; per-service read endpoints must be read from the tenant's API
documentation).

PC-side rules that need no vendor API (workstations / windows-server targets):
**CPEP-MSI-RECONFIGURE-AT-BOOT** (eventlog Application, provider MsiInstaller, ids 1035/1040, message
match the vendor name, count per host gt 3 in 7 days; medium; HLT-016, KN-installer-reconfigured-every-boot),
**CPEP-CLIENT-CODEINTEGRITY-REFUSED** (eventlog Microsoft-Windows-CodeIntegrity/Operational id 3033
message match `CP_Amsi`, and System 7000/7011/7043 with the vendor name; medium; LOG-012,
KN-endpoint-amsi-dll-refused), **CPEP-CLIENT-CRASH** (Application 1000/1001 with the vendor process
names; low; LOG-013), **CPEP-CLIENT-BLOCKS-SHUTDOWN** (System 7043/7011/6008 with the vendor
service; medium; AVL-012, KN-endpoint-agent-blocks-shutdown), **CPEP-CLIENT-VERSION-OLD** (sccm type
`wmi/SMS_G_System_ADD_REMOVE_PROGRAMS` DisplayName like the client name, `Version` lt threshold;
medium; LCM-006), **CPEP-BROWSE-EXTENSION-NOT-FORCED** (registry
`SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` and the Edge twin lacking the extension
id threshold; low; LCM-007), **CPEP-XS-COMPUTER-NO-CLIENT** (store: active AD computers without the
client in the sccm inventory; high; CFG-046), **CPEP-INSTALLER-LAUNCHER-UNKNOWN** (cim
`Win32_StartupCommand` / registry Run keys matching the package share path; medium; HYG-010).

## 5. Harmony Email & Collaboration (`rules\harmony-email.yaml`, system `harmony-email`, integration `http` with auth `session-login`, same gap as section 4)

Every HEM- rule reads the Email & Collaboration service through the Infinity token (sections 4 and 17);
paths are a guess until read from the tenant's API documentation. Entra-side rows map to existing
ENTRA-* rules (see the map). Rules, each one read of the relevant object with the condition in
words: **HEM-CONNECTOR-DISCONNECTED** (SaaS-application state ne connected or last sync age-gt 1 h;
critical; HLT-001), **HEM-COLLAB-CONNECTOR-DISCONNECTED** (same for SharePoint/OneDrive/Teams when
onboarded; high; HLT-006, CFG-016), **HEM-SCAN-LATENCY-HIGH** (average scan time gt 60 s or pending
gt 100; high; HLT-002), **HEM-RESTORE-REQUEST-PENDING** (restore requests older than 1 business day;
medium; HLT-003), **HEM-XS-MAILBOX-UNPROTECTED** (protected users joined in the store with graph
`/users` holding a mailbox; high; HLT-004, CFG-029), **HEM-SYSTEM-EVENT-ERROR** (system events with
severity error in 7 days; medium; HLT-005, LOG-002), **HEM-REMEDIATION-TASK-FAILED** (remediation
tasks failed or running gt 1 h; high; HLT-007), **HEM-USER-REPORT-BACKLOG** (user reports older than
2 business days; medium; LOG-003), **HEM-MALICIOUS-RELEASED** (quarantine release of a malware or
high-confidence phishing verdict by an end user; high; LOG-005), **HEM-POLICY-SCOPE-PARTIAL**
(policy scope not all users and not a documented group list; high; CFG-001),
**HEM-POLICY-NOT-PREVENT** (anti-phishing mode ne prevent inline; high; CFG-002),
**HEM-MALWARE-POLICY-DETECT-ONLY** (anti-malware mode ne prevent or emulation off; high; CFG-003),
**HEM-ANTISPAM-DOUBLE-QUARANTINE** (anti-spam quarantines while the EOP policy also quarantines -
store join with the EXO read; medium; CFG-004), **HEM-URL-PROTECTION-OFF** (CFG-005),
**HEM-DLP-POLICY-OFF** (CFG-006), **HEM-ANOMALY-DETECTION-OFF** (CFG-007), **HEM-POLICY-INBOUND-ONLY**
(CFG-008), **HEM-ALLOWLIST-WILDCARD-OR-OLD** (entry is a wildcard domain or older than 365 days;
medium; CFG-009), **HEM-XS-BLOCKLIST-CONTRADICTION** (store join with the EXO tenant block list; low;
CFG-010), **HEM-USER-RELEASE-MALWARE** (CFG-011), **HEM-DIGEST-OFF** (CFG-012),
**HEM-GEO-LANGUAGE-RULES-DEFAULT** (info; CFG-017), **HEM-SMART-BANNERS-OFF** (CFG-020),
**HEM-POLICY-EXCLUSION-PRESENT** (CFG-021), **HEM-VIP-LIST-INCOMPLETE** (protected list lacks a role
from the threshold list; medium; CFG-022), **HEM-ENCRYPTED-ATTACHMENT-DELIVERED** (CFG-023),
**HEM-RETROACTIVE-REMEDIATION-OFF** (CFG-024), **HEM-QUARANTINE-RETENTION-SHORT** (lt 30 days;
BCK-003), **HEM-SIEM-EXPORT-OFF** (MON-001), **HEM-NOTIFY-RECIPIENT-LEFT** (MON-002),
**HEM-SECURITY-EVENT-OPEN-LONG** (open events older than 2 business days; MON-003),
**HEM-REPORT-NOT-SENT** (MON-004), **HEM-XS-POLICY-REFERENCE-STALE** (policy references joined with
Entra users/groups; low; HYG-007), **HEM-FEATURE-UNLICENSED** (CST-003),
**HEM-XS-PROTECTED-USER-DISABLED** (protected users joined with Entra accountEnabled eq 0; low;
CST-005). Refs: NIST-800-53:SI-8, SI-3, SI-4, AU-6, AC-6; CIS-Controls-v8:9.7, 9.3, 8.11.

Exchange Online rows need the `exchange-online` type (section 17): **EXO-INBOUND-CONNECTOR-UNRESTRICTED**
(`Get-InboundConnector`: partner connector with `RestrictDomainsToIPAddresses` and
`RestrictDomainsToCertificate` both false, or `RequireTls` false; high), **EXO-INBOUND-CONNECTOR-NO-EF-SKIP**
(`EFSkipIPs`/`EFSkipLastIP` unset on the gateway connector; medium), **EXO-OUTBOUND-CONNECTOR-SMARTHOST**
(`Get-OutboundConnector` smart host outside the documented list; high), **EXO-TRANSPORT-RULE-SCL-BYPASS**
(`Get-TransportRule` SetSCL -1 without a documented reason; medium), **EXO-CONNECTION-FILTER-IP-ALLOW**
(`Get-HostedConnectionFilterPolicy` IPAllowList not empty; critical), **EXO-ADVANCED-DELIVERY-BROAD**
(`Get-PhishSimOverridePolicy` rule keyed on a whole domain; medium), **EXO-DKIM-DISABLED** /
**EXO-DKIM-NOT-ROTATED** (`Get-DkimSigningConfig` Enabled false; RotateOnDate older than 365 days),
**EXO-PRESET-POLICY-STATE** (`Get-EOPProtectionPolicyRule`, `Get-ATPProtectionPolicyRule` state as
info), **EXO-MESSAGE-HEADER-NO-FILTER-STAMP** (`Get-MessageTraceDetail` sample without the filter
header; high), **EXO-REPORT-SUBMISSION-SPLIT** (`Get-ReportSubmissionPolicy` two destinations; low),
**EXO-MAILBOX-EXTERNAL-FORWARD** (`Get-Mailbox` ForwardingSmtpAddress set outside the exception
list, `Get-InboxRule` forwarding; medium), **EXO-DMARC-REPORTS-NOT-ARRIVING** (`Get-MessageTrace` to
the report mailbox returns nothing in 10 days; medium), **M365-AUDIT-SP-MAILBOX-ACTIONS** (unified
audit log: Send or HardDelete by the vendor service principal; medium - the Graph audit query API is
a POST job). Confidence: likely (cmdlet names are documented); the type does not exist yet.

## 6. Harmony SASE (`rules\harmony-sase.yaml`, system `harmony-sase`, integration `http` with auth `session-login` - no new type)

The public API (inherited from the previous product name) issues a bearer token by `POST
/api/v1/auth/authorize` with an API key, then `GET /api/v1/members`, `/api/v1/groups`,
`/api/v1/networks`, `/api/v1/regions` (paged). That is exactly `session-login` (`loginPath`
the authorize path, key id and secret as the two login fields, `header` Authorization, `prefix`
`Bearer `), so every GET read below is expressible as plain `http`. Console-only objects (posture profiles, firewall
rules, web filtering, agent settings, API keys, admins, notifications) are new-file exports until
the vendor confirms read endpoints. **HSASE-GATEWAY-NOT-ACTIVE** (networks `gateways[].status` ne
active; critical; HLT-001), **HSASE-NETWORK-SINGLE-GATEWAY** (gateways per network lt 2 or one
region; high; AVL-003), **HSASE-NETWORK-LEGACY-PROTOCOL** (gateway protocol notin [wireguard,
ipsec]; medium; AUT-005), **HSASE-SPLIT-TUNNEL-UNEXPECTED** (CFG-011), **HSASE-MEMBERS-CONNECTED-LOW**
(members with `lastLogin` in 7 days lt a floor threshold; high; HLT-002), **HSASE-MEMBER-IDLE**
(`lastLogin` age-gt 90 among enabled members; low; HYG-007), **HSASE-MEMBER-LOCAL-PASSWORD**
(member authentication type local; high; AUT-001), **HSASE-XS-GROUP-DRIFT** (groups joined with the
Entra assigned groups' enabled member counts; medium; CFG-023), **HSASE-TUNNEL-FAILURE-RATE** /
**HSASE-POSTURE-FAILURE-RATE** (activity logs if a GET exists; HLT-003, LOG-003),
**HSASE-ADMIN-UNEXPECTED** / **HSASE-LOCAL-ADMIN-COUNT** / **HSASE-LOCAL-LOGIN-ENABLED** /
**HSASE-APIKEY-OLD** / **HSASE-ALERT-OPEN-LONG** (team, identity-provider, API-key and alert reads;
IAM-001, AVL-005, IAM-002, IAM-006, MON-004), **HSASE-LEGACY-TENANT-ACTIVE** (http-probe of the
legacy console URL not redirecting; low; LCM-007). New-file exports (`imports\harmony-sase\*.csv`):
**HSASE-GATEWAY-NEAR-CAPACITY** (HLT-004), **HSASE-AGENT-AUTOUPDATE-OFF** (LCM-005),
**HSASE-POSTURE-PROFILE-MISSING** (CFG-008), **HSASE-ALWAYS-ON-OFF** (CFG-009),
**HSASE-TRUSTED-NETWORK-UNEXPECTED** (CFG-010), **HSASE-FIREWALL-RULE-ANY-ALLOW** (CFG-012),
**HSASE-APP-ASSIGNED-TO-ALL** (CFG-013), **HSASE-WEBFILTER-RULE-MISSING** (CFG-014),
**HSASE-DNS-FILTERING-OFF** (CFG-015), **HSASE-SESSION-TIMEOUT-LONG** (CFG-016, AUT-003),
**HSASE-APP-NO-MFA-OR-PLAINTEXT** (AUT-004), **HSASE-DEFAULT-GROUP-HAS-ACCESS** (AUT-006),
**HSASE-POSTURE-CERT-RULE-STALE** (PKI-003), **HSASE-LOG-RETENTION-SHORT** (MON-001),
**HSASE-SIEM-EXPORT-OFF** (MON-002), **HSASE-NOTIFY-RECIPIENT-LEFT** (MON-003),
**HSASE-REPORT-NOT-SENT** (MON-006), **HSASE-FEATURE-UNLICENSED** (CST-005). Refs:
NIST-800-53:AC-17, SC-7, IA-2(1), AC-12; CIS-Controls-v8:12.7, 13.5. Confidence: likely for
members/groups/networks GETs; guess for everything else.

PC-side and SCCM rules (no vendor API): **HSASE-XS-CLIENT-HALF-INSTALLED** (sccm ARP rows without a
matching `SMS_G_System_SERVICE` row and vice versa - store; medium; HLT-007),
**HSASE-AGENT-VERSION-OLD** (sccm ARP `Version` lt threshold; medium; LCM-001),
**HSASE-AGENT-EVENT-ERRORS** (eventlog Application providers matching the agent; low; LOG-004),
**HSASE-XS-SCCM-DEPLOYMENT-ACTIVE** (sccm `wmi/SMS_Application` name match with an active deployment;
low; CFG-019), **HSASE-XS-NOT-MONITORED** (gateway names vs PRTG rows; medium; MON-008).

## 7. Network devices (`rules\network-devices.yaml`, system `network-devices`, integrations `snmp` and `config-text` - new types; the Cisco Prime reads use the generic `http` with basic auth)

Three sources: SNMP v3 GET/WALK of standard and Cisco MIBs per device (`snmp` type, section 17);
a parser over exported running configurations dropped into `imports\network-config\` (`config-text`
type - a text-regex protocol, since the `file` protocol reads only json/xml/csv); and the Cisco
Prime Infrastructure REST API (`cisco-prime`, generic http with basic auth: `GET
/webacs/api/v4/data/<Resource>.json?.full=true&.firstResult=0&.maxResults=1000`, items
`queryResponse.entity[].<resource>DTO`). Device inventory is the snmp integration's target list
(seeded by the discovery sweep).

SNMP rules (one per catalogue row, key = device or `device|ifIndex`; MIB objects as named in the
catalogue; severities as the catalogue): **NET-DEVICE-UNREACHABLE** (sysUpTime unanswered -
integration failure per target; critical; HLT-001), **NET-DEVICE-RELOADED** (sysUpTime lower than
the previous run minus elapsed - store; high; HLT-002), **NET-DEVICE-UPTIME-LONG** (snmpEngineTime
gt 400 days; low; HLT-003), **NET-DEVICE-CPU-HIGH** (cpmCPUTotal5minRev gt 70; high; HLT-004),
**NET-DEVICE-MEMORY-LOW** (ciscoMemoryPoolFree / (Used+Free) lt 20 %; high; HLT-005),
**NET-SENSOR-TEMPERATURE** / **NET-SENSOR-FAN** / **NET-PSU-FAILED-OR-SINGLE** (ciscoEnvMon states
ne normal; PSU count lt 2 on core roles; high/medium/high; HLT-006..008), **NET-POE-BUDGET-HIGH**
(pethMainPseConsumptionPower / pethMainPsePower gt 80 %; medium; HLT-009), **NET-PORT-ERRORS** /
**NET-PORT-DISCARDS** / **NET-PORT-BROADCAST-HIGH** / **NET-UPLINK-UTILISATION-HIGH** (counter
deltas across runs - store rules over row_seen; HLT-010..012, HLT-014), **NET-PORT-HALF-DUPLEX**
(dot3StatsDuplexStatus eq 2 or ifHighSpeed lt 1000 on an up access port; medium; HLT-013),
**NET-PORT-ERRDISABLED** (cErrDisableIfStatusCause rows; medium; HLT-015), **NET-PORT-FLAPPING**
(ifLastChange within 7 days on infrastructure ports; medium; HLT-016), **NET-STACK-DEGRADED**
(cswSwitchState ne ready or cswRingRedundant false; high; HLT-017), **NET-TABLE-NEAR-LIMIT** (FDB
or ARP row count gt 70 % of the per-model threshold; medium; HLT-018), **NET-WLC-RESOURCES-HIGH**
(AIRESPACE agent CPU gt 70 or free memory lt 20 %; high; HLT-021), **NET-DEVICE-INVENTORY** (ENTITY-MIB
chassis rows as info; LCM-001), **NET-HARDWARE-EOS** / **NET-SOFTWARE-UNSUPPORTED** /
**NET-SOFTWARE-VERSION-MIXED** (model or software vs threshold tables; LCM-002, LCM-003, LCM-005),
**NET-CPE-VERSION-UNKNOWN** (cdpCacheVersion on the carrier handoff port absent; low; LCM-010),
**NET-OPTIC-UNSUPPORTED** (transceiver vendor type outside the approved list or a threshold
evaluation flagged; low; LCM-011), **NET-LOG-BUFFER-ERRORS** / **NET-LOGIN-FAILURES** /
**NET-STP-EVENT** / **NET-L2-SECURITY-VIOLATION** / **NET-HARDWARE-LOG-ALARM** (clogHistTable
messages matching the signature regexes; LOG-004..009), **NET-CONFIG-CHANGE-EVENT** /
**NET-CHANGE-IN-BUSINESS-HOURS** / **NET-CONFIG-UNSAVED** (ccmHistoryEventTable; running changed
after last saved; LOG-007, AVL-014, CFG-023), **NET-ACCESS-SINGLE-UPLINK** (lldpRemTable distinct
upstream bridges lt 2 - store; high; AVL-001), **NET-LAG-MEMBER-DOWN** (dot3adAggPortAttachedAggID
member with ifOperStatus down; high; AVL-002), **NET-STP-ROOT-UNEXPECTED** /
**NET-STP-TOPOLOGY-CHANGES-HIGH** / **NET-STP-MODE-LEGACY** (dot1dStpDesignatedRoot ne the core
bridge threshold; dot1dStpTopChanges delta gt 10; dot1dStpVersion lt 2; AVL-003..005),
**NET-FHRP-NO-STANDBY** (cHsrpGrpStandbyState rows without one active and one standby per group;
high; AVL-007), **NET-PSU-SINGLE-FEED** (ciscoEnvMonSupplySource identical for both PSUs; medium;
AVL-008), **NET-SITE-SINGLE-WAN-PATH** (ipCidrRouteTable next hops per remote prefix lt 2; medium;
AVL-012), **NET-ROUTING-NEIGHBOR-DOWN** (ospfNbrState ne full; route count change gt 5 %; medium;
AVL-013), **NET-XS-SUBNET-NOT-IN-AD-SITE** / **NET-XS-SUBNET-NOT-IN-SCCM-BOUNDARY** /
**NET-XS-SUBNET-NO-DHCP-SCOPE** (ipAddressTable SVI networks joined in the store with AD subnets,
SCCM boundaries, DHCP scope export; high/high/medium; CFG-001..003), **NET-VLAN-UNNAMED** /
**NET-VLAN1-IN-USE** / **NET-VLAN-UNUSED** (dot1qVlanStaticName regex; dot1qPvid eq 1 on up access
ports; VLANs without egress ports; CFG-004, CFG-005, HYG-003), **NET-PORT-UNUSED-ENABLED** /
**NET-PORT-ADMIN-DOWN-NO-REASON** / **NET-INFRA-PORT-NO-DESCRIPTION** (ifAdminStatus/ifOperStatus/
ifLastChange/ifAlias patterns; CFG-008, HYG-004, HYG-001), **NET-CDP-ON-USER-PORT**
(cdpInterfaceEnable on ports without a phone/AP neighbour; low; CFG-010),
**NET-ACCESS-PORT-MANY-MACS** / **NET-MAC-ON-TWO-PORTS** (dot1qTpFdbPort counts per port gt 2; a MAC
on two access ports - store; CFG-011, HYG-005), **NET-DHCP-SNOOPING-OFF** (cdsVlanDhcpSnoopingEnable
false on user VLANs; high; CFG-012), **NET-NTP-NOT-SYNCHRONISED** (cntpSysStratum gt 4 or mode not
synchronised; medium; CFG-024), **NET-SYSINFO-INCOMPLETE** (sysName/sysLocation/sysContact regex;
low; CFG-028), **NET-UNKNOWN-DEVICE** (sweep responders with a network-vendor sysObjectID not in the
inventory - store; medium; MON-007), **NET-CLOSET-PORT-UTILISATION** / **NET-WAN-LINE-UNDERUSED**
(up-port share outside 40-85 %; WAN counters vs contracted speed; low; CST-003, CST-004),
**NET-CONFIG-BACKUP-OLDER-THAN-CHANGE** (ccmHistoryRunningLastChanged newer than the archive file
time - store; medium; BCK-002), **NET-ERRDISABLE-RECOVERY-OFF** (cErrDisableRecoveryEnable false for
benign causes; low; HYG-008). Refs across the family: NIST-800-53:SI-4, CP-2, CM-8, SC-7, AU-6;
CIS-Controls-v8:1.1, 4.4, 12.x. Confidence: likely (standard MIBs); Cisco enterprise MIB objects
as named in the catalogue.

Config-text rules (regex over each device's exported configuration; key = device or `device|line`):
**NET-LEGACY-PROTOCOL-ENABLED** (`vstack` without `no`, `vtp mode server`, `ip http server`,
`service pad|finger`, `ip bootp server`; high; LCM-012), **NET-BOOT-IMAGE-STALE** (boot system
not the running image; low; LCM-006), **NET-SYSLOG-TARGET-MISSING** / **NET-LOGGING-LEVEL-LOW** /
**NET-LOG-TIMESTAMPS-OFF** (`logging host` absent; `logging trap` below informational; `service
timestamps log datetime msec` absent; LOG-001..003), **NET-UPLINK-NO-LOOPGUARD** (no `loopguard` or
`udld aggressive` on fibre uplinks; medium; AVL-006), **NET-DHCP-RELAY-STALE** (`ip helper-address`
targets joined in the store with the DHCP server list; high; AVL-010), **NET-TRUNK-NATIVE-VLAN-SHARED**
/ **NET-TRUNK-UNPRUNED-OR-DTP** / **NET-ACCESS-PORT-NO-PORTFAST** / **NET-DAI-OFF** /
**NET-BPDU-GUARD-OFF** / **NET-STORM-CONTROL-OFF** / **NET-FLOOD-BLOCKING-OFF** /
**NET-VOICE-VLAN-MISSING** (trunk and access-port hardening statements; CFG-006, CFG-007,
CFG-009, CFG-013, CFG-014, CFG-016, CFG-017, CFG-020), **NET-DOT1X-OPEN-MODE** (`authentication
open` present; high; CFG-018 sibling), **NET-MGMT-NO-ACCESS-CLASS** / **NET-OT-VLAN-NO-ACL** /
**NET-SENSITIVE-VLAN-NO-ACL** / **NET-ACL-UNREFERENCED-OR-PERMIT-ANY** (`access-class` on vty; `ip
access-group` on sensitive SVIs; unreferenced ACLs; `permit ip any any` in management ACLs;
CFG-021, CFG-022, CFG-026, HYG-006), **NET-IP-SERVICES-ENABLED** / **NET-QOS-MISSING** (CFG-025,
CFG-027), **NET-AAA-NOT-CENTRAL** / **NET-LOCAL-ACCOUNTS-MANY** / **NET-LOCAL-SECRET-NOT-ROTATED** /
**NET-WEAK-PASSWORD-TYPE** / **NET-NO-COMMAND-AUTHORISATION** / **NET-LINE-HARDENING-MISSING** /
**NET-SNMP-NO-VIEW-OR-ACL** / **NET-LOGIN-HARDENING-MISSING** / **NET-ROUTING-UNAUTHENTICATED** /
**NET-AAA-ACCOUNTING-OFF** (AAA, username, hash type, line, SNMP group/ACL, login block, routing
authentication and accounting statements; IAM-001..007, AUT-005, AUT-006, MON-009),
**NET-TELNET-OPEN** / **NET-HTTP-MGMT-OPEN** (`transport input` includes telnet; `ip http server`;
plus tcp-probe; AUT-001, AUT-002), **NET-TRAP-TARGET-RETIRED** (`snmp-server host` / `logging host`
joined with stale AD computers; medium; MON-001), **NET-NETFLOW-OFF** /
**NET-MONITOR-SESSION-UNDOCUMENTED** (MON-004, MON-008). Refs: CIS-Controls-v8:4.x, 5.x, 12.x;
NIST-800-53:AC-17, IA-5, CM-6, CM-7. Confidence: likely (IOS syntax); the parser is the gap.

Cisco Prime rules (cisco-prime type): **NET-AP-NOT-JOINED** (AccessPoints `status` ne associated;
high; HLT-019), **NET-RADIO-UTILISATION-HIGH** (RadioDetails channel utilisation gt 60 or client
count gt 40; medium; HLT-020), **NET-AP-MODEL-EOS** (AccessPoints model in the EOS list; medium;
LCM-007), **NET-PRIME-VERSION-OLD** (`/webacs/api/v4/op/info/version.json` lt threshold; medium;
LCM-008), **NET-WLAN-ALARM-OPEN** / **NET-PRIME-ALARM-UNACKNOWLEDGED** (Alarms severity
CRITICAL/MAJOR and `acknowledged` false; medium; LOG-010, MON-006), **NET-WLC-NO-REDUNDANCY**
(Devices HA state for the controller ne paired; high; AVL-009), **NET-SSID-UNREGISTERED** /
**NET-SSID-WEAK-SECURITY** / **NET-SSID-PSK-NOT-ROTATED** / **NET-SSID-MFP-OFF** /
**NET-GUEST-SSID-NOT-ISOLATED** / **NET-RF-PROFILE-WEAK** (WlanProfiles and RF profile fields:
enabled SSID not in the register threshold; security not WPA2/3-Enterprise; PSK age via config
archive diff; MFP off; guest P2P blocking off; country code or data rates; CFG-029..031,
AUT-007..010), **NET-COMPLIANCE-VIOLATION** (`/op/compliance/violationSummary.json` Critical/High gt
0; medium; CFG-032; confidence likely), **NET-PRIME-USER-IDLE** (user list - admin scope; guess;
IAM-008), **NET-CONFIG-BACKUP-STALE** / **NET-PRIME-BACKUP-STALE** (ConfigVersions newest per
device older than 7 days; the controller likewise; high; BCK-001, BCK-004),
**NET-PRIME-COLLECTION-FAILED** (Devices `collectionStatus` ne success or `reachability` ne
reachable; medium; MON-005), **NET-WLC-CERT-EXPIRING** (web-auth certificate expiry if exposed, else
tls targets; medium; PKI-004), **NET-AP-NOT-ON-MAP** (AccessPoints `mapLocation` empty; low;
HYG-012), **NET-XS-DEVICE-NOT-MONITORED** (snmp inventory joined with PRTG devices and Prime Devices;
medium; MON-002). New-file: **NET-PSIRT-OPEN** (PSIRT openVuln JSON export joined with device
versions; high; LCM-004), **NET-WLC-LOCAL-ADMIN** (controller management-user export; high;
IAM-010). Probes: **NET-REMOTE-SITE-UNREACHABLE** (tcp-probe; high; HLT-022),
**NET-MGMT-NO-OOB** (tcp-probe from two vantage points; medium; AVL-011),
**NET-SSH-WEAK-ALGORITHMS** / **NET-SSH-HOSTKEY-CHANGED** (ssh-probe; medium; AUT-003, PKI-003),
**NET-SNMP-V2C-ENABLED** (snmp v2c probe expected to time out; high; AUT-004).
**NET-LOG-RETENTION-SHORT** / **NET-SIEM-DEVICE-SILENT** / **NET-ALERT-RECIPIENT-LEFT** need a SIEM
read and a PRTG notification read (section 17). Rows: LOG-011, MON-010, MON-003.

## 8. NAC (`rules\portnox.yaml`, system `portnox`, integration `files` + the cim/sql packs)

The on-premises NAC product has no public read API for policies; console exports (CSV) dropped into
`imports\portnox\` feed `file` rules. Host-level rows are the windows-server and sql-server packs.
Switch-side rows are config-text (section 7) and are defined here because the NAC pack owns them:
**PNX-PORT-NO-AUTH** (access-mode interface without `authentication port-control auto` or `mab`,
outside the documented uplink/server list; high; PORTNOX-CFG-001, NETINFRA-CFG-015),
**PNX-SWITCH-RADIUS-SINGLE** (fewer than two `radius server` entries or one server group; critical;
AVL-001, NETINFRA-CFG-018), **PNX-SWITCH-DEAD-ACTION-MISSING** (no `authentication event server
dead action` statement; high; AVL-003, NETINFRA-CFG-019), **PNX-SWITCH-SNMP-RW-COMMUNITY**
(`snmp-server community ... RW`; high; CFG-009, NETINFRA-IAM-007), **PNX-SWITCH-COA-CLIENT-OPEN**
(`aaa server radius dynamic-author` client outside the NAC servers; medium; CFG-010),
**PNX-SWITCH-NO-REAUTH-TIMER** (no `authentication timer reauthenticate` on access ports; low;
CFG-016), **PNX-SWITCH-SHARED-ADMIN-ACCOUNT** (the NAC's switch account at privilege 15 or the
shared admin name; high; IAM-005), **PNX-RADIUS-SECRET-WEAK** (`radius server ... key 7` type-7
storage or a key older than 365 days by archive diff; high; AUT-002, NETINFRA-AUT-011),
**PNX-SWITCH-RADIUS-STALE-SERVER** (a radius server address belonging to a retired host; medium;
LCM-004), **PNX-OT-PORT-NO-AUTH** (ports in camera/OT VLANs without authentication or port security;
medium; CFG-013).

File rules over console exports (`format: csv`, key the row id): **PNX-RADIUS-REJECT-RATE**
(reject share gt 20 % per switch or one reason gt 50 %; high; HLT-003, LOG-001),
**PNX-DEVICE-POLL-FAILED** (managed device last poll age-gt 1; medium; HLT-007),
**PNX-DEVICE-UNKNOWN-SHARE** (unknown + unauthorised gt 2 % of active; medium; HLT-008),
**PNX-SYSLOG-EXPORT-OFF**, **PNX-AUDIT-OFF**, **PNX-LOG-RETENTION-SHORT** (lt 180 days), (LOG-003..005),
**PNX-ENFORCEMENT-MONITOR-ONLY** (segment mode eq monitor where the design says enforce; high;
AVL-004), **PNX-DIRECTORY-SINGLE-DC** (directory servers lt 2 or port 389; medium; AVL-005),
**PNX-SSID-NOT-8021X** (cisco-prime WlanProfiles: corporate SSID without 802.1X; high; CFG-002),
**PNX-EAP-NO-SERVER-VALIDATION** / **PNX-EAP-CERT-PROFILE-MISMATCH** / **PNX-REVOCATION-CHECK-OFF**
(GPO XML report via `file format: xml` with XPath on the wired/wireless policy: validate server
certificate off, trusted roots or server names not matching the EAP certificate key date; console
CRL/OCSP off; high/medium/high; CFG-003, PKI-004, PKI-003), **PNX-MAB-EXCEPTION-UNOWNED** (exception
without owner or on a user port; high; CFG-004), **PNX-UNKNOWN-DEVICE-PRODUCTION-VLAN** (unknown
device action lands in a production VLAN; critical; CFG-005), **PNX-POSTURE-OFF** (CFG-007),
**PNX-POLICY-ALLOW-ALL-FIRST** (CFG-008), **PNX-GUEST-NO-EXPIRY** (CFG-011),
**PNX-PROFILING-SOURCES-FEW** (CFG-012), **PNX-RADIUS-CLIENT-STALE** (client not in the Prime device
inventory - store; medium; CFG-015), **PNX-ADMIN-UNEXPECTED** / **PNX-CONSOLE-LOCAL-AUTH** /
**PNX-API-KEY-UNOWNED** (IAM-001, IAM-002, IAM-007), **PNX-AUTH-PAP-ENABLED** (AUT-003),
**PNX-NOTIFY-RECIPIENT-LEFT** (recipients joined with Entra users; MON-002),
**PNX-NEW-UNKNOWN-DEVICE** / **PNX-MAC-ON-TWO-PORTS** / **PNX-EXCEPTION-DEVICE-UNSEEN** /
**PNX-REPORT-NOT-SENT** (MON-003, MON-004, HYG-003, MON-005). Refs: CIS-Controls-v8:13.9, 1.1, 12.6;
NIST-800-53:AC-3, IA-3, SC-7. Confidence: likely (exports exist as console CSV downloads; column
names to confirm on the first export).

Host rules via existing packs plus small generic additions: **PNX-VERSION-UNSUPPORTED** (registry
protocol `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` DisplayName like the product,
`DisplayVersion` lt threshold; high; LCM-001), **PNX-AGENT-VERSION-OLD** (sccm ARP; low; LCM-003),
**PNX-EVENTLOG-ERRORS** (eventlog Application providers matching the product, level error, 7 days;
medium; LOG-002), **WS-WIRED-AUTOCONFIG-OFF** (workstations pack, cim `Win32_Service` Name
dot3svc StartMode ne Auto or State ne Running; medium; CFG-014), **WINSRV-SCHANNEL-LEGACY-TLS**
(windows-server pack, registry `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server`
Enabled ne 0; low; AUT-005), **SQL-DB-EXPRESS-SIZE-CAP** (sql-server pack: `SERVERPROPERTY('Edition')`
like Express and the largest database size gt 8 GB; high; HLT-005, EKRAN-HLT-004).

## 9. File-sanitisation gateway (`rules\opswat.yaml`, system `opswat`, integration `http`, auth `api-key-header` `apikey`)

MetaDefender Core REST: `GET /version` (`version`), `GET /stat/engines` (array of
`{eng_name, eng_ver, def_time, active, state, eng_type}`), `GET /stat/nodes`, `GET /admin/license`
(`expiration`, `days_left`, `max_agent_count`, `product_id`, enabled features), `GET
/admin/config/rule` (workflow rules with scan options), `GET /admin/user`, `GET /admin/role`,
`GET /admin/config/session`, `GET /admin/config/update`, `GET /admin/config/syslog`, audit log and
processing history endpoints. Header `apikey: <key>` of a user with read rights. Confidence: likely
for `/version`, `/stat/engines`, `/stat/nodes`, `/admin/license`, `/admin/user`; guess for the
config sub-paths and history.

**OPSWAT-ENGINE-DEFS-STALE** (`def_time` age-gt 1 where `active` true; high; LCM-002),
**OPSWAT-ENGINE-INACTIVE** (`active` false or `state` ne ok; medium; LCM-003),
**OPSWAT-VERSION-UNSUPPORTED** (`/version` lt threshold; high; LCM-001), **OPSWAT-QUEUE-HIGH**
(`/stat/nodes` queue gt 50; medium; HLT-004), **OPSWAT-SINGLE-NODE** (`/stat/nodes` `count: { op:
lt, value: 2 }`; medium; AVL-002), **OPSWAT-SCAN-FAILURE-RATE** / **OPSWAT-BLOCKED-FILES-REPORT**
(processing history: failed share gt 1 %; blocked by reason as info; HLT-005, LOG-001; guess),
**OPSWAT-CM-INSTANCE-OFFLINE** (Central Management instances last check-in age-gt 0.05; medium;
HLT-007; guess), **OPSWAT-UPDATE-SOURCE-STALE** (`/admin/config/update` offline source newest package
age-gt 7; high; LCM-005; guess), **OPSWAT-RULE-CDR-OFF** / **OPSWAT-RULE-MULTISCAN-THRESHOLD** /
**OPSWAT-RULE-FILETYPE-NOT-BLOCKED** / **OPSWAT-RULE-ARCHIVE-UNBOUNDED** / **OPSWAT-RULE-TIMEOUT-ALLOW**
/ **OPSWAT-RULE-FAIL-OPEN** (`/admin/config/rule`: Deep CDR disabled for Office/PDF/image types;
block threshold not "any engine"; executables/scripts allowed or mismatch not blocked; archive
recursion gt 5 or encrypted archives allowed; timeout action allow; failure action allow; all high;
CFG-005..010), **OPSWAT-RETENTION-UNSET** (CFG-015), **OPSWAT-LICENSED-FEATURE-UNUSED** (licence
features not referenced by any rule; low; CFG-016, CST-003), **OPSWAT-LICENSE-EXPIRING**
(`days_left` lt 30; high; CST-001), **OPSWAT-DEFAULT-ADMIN-ENABLED** / **OPSWAT-ADMIN-COUNT-HIGH** /
**OPSWAT-ADMIN-LOCAL-ONLY** / **OPSWAT-USER-LEFT** / **OPSWAT-APIKEY-ADMIN-ROLE** (`/admin/user`: name
admin enabled; admins gt 3; directory field local for every user; users joined with Entra disabled;
users with an API key and an admin role; IAM-001..004), **OPSWAT-SESSION-TIMEOUT-LONG** (AUT-003),
**OPSWAT-AUDIT-LOG-OFF** / **OPSWAT-SYSLOG-OFF** / **OPSWAT-NOTIFY-OFF** (LOG-003, LOG-004, MON-002;
guess), **OPSWAT-EVENTLOG-ERRORS** (eventlog; LOG-002), **OPSWAT-KIOSK-VERSION-OLD** (sccm ARP;
LCM-006). New-file: **OPSWAT-RELEASE-APPROVERS** (CFG-011), **OPSWAT-KIOSK-UNMANAGED** (CFG-012).
Refs: NIST-800-53:SI-3, SC-24, AC-6, CM-7; CIS-Controls-v8:10.1, 9.6, 5.4.

Entra application-proxy rules (graph type, generic for every published app, `rules\entra.yaml`):
**ENTRA-APPPROXY-CONNECTOR-INACTIVE** (`/onPremisesPublishingProfiles/applicationProxy/connectors`
`status` ne active; high; OPSWAT-HLT-003), **ENTRA-APPPROXY-CONNECTOR-GROUP-SINGLE** (for_each
`/onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}/members` active count lt 2;
medium; AVL-004), **ENTRA-APPPROXY-PASSTHROUGH** (`/applications?$select=id,displayName,onPremisesPublishing`
where `onPremisesPublishing.externalAuthenticationType` eq passthru; critical; CFG-002),
**ENTRA-APPPROXY-INTERNAL-HTTP** (`onPremisesPublishing.internalUrl` match `^http://`; medium;
CFG-004), **ENTRA-APPPROXY-BACKEND-STALE** (store join: internalUrl host vs AD computers that are
stale or absent; high; CFG-001, HYG-005). Confidence: likely (beta surface for
onPremisesPublishing on v1.0 may need `version: beta`).

## 10. Mail gateway appliance (`rules\pineapp.yaml`, system `pineapp`, integration `files`)

No public API; console page exports (CSV) in `imports\pineapp\` feed `file` rules, one per row:
**PINEAPP-QUEUE-HIGH** (queued gt 100 or oldest gt 30 min; high; HLT-002), **PINEAPP-SERVICE-DOWN**
(HLT-004), **PINEAPP-VERSION-UNSUPPORTED** / **PINEAPP-FIRMWARE-OLD** / **PINEAPP-ENGINE-UPDATE-STALE**
(LCM-001..003; support end also as a key date), **PINEAPP-DEFERRALS-HIGH** / **PINEAPP-SYSLOG-OFF** /
**PINEAPP-LOG-RETENTION-SHORT** (LOG-002..004), **PINEAPP-QUEUE-LIFETIME-SHORT** (lt 48 h; AVL-003),
**PINEAPP-ENGINE-FAIL-OPEN** (AVL-004), **PINEAPP-OPEN-RELAY-RULE** (critical; CFG-005),
**PINEAPP-RECIPIENT-VALIDATION-OFF** (CFG-006), **PINEAPP-SPF-DMARC-NOT-ENFORCED** (CFG-008, CFG-018),
**PINEAPP-AV-ENGINE-DISABLED** (CFG-009), **PINEAPP-DANGEROUS-TYPES-ALLOWED** (CFG-010),
**PINEAPP-DNSBL-DEAD** (CFG-011), **PINEAPP-ALLOWLIST-WILDCARD** (CFG-012), **PINEAPP-ARCHIVE-UNMANAGED**
(CFG-014), **PINEAPP-USER-RELEASE-VIRUS** (CFG-016), **PINEAPP-MTA-LIMITS-UNSET** (CFG-019),
**PINEAPP-ADMIN-UNEXPECTED** / **PINEAPP-DEFAULT-ADMIN-PRESENT** / **PINEAPP-ADMIN-LEFT** /
**PINEAPP-REMOTE-SUPPORT-ON** / **PINEAPP-AUDIT-OFF** (IAM-001..003, IAM-005, IAM-006),
**PINEAPP-ADMIN-NO-MFA** / **PINEAPP-SNMP-V2** (AUT-002, AUT-004), **PINEAPP-NOTIFY-RECIPIENT-LEFT**
(MON-002). Probes: **PINEAPP-CONSOLE-UNREACHABLE** (http-probe; HLT-001), **PINEAPP-SSH-OPEN**
(tcp-probe 22; AUT-003), **PINEAPP-DISK-FULL** (snmp HOST-RESOURCES-MIB hrStorageTable used gt 80 %;
HLT-003), **PINEAPP-NOT-IN-PATH** (exchange-online message trace volume and Received headers;
HLT-005, LOG-001). DNS and EXO rows map to sections 5 and 15. Refs: CIS-Controls-v8:9.x, 4.7, 6.5;
NIST-800-53:SC-7, SI-3, IA-2(1). Confidence: guess (export column names).

## 11. Plate-recognition enforcement application and its video management system (`rules\enforcement-app.yaml`, system `enforcement-app`; integrations `http` with auth `session-login` for the video management REST API, `sql` for the application database, plus the existing `cim`/`registry`/`eventlog` packs)

The video management system signs in with a form POST to its identity endpoint (grant type, user,
password) and answers with an access token that the REST API wants as a bearer header. That is
`session-login` with `body: form`, `loginFields.grant_type`, `tokenField: access_token`, `prefix:
"Bearer "`, then plain GET reads under the REST root. The application database has a vendor schema
that must be read once on a real instance; every `sql` rule below is `guess` until the table and
column names are confirmed (a wrong name is `unknown`, never a pass).

**NTZ-CAMERA-RECORDING-GAP** - Catches: an enforcement camera with a recording or sequence gap longer
than five minutes in the window. Severity: high. Source: GET the REST camera and recording-sequence
resources, `for_each` over the camera list (cap `max`), key camera id; fields name, `enabled`,
sequence start and end times. Condition: a gap greater than the threshold `ntz.max-gap-minutes`
(engine cannot subtract two dates across rows; use the product's own "gap" or "last recorded"
field and `age-gt` on it). Refs: NIST-800-53:AU-12, NIST-800-53:CP-9. Fix: restore the recorder or
the camera feed; record the accepted gaps. Confidence: guess (resource names). Rows: NTZ-HLT-003.

**NTZ-VMS-VERSION-OLD** - Catches: a management server older than the supported releases, or a care
agreement about to lapse. Severity: high. Source: GET the REST "sites" resource (`version`) or the
registry Uninstall key on the server targets; care expiry stays a key date in the register. Condition:
`version` notmatch `ntz.supported-version-pattern`. Refs: NIST-800-53:SI-2. Confidence: likely.
Rows: NTZ-LCM-002. Sibling **NTZ-APP-VERSION-OLD** (registry `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`
`DisplayVersion` for the application and analytics components lt a threshold; high; NTZ-LCM-001).

**NTZ-CAMERA-FIRMWARE-KEV** - Catches: a camera model whose firmware matches a known-exploited
vulnerability advisory. Severity: high. Source: GET the REST hardware list (`model`, `firmwareVersion`)
joined in the store with the public known-exploited-vulnerabilities JSON (generic `http`, auth `none`,
a separate integration instance) and a threshold table `ntz.firmware-advisories` that maps model and
firmware to advisory ids. Refs: NIST-800-53:SI-2, CIS-Controls-v8:7.4. Fix: schedule the firmware
update; segment the camera network. Confidence: guess (join keys). Rows: NTZ-LCM-004.

**NTZ-CAMERA-EDGE-STORAGE-OFF** - Catches: a camera without on-device storage and retrieval
configured, so a recorder outage becomes a permanent gap. Severity: high. Source: the REST hardware
and recording-settings resources, `for_each` over hardware. Condition: the edge-storage flag absent or
false on cameras in the enforcement group threshold. Confidence: guess. Rows: NTZ-AVL-003.

**NTZ-VMS-USER-LEFT** - Catches: a management-system user or role member who is disabled or absent in
the directory. Severity: high. Source: GET the REST users and role-members resources, joined in the
store with the AD scan on the account name; local application users beyond a documented list also fail.
Refs: NIST-800-53:AC-2(3). Confidence: likely for the join, guess for the paths. Rows: NTZ-IAM-003.

**NTZ-PLATE-READS-LOW** - Catches: plate reads per hour well below normal during working hours, or a
growing unprocessed backlog. Severity: high. Source: `sql` count of reads per hour for the last day and
the backlog of unprocessed reads. Condition: working-hour reads lt `ntz.min-reads-per-hour`, backlog gt
`ntz.max-backlog-hours`; a fixed floor is used because the engine keeps no moving baseline. Confidence:
guess. Rows: NTZ-HLT-004. Same source family: **NTZ-VIOLATION-TRANSFER-FAILED** (violations created
versus transferred to the back office per day, failed transfers older than 24 h; high; HLT-005).

**NTZ-PLATE-SEARCH-AUDIT-OFF** / **NTZ-VIOLATION-CANCELLED-UNREASONED** / **NTZ-CANCEL-ROLE-BROAD** -
Catches: plate searches, views and exports not audited or retained for the required period;
cancellations and edits of violations without a recorded reason or reviewer; more roles than allowed
holding cancel or edit rights, or one user both issuing and cancelling. Severity: high. Source: `sql`
on the audit and change tables (searches per user per day, oldest audit entry, cancellations per user
in 90 days) and on the role table. Condition: oldest audit entry younger than the retention threshold,
a cancellation with an empty reason field, roles with cancel rights gt 3. Refs: NIST-800-53:AU-2,
NIST-800-53:AU-11, NIST-800-53:AC-6, privacy-law audit duties. Confidence: guess. Rows: NTZ-LOG-001,
NTZ-LOG-002, NTZ-IAM-001.

**NTZ-NONVIOLATION-READS-RETAINED-LONG** / **NTZ-VIOLATION-NO-INTEGRITY-HASH** - Catches: personal
data of vehicles that committed no violation kept beyond the approved short period; evidence items
stored without an integrity value. Severity: high / medium. Source: `sql` minimum read date for
non-violation reads versus `ntz.nonviolation-retention-days`; count of violation rows whose integrity
column is empty. Refs: NIST-800-53:SI-12, NIST-800-53:SI-7. Confidence: guess. Rows: NTZ-CFG-003,
NTZ-CFG-004.

**NTZ-EVENTLOG-ERRORS** - `eventlog` Application and System, error level, 7 days, grouped by provider
on the application and analytics servers; recurring signature fails (medium; NTZ-LOG-003). The
vendor's own log folders are not readable by Keeper (file-share-read is not a protocol, section 17).
**WINSRV-TIME-SYNC-EVENTS** - `eventlog` `Microsoft-Windows-Time-Service/Operational` errors and
W32Time offset warnings on the servers (high; NTZ-HLT-009); camera clock accuracy remains an
attestation. **SNOW-CI-RECURRING-INCIDENTS-NO-PROBLEM** - `servicenow` type: incidents per
configuration item in `{DAYS_AGO:180}` that share a cause and have no `problem_id` (medium;
NTZ-MON-004; generic, usable for any system).

## 12. Multi-factor authentication service (`rules\duo.yaml`, system `duo`)

The service's Admin API signs every request with an HMAC over the method, host, path and parameters
using an integration key and a secret key; it is not a bearer, basic or session scheme, so the
Admin-API rules need a signed-request auth kind (`hmac-signature`, section 17). Everything that does not
need the Admin API is already expressible and is listed here.

**DUO-PROXY-VERSION-OLD** - Catches: an authentication proxy below the supported release. Severity:
high. Source: `sccm` type `wmi/SMS_G_System_ADD_REMOVE_PROGRAMS` where `DisplayName` like the proxy
name, key host; `Version` lt threshold `duo.proxy-min-version`. Refs: NIST-800-53:SI-2. Confidence:
likely. Rows: DUO-LCM-001.

**DUO-WINLOGON-HOST-INVENTORY** - info list of every host that has the Windows logon component (ARP
rows joined with the computer's OS and last activity). Rows: DUO-HLT-005. Siblings on the same read:
**DUO-WINLOGON-VERSION-OLD** (`Version` lt threshold; high; LCM-002), **DUO-WINLOGON-PRIVILEGED-HOST-MISSING**
(store: hosts tagged privileged in a threshold list or by role, absent from the inventory; high;
CFG-015). Registry sibling **DUO-WINLOGON-RDP-ONLY** (`registry` `SOFTWARE\Duo Security\DuoCredProv`
values for RDP-only and UAC elevation versus the documented design; medium; CFG-016) and event sibling
**DUO-WINLOGON-EVENT-ERRORS** (`eventlog` Application, providers starting with the vendor name, levels
error and warning, 7 days; low; LOG-005). Refs: NIST-800-53:IA-2(1), NIST-800-53:IA-2(2). Confidence:
likely for ARP and event reads, guess for the registry value names.

## 13. Security testing tools: attack simulation and vulnerability scanner

### 13a. Breach-and-attack simulation (`rules\cymulate.yaml`, system `cymulate`, integration `http` with a token header)

The public API documentation is login-walled, so every console read is `guess` and the pack applies
only while the product is in use (each rule is skipped when the system register says it is not live).
Reads would be GET with an `x-token`-style header (`api-key-header`).

**CYM-AGENT-OFFLINE** - agents whose last-seen age gt 7 days (agents list; medium; HLT-002).
**CYM-VECTOR-NOT-RUN** (assessment history: a licensed vector not run within its interval; medium;
HLT-004), **CYM-IMMEDIATE-THREAT-NOT-RUN** (no immediate-threat assessment within 30 days; low; LCM-003),
**CYM-ASSESSMENT-RUN-RECENT** (info list of runs in `{DAYS_AGO:7}` with initiator and target agents;
every run needs a ticket, matching stays manual; high; LOG-001), **CYM-AUDIT-EVENT-RECENT** (audit
events in `{DAYS_AGO:90}`, info; medium; LOG-003), **CYM-TEMPLATE-DESTRUCTIVE** (assessments using
destructive payload types against targets outside a test-data list threshold; high; AVL-002),
**CYM-FINDING-HIGH-OPEN-LONG** (findings of high severity with first-found age gt 30; medium; MON-001).
Identity: **CYM-USER-LEFT** (users joined in the store with Entra state, more than 4 named users fails;
high; IAM-001), **CYM-LAUNCH-ROLE-MANY** (roles able to create and launch assessments gt 2; high;
IAM-003), **CYM-APIKEY-UNOWNED** (API keys without an owner, broader than read-only, or unused for 90
days; medium; IAM-004).

Agent placement through the `sccm` type: **CYM-AGENT-UNAPPROVED-HOST** (ARP and service inventory
estate-wide for the agent name, hosts not in the approved list threshold; high; HLT-003),
**CYM-AGENT-ON-USER-DEVICE** (agent hosts that appear in a user-device relationship or workstation
collection; high; CFG-001), **CYM-AGENT-VERSION-OLD** (ARP `Version` lt threshold; medium; LCM-001).
Exports (`format: csv` or json under `imports\cymulate\`, `file` rules): **CYM-LOCAL-LOGIN-ENABLED**
(authentication settings: local logins on, SSO not enforced; high; IAM-002), **CYM-LATERAL-ACCOUNT-ENABLED**
(account names from the lateral-movement settings joined in the store with AD: enabled outside windows
or privileged; high; CFG-006), **CYM-EXFIL-REAL-DATA** (data-set type not synthetic; medium; CFG-007),
**CYM-WAF-TARGET-UNOWNED** (targets not in the owned-domain list; medium; CFG-012),
**CYM-NOTIFY-RECIPIENT-LEFT** (recipients joined with Entra users; low; MON-003). Workstation side:
**INTUNE-AV-EXCLUSION-PATH-BROAD** (Graph Intune antivirus policy settings, exclusions that are a drive
root, a user-profile root, a whole-extension wildcard or a system directory; other endpoint products'
exclusions are exports; high; CYMULATE-CFG-003, also a general rule), **TOOLS-MREMOTENG-SAVED-PASSWORD**
(`file` format xml over a copy of the remote-connection file in `imports\`, XPath nodes with a password
attribute, presence only; low; HYG-005). Refs: NIST-800-53:CA-8, AC-2, AC-6, SI-3; CIS-Controls-v8:18.x.

### 13b. Vulnerability scanner (`rules\nexpose.yaml`, system `nexpose`, integration `http` with auth `basic`)

The console REST v3 API (`/api/3/...`) takes basic auth of a read-only user, answers JSON with a
`resources` array and `page` metadata; set `items: resources`, `paging: offset` with `offsetParam:
page`, `limitParam: size` (page-index paging; confirm on first run). Confidence: likely for the
resource names below (public API reference), guess where marked.

Platform health: **NXP-ENGINE-NOT-ACTIVE** (GET `/api/3/scan_engines`: `status` ne active or
`lastRefreshedDate` age-gt 1; high; HLT-002), **NXP-ENGINE-VERSION-MISMATCH** (`productVersion` differs
from `/api/3/administration/info`; medium; LCM-004), **NXP-SITE-ENGINE-UNAVAILABLE** (site engine id
absent or not active; unreachable-asset rate from the export; medium; AVL-001), **NXP-SITE-SCAN-STALE**
(GET `/api/3/sites`: `lastScanTime` age-gt interval+1 or age-gt 30; schedule via `for_each`
`/api/3/sites/{id}/scan_schedules`; high; HLT-003), **NXP-SCAN-FAILED-RECENT** (GET
`/api/3/scans?active=false` with `startTime ge {DAYS_AGO:30}`, `status` in aborted/stopped/error; medium;
HLT-004), **NXP-DB-MAINTENANCE-STALE** (`/api/3/administration/settings` maintenance last run age-gt 30;
medium; HLT-006; guess), **NXP-CONTENT-UPDATE-STALE** (`administration/info` content update age-gt 1;
high; LCM-002), **NXP-VERSION-OLD** (`version` lt threshold; support end also a key date; high; LCM-001),
**NXP-LICENSE-EXPIRING** (`administration/license` expiry until-lt 60 or used gt 95 % of licensed; high;
CST-001), **NXP-ASSET-STALE** (assets whose last scan age-gt 90; low; HYG-004), **NXP-DISCOVERY-CONNECTION-INACTIVE**
(`/api/3/discovery_connections` status not active or refresh age-gt 1; medium; CFG-011),
**NXP-NO-SCHEDULED-REPORT** / **NXP-REPORT-NOT-DELIVERED** (`/api/3/reports` frequency empty; newest
history age-gt 35; low; LOG-004, MON-006; guess).

Coverage and configuration: **NXP-XS-HOST-NOT-ASSESSED** (store join of assets with last scan against AD
servers, SCCM active clients and cloud instances; high; CFG-001), **NXP-XS-SUBNET-NOT-IN-SITE**
(`for_each` `/api/3/sites/{id}/included_targets` joined with the directory's subnets; high; CFG-006),
**NXP-SITE-DISCOVERY-TEMPLATE** (site `scanTemplateId` resolving to a discovery-only template; medium;
CFG-005), **NXP-SITE-SCHEDULE-INFREQUENT** (schedule interval gt 7 days for server sites, gt 31 for
others; medium; CFG-007), **NXP-SITE-NO-BLACKOUT** (fragile-segment sites without a blackout or gentle
template; low; AVL-003; guess), **NXP-TEMPLATE-AGGRESSIVE** (`maxParallelAssets`, process count and
packet rate above thresholds for sites crossing a wide-area link; medium; AVL-002), **NXP-ASSET-UNTAGGED**
(server assets without a system or owner tag; low; CFG-008; heavy `for_each`, sample by site),
**NXP-EXCEPTION-NO-EXPIRY** (`/api/3/vulnerability_exceptions`: no `expires`, expiry gt 365 days away,
global scope on a critical item, no reviewer; high; CFG-009).

Credentials and identity: **NXP-SCAN-ACCOUNT-PRIVILEGED** (`/api/3/shared_credentials` account names
joined with AD privileged groups; high; CFG-003), **NXP-CREDENTIAL-PLAINTEXT-SERVICE** (credential
service type telnet, ftp or plain http, or no site restriction; medium; CFG-004),
**NXP-CREDENTIAL-NO-SSH-SNMP** (sites holding network or hypervisor targets with no ssh/snmp credential;
medium; CFG-015), **NXP-SCAN-ACCOUNT-LOGON-SOURCE** (`eventlog` Security 4624 on domain controllers for
the scan account, workstation name not in the engine host list; high; IAM-005), **NXP-USER-LEFT**
(`/api/3/users` joined with AD/Entra, disabled or absent; more than a handful enabled; high; IAM-001),
**NXP-USER-LOCAL-AUTH** (`authentication.type` local, built-in administrator enabled; high; IAM-002),
**NXP-GLOBAL-ADMIN-MANY** (`count` of the global administrator role gt 2; medium; IAM-003),
**NXP-REPORT-BROAD-RECIPIENTS** (report delivery to distribution lists outside the security group;
medium; IAM-006), **NXP-SESSION-TIMEOUT-LONG** (timeout gt 30 min, lockout gt 10; low; AUT-004; guess).

Exports under `imports\nexpose\` (`format: csv`; the console's SQL query export on the reporting data
model): **NXP-CREDENTIAL-FAILURE-RATE** (share of assets with a failed authentication at the last scan
per site gt 5 %; high; LOG-002), **NXP-VULN-CRITICAL-OVERDUE** (critical older than 15 days, high older
than 30; high; MON-001), **NXP-VULN-KEV-OPEN** (open CVE ids joined in the store with the public
known-exploited JSON, past its due date; critical; MON-002), **NXP-AUDIT-UNATTRIBUTED** (audit export:
changes without a named user; medium; LOG-003), **NXP-ALERT-RECIPIENT-LEFT** (alert recipients joined
with Entra users; medium; MON-004). Refs: NIST-800-53:RA-5, SI-2, CA-2, AC-2, AC-6; CIS-Controls-v8:7.x,
5.x.

## 14. Privileged-session recording (`rules\session-recording.yaml`, system `ekran`; integrations `sql` for the management database, `http` with auth `session-login` for the token API where it exists, `files` for console exports, plus the `sccm`, `cim`, `registry`, `eventlog` packs)

The product keeps clients, sessions and its own audit trail in a management database that Keeper can
read with a read-only SQL login; table and column names must be read once from a real instance, so every
`sql` rule here is `guess` until then. Settings that live only in the console are exports.

Health (sql and inventory): **EKRAN-CLIENT-OFFLINE** (client table, last connection age-gt 1 on
clients in the privileged-host list, or more than a small share of all clients; high; HLT-002),
**EKRAN-CLIENT-NO-DATA** (online clients with no session or screenshot in 24 h; medium; HLT-005),
**EKRAN-CLIENT-CACHE-OLD** (client status offline-cache age gt 24 h through the token API; low; HLT-006;
confidence guess), **EKRAN-CLIENT-STALE** (clients unseen for 30 days joined in the store with AD
computers that are disabled or absent; low; HYG-004), **EKRAN-VERSION-UNSUPPORTED** (`registry`
Uninstall key on the server target, `DisplayVersion` lt threshold; high; LCM-001),
**EKRAN-AGENT-VERSION-OLD** (`sccm` ARP rows grouped by `Version`; medium; LCM-002),
**EKRAN-EVENTLOG-ERRORS** / **EKRAN-AGENT-EVENT-ERRORS** (`eventlog` Application, providers starting with
the vendor names, errors in 7 days, server and monitored hosts; medium / low; LOG-001, LOG-002; the
product's own log folder is a file-share read, section 17).

Coverage (store joins): **EKRAN-XS-PRIVILEGED-HOST-NO-AGENT** (privileged-host tag or list versus ARP
rows and the client list; high; CFG-001), **EKRAN-XS-SERVER-NO-AGENT** (live AD servers without a client;
medium; CFG-002), **EKRAN-XS-LINUX-NO-AGENT** (`vcenter` guest OS family and cloud instances versus the
client list; low; CFG-015), **EKRAN-XS-VENDOR-LOGON-UNRECORDED** (vendor accounts that logged on to
servers, from domain-controller Security 4624, with no recorded session; high; CFG-004).

Audit and retention (sql): **EKRAN-RECORDING-ACCESS-RECENT** (info list of view and export actions in
the window; ticket matching manual; high; LOG-003), **EKRAN-RECORDING-DELETED-MANUALLY** (delete or purge
entries not issued by the scheduled cleanup; high; LOG-005), **EKRAN-RETENTION-EXCEEDED** (oldest
session older than `ekran.retention-days`; medium; CFG-006), **EKRAN-ALERT-HIGH-UNACKNOWLEDGED**
(alerts of high severity unacknowledged for over one business day; high; MON-001).

Console exports (`file`, csv under `imports\ekran\`): **EKRAN-ALERT-RULES-MISSING** (no active rule for
account creation, group change, security-tool tampering, credential tools, remote-execution tools, mass
file actions, removable media; medium; CFG-008), **EKRAN-BUILTIN-ADMIN-USED** (built-in administrator
login within 90 days; high; IAM-004), **EKRAN-CAPTURE-SETTINGS-DRIFT** (capture frequency, keystroke,
clipboard settings differ from the approved values as thresholds; medium; CFG-005),
**EKRAN-CLIENT-CHANNEL-UNENCRYPTED** (client channel without encryption or server certificate; the agent
port can also be a `tls` target; medium; AUT-002), **EKRAN-CLIENT-PROTECTION-OFF** (protected mode off or
uninstall key not set; high; CFG-007), **EKRAN-CONSOLE-NO-2FA** (console users without second factor; high;
IAM-002), **EKRAN-GROUP-RECORDING-OFF** (privileged hosts in a non-recording client group; medium;
CFG-013), **EKRAN-LOGON-NOTICE-OFF** (no logon notice; medium; CFG-010), **EKRAN-NOTIFY-RECIPIENT-LEFT**
(recipients joined with Entra users; medium; MON-002), **EKRAN-OFFLINE-CACHE-SMALL** (cache sized for
less than 24 h; medium; AVL-001), **EKRAN-RECORDED-ADMIN-CAN-VIEW** (console roles with view, delete or
settings rights held by accounts in privileged AD groups; high; IAM-003), **EKRAN-SESSION-TIMEOUT-LONG**
(gt 30 min; low; AUT-004), **EKRAN-SIEM-EXPORT-OFF** (integration off; the receiving side needs a SIEM
read; medium; LOG-004), **EKRAN-TAMPER-ALERT-OFF** (client offline / uninstalled notification off for
privileged groups; high; MON-003), **EKRAN-USER-EXCLUSION-PRIVILEGED** (excluded users or groups that are
privileged or vendor accounts, joined with AD; high; CFG-003), **EKRAN-USER-UNEXPECTED** (users with
administrative rights gt 5, departed or shared accounts, joined with AD/Entra; high; IAM-001),
**EKRAN-VAULT-CREDENTIAL-NOT-ROTATED** (stored credential metadata: rotation age gt 90 or no owner,
only if the vault feature is used; medium; IAM-006). Refs: NIST-800-53:AU-2, AU-9, AU-12, AC-6(9),
CM-7; CIS-Controls-v8:8.x, 5.4. Confidence: guess for all exports (column names).

## 15. Public DNS, registrars and the DNS/CDN provider (`rules\public-dns.yaml`, `rules\cloudflare.yaml`; systems `public-dns`, `cloudflare`)

Three kinds of read: the provider's REST API (`http` with auth `bearer`, reads under `/client/v4`,
`items: result`, page paging), public registration data (RDAP, certificate-transparency JSON: `http`
with auth `none` as a separate instance), and live DNS answers (the `dns` protocol of section 17; the
rows that need it map to that type and are not listed as rules here beyond their ids in the map).
Domain-level rules need a list of domains to iterate; until the engine can iterate a static list
(section 17), the list is the result of the provider's zone listing used as the `for_each` parent and
the RDAP/CT reads are run per zone through a second integration. Route 53 variants of the registrar and
zone rows are in section 2 (`aws`).

Registration (RDAP): **DNS-REG-DOMAIN-INVENTORY** (info list: registrar, registrant, status, expiry for
every domain; union with the zone listing in the store; high; DOMAINS-LCM-001), **DNS-REG-EXPIRING**
(`events[eventAction=expiration]` until-lt 60, critical below 14; critical; LCM-002), **DNS-REG-REGISTRAR-UNEXPECTED**
(registrar entity notmatch threshold `dns.allowed-registrars`; high; LCM-004), **DNS-REG-REGISTRANT-UNEXPECTED**
(registrant organisation not the municipality, expiry lt 365 days, name servers outside municipal
control for the forest-named domain; critical; LCM-005), **DNS-REG-CONTACT-UNEXPECTED** (contact
addresses personal or departed; often redacted, then `unknown`; high; IAM-004), **DNS-REG-TRANSFER-LOCK-OFF**
(status array lacks `client transfer prohibited`; high; IAM-001), **DNS-REG-REGISTRY-LOCK-OFF** (lacks
`server transfer prohibited`; medium; IAM-002), **DNS-REG-LOOKALIKE-REGISTERED** (variant names generated
from a threshold list, registered ones listed; low; HYG-008). Refs: NIST-800-53:CM-8, SC-20; CIS-Controls-v8:12.x.
Confidence: likely for the RDAP field names, guess for lock status on country registries.

Certificate transparency: **DNS-CT-UNEXPECTED-CERT** (per domain JSON of issued certificates in
`{DAYS_AGO:90}`; issuer or name not in the hostname inventory / allowed-CA threshold; high; PKI-008).
**DNS-EXTERNAL-SCAN-SCORE** (a public scanner's JSON where it offers an account-free read; score below
the previous run; low; MON-007; guess).

Provider zone and account reads (all `GET`, bearer token with read-only scopes): **CF-ZONE-RECORD-INVENTORY**
(`/zones`, `for_each` `/zones/{id}/dns_records`, info list; medium; CFG-001), **CF-ZONE-NOT-ACTIVE**
(`/zones` `status` ne active; low; HYG-007), **CF-ZONE-PLAN-MISMATCH** (`plan.name` versus the features in
use; low; CST-003), **CF-RECORD-WILDCARD** (`name` match `^\*`; medium; CFG-002), **CF-RECORD-PRIVATE-ADDRESS**
(A `content` in private or shared ranges; report the class only; medium; CFG-003), **CF-RECORD-CNAME-CONFLICT**
(apex CNAME unflattened or a CNAME name that also holds other types, store grouping; medium; CFG-005),
**CF-RECORD-TEST-NAME-PUBLIC** (name match `test|dev|stg|uat|poc|demo`; medium; CFG-011),
**CF-RECORD-PROXY-STATE-WRONG** (`proxied` versus record role: web proxied, mail/VPN/transfer DNS-only;
medium; CFG-014), **CF-RECORD-SERVICE-ORPHAN** (SRV and underscore labels with no owning system in the
register, store; low; CFG-018), **CF-RECORD-INACTIVE-SYSTEM** (record names matching retired systems in
the register; medium; HYG-005), **CF-RECORD-EXTERNAL-TARGET** (CNAME/NS/A targets outside municipal and
approved-provider patterns; medium; HYG-010), **CF-RECORD-MALFORMED** (duplicates, TTL 0, uppercase or
underscore in host labels, store grouping; chain depth needs `dns`; low; HYG-006). Settings:
**CF-ZONE-TLS-SETTINGS-WEAK** (`/zones/{id}/settings/ssl`, `min_tls_version`, `always_use_https`,
`security_header`, `tls_1_3`: ssl not strict, min lt 1.2, redirect off, HSTS max-age lt 31536000; medium;
CFG-015), **CF-ZONE-SSL-NOT-STRICT** (`settings/ssl` ne strict; origin reachability from outside via
`tcp-probe`; medium; PKI-011), **CF-ZONE-WAF-OFF** (managed ruleset absent in `/zones/{id}/rulesets` phase
`http_request_firewall_managed`, `security_level` below medium; medium; CFG-016). Account:
**CF-ACCOUNT-MEMBER-NO-2FA** (`/accounts/{id}/members` two-factor off or personal-mail domain; high;
IAM-003), **CF-ACCOUNT-SINGLE-SUPER-ADMIN** (`count` of super-admin role lt 2; medium; BCK-002),
**CF-TOKEN-UNUSED-OR-BROAD** (`/user/tokens`, the calling user's tokens only: no expiry, all zones,
`last_used_on` age-gt 90; medium; IAM-006), **CF-AUDIT-DNS-CHANGE-RECENT** (`/accounts/{id}/audit_logs`
with `since={DAYS_AGO:7}` for zone, record and registrar actions, info; medium; LOG-004),
**CF-REGISTRAR-AUTORENEW-OFF** (`/accounts/{id}/registrar/domains` `auto_renew` false; high; LCM-003),
**CF-BILLING-PAYMENT-EXPIRING** (billing profile payment-method expiry until-lt 60; high; CST-002; guess).
Tenant verification: **ENTRA-DOMAIN-UNVERIFIED-OLD** (Graph `/domains` `isVerified` false and older than
a threshold, or verified domains whose registration is not municipal, store join with the inventory;
high; CFG-008; dangling verification records are a `dns` read). Exports: **DNS-DMARC-AGGREGATE-UNKNOWN-SOURCE**
(`file` format xml over aggregate reports, XPath `feedback/record`: known senders failing SPF and DKIM,
unknown sources over a volume share; medium; MON-002), **DNS-TLSRPT-FAILURES** (`file` format json,
`policies[].summary.total-failure-session-count` gt 0; low; MON-003).

## 16. Cross-system Entra, Intune, inventory and appliance additions

Generic rules that several catalogue rows share; most are `graph` reads of the application-gating
groups and enterprise applications of the single-sign-on and provisioning pattern, so they apply to any
application, with the application and group ids supplied as settings.

Enterprise application and group hygiene (`graph`): **ENTRA-SP-DIRECT-USER-ASSIGNMENT** (`/servicePrincipals/{id}/appRoleAssignedTo`
with `principalType` eq User; medium; HARMONY-SASE-CFG-001), **ENTRA-GROUP-EMPTY-APP-ASSIGNED** (assigned
group with no members, `for_each` `/groups/{id}/members` count; low; HYG-005), **ENTRA-GROUP-MEMBERSHIP-CYCLE**
(`/groups/{id}/transitiveMembers` containing the group itself, or a group nested in another assigned
group; medium; CFG-003 and the known SASE nested-group check), **ENTRA-APP-GROUP-NO-OWNER** (`/groups/{id}/owners`
fewer than 2 or outside the allowed-manager threshold; medium; CFG-004), **ENTRA-APP-GROUP-EDITORS-BROAD**
(principals able to change membership: owners plus directory role assignments carrying group-write; set
outside the allowed list; medium; IAM-004), **ENTRA-APP-GROUP-EDITORS-CHANGED** (store diff of that set
across runs; medium; IAM-005), **ENTRA-APP-GROUP-NAMING-NONCOMPLIANT** (assigned-group display name
notmatch the naming threshold; info; HYG-006), **ENTRA-AUDIT-GROUP-ADD-RECENT** (`/auditLogs/directoryAudits`
'Add member to group' for the gating groups in `{DAYS_AGO:7}`, info list; medium; IAM-010),
**ENTRA-AUDIT-CONSENT-RECENT** (consent and user-creation activity around an application's onboarding,
info; low; HARMONY-EMAIL-IAM-008). Sign-ins: **ENTRA-APP-SIGNIN-FAILURES-RECENT** (`/auditLogs/signIns`
by `appId`, `status/errorCode ne 0`, `{DAYS_AGO:7}`, failure share gt 5 % or error 50105 for enabled
staff; medium; LOG-001), **ENTRA-APP-SIGNIN-SINGLE-FACTOR** (`authenticationRequirement` eq
singleFactorAuthentication for the application; high; AUT-002), **ENTRA-SP-SIGNIN-FAILURES-RECENT**
(service-principal sign-in events with an error for the connector application; high; HARMONY-EMAIL-LOG-001).
Single sign-on and provisioning: **ENTRA-SP-SAML-NAMEID-MISMATCH** (`samlSingleSignOnSettings` and the
application's optional claims versus the identifier the provisioning matches on; medium; CFG-022),
**ENTRA-SP-SAML-GROUPS-CLAIM-MISSING** (`groupMembershipClaims` on the application object or a claims
mapping policy absent where the portal expects a groups claim; low; CHECKPOINT-IAM-011, CFG-019),
**ENTRA-PROVISIONING-SCOPE-ALL-USERS** (synchronization job schema scope not "assigned only"; high; CFG-007),
**ENTRA-PROVISIONING-NOTIFICATION-UNSET** (job notification address empty or not a monitored mailbox;
medium; MON-005).

Intune: **INTUNE-APP-INSTALL-FAILED** (`/deviceAppManagement/mobileApps/{id}/deviceStatuses` `installState`
failed or error codes for the package, `for_each` over Required apps; high; HARMONY-SASE-HLT-005 and the
known client-pin statuses check), **INTUNE-LOB-APP-VERSION-DETECTION-ON** (`ignoreVersionDetection` false
on a pinned package, or `productVersion` more than two releases old; medium; LCM-002),
**INTUNE-APP-ASSIGNMENT-NOT-REQUIRED** (assignment `intent` not required for groups that need the
client; medium; CFG-018), **INTUNE-DETECTED-APP-VERSION-OLD** (`/deviceManagement/detectedApps` for the
package name, devices below the current release; low; LCM-006).

Inventory and fleet: **WSF-SW-VPN-CLIENT-MULTIPLE** (`sccm` ARP: more than one tunnelling client per
device outside an approved combination list; medium; HARMONY-SASE-LCM-004), **WS-ROOT-CA-UNEXPECTED**
(`registry` `SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates` subkeys on workstation targets: the
inspection CA thumbprint present only on managed PCs and listed; medium; HARMONY-SASE-PKI-002),
**VMW-VM-POWERED-OFF** (`vcenter` `/api/vcenter/vm` `power_state` POWERED_OFF for systems recorded as
retired, info; medium; OPSWAT-HYG-008), **VENDOR-STATUS-INCIDENT-OPEN** (a vendor status page JSON feed
through `http` auth `none`, open incidents; info; confidence guess).

Late additions to section 1 and section 7 (same reads as their siblings): **FGT-IPSEC-WEAK-ALGORITHM**
(phase 1 and phase 2 proposals over all tunnels: des/3des/md5/sha1, DH group 1/2/5, aggressive mode;
high; FORTIGATE-AUT-008), **FGT-IPSEC-SA-CHURN** (`creation_time` of phase 2 security associations
compared across two runs in the store, with tunnel-up event counts; high; AVL-002),
**FGT-BGP-GRACEFUL-RESTART-OFF** (`graceful-restart`, neighbour capability and soft reconfiguration
disabled; low; CFG-016), **FGT-DAEMON-CRASH** (GET `/api/v2/monitor/system/crashlog`, any crash in 7
days; high; LOG-011; path likely). **NET-ROGUE-AP-ON-NETWORK** (Prime `RogueApAlarms.json`: any
on-network or malicious rogue not acknowledged, or rogue detection off; high; NETINFRA-AUT-009).

Obligation rows (attestations, key dates, registers) map to existing `OBL-*` and `REG-*` ids in the
per-row map and need no new rule.

## 17. Integration types to add

Ordered by the number of catalogue rows each unlocks, largest first (the per-row map holds the counts).
Items 1, 6, 9 and 10 are small changes to existing types; the rest are new types.

1. **`http` read-only POST mode** - the largest gap. Management-server, Gaia and Infinity-portal
   commands are POSTs with a JSON body that only read (`show-*`, queries). Sign-in is already solved by
   `session-login`. Proposal: a rule field `method: post` plus `body` (mapping, macros allowed), accepted
   only when the integration lists `readPostPaths` (allow-list of path patterns, for example
   `/web_api/show-*`), so the engine can never POST to a mutating command. Needs paging by `offset`/`limit`
   in the body and a per-rule `for_each` over layers or gateways. Unlocks the management, gateway-OS and
   portal rules of sections 3, 4 and 5 and the cross-references from other products.
2. **`snmp`** - v3 GET/WALK of standard and enterprise MIBs per device target, one row per table index,
   credentials as authPriv user. Unlocks the network-device, gateway-counter and appliance rules of
   sections 3, 7, 10 and 11 of this file.
3. **`dns`** - a protocol for live resolution from the scanner and from a public resolver: record types
   including TXT, MX, NS, SOA, TLSA, DS/RRSIG, CAA, CNAME chains and zone-delegation consistency across
   name servers; rows hold the answers per name server. Unlocks the mail-authentication, delegation,
   dangling-record and DNSSEC rows of section 15 and the mail-routing rows of sections 5 and 10.
4. **`config-text`** - a text-regex protocol over device configuration exports dropped under `imports\`
   (one row per device and matching line, absence rules via `count`). Unlocks the switch-hardening,
   authentication-on-ports and banner rows of sections 7 and 8.
5. **`aws`** - SigV4-signed read calls (EC2, CloudWatch, DirectConnect, Backup, Inspector, Cost Explorer,
   CloudTrail, Route 53, Health, ELB, Auto Scaling, ACM, CloudFormation) with an access key or a
   role session, an allow-list of read actions, and result paths per action (section 2).
6. **`http` auth kind `hmac-signature`** - requests signed with an integration key and secret (method,
   host, path, sorted parameters, date) as the multi-factor service's Admin API requires. Unlocks the
   Admin-API rules of section 12 (users, devices, policies, logs, administrators).
7. **`exchange-online`** - read cmdlets only (`Get-*`), through the supported module or its REST
   endpoint, for connectors, transport rules, quarantine and policy objects, DKIM, accepted domains,
   message trace (section 5).
8. **`file-share-read`** - file metadata (existence, modified time, size) of a configured path on a
   share: backup folders, log folders, exported archives. Authenticode and ACL reads are separate asks
   and stay out. Used by backup-freshness, log-folder and cache-folder rows of several products.
9. **`probe` protocols** - `http-probe` (status, title, redirect target, selected headers; redirects
   not followed), `tcp-probe` (connect or refuse), `ssh-probe` (banner and offered algorithms). `tls`
   gains a `starttls` option for SMTP so the existing TLS rules apply to mail gateways.
10. **SIEM read** (one type per product, starting with the one in use) - event counts per source and
    alert-definition listing, for log-centralisation and alert-routing rows.
11. Minor: `http` iteration over a static list (`for_each` fed by a setting or a `files` list, needed for
    per-domain RDAP and certificate-transparency reads); a generic `graphql` integration type (the
    protocol exists, but only named types carry it) for the provider analytics queries; an extension
    of the `prtg` type to read notification recipients; offline rulebase analysis stays a `file` job
    over an exported rulebase.

No new type is needed for the firewall appliances that take an API token (bearer), for the wireless
manager (basic), for the vulnerability scanner (basic), for the single-sign-on-style security gateways
(session-login), or for the video management system (session-login with a form body).
