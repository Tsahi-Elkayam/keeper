# Network devices and firewalls

Two ways in, chosen by what the device offers. Neither holds a login to a switch or router, and neither sends
anything to one.

## Cisco-style devices: from their configuration backups

Cisco IOS, IOS-XE, NX-OS and Arista EOS have no API most sites switch on, but almost every site already keeps their
configurations (Oxidized, RANCID, a scheduled export, NetBox). Keeper reads those files, so a device is never logged
in to, locked out or put in configuration mode, and no device credential exists to leak.

**Getting the files in.** One file per device, the device's name as the file name (`core-sw01`, `core-sw01.cfg`):

- on the machine Keeper runs on: `<Keeper home>/data/imports/network-config/`;
- or on a backup server: add an `ssh` integration to it and set the tenant setting
  `threshold.network.config-folder` to the backup folder
  (`keeper decide setting threshold.network.config-folder /var/lib/oxidized/configs --reason "..."`, then `keeper qm run`).

Then `keeper scan cisco-ios` (or `keeper run`). `rules/cisco-ios.yaml` has 15 rules: remote login that is not SSH-only,
no access list on the login lines, a readable enable password or user password, no enable secret, no AAA, SSH version 1
or not forced to 2, plain HTTP management, default or read-write SNMP communities, no time source, no log server,
and a backup older than `threshold.network.config-max-age-days` (14).

**Secrets.** Backups are full of them. They are scrubbed while the file is read, before any row exists, so no row,
result, finding or stored run holds one: `enable secret 5 set`, `snmp-server community <default> RO`. What a rule
needs stays (the keyword, the encryption type, whether a community is a well-known default). The backup files
themselves still hold the raw configuration; keep that folder as private as the Keeper home. A file that holds a
private key is skipped and named, and the rest are still read. Add cases to the scrubber (`NetworkConfig.Scrub`) with
a test if your configuration keeps a secret somewhere it does not cover.

**Limits.** A backup shows what was saved, not what is running now; the stale-backup rule is there for that. The
parser reads Cisco-style indentation. Juniper (`set` or braces), HP/Aruba and others need another style.

## FortiGate: over its REST API

Read-only, through the `http` runner and the `fortigate` integration type; no parsing, no SSH.

1. In FortiOS create an access profile that is read-only for the tables below, an administrator of type REST API
   with that profile and trusted hosts limited to the Keeper machine, and note its token.
2. `keeper integration add edge-fw --type fortigate --auth bearer --endpoint https://<firewall>`
   (add `--option "caCertificate=$(cat device.pem)"` when it presents its own certificate), then
   `keeper integration set-secret edge-fw token`.
3. `keeper scan fortigate`.

What it may read is a short list of configuration tables (system global, interface, admin, SNMP communities, NTP, DNS,
firewall policy and address, IPsec phases, syslog) and two status pages. Not the configuration backup (which holds keys),
API users, certificates or licence data; the runner refuses any other path before sending. `rules/fortigate.yaml` has
11 rules: management over HTTP or Telnet, accept-all policies, accepting policies that are not logged, administrators
with no trusted host or no second factor, the default admin account, strong crypto off, a long idle timeout, SNMP v1/v2c
communities, no NTP, and weak IPsec proposals.

**Not verified on a real FortiGate.** Field names are FortiOS 7.x's from its documentation. A build that names one
differently makes that rule unknown (never a pass); the first run on your model shows which.

## Not built yet

Live login to Cisco-style devices, SNMP polling (health, counters), Palo Alto, Juniper and Check Point packs.
