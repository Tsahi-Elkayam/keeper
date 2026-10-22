# Backlog - VMware vCenter (rules/vmware.yaml)

Legacy VMware health checks from the catalogue (`checks-VMWARE.csv`, ~149 rows: HLT, LCM, LOG, AVL,
CFG) that `rules/vmware.yaml` cannot express yet, one line each with the reason and the legacy
CheckId. Source: `rgcheck` = the legacy health-check catalogue. The high-level VMware gaps are also
summarised in `infrastructure.md`; this file is the per-CheckId detail. `(Restored1)` rows ignored.

What this pass added (now expressible through the vSphere Automation REST API the `vcenter`
integration binds): old virtual hardware version and failed hardware upgrade (VMW-VM-HARDWARE-*),
legacy BIOS firmware (VMW-VM-FIRMWARE-BIOS), legacy NIC and SCSI controllers (VMW-VM-LEGACY-NIC,
VMW-VM-LEGACY-SCSI), floppy and serial/parallel devices (VMW-VM-FLOPPY-PRESENT, VMW-VM-LEGACY-IO-PORT),
CPU hot-add (VMW-VM-CPU-HOTADD-ENABLED), NFSv3 datastores (VMW-DATASTORE-NFS-V3) and the datastore
coverage guard (VMW-DATASTORE-NONE). The items below are what is still open.

## SOAP-only - the vSphere Web Services (SOAP) API, not the Automation REST API

The Automation API host list returns only name, connection_state and power_state, and there is no
host-config GET; the cluster list returns name, ha_enabled and drs_enabled only. Everything that
needs per-host or per-cluster configuration, hardware, performance counters or events needs the Web
Services (SOAP) runner, which would be a new integration. Checks waiting for it:

- ESXi version/build per host against end of support, and build consistency per cluster. VMWARE-LCM-002, VMWARE-LCM-003.
- Host hardware health sensors (CPU, memory, power, fan, temperature, drives). VMWARE-HLT-009.
- Host CPU/memory utilisation, ballooning, compression and swapping; host uptime. VMWARE-HLT-011, VMWARE-HLT-012, VMWARE-HLT-013.
- Host in maintenance mode or standby with no change record. VMWARE-HLT-008.
- Datastore inaccessible / APD / PDL / not mounted on every cluster host. VMWARE-HLT-015.
- VM CPU ready and co-stop, VM ballooning/swap, storage and disk latency. VMWARE-HLT-020, VMWARE-HLT-021, VMWARE-HLT-022.
- Multipathing: dead paths and single-path LUNs; LUN visibility and HBA/initiator redundancy per host. VMWARE-HLT-023, VMWARE-AVL-017, VMWARE-AVL-018.
- Host physical NIC link state/speed, uplink redundancy, packet drops; management and vMotion vmkernel redundancy; distributed-switch health. VMWARE-HLT-024, VMWARE-HLT-025, VMWARE-AVL-014, VMWARE-AVL-015, VMWARE-AVL-016.
- ESXi boot device / scratch / core-dump location persistent. VMWARE-HLT-026.
- HA detail: host monitoring, admission-control policy and current failover capacity, datastore heartbeating, isolation response and addresses, per-VM restart priority and VM monitoring, VM Component Protection. VMWARE-AVL-001..007.
- DRS detail: automation level and migration threshold, anti-affinity and VM-host rules, cluster imbalance and pending recommendations, cluster size/standalone design. VMWARE-AVL-008..012.
- VMs on local (non-shared) datastores inside an HA cluster. VMWARE-AVL-013.
- VM orphaned/inaccessible/invalid/disconnected connection state (Runtime.ConnectionState). VMWARE-AVL-022. Partial: VMW-VM-CONFIG-UNAVAILABLE.
- VM pending question or stuck long-running task. VMWARE-AVL-023.
- CPU/memory reservations and limits; resource-pool nesting and shares. VMWARE-AVL-024, VMWARE-AVL-025.
- Fault Tolerance state and FT network. VMWARE-AVL-026.
- Host and BIOS power-management profile. VMWARE-AVL-027.
- vSphere Replication / replica VM state and age. VMWARE-AVL-028.
- ESXi lockdown mode. VMWARE-CFG-001.
- Host services (SSH/TSM-SSH, ESXi Shell/TSM, DCUI, SLP/slpd, CIM, SNMP, X.Org) running and policy. VMWARE-CFG-002, VMWARE-CFG-003, VMWARE-CFG-011, VMWARE-LCM-016.
- ESXi shell/DCUI timeouts; account lockout and password policy; MOB disabled; shell-warning suppression and banners; page-sharing salt; Secure Boot / TPM attestation / execInstalledOnly; firewall default-deny and per-rule source restriction. VMWARE-CFG-004..010.
- Standard and distributed vSwitch/portgroup security (promiscuous, MAC changes, forged transmits), MAC learning, VLAN hygiene, traffic separation and vMotion encryption, orphaned portgroups, NetFlow/port-mirror targets. VMWARE-CFG-012..017.
- iSCSI CHAP and NFS export restrictions. VMWARE-CFG-018.
- Host DNS/FQDN identity and Active Directory host authentication (ESX Admins group, CVE-2024-37085). VMWARE-CFG-019, VMWARE-CFG-020.
- Host client/API session timeout; host configuration drift / host-profile compliance; host advanced-setting drift (BPDU filter, DVFilter, etc.). VMWARE-CFG-021, VMWARE-CFG-022, VMWARE-CFG-044, VMWARE-CFG-045.
- VM isolation.tools.* and device/console hardening, VM logging limits (ExtraConfig). VMWARE-CFG-023, VMWARE-CFG-024.
- VM encryption / vTPM / UEFI Secure Boot enabled (bootOptions.efiSecureBootEnabled, Config.KeyId); only legacy BIOS firmware is readable (VMW-VM-FIRMWARE-BIOS). VMWARE-CFG-026.
- VM hot-add detail beyond CPU, cores-per-socket vs NUMA; disk mode (independent/RDM/multi-writer, disk.EnableUUID); Changed Block Tracking state; guest-OS type vs running OS; passthrough/SR-IOV/vGPU devices. VMWARE-CFG-027..031.
- VMware Tools time-sync-with-host and Tools upgrade policy per VM (Config.Tools.*; the Automation tools object has run state and version only). VMWARE-LCM-008.
- VM templates age (the VM list carries no template flag). VMWARE-LCM-022.
- EVC mode per cluster; distributed-switch version. VMWARE-LCM-012, VMWARE-LCM-021.

## Responses that are not a list of objects

The Automation API answers some reads with a bare scalar, a bare array of strings, or a map; the
rules use the deprecated `/rest` base path where it wraps them, but some shapes still yield no rows.

- Appliance system uptime and pending-reboot-after-patch is a bare number, so no row. VMWARE-HLT-006. Partial: VMW-VCSA-UPDATE-* for the update state.
- Appliance NTP servers and ESXi syslog/host NTP are bare string arrays (or SOAP), so "exactly N servers" has no row. VMWARE-LOG-017, VMWARE-CFG-040 (NTP-server-count part). See infrastructure.md VMW-VCSA-NTP-SINGLE-SERVER.
- Content Library configuration (subscribed/local, external URL, auth) - `/api/content/library` returns a bare array of library-id strings, so `for_each` has no field to walk. VMWARE-CFG-042.
- Trusted-root chains and local accounts other than root are bare string arrays. (infrastructure.md).

## Engine gaps - the data is in the API, the engine cannot use it yet

- Thin-provisioning over-commit per datastore (sum of VM provisioned / capacity) - needs cross-row aggregation and arithmetic. VMWARE-HLT-016.
- Datastore free space as a percentage (free / capacity) - needs field-to-field arithmetic. VMWARE-HLT-014. Partial: VMW-DATASTORE-FREE-SPACE (absolute bytes).
- All event- and task-history checks (host connectivity, HA failover, storage APD/PDL, VM power/crash, PSOD, snapshot lifecycle, failed logons, permission/role/SSO changes, vMotion/DRS failures, certificate and backup events, recurring signatures) - the events/tasks API is a time-windowed stream, not a state read, and the signature checks need run-to-run comparison. VMWARE-LOG-006..015, VMWARE-LOG-019..022.
- Event/task retention and database size - advanced settings (SOAP) plus a size read. VMWARE-LOG-016.
- Composite/estate checks: host evacuation feasibility, dedicated-cluster HA bar, deployment-topology estate view, vCenter VM placement. VMWARE-AVL-030, VMWARE-AVL-029, VMWARE-LCM-017, VMWARE-AVL-020.
- vLCM image/baseline compliance per cluster (`/api/esx/settings/clusters/{id}/software/compliance`) - a per-cluster `for_each` the pack has not written; status word mapping and the UNKNOWN=unverified handling to confirm first. VMWARE-LCM-004.

## Joins across systems

- Host and VM inventory reconciled against AD / the CMDB / the documented list; ESXi hosts in no vCenter. VMWARE-HLT-030, VMWARE-LCM-019, VMWARE-LCM-020. Belongs to cross-system.
- Backup footprint and protection-gap joins (VMs touched by a backup account, replicas of deleted sources). VMWARE-LOG-020, VMWARE-AVL-028. Belongs to the Veeam/cross-system join.

## Not in scope of the vcenter integration

- vSAN health and capacity - the vSAN health system is a separate SOAP/management API. VMWARE-HLT-029.
- Triggered and default alarms - the alarm manager is SOAP, not Automation REST. VMWARE-HLT-027, VMWARE-HLT-028.
- vCenter plug-ins / extensions and scheduled tasks - ExtensionManager and ScheduledTaskManager are SOAP. VMWARE-LCM-015, VMWARE-CFG-043.
- SSO identity sources and local-only vsphere.local administrators, and identity-source responsiveness - the SSO admin interface, not the Automation API. VMWARE-AVL-021.
- vCenter HA (VCHA) state - rarely deployed and "not configured" is normal for a single appliance, so a generic rule would be all false positives; the file-based backup rules (VMW-VCSA-BACKUP-*) are the mitigation instead. VMWARE-AVL-019.
- vCenter / ESXi STS and machine SSL certificates on hosts and other ports - belongs to `rules/certificates.yaml` (tls protocol); the vCenter signing-certificate route returns PEM chains without parsed dates. VMWARE-LOG-019 (cert part), and see infrastructure.md.
- iDRAC / Redfish hardware health and predictive drive failure, host firmware/BIOS/driver versions, server model EOL/warranty - a different endpoint per server; needs a Redfish integration. VMWARE-HLT-010, VMWARE-LCM-010, VMWARE-LCM-011.
- Externally hosted camera vCenter and its deletion-event forensics - a provider-held tenant and an event query. VMWARE-LCM-018, VMWARE-LOG-022.
- VCSA disk partitions below N% used and CPU/mem/swap trend - the monitoring/query API returns time series, not a state; the health colours (VMW-VCSA-HEALTH-*) are the state proxy. VMWARE-HLT-003, VMWARE-HLT-004.

## Unverified details - rule not written

- VCSA pending-update list (`/api/appliance/update/pending`): undocumented whether an up-to-date appliance answers an empty list or 404. VMWARE-LCM-005. Partial: VMW-VCSA-HEALTH-PACKAGES, VMW-VCSA-UPDATE-*.
- vCenter patch release date (`/api/appliance/system/version` releasedate): format undocumented, so "patch older than N days" waits for a first real answer. VMWARE-LCM-001 (patch-age part).
- DCUI / console-CLI enabled on the appliance (`/api/appliance/access/dcui`, `/consolecli`): console-only and often left on by policy, so not written; SSH and the Bash shell (the real risks) are covered by VMW-VCSA-SSH-ENABLED and VMW-VCSA-SHELL-ENABLED. VMWARE-CFG-038.
- Datastore VMFS major version (VMFS5 vs VMFS6): the datastore summary carries the type but not the VMFS version. VMWARE-LCM-014.

## Thresholds this pass adds

Set as `threshold.<name>` in the Keeper home; the value in the rule applies when it is not set.

| Threshold | Default | Rule |
|---|---|---|
| vmware.vm-hardware-old-pattern | `^VMX_(0[0-9]\|1[0-4])$` (vmx-14 and below) | VMW-VM-HARDWARE-VERSION-OLD |

## To confirm on the first real run

- `/api/vcenter/vm/{vm}/hardware` returns `version` (VMX_nn), `upgrade_status` (NONE/PENDING/SUCCESS/FAILED), `upgrade_version` and `upgrade_error`; `/api/vcenter/vm/{vm}/hardware/boot` returns `type` (BIOS/EFI).
- `/rest/vcenter/vm/{vm}` renders `nics`, `scsi_adapters`, `floppies`, `serial_ports` and `parallel_ports` as `[{key, value}]` (as it does `cdroms`), and exposes `cpu.hot_add_enabled` and `cpu.count` on the `value` object; the device adapter `type` enums (E1000, E1000E, VMXNET3, BUSLOGIC, LSILOGIC, LSILOGICSAS, PVSCSI) match the API spelling.
- `/api/vcenter/datastore` reports NFSv3 as type `NFS` and NFS 4.1 as `NFS41` (so VMW-DATASTORE-NFS-V3 does not fire on 4.1).
- The per-VM config rules walk the whole VM list (powered-on and off), capped at 2000; beyond that they are partial.
- A vCenter that manages hosts always presents at least one datastore, so an empty datastore list is a lost permission, not a clean estate (VMW-DATASTORE-NONE).
