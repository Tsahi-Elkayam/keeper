# Printers: network and USB

Printers are scanned, inventoried and judged: what they expose, what they say about themselves, and how much they
are used. Everything is read-only, and nothing is ever sent to a print port (it would print).

## Network printers (`printer` integration, `rules/printers.yaml`)

```
keeper integration add office-printers --type printer --auth snmp-v2c --endpoint 192.0.2.0/24 \
        --option targets=192.0.2.50,192.0.2.51 --reason "..."
keeper qm run
keeper integration set-secret office-printers community        # only for the SNMP reads
keeper scan printers
```

Instead of listing them, `--option targetsFrom=discovery --option targetsKind=printer` takes every answering printer
that `keeper discover` found inside the scope (a missing, degraded or old inventory makes the scan partial and says so).

The endpoint is where the integration may talk (CIDR ranges, addresses, host names, `*.suffix`); a printer outside it
gets nothing sent. `--auth none` is enough for ports, IPP and the `public` check. One integration per community.

Three reads per printer, all read-only:

| Read | What it does | What it learns |
|---|---|---|
| `ports` | A TCP connect to ftp, telnet, http, https, smb, lpd, ipp, 8080, 8443 and 9100, then hang up. **Not one byte is sent.** | Which services answer |
| `ipp` | IPP `Get-Printer-Attributes`: the printer is asked about itself. No job, no document, no way to build another operation. Plain, or `scheme: ipps` to also record its certificate. | Make and model, firmware, state, supplies (marker levels), whether TLS and sign-in are offered, accepting jobs, about 150 attributes |
| `snmp` | Printer-MIB over SNMP v2c, GET and GETNEXT only: `info`, `supplies`, `alerts`; or `public-community`, which asks for one value with the community `public`, once. | Model, serial number, status, faults, **the printed page count** and its unit, supply levels, alerts |

Thirteen rules: Telnet, FTP, LPD or raw printing open, a web page without HTTPS, the `public` community answering,
IPP without TLS, a certificate about to expire, not accepting jobs, a fault state, a critical alert, a supply nearly
out, a waste container nearly full. A supply a printer itself calls "unknown" is not judged: some tank printers
report 0 for every ink over SNMP while IPP says 100.

**Seeing what was collected.** The values are stored with every scan. `keeper query printers` lists each printer with
its model, serial number, firmware, state and printed page count; `keeper query printers --kind usb` narrows it.
Run it on different days and the page counts show how much each printer is used.

## USB and local printers (`host` protocol, `rules/printers-local.yaml`)

A USB printer has no network address, so a network scan cannot see it. It is read from the computer it is attached
to, through CUPS (Linux and macOS), locally or over an `ssh` integration:

- `read: cups, what: printers`: every queue, how it is attached (**USB with vendor, model and serial**, or the
  network address by protocol), its state, and whether it takes jobs. A password in a queue's address (`smb://user:pass@...`)
  is replaced before a row exists.
- `what: settings`: whether CUPS shares this computer's printers, allows remote administration, or listens on every address.
- `what: pages`: **pages printed through this computer**, per queue, from CUPS's `page_log`: pages, jobs, how many
  different users, first and last print. User names, job names and addresses are never kept.

**Page counts, and their limit.** For a USB printer the count is *what this computer sent to it*. It misses pages
printed from another computer or from the printer's own buttons, and a rotated log starts again. The printer's own
lifetime counter is not reachable over USB without vendor commands, which are sent as print data; Keeper does not
do that. A printer that speaks IPP over USB (the `ipp-usb` service on Linux) shows up as a local network address:
add `127.0.0.1` to a printer integration's scope and targets to read what it reports.

Nine rules: remote administration or any-address access to CUPS, shared printers, debug logging, a queue that writes
to a file, a password in a queue's address, raw or LPD queues, a stopped queue, a queue unused for 180 days, and
a USB printer attached (listed, so it is known).

## Not built yet

SNMPv3 for printers; Windows computers' printers and spooler counters (a Windows reader, with the Windows rules in
`windows-server.yaml` and `workstations.yaml`, which already cover the print spooler and Point and Print); a
rule on page-count trends; vendor MIBs (toner part numbers, firmware over SNMP).
