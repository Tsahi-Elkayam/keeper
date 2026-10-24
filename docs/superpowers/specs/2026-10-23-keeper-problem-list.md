# Keeper: problem list

Date: 2026-10-23. Status: draft from a conversation with the owner; problem level only, no design
or build decisions. Items marked *(guess)* are not the owner's words.

## The idea

Every Sunday, run Keeper over everything in the network that has an IP (servers, workstations,
firewalls, switches, printers) and get one list: what is wrong, what to address systematically, and
what to fix first by severity and exposure. Scan and report only. No live detection.

## Questions Keeper answers

1. What is broken or not functioning?
2. What exists but is configured wrong, or against best practice?
3. What is not configured and should be?
4. What is about to be broken? Dated (certificates, licences, support end) and *(guess)* trending
   (disk filling, backups ageing).

Possible further question, not decided: what am I paying for and not using (FinOps). The cost rules
and `keeper report finance` already exist.

## Problems to solve

1. **Discovery.** Keeper only scans systems added by hand or found through another system (AD
   computers, cloud inventories). Nothing finds what has an IP and is in no inventory, or reconciles
   the network against AD, cloud and SCCM. Related: `docs/ENGINE-ROADMAP.md` stage 6 (Network).
   What the owner wants (2026-10-23):
   - Several discovery mechanisms feeding one inventory: DNS, the AD scanner, and scanning IP ranges.
   - Smart and configurable. A finding from one mechanism can widen another: when DNS shows a
     specific IP, the range around it is scanned too.
   - Identification of what answers by its management protocols (SSH, WinRM, RPC, and so on).
   - Every device can be stale: the inventory has to say when something was last seen, and how it was
     seen, rather than treat a DNS or AD record as proof that the device exists.
   Owner's idea was nmap as a plugin. Decided (owner, 2026-10-23): no nmap. Keeper's rule is that it
   never starts another program (README, ENGINE-ROADMAP) and nmap's licence restricts
   redistribution, so Keeper gets its own standalone scanner, with fewer features than nmap
   (roadmap stage 6 already plans in-process probes and SNMP v3). Reading nmap's XML output stays
   possible as an import, as in Crimson `net`, but is not the plan.
   An inventory file (owner): every asset Keeper has found, with how responsive each system is, per
   scan: which protocols and ports answered, how fast, last seen, and the history of that. *(Guess at
   what it gives: a system that used to answer and stopped is a "broken" finding; one that never
   answers on its management protocols is a blind spot; a flapping one points at a network cause.)*
   Two files (owner): a **targets** file (what to scan) and an **inventory** file (what was found
   and how it responded). Two modes: *free* (Keeper is allowed to look for machines itself) and
   *manual* (it scans only what the targets file lists). A switch ignores the inventory history for
   a clean run. Why the inventory file exists, by the owner's
   example: a machine that AD or DNS lists but that does not answer on the first, second and third
   attempt can be declared not existing, without waiting for a fourth. The number three and the
   timing are only an example, not a rule; the owner says it does not matter. *(My suggestion: make
   the number of attempts a setting. A powered-off laptop or a blocked port looks the same as a
   machine that is gone, so the result should be a state such as "not answering" or "likely gone",
   not a deletion, and an AD or DNS record with nothing behind it is itself a finding.)*
   SNMP is part of it (owner). Roadmap stage 6 already plans v3 read-only (GET, GETNEXT, GETBULK).
   *(Guess at what it adds: name, description and uptime, which shows reboots; interfaces; ARP and
   MAC tables and CDP/LLDP neighbours, which find more devices; printer status and supplies.)* Decided (owner): Keeper is generic, so
   what exists at the owner's site is not the yardstick; it must handle what customers have. *(My
   reading: v3 first, v2c supported but off unless chosen, with a warning that community strings
   cross the network in clear text, and an SNMP device that only speaks v2c reported as a finding.)*
   Open: whether the file is only an export of what Keeper stores (it keeps history in SQLite), or
   also something the owner edits or imports, for example to declare known assets by hand.
   Note: Crimson `web` already vendors discovery tools (`dnsx`, `subfinder`, `httpx`, `masscan`) and
   Rikto has a DNS-footprint `--expand` option; their relevance is not yet assessed.
2. **Certificates at 100%.** One inventory of every certificate: probed from the network and read
   from inside each system (IIS bindings, certificate stores, ACM, private CA, Entra, devices), then
   reconciled. Certificates seen on the network but in no known system, and the reverse, are findings.
   Software that keeps certificates in files and config, not a store, counts too: nginx
   (`ssl_certificate` per server block), Apache, HAProxy, Tomcat, mail servers, and so on. This needs
   a way to read Linux hosts (see items 9 and 11); IIS is the Windows counterpart.
3. **Marketplace and purchased services.** What was bought (for example AWS Marketplace) and when to
   look at renewal. Today marketplace agreements are only a hand-filled register, and AWS Marketplace
   agreements are on the AWS backlog.
4. **Coverage per product.** Packs cover what someone thought of, not the whole product. Examples:
   no IIS rules at all; VMware has Tools version but no ESXi version or licence rule found.
   Open: what counts as 100% for a product (vendor hardening guide, CIS, or the owner's list).
5. **Exposure in the ranking.** Ranking is deadlines, severity, age. Exposure is missing. Open: what
   the owner means by it (internet-reachable, or reachable from many internal machines).
6. **Devices.** No integration for firewalls, switches or printers. Crimson `device` reads Cisco and
   Junos configs from files, with no live collector.
7. **Logs: collect, then say what is wrong network-wide.** Owner's words: not a syslog, "collect logs
   and tell me what the common wide network issues are". Collected during the scan, analysed across
   machines, reported weekly. Two kinds of result: security patterns over the last 7 days (repeated
   failures on one account, one source across many accounts, failures then success; not single
   failures), and wide issues (the same error or event on many machines or devices, which points at a
   shared cause such as a DC, a switch, a DNS server or a bad policy). Health events are already read
   per host; no rule reads the Security log, and no rule groups the same event across hosts. The event
   runner caps rows per host. Sources beyond Windows event logs (firewalls, switches, Linux) are
   undecided.
8. **Devices attached to workstations.** A USB printer (or other USB peripheral) has no IP address, so
   network discovery never sees it. It can only be inventoried by reading the workstation it is plugged
   into. Today only network printers added by WSD and removable-storage policy are checked.
9. **Non-Microsoft infrastructure.** The owner wants it covered, Google Cloud among it. Today: Google
   Cloud has 167 rules but reads only Cloud Asset Inventory (no Workspace/Cloud Identity, Security
   Command Center, Cloud SQL users, VM patch state). There are no rules for Linux or Unix hosts, and
   no SSH runner. Network devices have none; `docs/ENGINE-ROADMAP.md` stage 6 plans probes, SNMP v3
   and config text but is unbuilt. Crimson `os` has Linux and macOS packs and `device` has
   Cisco/Junos parsers, not yet compared against what Keeper would need. Named by the owner as
   the focus: firewalls, Cisco, VMware, "etc". VMware already has a rule file (59 rules) with known
   gaps (no ESXi version or licence rule found). Firewall vendors in use (owner): Fortinet and Check Point. Others are
   "the common ones" with no names given. Crimson `device` already recognizes Check Point but
   refuses to parse it until a real redacted export exists; it has no Fortinet support. Open:
   the order, and whether real config exports can be provided.
10. **More ticketing and task systems.** `keeper push` opens tickets only in ServiceNow and monday.com.
    Owner wants Jira and the other commonly used systems. *(Guess at the list: Jira, Azure DevOps
    Boards, Asana, ClickUp, Trello, Freshservice, Zendesk, ManageEngine ServiceDesk Plus; the owner
    has named only Jira.)* Open: which others, and whether state comes back (it does today:
    "ticket state back").
11. **Linux and macOS support, both ways.** Owner: "we want support for linux as well", "and macos".
    Confirmed by the owner: both, Keeper running on them and scanning their hosts. Today Keeper's
    secrets use Windows DPAPI and the build is PowerShell-driven; the README allows an osx-arm64 build
    (unsigned, needs codesign) and does not mention Linux. Scanning Linux hosts is covered under
    item 9; scanning macOS hosts is not listed anywhere yet.
12. **Graphical interface.** Owner: missing, and not raised earlier. Today `keeper ui` writes one
    self-contained HTML page (no server, data embedded, read-only: overview, findings with their
    objects, correct, could not check; filter, copy, CSV). There is no interactive application: no
    running scans, no decisions (snooze, accept, delegate), no setup, no integrations, no users or
    roles. Open: what the interface must let the owner do, and for whom.
    Owner, 2026-10-23: user management is low priority for now, but it will need integrations with
    existing identity systems *(guess at which: Entra ID, Okta, AD/LDAP, through SAML or OpenID
    Connect single sign-on; not named by the owner)*.
13. **Environment assumptions.** English default AD group names, Microsoft-heavy, Windows-first,
   tickets to ServiceNow and monday only. No scan has run on a live system yet.

## Release intent

The owner wants to release Keeper later, maybe as open source, and wants it to be sellable: inclusive
across platforms and vendors, so for integrations (ticketing, firewalls, clouds) the common, widely
used systems come first. Open: open source, sold, or both (not discussed). Consequences to settle:
- Environment assumptions (item 13) become blockers rather than footnotes.
- Anything bundled or started must allow redistribution (nmap's licence restricts it).
- Per the owner, Keeper was written with the owner's own resources (a private Claude account and a
  private GitHub account) and only tested at the workplace, where the same pain is assumed to be
  shared by others. The employment contract has not been checked. The GitHub repo is currently listed
  as public.

## What stands between Keeper and a sellable, must-have product

The assistant's honest assessment (2026-10-23), combined with an independent read by Opus of the
code. Items marked *(guess)* are judgement, not verified.

Blockers: nobody will use it without these.
1. **Proof on a live system.** Never run live; rules have no behavioural tests; the 716-rule
   `windows-baseline` pack was machine-generated and its own header admits that every host fails
   one rule of each CLIENT/SERVER pair.
2. **Legal.** Public repo with no LICENSE file; employment contract unchecked; rule ids use CIS
   numbering and CIS Benchmarks are licensed non-commercially *(guess: needs checking)*.
3. **Runs on Linux and macOS.** The vault works only on Windows; CIM and registry access are
   Windows-only.

What makes it a product, not a tool.
4. **A real application,** not a static HTML page: users and roles, scheduling, service mode, and
   multi-tenant for service providers (see item 12 above).
5. **Discovery,** because coverage cannot be claimed over a network Keeper does not know.
6. **A coverage measure** per product against a stated yardstick (item 4 above).
7. **Trust.** Least-privilege permissions documented per integration, signed builds, an SBOM, an
   encrypted store, an external security test, and the contradiction between `SECURITY.md` (one
   process per system) and `ARCHITECTURE.md` (one process for all) resolved.
8. **Operations.** Install, upgrade, a feed for rule updates, documentation, support. Rule
   maintenance never ends.

What makes it mandatory.
9. **An outside reason to need it** *(guess)*: audits and frameworks (ISO 27001, SOC 2, NIS2, cyber
   insurance). Keeper already has an evidence pack, and shortening certificate lifespans give a
   deadline.
10. **Integrations:** Jira and the common ticketing systems, SIEM export, single sign-on.
11. **Ranking by exposure and by whether a flaw is being exploited,** since competitors do it.
12. **Community rules** *(guess)*.

From a second opinion (Gemini, pasted by the owner), checked against the code on 2026-10-23.
13. **Exact fixes, not advice.** Every rule has a `fix:` field (3,543), but it is prose; few are a
    runnable PowerShell or CLI command, or the exact GPO change. 500 open findings without a
    concrete fix is work handed to the admin, not a solution.
14. **Easy and trusted first run.** A CISO must be able to try an unknown tool with access to AD and
    cloud. Nothing exists yet: no Terraform or CloudFormation template that creates a clearly
    read-only role, no container image. `keeper setup` has a dry run.
15. **Scale and API throttling.** The HTTP and AWS runners already retry on 429 and 503 and honour
    `Retry-After`. Not verified for Graph/M365 at 50,000-user scale; never tried on a large estate.
16. **A view for management.** `keeper report trends` already compares now with 30 and 90 days ago
    (fixed vs new, sparklines), and findings store when they were resolved. No mean-time-to-fix
    figure and no "risks closed this month" summary found. Needed to justify the purchase and the
    renewal.

The assistant's order *(guess)*: items 14, 13 and 16 first; 15 only when a large real environment
shows a problem. A live run on a real network (item 1) comes before all of them.

Honest limit: "mandatory in every environment" has not been achieved by any product, and not by a
single builder. The realistic target is mandatory in one segment (for example IT teams of 200 to
5,000 users on a hybrid Microsoft estate), then expansion. Logs, USB peripherals, firewalls and
FinOps increase the work without moving toward a first sale *(assistant's view; the owner has not
agreed)*.

## Decisions so far

- Language: C#. Rust (rewrite or merge with Crimson) is parked; revisit only if an endpoint agent is
  wanted or Keeper and Crimson are merged (owner, 2026-10-23).
- Remote scanning only, no agent on the machines (owner, 2026-10-23).
- Licence and prices are decided after the product is shown to work (owner, 2026-10-23).
- Keeper and Crimson are two separate products (owner, 2026-10-23): Keeper is reporting; Crimson is
  continuous tracking and management. Not yet settled: Keeper today already keeps findings history
  and decisions, so where the line falls between "reporting" and "tracking" is open, and so is
  whether the certificate and FinOps products belong to Crimson (their folders sit there now).
- Proposed split into four parts: engine, rules, interface, plugins. What a plugin may do (collect
  only, or also tickets, discovery, reports) is open.
- Two kinds of extension (owner, 2026-10-23): **plugins** add a system (a collector such as Fortinet
  or Check Point, or a notifier such as Jira) and use the existing engine; **modules** are further
  engines on the same core (certificate tool, FinOps) with their own data model and analysis. Rules
  stay data (YAML), plugins and modules are code (C#). Open: whether a module may add its own
  screens and tables or only findings to the core. The assistant's suggested order *(guess)*: core,
  then the certificate module, FinOps last.
- Certificates become a **separate, standalone product** that integrates with Keeper, instead of a
  Keeper module (owner, 2026-10-23). Generic: works on Windows, Linux and a third system the owner
  named unclearly *(assumed macOS)*. It would find and track certificates, alert, manage them, issue
  certificates signed by itself (*my reading: self-signed or from its own internal CA*), replace
  them, and go to outside providers such as GoDaddy to buy or renew through them. Consequences
  noted by the assistant: it needs write access (deploying a certificate, reloading a service) and
  money and key handling, which Keeper deliberately does not, so the two have separate trust
  boundaries, and Keeper's read-only claim stays intact. Certificate discovery would live in one
  product, with the other consuming it. The ACME protocol is the likely common way to talk to
  providers; whether GoDaddy supports it was not checked. Item 2 above (certificates at 100%) moves
  to that product. It competes with Venafi, Keyfactor and DigiCert, and may itself be the wedge.
  The certificate product also covers **code signing** (owner): signing scripts (for example
  PowerShell, for environments that only run signed scripts), and *(my extension, to confirm)*
  signing executables and packages, and Keeper's own builds. Code-signing keys are far more
  sensitive than server certificates: a stolen one signs malware as the owner. As I recall, public
  CAs now require code-signing private keys to sit on hardware (not checked), so this implies
  hardware or cloud key vaults, approvals and an audit log of every signature.
  Owner, asked what to sign first: "Linux". *(My reading, to confirm: Linux signing comes first.
  Unlike Windows Authenticode, Linux has no single standard: GPG signatures for scripts and
  files, signed rpm and deb packages and repositories, container image signatures such as cosign,
  and kernel module or Secure Boot signing.)*
- FinOps goes the same way as certificates (owner, 2026-10-23): a **standalone product** covering the
  big clouds (Amazon, Google, Microsoft), integrated with Keeper. Keeper itself gets a basic **cost
  module** at default level: "not really FinOps", just things like "the Amazon account costs $1000
  today". *(My reading: the same free-versus-paid split as certificates, with the basic view free in
  Keeper and the full FinOps product paid; to confirm.)* Today Keeper has cost-category rules
  (waste and licences) but its AWS backlog lists Budgets and CUR/Data Exports as not read, so spend
  amounts are not read yet *(from the backlog, not verified in code)*. Replaces the earlier open
  question of whether FinOps is a fourth question, a report or a module.
- The certificate product in one line (owner): a product that answers every certificate need.
  Needs, as the assistant groups them: discover and inventory; monitor and alert; issue (public
  providers, own CA); renew; deploy and replace; buy and renew through providers; sign code and
  scripts; audit trail; integrate with Keeper. The assistant's suggested build order *(guess)*:
  read-only first (discover, inventory, alert), then renewal, then deployment, then signing, so
  trust is earned before write access is asked for. "Every need" is the scope of Venafi and
  Keyfactor, which are large companies.
- Third module (owner, 2026-10-23): **repair advisor.** For each finding, how to fix it: the exact
  command, GPO change or console steps (item 13). Decided by the owner: the advisor only recommends;
  nothing is applied and Keeper stays read-only towards systems. (Crimson `os` already writes one
  reviewable script per finding with an impact verdict, which is a possible model for the output.)

## Priority order (owner, 2026-10-23)

Already there: rules, scanning and reports.
1. **The scanner** (discovery, the standalone one that replaces nmap).
2. **The engine running with the rules**, on top of that scanner.
3. **Extensions:** the interface, management and users.
4. **Later:** separate tools such as the certificate product and FinOps.
5. **Then:** expand to Linux and macOS (running on them and scanning them, item 11). The owner did
   not say whether this comes before or after step 4.

The assistant's note *(guess)*: step 2 is where the rules first meet a real network, so it should
include measuring and removing noisy rules (see "What stands between", item 1). The scanner's TLS
probing in step 1 is also the groundwork the certificate product would build on. Since Linux and
macOS come later, the scanner written in step 1 should not tie itself to Windows-only calls where a
portable one exists, so that step 5 does not mean a rewrite.

## Not goals

- Live or continuous detection.
- Repair. Keeper stays read-only towards systems *(Crimson's `os` has repair; not proposed here)*.

## Open

- Relationship to Crimson (`net`, `os`, `directory`, `device`): not decided.
- Whether FinOps is a fourth question or a separate report.
