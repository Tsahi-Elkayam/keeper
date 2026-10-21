# Engine roadmap

What the engine still needs so that rules can be written for every product in the catalogue
(`docs/proposals/catalog-*.md`, `docs/backlog/*.md`). Rows = old-catalogue checks each gap blocks.
Everything runs in-process: no external program is ever started (no aws.exe, snmpwalk or PowerShell
modules). Each stage is built, reviewed independently and fixed until a review finds nothing serious.

## Build order

1. **HTTP read core** (~260 rows; most later stages build on it)
   - Read-only POST/PUT: the integration type carries an allow-list of verb + path pattern and of body
     command names; anything else is refused, the way GraphQL mutations are. Paging inside the body.
   - XML response bodies (the file runner's XML-to-object code).
   - Paging styles: ARM `nextLink`, `nextPageKey`, cursors. Response shapes: a map as rows, string arrays
     kept. Response headers as fields. Quoted path segments (`@odata.type`). Graph `Prefer` header.
   - http targets (a list of URLs), `for_each` from a list or threshold, `for_each` placeholders in
     params, 404 as empty, an environment label on the integration.
   - Thresholds in requests (`{DAYS_AGO:threshold.x|90}`), macros in GraphQL documents.
2. **Condition language** (built): count per group / distinct / share; same-element array conditions
   (min/max over an array is `element` with `match: all`); operators `version-*`, ISO 8601 durations,
   epoch and named date formats (`format:` ole, unix, custom), `in-cidr`, `hour-in` on the organisation's
   clock, `sid-in` with well-known names and RIDs, `changed` against the last clean read (`_new`,
   `_previous`); constant deadline, masked fields, overrides with an end date; two-level `for_each`.
3. **Microsoft APIs on other token audiences** (~330; built, never run against a tenant): one integration
   type per API with its own token resource and hosts - Power Platform (admin, Apps, Automate, API),
   Dataverse, Power BI, Defender for Endpoint, Cloud Apps, Key Vault (a path allow-list: metadata only);
   Exchange Online and Purview through the REST endpoint the modules call, `Get-*` cmdlets only.
4. **AWS** (~377; built, never run against an account): SigV4 signed by hand (no SDK), checked against
   AWS's signing test suite; an access key, STS AssumeRole into each account's read-only role; Query/XML,
   JSON, REST-JSON and REST-XML (S3 bucket settings, never objects); accounts x regions; only reads, with
   an explicit deny list (GetObject, GetSecretValue, GetParameter(s), GetPasswordData, token issuers);
   billed APIs daily. Not yet: IAM Roles Anywhere (X.509 sign-in), S3 buckets in other regions than asked.
5. **Windows reads** (~200): security descriptors (LDAP with the SD-flags control, NTFS and share ACLs);
   SMB/SYSVOL file reads and a GPO parser (registry.pol, GptTmpl.inf, audit.csv, GPP with cpassword
   masked); LDAP binary attributes and per-DC reads; registry binary values and the machine certificate
   store; SQL per-database loop and allow-listed read procedures; cim/eventlog extensions.
6. **Network** (~230): probes (tcp, http, ssh banner, ntp) and config text first; then dns (DnsClient),
   snmp v3 GET/GETNEXT/GETBULK only (Lextm.SharpSnmpLib), tls extensions (BouncyCastle).
7. **Other auth kinds and types** (~330): jwt-bearer service accounts (GCP, Google Admin), HMAC-signed
   requests (Duo, AnyDesk), and named vendor types with allowed hosts (each checked against the vendor).
8. **SOAP** (134): vSphere and unified communications, allow-listed read methods only.

## Not built
- Hosting PowerShell in the process (EDR flags it as unmanaged PowerShell): REST, CIM, registry, SMB or
  an attestation instead.
- SharePoint admin REST (needs Sites.FullControl.All) and the Teams module endpoint: the ScubaGear import.
- CA API / CA database over DCOM: the CA's registry and event log through the existing runners.
- Performance sampling, DHCP discover probes, user RSoP: other tools, or low value.
- Graph export jobs and CloudWatch `StartQuery`: they create server-side jobs, so they count as writes.
- Vendor config exports and offline rulebase analysis: imported through the file runner.
