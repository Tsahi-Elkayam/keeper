# Proposals - certificates, registers, obligations and imported tools

What Keeper should check next in `rules/certificates.yaml` (TLS-), `rules/domain-controller-certificates.yaml`
(DC-), `rules/registers.yaml` (REG-), `rules/obligations.yaml` (OBL-), `rules/pingcastle.yaml` (PC-),
`rules/maester.yaml`, `rules/scubagear.yaml` and `rules/prowler.yaml`. Nothing here is written as a rule
yet: each entry is a spec for whoever writes the YAML. Ids were checked against every id in `rules\`
(none collide). Every store draft was written against the real schema (`Migrations/001-review.sql`,
`002-registers.sql`); every file/tls draft against the runner code (`TlsRunner.cs`, `FileRunner.cs`,
`Evaluator.cs`).

Confidence: **verified** = the row field or table and the engine behaviour were read in the code or the
schema; **likely** = the tool's documented output or a standard says so but the exact element was not
confirmed in a real file; **guess** = plausible, must be tried on a real file before shipping.

Facts about the engine that the entries rely on (all verified in code):

- A TLS row carries: `endpoint, host, port, subject, issuer, notBefore, notAfter, daysLeft, serial,
  thumbprint, keyAlgorithm, keySize, signatureAlgorithm, protocol, cipherSuite, chainValid, nameMatches,
  chainErrors, selfSigned, sans, eku`. `protocol` is .NET `SslProtocols` text (`Tls`, `Tls11`, `Tls12`,
  `Tls13`); `cipherSuite` is .NET `TlsCipherSuite` text (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384` ...); `chainErrors` is the comma-joined `X509ChainStatusFlags` names;
  `sans` is an array of DNS names only; `eku` is an array of OIDs (empty array when the extension is
  absent).
- `contains` / `notcontains` on an array compare whole elements, case-insensitive; on text they are
  substring matches. `empty` on an array is "zero elements". `match` on an array fires if any element
  matches. A missing field is n/a, never a pass.
- `threshold:` replaces `value` with the setting `threshold.<name>` when set - including a regular
  expression for `match` / `notmatch` (REG-KEY-PAYMENT-DUE already does this). A rule whose default
  pattern can never fail (`.` with `notmatch`) is "off until the tenant sets the pattern": the way to
  express expected-issuer checks without per-target labels.
- Store rules: one SELECT/WITH, `:now` (ISO) and `:today` (yyyy-MM-dd) bound, read-only. `julianday()`
  accepts both the register dates (`yyyy-MM-dd`) and the ISO `updated_at` / `recorded_at` text.
  `updated_at` can also be judged by the evaluator (`age-gt`) without SQL arithmetic.
- Rules with identical `query` text share one read. Adding a column to a shared query changes its
  fingerprint; keep every copy identical or give the new rule its own query (one extra read, harmless).
- `count: { op, value, where }` on a file rule counts rows of the newest file: a must-exist check over an
  imported report is one finding for the whole system.
- Findings are keyed `sha256(instance|check|target)`: two failing rows with the same `key` collapse into
  one finding. PROWLER-REPORT-STALE uses this; confirm the scanner does not refuse duplicate keys first.

Links used throughout: RFC 5280 <https://www.rfc-editor.org/rfc/rfc5280>; CA/Browser Forum Baseline
Requirements <https://cabforum.org/working-groups/server/baseline-requirements/documents/>; NIST SP 800-53
r5 <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>; NIST SP 800-52 r2
<https://csrc.nist.gov/pubs/sp/800/52/r2/final>; CIS Controls v8 <https://www.cisecurity.org/controls/v8>;
.NET `X509ChainStatusFlags`
<https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509chainstatusflags>;
.NET `TlsCipherSuite` <https://learn.microsoft.com/dotnet/api/system.net.security.tlsciphersuite>; LDAPS
certificate requirements
<https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority>;
PingCastle <https://www.pingcastle.com/documentation/>; Maester <https://maester.dev/docs/>; ScubaGear
<https://github.com/cisagov/ScubaGear>; Prowler <https://docs.prowler.com/>.

---

## Priority 1 - highest value, mechanics verified

### Certificates on TLS endpoints (`certificates.yaml`)

**TLS-EKU-NO-SERVER-AUTH**
- Catches: a certificate served on a TLS endpoint whose extended key usage does not allow server
  authentication. Browsers and Schannel refuse it; the service "works" only for clients that do not
  validate. Usually a certificate issued from the wrong template (client, code-signing, a CA template).
- Severity: high.
- Source: `certificates.yaml`, `tls`, fields `eku`, `subject`, `issuer`, `endpoint`. Existing shared
  query (`{ protocol: tls, key: endpoint, name: subject }`) already returns them.
- Condition: `eku` is not empty AND `eku` notcontains `1.3.6.1.5.5.7.3.1` (server authentication) AND
  `eku` notcontains `2.5.29.37.0` (any purpose). An empty EKU means "any purpose" under RFC 5280 and is
  TLS-EKU-MISSING's job, so it is excluded here to avoid double reporting.
- Refs: `RFC-5280:4.2.1.12`, `CABF-BR:7.1.2.7.10`, `NIST-800-53:SC-17`.
- Fix: reissue from a template (or CA profile) that includes Server Authentication; on an AD CS CA use
  the Web Server or Kerberos Authentication template; replace the certificate everywhere it is bound.
- Confidence: verified (row field, array semantics); the CA/B section number is likely
  (<https://cabforum.org/working-groups/server/baseline-requirements/documents/>).

**TLS-ISSUER-UNEXPECTED**
- Catches: a certificate issued by a CA the organisation did not expect - a TLS-inspecting proxy in the
  path (certificate-pinned agents then fail silently), a rogue or test CA, or a public CA on an internal
  name. TLS-CHAIN-UNTRUSTED-ROOT misses an inspection CA that the scan host trusts.
- Severity: high.
- Source: `certificates.yaml`, `tls`, fields `issuer`, `subject`, `endpoint`, `thumbprint`. Existing query.
- Condition: `issuer` notmatch pattern, `value: '.'`, `threshold: tls.expected-issuer-pattern`. With the
  default `.` nothing fails; the tenant sets `threshold.tls.expected-issuer-pattern` to a regular
  expression naming its own CAs and the public CAs it buys from (per tls integration, since a lab
  integration has its own override). Document in the rule comment that the rule is dormant until set.
- Refs: `NIST-800-53:SC-17`, `NIST-800-53:SC-8`, `CIS-Controls-v8:3.10`.
- Fix: identify the issuer in the evidence; if it is an inspection proxy, exempt the pinned agents' and
  the service's destinations from inspection; if it is an unknown CA, treat as an incident and replace.
- Confidence: verified (threshold-on-regex is used by REG-KEY-PAYMENT-DUE). Closes the backlog item
  "TLS interception" for the per-integration case; per-target patterns stay an engine gap.

**TLS-CHAIN-WEAK-SIGNATURE**
- Catches: a chain in which an intermediate or root carries a signature the platform rates as weak
  (`HasWeakSignature`, typically SHA-1 or MD5 on an intermediate) while the leaf itself is SHA-256, so
  TLS-WEAK-SIGNATURE passes and clients still reject the chain.
- Severity: high.
- Source: `certificates.yaml`, `tls`, field `chainErrors`. Existing query.
- Condition: `chainErrors` contains `HasWeakSignature`. Add `notcontains HasWeakSignature` to
  TLS-CHAIN-INVALID's exclusions so the generic rule stops reporting the same endpoint.
- Refs: `NIST-SP-800-131A`, `RFC-5280:4.1.1.2`, `NIST-800-53:SC-17`.
- Fix: install the issuer's current intermediate (CAs re-signed their intermediates with SHA-256 years
  ago); if the issuing CA itself still signs with SHA-1, reissue the leaf from a current CA.
- Confidence: verified (flag name from .NET docs; chainErrors join in `TlsRunner.Row`).

**TLS-CHAIN-NOT-VALID-FOR-USAGE**
- Catches: the platform's chain engine found a key usage or EKU that does not allow this use
  (`NotValidForUsage`) - the leaf, or a CA above it, is constrained to another purpose. Complements
  TLS-EKU-NO-SERVER-AUTH, which reads the leaf only.
- Severity: high.
- Source: `certificates.yaml`, `tls`, field `chainErrors`. Existing query.
- Condition: `chainErrors` contains `NotValidForUsage`. Exclude it from TLS-CHAIN-INVALID as above.
- Refs: `RFC-5280:4.2.1.3`, `RFC-5280:4.2.1.12`, `NIST-800-53:SC-17`.
- Fix: read which certificate in the chain is constrained (evidence shows issuer); reissue from a CA whose
  EKU constraints include server authentication, or fix the subordinate CA's certificate.
- Confidence: verified (flag name).

### Domain controller certificates (`domain-controller-certificates.yaml`)

The three DC- rules run over every DC on port 636 with their own targets, so the TLS- hygiene rules in
`certificates.yaml` never see domain controllers. The DC pack needs its own copies of the checks that
matter for Kerberos and LDAPS.

**DC-CERT-NO-SERVER-AUTH-EKU**
- Catches: a DC certificate without Server Authentication (`1.3.6.1.5.5.7.3.1`). Schannel will not pick
  it for LDAPS, so the DC answers 636 with another certificate or none, and LDAPS clients that validate
  fail. Microsoft's LDAPS requirements list this EKU explicitly.
- Severity: high.
- Source: `domain-controller-certificates.yaml`, `tls` port 636, field `eku`. Existing DC query.
- Condition: `eku` notcontains `1.3.6.1.5.5.7.3.1` AND `eku` notcontains `2.5.29.37.0`.
- Refs: `NIST-800-53:SC-17`, `NIST-800-53:SC-8`, `MS-PKCA`.
- Fix: enrol from the Kerberos Authentication template (Server Authentication, Client Authentication,
  Smart Card Logon, KDC Authentication), then remove the old certificate so Schannel cannot choose it.
- Confidence: verified (row field; Microsoft LDAPS doc:
  <https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority>).

**DC-CERT-LEGACY-PROTOCOL**
- Catches: a domain controller that negotiates TLS 1.0 or 1.1 (or SSL 3) on 636. The same Schannel
  settings serve RDP, WinRM over HTTPS and every other service on the DC, so this is the whole DC's
  protocol policy, not just LDAPS.
- Severity: high.
- Source: DC file, `tls` port 636, fields `protocol`, `cipherSuite`. Existing DC query.
- Condition: `protocol` in `[Ssl2, Ssl3, Tls, Tls11]`.
- Refs: `RFC-8996`, `NIST-SP-800-52r2`, `CIS-Controls-v8:3.10`.
- Fix: disable TLS 1.0/1.1 server-side in Schannel on the DCs (group policy or registry), enable TLS 1.2
  and 1.3, and find the client that still needed them from the DC's Schannel event log first.
- Confidence: verified (same mechanics as TLS-LEGACY-PROTOCOL).

**DC-CERT-WEAK-KEY-OR-SIGNATURE**
- Catches: a DC certificate with an RSA key below 2048 bits or a SHA-1/MD5 signature. Old
  "Domain Controller" (v1) template certificates are often still in use on DCs promoted years ago.
- Severity: high.
- Source: DC file, `tls` port 636, fields `keyAlgorithm`, `keySize`, `signatureAlgorithm`.
- Condition: any of: (`keyAlgorithm` match `^RSA` AND `keySize` lt 2048, threshold
  `tls.min-rsa-key-bits`); `signatureAlgorithm` match `^(md2|md4|md5|sha1)`.
- Refs: `NIST-SP-800-131A`, `NIST-800-53:SC-17`.
- Fix: supersede the Domain Controller template with Kerberos Authentication (2048-bit minimum, SHA-256),
  re-enrol every DC, remove the old certificates.
- Confidence: verified.

### Registers (`registers.yaml`)

**REG-VEN-REJECTED-WITH-AGREEMENT**
- Catches: a vendor marked `rejected` that still has a current contract or licence - either the
  organisation is still paying a vendor it decided to drop, or the vendor still holds access and data
  while everybody believes the relationship ended.
- Severity: high.
- Source: `registers.yaml`, `store`. New shared query for non-confirmed vendors (also used by
  REG-VEN-CANDIDATE-STALE):
  ```sql
  SELECT v.vendor_id, v.name, v.state, v.updated_at,
         (SELECT COUNT(*) FROM contract c
           WHERE c.vendor_id = v.vendor_id
             AND COALESCE(c.decision, '') <> 'end'
             AND COALESCE(NULLIF(TRIM(c.end_on), ''), '9999-12-31') >= :today) AS current_contracts,
         (SELECT COUNT(*) FROM licence l
           WHERE l.vendor_id = v.vendor_id
             AND COALESCE(NULLIF(TRIM(l.expires_on), ''), '9999-12-31') >= :today) AS current_licences
  FROM vendor v
  WHERE v.state <> 'confirmed'
  ```
  `key: vendor_id`, `name: name`.
- Condition: `state` eq `rejected` AND (`current_contracts` gt 0 OR `current_licences` gt 0).
- Refs: `NIST-800-53:SA-9`, `NIST-800-53:PS-7`, `CIS-Controls-v8:15.7`.
- Fix: end the agreements (record `decision: end`, let the licence lapse), remove the vendor's accounts
  and access, confirm data return or destruction - or, if the rejection was wrong, set the vendor back to
  `confirmed` with a note.
- Confidence: verified (schema).

**REG-LIC-SYSTEM-INACTIVE**
- Catches: a current licence tied to a system marked inactive in the system register - paying for a
  retired system (shelfware nobody will ever reclaim because the system is gone).
- Severity: medium.
- Source: `store`. The shared licence query plus two columns (update every copy identically or give this
  rule its own query): add `LEFT JOIN system s ON s.system_id = l.system_id` and select
  `s.active AS system_active, s.name AS system_name`.
- Condition: `system_active` eq 0 AND (`expires_on` absent OR `days_left` ge 0).
- Refs: `NIST-800-53:CM-10`, `NIST-800-53:SA-4`.
- Fix: cancel at the next term (or now, if the terms allow), or move the licence to the system that
  really uses it. If the system is not retired, set it active again.
- Confidence: verified (schema: `system.active`).

**REG-CON-SYSTEM-INACTIVE**
- Catches: a current contract for an inactive system - support or subscription paid for something
  switched off.
- Severity: medium.
- Source: `store`. The shared contract query plus `LEFT JOIN system s ON s.system_id = c.system_id` and
  `s.active AS system_active, s.name AS system_name`.
- Condition: `system_active` eq 0 AND `decision` ne `end` AND (`end_on` absent OR `days_left` ge 0).
- Refs: `NIST-800-53:SA-4`, `NIST-800-53:SA-9`.
- Fix: record `decision: end` and give notice, or reassign the contract to the live system.
- Confidence: verified.

**REG-LIC-AUTORENEW-SHORT-NOTICE**
- Catches: an auto-renewing licence whose `notice_days` is shorter than the cancellation window vendors
  usually require (30-90 days before term). By the time REG-LIC-AUTORENEW-DUE fires, the right to cancel
  or cut seats has already passed - the register warns too late by construction.
- Severity: medium.
- Source: `store`, shared licence query (fields `auto_renews`, `notice_days`, `expires_on`, `days_left`).
- Condition: `auto_renews` eq 1 AND `notice_days` lt 45 (threshold `registers.min-autorenew-notice-days`)
  AND (`expires_on` absent OR `days_left` ge 0).
- Refs: `NIST-800-53:CM-10`, `NIST-800-53:SA-4`.
- Fix: read the cancellation clause and set `notice_days` to that window plus the time a decision takes
  (typically 90). If the licence can be cancelled any time, write that in notes and keep the short
  notice.
- Confidence: verified.

**REG-CON-NOTICE-TOO-SHORT**
- Catches: a contract whose `notice_days` is 0 or shorter than the termination-notice period such
  agreements carry. The schema defaults to 90, so a short value was typed deliberately or copied from a
  renewal-date reminder; either way the decision date it computes is too late.
- Severity: medium.
- Source: `store`, shared contract query (`notice_days`, `end_on`, `days_left`, `decision`).
- Condition: `notice_days` lt 30 (threshold `registers.min-contract-notice-days`) AND `decision` ne
  `end` AND (`end_on` absent OR `days_left` ge 0).
- Refs: `NIST-800-53:SA-4`.
- Fix: set `notice_days` to the contractual termination notice plus the procurement lead time.
- Confidence: verified.

**REG-INI-STALE**
- Catches: an approved or in-progress saving initiative nobody has touched for two months. "Approved"
  work that stops moving is the promised saving that never arrives on the bill.
- Severity: medium.
- Source: `store`. New shared initiative query (all REG-INI- rules):
  ```sql
  SELECT i.initiative_id, i.title, i.status,
         NULLIF(TRIM(i.owner), '') AS owner,
         COALESCE(NULLIF(TRIM(i.owner), ''), 'nobody') AS owner_shown,
         i.saving_monthly, i.currency,
         COALESCE(i.measured, 'not measured') AS measured,
         NULLIF(TRIM(i.notes), '') AS notes,
         i.updated_by, i.updated_at,
         CAST(julianday(:now) - julianday(i.updated_at) AS INTEGER) AS days_since_update
  FROM initiative i
  ```
  `key: initiative_id`, `name: title`.
- Condition: `status` in `[approved, in-progress]` AND `days_since_update` gt 60 (threshold
  `registers.initiative-stale-days`).
- Refs: `NIST-800-53:PM-3`, `NIST-800-53:SA-2`.
- Fix: the owner updates status and notes (what was done, what blocks it), or the initiative is dropped
  with the reason so the saving is removed from the forecast.
- Confidence: verified (schema; `updated_at` is ISO text, `julianday` reads it; if the store writes a
  format `julianday` returns NULL for, the row is n/a - the evaluator's `age-gt` on `updated_at` is the
  safer alternative). Closes backlog "Initiative register has no rules yet".

**REG-INI-NO-OWNER**
- Catches: an approved or in-progress initiative with no owner - a saving everyone agreed to and nobody
  is doing.
- Severity: medium.
- Source: `store`, shared initiative query.
- Condition: `status` in `[approved, in-progress]` AND `owner` absent.
- Refs: `NIST-800-53:PM-3`.
- Fix: name the person who delivers it; otherwise drop it.
- Confidence: verified.

**REG-INI-DONE-ESTIMATE-ONLY**
- Catches: an initiative marked done whose saving is still an estimate (or unmeasured) - reported as
  achieved to management without the bill proving it.
- Severity: low.
- Source: `store`, shared initiative query.
- Condition: `status` eq `done` AND `measured` ne `bill`.
- Refs: `NIST-800-53:PM-3`, `NIST-800-53:SA-2`.
- Fix: compare the invoice before and after, set `saving_monthly` to the measured figure and `measured`
  to `bill`; if the saving did not materialise, say so in notes.
- Confidence: verified.

### Obligations (`obligations.yaml`)

All obligation rules below use the existing template (one row per attested target, plus a `-` row when
never attested; fails when the latest attestation is not `na` and there is no `yes` with `done_on` inside
the interval; `due_on` computed from the setting `threshold.obligations.<id>.interval-days` with the
default as fallback). Substitute `{{ID}}`, `{{TITLE}}`, `{{DEFAULT}}` into the SQL of
OBL-BACKUP-RESTORE-TEST exactly; the condition is `latest_state ne na AND (last_done absent OR last_done
age-gt {{DEFAULT}} threshold obligations.{{ID}}.interval-days)`; `deadline: due_on`; evidence
`"{title} ({item}): {status_text}; was due {due_on}. Latest attestation: {latest_state}"`. Add each new id
to the severity maps of OBL-ATTESTATION-EXPIRED and OBL-ATTESTED-NO where the severity is not medium.
Confidence for every obligation is **verified** for the mechanics (the template runs in the shipped-rules
test) and **likely** for the interval defaults (taken from CIS Controls v8 safeguard wording and NIST
800-53 control frequencies, both linked above).

**OBL-IAM-USER-ACCESS-REVIEW** - obligation `iam.user-access-review`, default 180 days, target = an
application, share or group.
- Catches: nobody has recertified who can access what (beyond the privileged groups
  OBL-IAM-PRIVILEGED-ACCESS-RECERTIFICATION covers): shares, applications, mailbox delegations, cloud
  roles below admin. Access only ever accumulates.
- Severity: medium. Refs: `NIST-800-53:AC-2(3)`, `NIST-800-53:AC-6(7)`, `CIS-Controls-v8:6.1`,
  `CIS-Controls-v8:6.2`, `ISO-27001:A.5.18`.
- Fix: each owner confirms every member or permission on their system, removals are applied, then attest
  with the system as target.

**OBL-IR-EXERCISE** - `ir.exercise`, default 365 days, target `-` or a scenario.
- Catches: the incident-response plan has never been rehearsed (tabletop or live). The first ransomware
  afternoon is the wrong time to learn who declares, who isolates, who calls whom.
- Severity: high. Refs: `NIST-800-53:IR-3`, `NIST-800-53:IR-4`, `CIS-Controls-v8:17.7`, `ISO-27001:A.5.24`.
- Fix: run a tabletop with IT, management and communications on a realistic scenario, record the gaps
  as findings, update the plan, attest.

**OBL-VULN-SCAN-INTERNAL** - `vuln.scan-internal`, default 90 days, target `-` or a network.
- Catches: no authenticated vulnerability scan of internal assets inside the interval - patch compliance
  reports show what the patch tool knows, not what is exposed.
- Severity: medium. Refs: `NIST-800-53:RA-5`, `CIS-Controls-v8:7.5`, `ISO-27001:A.8.8`.
- Fix: run the scanner (authenticated) over every internal subnet, triage criticals, attest with the
  report as evidence.

**OBL-VULN-SCAN-EXTERNAL** - `vuln.scan-external`, default 30 days, target `-`.
- Catches: the internet-facing surface (published services, VPN, mail, remote access) has not been
  scanned from outside inside the interval.
- Severity: high. Refs: `NIST-800-53:RA-5`, `CIS-Controls-v8:7.6`, `ISO-27001:A.8.8`.
- Fix: scan every public address and DNS name from outside, compare with the known inventory
  (unexpected open services are findings in themselves), attest.

**OBL-NET-FIREWALL-RULE-REVIEW** - `net.firewall-rule-review`, default 180 days, target = a firewall
or security zone.
- Catches: rule bases that only grow: temporary "any" rules, vendor remote-access holes, rules for
  systems that no longer exist. Nobody reads them unless a review forces it.
- Severity: medium. Refs: `NIST-800-53:SC-7`, `NIST-800-53:CM-7(1)`, `CIS-Controls-v8:4.4`,
  `CIS-Controls-v8:13.4`, `ISO-27001:A.8.20`.
- Fix: export the rule base, mark every rule with its owner and purpose, remove unused and over-broad
  ones (hit counters help), attest with the firewall as target.

**OBL-LOG-REVIEW** - `log.review`, default 7 days, target `-` or a log source.
- Catches: nobody looked at security logs or SIEM alerts this week. Collected-but-unread logs satisfy
  no auditor and catch no attacker.
- Severity: medium. Refs: `NIST-800-53:AU-6`, `CIS-Controls-v8:8.11`, `ISO-27001:A.8.15`.
- Fix: a named person reviews the week's alerts and the top anomalies, records what was followed up,
  attests. If a SOC does this, attest `na` per log source with the service as evidence.

**OBL-PATCH-COMPLIANCE-REVIEW** - `patch.compliance-review`, default 30 days, target = an estate
(servers, workstations, network devices, appliances).
- Catches: no monthly look at patch compliance across the estate - the devices the patch tool does not
  manage (appliances, hypervisors, network gear, the servers that fail every month) stay unpatched for
  years because the dashboard looks green for the managed ones.
- Severity: medium. Refs: `NIST-800-53:SI-2`, `NIST-800-53:SI-2(2)`, `CIS-Controls-v8:7.3`,
  `CIS-Controls-v8:7.4`, `ISO-27001:A.8.8`.
- Fix: list every device class, its patch source and its compliance figure; chase the persistent
  failures; attest per estate.

**OBL-SEC-AWARENESS-TRAINING** - `sec.awareness-training`, default 365 days, target `-`.
- Catches: no awareness training or phishing exercise for staff inside the year.
- Severity: low. Refs: `NIST-800-53:AT-2`, `NIST-800-53:AT-2(3)`, `CIS-Controls-v8:14.1`,
  `CIS-Controls-v8:14.2`, `ISO-27001:A.6.3`.
- Fix: run the annual programme (or a phishing simulation with follow-up), keep completion figures as
  evidence, attest.

**OBL-BCP-REVIEW** - `bcp.review`, default 365 days, target `-` or a critical system.
- Catches: the business continuity plan (which systems first, what manual fallback, who decides) has not
  been reviewed. DR drills (OBL-DR-DRILL) test the technical restore; this tests whether the plan still
  matches the organisation.
- Severity: medium. Refs: `NIST-800-53:CP-2`, `NIST-800-53:CP-2(1)`, `CIS-Controls-v8:11.1`,
  `ISO-27001:A.5.29`, `ISO-27001:A.5.30`.
- Fix: walk the plan with the business owners of the critical systems, update contacts, priorities and
  recovery targets, attest.

**OBL-BACKUP-OFFLINE-COPY-VERIFIED** - `backup.offline-copy-verified`, default 30 days, target = a
backup system or protected system.
- Catches: nobody confirmed this month that an immutable or offline copy of the backups exists and is
  current. Ransomware deletes the online copies first; a backup job that "succeeds" to a share the
  attacker can reach is not a backup.
- Severity: high. Refs: `NIST-800-53:CP-9`, `NIST-800-53:CP-9(8)`, `NIST-800-53:CP-6`,
  `CIS-Controls-v8:11.4`, `ISO-27001:A.8.13`.
- Fix: check the immutability lock or the offline media rotation, the age of the newest offline point,
  and that the credentials to delete it are not the ones the backup server uses; attest.

**OBL-IAM-BREAK-GLASS-TEST** - `iam.break-glass-test`, default 90 days, target = a directory or tenant.
- Catches: the emergency admin accounts (cloud tenant, directory, hypervisor, firewall) have not been
  signed in with and verified recently. They are excluded from conditional access and MFA by design, so
  a wrong password, an expired credential or a policy drift is found only during the outage.
- Severity: high. Refs: `NIST-800-53:AC-2`, `NIST-800-53:CP-2`, `CIS-Controls-v8:5.4`,
  `ISO-27001:A.5.16`.
- Fix: sign in with each emergency account from the documented location, confirm the sign-in alert
  fired, rotate the credential if the procedure says so, attest with the tenant as target. (Microsoft's
  guidance for emergency access accounts suggests this cadence:
  <https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access>.)

**OBL-ATTESTED-NA-NO-EXPIRY**
- Catches: an obligation excused for ever: the latest attestation is `na` and has no `expires_on`.
  "Does not apply" was true the day it was written; nothing ever asks again.
- Severity: medium.
- Source: `store`, the existing shared latest_attestation query (OBL-ATTESTATION-EXPIRED).
- Condition: `state` eq `na` AND `expires_on` absent.
- Refs: `NIST-800-53:CA-7`, `NIST-800-53:PL-2`.
- Fix: re-record the `na` with an `expires_on` (a year at most) so the exemption is re-confirmed.
- Confidence: verified.

**OBL-ATTESTATION-UNKNOWN-ID**
- Catches: an attestation whose obligation id matches no obligation rule - a misspelt id proves nothing
  and the real obligation stays "never done" while the person believes it is recorded.
- Severity: low.
- Source: `store`:
  ```sql
  SELECT la.obligation, la.target,
         CASE WHEN la.target = '-' THEN la.obligation ELSE la.obligation || '@' || la.target END AS item,
         la.state, la.actor, la.recorded_at
  FROM latest_attestation la
  WHERE la.obligation NOT IN (
    'ad.krbtgt-rotation', 'ad.dsrm-password-rotation', 'ad.system-state-backup', 'ad.forest-recovery-test',
    'iam.privileged-access-recertification', 'ad.gpo-backup', 'iam.stale-account-cleanup',
    'pki.certificate-inventory-review', 'backup.restore-test', 'dr.drill', 'licence.review',
    'iam.vendor-access-review', 'security.penetration-test', 'keeper.deep-review', 'change.code-review'
    /* plus every obligation added from this document */)
  ```
  `key: item`, `name: obligation`, `each: any`.
- Refs: `NIST-800-53:CA-7`.
- Fix: re-record under the right id (`keeper-rules list --system obligations` shows them); keep the list
  in this query in step with the file. Stopgap for the backlog's "no obligation catalogue".
- Confidence: verified.

### Imported tools

**PC-KRBTGT-AGE**
- Catches: PingCastle's report says the krbtgt password is older than the rotation interval - machine
  proof for OBL-AD-KRBTGT-ROTATION, independent of what people attest.
- Severity: high.
- Source: `pingcastle.yaml`, `file` xml, `items: /HealthcheckData/KrbtgtLastChangeDate`, `key: _file`,
  field `_text`.
- Condition: `_text` age-gt 180, threshold `obligations.ad.krbtgt-rotation.interval-days` (the same
  setting the obligation uses, so one number governs both).
- Refs: `NIST-800-53:IA-5`, `MITRE-ATTACK:T1558.001`.
- Fix: rotate krbtgt twice with replication in between, re-run PingCastle, attest the obligation.
- Confidence: likely (element name from the PingCastle health-check data model; verify on a real XML).

**PC-SCORE-STALE-OBJECTS**, **PC-SCORE-PRIVILEGED**, **PC-SCORE-TRUSTS**, **PC-SCORE-ANOMALIES** (one
entry, four ids)
- Catches: a category score above target. PC-GLOBAL-SCORE is the worst category only; a domain at 30
  overall can hide a privileged-accounts category at 30 and three others at 0 - or four at 30. Per
  category the trend is visible and each can carry its own target.
- Severity: by `_text` ranges as PC-GLOBAL-SCORE.
- Source: `file` xml, `items: /HealthcheckData/StaleObjectsScore`, `/HealthcheckData/PrivilegiedGroupScore`
  (PingCastle's own spelling), `/HealthcheckData/TrustScore`, `/HealthcheckData/AnomalyScore`;
  `key: _file`, field `_text`.
- Condition: `_text` gt 25, thresholds `pingcastle.max-stale-score`, `pingcastle.max-privileged-score`,
  `pingcastle.max-trust-score`, `pingcastle.max-anomaly-score`.
- Refs: `PingCastle:score`, `NIST-800-53:CA-7`.
- Fix: work the category's highest-point rules (findings of the PC- rules), re-run, replace the XML.
- Confidence: likely (element names; `PrivilegiedGroupScore` spelling must be checked on a real file).

**SCUBA-PRODUCT-NOT-SCANNED** (family: one rule per product - AAD, DEFENDER, EXO, SHAREPOINT, TEAMS,
POWERPLATFORM)
- Catches: the newest ScubaGear run did not include a product, so every control of that product silently
  dropped out of the findings - a run with `-ProductNames aad` only looks like "no mail problems".
- Severity: medium.
- Source: `scubagear.yaml`, `file` csv `scubagear/ScubaResults*.csv`, field `Control ID`.
- Condition: `count: { op: lt, value: 1, where: { field: Control ID, op: match, value: '^MS\.EXO\.' } }`
  (and `^MS\.AAD\.`, `^MS\.DEFENDER\.`, `^MS\.SHAREPOINT\.`, `^MS\.TEAMS\.`, `^MS\.POWERPLATFORM\.`).
  A product the tenant does not license is disabled by override on that one rule.
- Refs: `NIST-800-53:CA-7`, `NIST-800-53:CA-2`.
- Fix: run `Invoke-SCuBA` with every licensed product in `-ProductNames`, copy the CSV and JSON in.
- Confidence: verified for the mechanics (`count.where` on a file rule is one finding for the system;
  the `Control ID` field is already used by SCUBA-FAILED); the control-id prefixes are likely
  (ScubaGear baseline ids are `MS.<PRODUCT>.<n>.<n>v<n>`).

**PROWLER-MANUAL**
- Catches: checks Prowler could not decide (`status_code: MANUAL`) - they need a person and are
  otherwise invisible: the report shows neither pass nor fail.
- Severity: low.
- Source: `prowler.yaml`, `file` json `prowler/*.ocsf.json`, fields `status_code`, `metadata.event_code`,
  `finding_info.title`, `status_detail`, `resources[].uid`. Existing Prowler query.
- Condition: `status_code` eq `MANUAL`. `emit.check: PROWLER-{metadata.event_code}`, title from
  `finding_info.title`.
- Refs: `NIST-800-53:CA-7`.
- Fix: do the manual check the detail describes, then mute it in Prowler's mutelist with the reason and
  a review date (it arrives as Suppressed and stops being reported). Closes the backlog's "Prowler MANUAL
  checks are not surfaced".
- Confidence: verified (the value is listed in the file's own header comment and Prowler's docs:
  <https://docs.prowler.com/>).

---

## Priority 2 - real value, one assumption each

### Certificates on TLS endpoints

**TLS-EKU-MISSING**
- Catches: a certificate with no extended key usage at all. RFC 5280 reads that as "any purpose", but
  public CAs must include it and current root programmes reject server certificates without
  `serverAuth`; an internal CA template that omits it will fail in browsers at some update.
- Severity: low (medium when the issuer is public - not expressible without an issuer pattern).
- Source: `tls`, field `eku`. Existing query.
- Condition: `eku` empty.
- Refs: `RFC-5280:4.2.1.12`, `CABF-BR:7.1.2.7.10`.
- Fix: add Server Authentication to the template or CA profile and reissue.
- Confidence: verified for the row (`TlsAndLdapTests` shows `eku` is `[]` without the extension); the
  root-programme requirement is likely (<https://googlechrome.github.io/chromerootprogram/>).

**TLS-EKU-OVERBROAD**
- Catches: a server certificate that also allows purposes a web server never needs - any purpose
  (`2.5.29.37.0`), code signing (`1.3.6.1.5.5.7.3.3`), OCSP signing (`1.3.6.1.5.5.7.3.9`), time stamping
  (`1.3.6.1.5.5.7.3.8`). A stolen web-server key then signs software or revocation answers.
- Severity: medium.
- Source: `tls`, field `eku`. Existing query.
- Condition: `eku` contains any of the four OIDs (an `any:` of four `contains` leaves).
- Refs: `RFC-5280:4.2.1.12`, `CABF-BR:7.1.2.7.10`, `NIST-800-53:SC-12`.
- Fix: reissue with Server Authentication (and Client Authentication only where the host really acts as
  a client); fix the template.
- Confidence: verified (row and array semantics); the CA/B prohibition of anyExtendedKeyUsage in
  subscriber certificates is likely.

**TLS-CHAIN-EXPLICIT-DISTRUST**
- Catches: a chain ending in a root the platform has explicitly distrusted (`ExplicitDistrust`) - a CA
  removed from trust stores after a compliance failure. Clients already reject it; the rule says why.
- Severity: high.
- Source: `tls`, field `chainErrors`. Existing query.
- Condition: `chainErrors` contains `ExplicitDistrust`; exclude from TLS-CHAIN-INVALID.
- Refs: `NIST-800-53:SC-17`.
- Fix: buy from another CA and replace.
- Confidence: verified (flag name); how often Windows sets it for public roots is likely.

**TLS-CIPHER-NOT-AEAD**
- Catches: a TLS 1.2 connection that settled on a CBC suite with an HMAC (padding-oracle class of
  attacks, SHA-1 MACs) although the endpoint is otherwise modern. TLS-WEAK-CIPHER covers only the broken
  suites; this covers the merely obsolete ones NIST says to prefer against.
- Severity: low.
- Source: `tls`, fields `cipherSuite`, `protocol`. Existing query.
- Condition: `protocol` eq `Tls12` AND `cipherSuite` notmatch `(_GCM_|_CCM|CHACHA20_POLY1305)`.
- Refs: `NIST-SP-800-52r2`, `RFC-7525`.
- Fix: order the server's suite list to prefer AES-GCM and ChaCha20-Poly1305 with ECDHE; enable TLS 1.3.
- Confidence: verified (suite names from the .NET enum).

**TLS-SERIAL-SHORT**
- Catches: a certificate serial number with fewer than 64 bits - a CA that numbers certificates
  sequentially or with a small counter. Public CAs must use at least 64 random bits (this is what made
  hash-collision forgeries practical against CAs that did not); on a private CA it marks an old or
  home-made issuing setup.
- Severity: low.
- Source: `tls`, field `serial` (hex text). Existing query.
- Condition: `serial` match `^0*[0-9A-Fa-f]{1,15}$` (15 hex digits or fewer after leading zeros = under
  64 bits).
- Refs: `CABF-BR:7.1`, `RFC-5280:4.1.2.2`.
- Fix: nothing to fix on the endpoint; raise it with whoever runs the issuing CA (or the vendor).
- Confidence: verified for the row; the regex should be checked against a serial with a leading `00`
  that .NET keeps.

### Domain controller certificates

**DC-CERT-NO-SAN**
- Catches: a DC certificate without a DNS subject alternative name. LDAPS and KDC validation match the
  DC's FQDN against the SAN; certificates from a hand-made request carry the name in the CN only and
  fail on strict clients (and on every current browser-based LDAP admin tool).
- Severity: medium.
- Source: DC file, `tls` port 636, field `sans`.
- Condition: `sans` empty.
- Refs: `RFC-9525`, `NIST-800-53:SC-17`.
- Fix: enrol from the Kerberos Authentication template (it builds the SAN from the DC's DNS name).
- Confidence: verified.

**DC-CERT-ISSUER-UNEXPECTED**
- Catches: a DC certificate from a CA other than the enterprise CA - a public CA (the DC's private key
  under someone else's lifecycle), a decommissioned CA, or an unknown one.
- Severity: medium.
- Source: DC file, `tls` port 636, field `issuer`.
- Condition: `issuer` notmatch `.`, threshold `dc.expected-issuer-pattern` (dormant until set).
- Refs: `NIST-800-53:SC-17`, `NIST-800-53:IA-5(2)`.
- Fix: reissue from the enterprise CA; investigate how the other certificate got there.
- Confidence: verified (mechanics as TLS-ISSUER-UNEXPECTED).

### Registers

**REG-KEY-NOTICE-TOO-SHORT**
- Catches: a key date of a kind that needs lead time (certificate, licence, renewal, contract, report)
  with `notice_days` under a week - the warning arrives when nothing can be done in time.
- Severity: low.
- Source: `store`, the shared key_date query without the kind filter (REG-KEY-DATE-PASSED's).
- Condition: `kind` in `[certificate, licence, renewal, contract, report]` AND `notice_days` lt 14
  (threshold `registers.min-key-date-notice-days`) AND `days_left` ge 0.
- Refs: `NIST-800-53:SA-4`, `NIST-800-53:SC-17`.
- Fix: set `notice_days` to the time the renewal really takes (certificates: at least 30).
- Confidence: verified.

**REG-LIC-COST-UNKNOWN**
- Catches: a current licence with no cost recorded. Every REG-LIC- rule treats an unknown cost as
  "paid", but the budget forecast and the "what do we spend on this vendor" question are blind to it.
- Severity: low.
- Source: `store`, shared licence query (`cost`, `expires_on`, `days_left`, `notes`).
- Condition: `cost` absent AND (`expires_on` absent OR `days_left` ge 0) AND `notes` notmatch
  `\b(free|open source|included|bundled)\b`.
- Refs: `NIST-800-53:CM-10`, `NIST-800-53:SA-2`.
- Fix: record cost and currency per term from the order; for a free product set cost 0.
- Confidence: verified.

**REG-LIC-USAGE-STALE**
- Catches: a licence whose row (and therefore `seats_used`) has not been updated in a quarter. Cap and
  waste rules then judge old numbers; a cap hit or a shelfware finding on stale data is a guess.
- Severity: low.
- Source: `store`, shared licence query plus `l.updated_at` (and `l.updated_by`).
- Condition: `seats` gt 0 AND `seats_used` exists AND `updated_at` age-gt 90 (threshold
  `registers.licence-usage-max-age-days`) AND (`expires_on` absent OR `days_left` ge 0).
- Refs: `NIST-800-53:CM-10`.
- Fix: read the current usage from the vendor console and update `seats_used` (the row's `updated_at`
  moves with it). Engine gap: there is no per-field as-of date, so the whole row's age stands in.
- Confidence: verified.

**REG-VEN-REFERENCE-DANGLING**
- Catches: a contract or licence whose `vendor_id` points at no vendor row - the vendor was removed, or
  the id was typed differently, and every vendor-level rule (sensitive, sole, rejected) skips it.
- Severity: low.
- Source: `store`:
  ```sql
  SELECT 'contract:' || c.contract_id AS item, 'contract' AS register, c.title AS title, c.vendor_id
  FROM contract c
  WHERE NULLIF(TRIM(c.vendor_id), '') IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM vendor v WHERE v.vendor_id = c.vendor_id)
  UNION ALL
  SELECT 'licence:' || l.licence_id, 'licence', l.product, l.vendor_id
  FROM licence l
  WHERE NULLIF(TRIM(l.vendor_id), '') IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM vendor v WHERE v.vendor_id = l.vendor_id)
  ```
  `key: item`, `name: title`, `each: any`.
- Refs: `NIST-800-53:SA-9`.
- Fix: create the vendor row or correct the id.
- Confidence: likely - the schema declares the foreign key, and if the store opens with
  `PRAGMA foreign_keys = ON` the condition can never occur (then the rule is a harmless safety net);
  check `Database.cs` before shipping.

**REG-VEN-UNCLASSIFIED**
- Catches: a confirmed vendor with a current agreement, `sensitive` left at its default 0 and no
  `data_handled` text - nobody ever decided whether this vendor handles data. The default is not a
  classification; REG-VEN-SENSITIVE-* rules all skip it.
- Severity: low.
- Source: `store`, the existing confirmed-vendor shared query (fields `sensitive`, `data_handled`,
  `current_contracts`, `current_licences`).
- Condition: `sensitive` eq 0 AND `data_handled` absent AND (`current_contracts` gt 0 OR
  `current_licences` gt 0).
- Refs: `NIST-800-53:SA-9`, `NIST-800-53:RA-2`, `CIS-Controls-v8:15.1`, `ISO-27001:A.5.19`.
- Fix: write in `data_handled` what the vendor touches (or "none - on-premises software, no access"),
  and set `sensitive` when it is personal, financial, health or privileged access.
- Confidence: verified.

**REG-VEN-NO-SLA**
- Catches: a confirmed vendor with a current contract and no SLA recorded (REG-VEN-SOLE-NO-SLA covers
  sole vendors only). During an outage the agreed response time is the only lever, and it has to be on
  record to be used.
- Severity: low.
- Source: `store`, confirmed-vendor shared query (`sla`, `sole_vendor`, `current_contracts`).
- Condition: `sole_vendor` eq 0 AND `sla` absent AND `current_contracts` gt 0.
- Refs: `NIST-800-53:SA-9`, `ISO-27001:A.5.20`.
- Fix: copy the support terms (hours, response, resolution, escalation) into `sla`; if there are none,
  write "none" so it is a known gap rather than a missing field.
- Confidence: verified.

**REG-VEN-ROW-STALE**
- Catches: a confirmed vendor with current agreements whose register row has not been touched in a year.
  Contacts, SLA, data handled and the security review are all a year or more old.
- Severity: low.
- Source: `store`, confirmed-vendor shared query plus `v.updated_at`.
- Condition: `updated_at` age-gt 365 (threshold `registers.vendor-row-max-age-days`) AND
  (`current_contracts` gt 0 OR `current_licences` gt 0).
- Refs: `NIST-800-53:SA-9`, `CIS-Controls-v8:15.1`.
- Fix: confirm the row's fields with the vendor contact and save it (an unchanged save still refreshes
  `updated_at`).
- Confidence: verified.

**REG-SYS-CRITICAL-NO-AGREEMENT**
- Catches: a system of criticality 1 (the organisation stops) with no current contract and no licence
  in the registers - either support for the most important system is unrecorded, or it is running on
  goodwill.
- Severity: medium.
- Source: `store`:
  ```sql
  SELECT s.system_id, s.name, s.criticality, s.team, s.owner, s.owner_person,
         (SELECT COUNT(*) FROM contract c
           WHERE c.system_id = s.system_id
             AND COALESCE(c.decision, '') <> 'end'
             AND COALESCE(NULLIF(TRIM(c.end_on), ''), '9999-12-31') >= :today) AS current_contracts,
         (SELECT COUNT(*) FROM licence l
           WHERE l.system_id = s.system_id
             AND COALESCE(NULLIF(TRIM(l.expires_on), ''), '9999-12-31') >= :today) AS current_licences
  FROM system s
  WHERE s.active = 1 AND s.system_id NOT IN ('KEEPER', 'ORG', 'UNMAPPED')
  ```
  `key: system_id`, `name: name`.
- Condition: `criticality` eq 1 AND `current_contracts` eq 0 AND `current_licences` eq 0.
- Refs: `NIST-800-53:SA-9`, `NIST-800-53:CP-2`, `ISO-27001:A.5.20`.
- Fix: record the support agreement; for an in-house system write a contract row titled "internal - no
  vendor" with the team as owner so the check is answered, not silenced.
- Confidence: verified (schema: `system.criticality`, `system.active`).

**REG-INI-NO-SAVING**
- Catches: an approved or in-progress initiative with no `saving_monthly` - effort committed to a saving
  nobody sized.
- Severity: low.
- Source: `store`, shared initiative query.
- Condition: `status` in `[approved, in-progress]` AND `saving_monthly` absent.
- Refs: `NIST-800-53:SA-2`, `NIST-800-53:PM-3`.
- Fix: estimate it from the bill lines it affects, record it with `measured: estimate`.
- Confidence: verified.

**REG-INI-PROPOSED-STALE**
- Catches: a proposal nobody decided on in a quarter.
- Severity: low.
- Source: `store`, shared initiative query.
- Condition: `status` eq `proposed` AND `days_since_update` gt 90 (threshold
  `registers.initiative-decision-days`).
- Refs: `NIST-800-53:PM-3`.
- Fix: approve or drop it; a dropped one keeps the reason in notes.
- Confidence: verified.

### Obligations

**OBL-GOV-POLICY-REVIEW** - `gov.policy-review`, default 365 days, target = a policy document.
- Catches: security policies (acceptable use, access control, backup, incident response ...) not
  reviewed inside the year - every NIST -1 control and ISO 27001 ask for a documented review cadence.
- Severity: low. Refs: `NIST-800-53:PL-1`, `NIST-800-53:AC-1`, `NIST-800-53:IR-1`, `ISO-27001:A.5.1`.
- Fix: review and re-approve each policy, record the version and approver as evidence, attest per
  document.

**OBL-IAM-SERVICE-ACCOUNT-REVIEW** - `iam.service-account-review`, default 180 days, target = a
directory or platform.
- Catches: service and automation accounts not inventoried and reviewed: owner, purpose, last use,
  password age, whether a gMSA or managed identity could replace them. Scans see the age; only a review
  decides what still needs to exist.
- Severity: medium. Refs: `NIST-800-53:AC-2`, `NIST-800-53:IA-5`, `CIS-Controls-v8:5.1`,
  `CIS-Controls-v8:5.6`, `ISO-27001:A.5.16`.
- Fix: list them, confirm each with an owner, disable the rest, rotate or migrate the survivors, attest.

**OBL-ASSET-INVENTORY-REVIEW** - `asset.inventory-review`, default 180 days, target `-` or a site.
- Catches: the hardware and software inventory has not been reconciled with what the network sees
  (discovery scan, DHCP, directory) inside the interval. Unknown devices are unpatched devices.
- Severity: medium. Refs: `NIST-800-53:CM-8`, `NIST-800-53:CM-8(3)`, `CIS-Controls-v8:1.1`,
  `CIS-Controls-v8:2.1`, `ISO-27001:A.5.9`.
- Fix: diff the inventory against discovery, classify the unknowns, attest.

**OBL-PKI-CA-KEY-BACKUP** - `pki.ca-key-backup`, default 90 days, target = a CA.
- Catches: no verified backup of the CA (database, private key, configuration) inside the interval. A
  lost CA key means every issued certificate is unrenewable and revocation stops.
- Severity: high. Refs: `NIST-800-53:CP-9`, `NIST-800-53:SC-12(1)`, `NIST-800-53:SC-17`.
- Fix: back up the CA (key, database, registry configuration) to offline storage with the key password
  in the vault, attest with the CA as target.

**OBL-PKI-CA-RESTORE-TEST** - `pki.ca-restore-test`, default 365 days, target = a CA.
- Catches: the CA backup has never been restored to a test host. An untested CA backup is the same hope
  as any other untested backup, with the whole PKI riding on it.
- Severity: medium. Refs: `NIST-800-53:CP-4`, `NIST-800-53:CP-10`, `NIST-800-53:SC-17`.
- Fix: restore to an isolated machine, issue a test certificate, publish a test CRL, attest.

**OBL-PKI-TEMPLATE-REVIEW** - `pki.template-review`, default 180 days, target = a CA.
- Catches: certificate templates not reviewed: enrolment permissions, "supply in request" subjects,
  dangerous EKU combinations, weak key sizes - the misconfigurations behind the well-known AD CS
  escalation paths.
- Severity: high. Refs: `NIST-800-53:SC-17`, `NIST-800-53:AC-6`, `MITRE-ATTACK:T1649`, `ADCS:ESC1`.
- Fix: review every published template against the escalation checklist, unpublish or fix, attest.

**OBL-PKI-CA-ACCESS-REVIEW** - `pki.ca-access-review`, default 180 days, target = a CA.
- Catches: who can manage the CA, issue certificates, and administer the CA host has not been
  recertified. CA administrators can mint credentials for anyone.
- Severity: medium. Refs: `NIST-800-53:AC-2`, `NIST-800-53:AC-6(7)`, `NIST-800-53:SC-17`,
  `CIS-Controls-v8:6.8`.
- Fix: confirm CA roles (administrator, certificate manager, local administrators of the CA host, backup
  operators), remove the rest, attest.

**OBL-ATTESTATION-EVIDENCE-THIN**
- Catches: a `yes` attestation whose evidence text is a word or two ("done", "ok") - it satisfies the
  rule and no auditor.
- Severity: low.
- Source: `store`, the shared latest_attestation query plus `LENGTH(TRIM(la.evidence)) AS evidence_length`.
- Condition: `state` eq `yes` AND `evidence_length` lt 20 (threshold `obligations.min-evidence-chars`).
- Refs: `NIST-800-53:CA-7`, `NIST-800-53:AU-6`.
- Fix: re-record with what was done, where the proof lives (ticket, report path, screenshot) and who
  witnessed it.
- Confidence: verified.

### Imported tools

**PC-FUNCTIONAL-LEVEL-OLD**
- Catches: a domain functional level below Windows Server 2016 (level 7). Below it the domain cannot use
  the newer Kerberos protections (armoring, authentication policies and silos) and still permits
  behaviours those levels removed.
- Severity: medium.
- Source: `pingcastle.yaml`, `file` xml, `items: /HealthcheckData/DomainFunctionalLevel`, `key: _file`,
  field `_text` (an integer: 0 = 2000 ... 7 = 2016).
- Condition: `_text` lt 7, threshold `pingcastle.min-functional-level`.
- Refs: `NIST-800-53:CM-6`, `NIST-800-53:SA-22`.
- Fix: retire the last DC of the older version, raise the domain (then forest) functional level.
- Confidence: likely (element name and the level-number mapping; check on a real file).

**MAESTER-VERSION-OUTDATED**
- Catches: the Maester module that produced the results is behind the published version - new tests
  (and fixes to false results) are missing from every run until it is updated.
- Severity: low.
- Source: `maester.yaml`, `file` json `maester/TestResults-*.json`, no `items` (the root object is the
  row), `key: _file`, fields `CurrentVersion`, `LatestVersion`, `ExecutedAt`, `TenantId`.
- Condition: `CurrentVersion` ne `LatestVersion` (both present; `LatestVersion` is absent when the run
  had no internet, which gives n/a - correct).
- Refs: `NIST-800-53:SI-2`, `NIST-800-53:CA-7`.
- Fix: `Update-Module Maester`, run again. Also: MAESTER-REPORT-STALE should judge `ExecutedAt` from
  this root row instead of the file's `_modified` (copying the file resets the modified time).
- Confidence: likely (field names from Maester's results JSON; <https://maester.dev/docs/>).

**SCUBA-OMITTED**
- Catches: controls omitted through ScubaGear's configuration (accepted risks). They vanish from the
  Fail list; this keeps them visible as an accepted-risk list so each is re-confirmed, not forgotten.
- Severity: info.
- Source: `scubagear.yaml`, `file` csv, fields `Control ID`, `Requirement`, `Result`, `Details`.
  Existing query.
- Condition: `Result` eq `Omitted`. `emit.check: SCUBA-{Control ID}`.
- Refs: `NIST-800-53:CA-5`, `NIST-800-53:RA-7`.
- Fix: keep the omission's rationale and expiry in the ScubaGear config; when it expires, re-decide. In
  Keeper, an `exception` override on the emitted check carries the decision.
- Confidence: verified for the mechanics; the `Omitted` result word is likely
  (<https://github.com/cisagov/ScubaGear>). Closes the backlog's "ScubaGear omissions".

**SCUBA-MANUAL-CHECK**
- Catches: controls ScubaGear cannot test (`Criticality` ending in `Not-Implemented` or `3rd Party`):
  they are policy or third-party checks a person must do, and the CSV marks them N/A so they look
  satisfied.
- Severity: info.
- Source: `scubagear.yaml`, `file` csv, fields `Control ID`, `Requirement`, `Criticality`, `Result`.
- Condition: `Criticality` match `(Not-Implemented|3rd Party)`.
- Refs: `NIST-800-53:CA-7`.
- Fix: check each one by hand (or the third-party product's own report); record it as an attestation
  (`obligation m365.manual-control`, target = the control id) so the evidence exists.
- Confidence: likely (the criticality wording is in the file's own header comment).

**PROWLER-MUTED-HIGH**
- Catches: a critical or high check that is muted (`status: Suppressed`). Muting hides it from
  PROWLER-FAILED for ever; an accepted critical risk should stay on the accepted-risk list.
- Severity: info.
- Source: `prowler.yaml`, `file` json, fields `status`, `status_code`, `severity`, `metadata.event_code`.
  Existing query.
- Condition: `status` eq `Suppressed` AND `status_code` eq `FAIL` AND `severity` in `[Critical, High]`.
- Refs: `NIST-800-53:CA-5`, `NIST-800-53:RA-7`.
- Fix: confirm the mute still has a reason and an owner; if not, unmute and fix.
- Confidence: verified (fields in the file's header comment).

**PROWLER-REPORT-STALE**
- Catches: the newest Prowler output is older than the interval - no cloud posture data for a month
  looks exactly like a clean account.
- Severity: medium.
- Source: `prowler.yaml`, `file` json, `key: cloud.account.uid`, field `time_dt` (OCSF event time, ISO)
  or `finding_info.created_time_dt`.
- Condition: `time_dt` age-gt 35, threshold `prowler.max-report-age-days`. Every row of a stale file
  fails; with `key: cloud.account.uid` they collapse into one finding per account (finding key =
  instance|check|target).
- Refs: `NIST-800-53:CA-7`, `CIS-Controls-v8:7.5`.
- Fix: schedule Prowler and copy each run's `.ocsf.json` in.
- Confidence: likely - `time_dt` is in Prowler's OCSF output (<https://docs.prowler.com/>), and the
  collapse of same-key rows must be confirmed in the scanner before relying on it. Closes the backlog's
  "Prowler has no stale-report rule" without an engine change.

---

## Priority 3 - useful, lower value or needs the tenant to decide

**TLS-SAN-INTERNAL-NAME**
- Catches: a certificate carrying an unqualified host name or a reserved suffix (`.local`, `.internal`,
  `.corp`, `.lan`, `.home`, `.intranet`) - public CAs may not issue these, and on internal CAs they show
  a certificate that will never match the FQDN clients use.
- Severity: low. Source: `tls`, field `sans`. Condition: `sans` match
  `(^[^.]+$|\.(local|localdomain|internal|corp|lan|home|intranet|private)$)`.
- Refs: `CABF-BR:7.1.2.7.12`, `RFC-6762`. Fix: reissue with the FQDN; retire short-name access paths.
- Confidence: verified for the row; the value depends on how many internal names the tenant uses -
  make it `info` if it is noisy.

**TLS-PROTOCOL-NO-TLS13**
- Catches: an endpoint that negotiates TLS 1.2 although the scan host offers 1.3 - the service or
  appliance has not enabled TLS 1.3 yet.
- Severity: info. Source: `tls`, field `protocol`. Condition: `protocol` eq `Tls12`.
- Refs: `NIST-SP-800-52r2`, `RFC-8446`. Fix: enable TLS 1.3 on the service.
- Confidence: guess - the result depends on the scan host's own TLS stack (the backlog says so); ship
  only on a host known to offer 1.3, and never as more than info.

**REG-CON-NO-VALUE**
- Catches: a current contract with no value recorded - the spend-per-vendor and the budget forecast are
  incomplete.
- Severity: low. Source: `store`, shared contract query. Condition: `value` absent AND `decision` ne
  `end` AND (`end_on` absent OR `days_left` ge 0).
- Refs: `NIST-800-53:SA-2`. Fix: record the annual value and currency from the signed contract.
- Confidence: verified.

**REG-VEN-CANDIDATE-STALE**
- Catches: a vendor in `candidate` state for more than a quarter - an evaluation nobody finished, or a
  vendor already in use that was never confirmed (and so never gets a security review).
- Severity: low. Source: `store`, the non-confirmed-vendor query above. Condition: `state` eq `candidate`
  AND `updated_at` age-gt 90 (threshold `registers.vendor-decision-days`) OR (`state` eq `candidate` AND
  (`current_contracts` gt 0 OR `current_licences` gt 0)).
- Refs: `NIST-800-53:SA-9`, `CIS-Controls-v8:15.1`. Fix: confirm (with a security review date) or reject.
- Confidence: verified.

**MAESTER-SKIPPED-MANY**
- Catches: more than N tests skipped or not run in the newest Maester results - a licence, a missing
  connection or an over-broad exclusion list is shrinking the suite without anyone noticing.
- Severity: low. Source: `maester.yaml`, `file` json, `items: Tests`. Condition:
  `count: { op: gt, value: 40, threshold: maester.max-skipped-tests, where: { field: Result, op: in, value: [Skipped, NotRun] } }`.
- Refs: `NIST-800-53:CA-7`. Fix: read the skip reasons in the report; connect the missing services, trim
  the exclusions, or lower the threshold to the number of tests the tenant's licences cannot run.
- Confidence: verified for the mechanics; the right default is a guess (it depends on licensing).

**MAESTER-REPORT-STALE (change, not new)**
- Replace the `_modified` judgement with `ExecutedAt` from the root object (see
  MAESTER-VERSION-OUTDATED): copying a results file into `imports\` gives it today's modified time, so
  the current rule never fires on a file copied late.
- Confidence: likely (field name).

---

## Counts

- Priority 1: 32 entries (4 TLS, 3 DC, 8 registers, 13 obligations, 4 imports; PC-SCORE-* is one entry
  with four ids, SCUBA-PRODUCT-NOT-SCANNED one entry with six).
- Priority 2: 31 entries (5 TLS, 2 DC, 10 registers, 8 obligations including
  OBL-ATTESTATION-EVIDENCE-THIN, 6 imports).
- Priority 3: 6 entries (2 TLS, 2 registers, 2 Maester - one of them a change to an existing rule).
- Total: 69 entries, 78 rule ids.

Backlog items these would close or narrow (`docs/backlog/certificates-registers-imports.md`): TLS
interception (per integration only), Extended key usage (the `eku` field now exists; the DC rule is
shipped, the server-auth rules are proposed here), Initiative register has no rules yet, Further
obligations from the PKI catalogue, No obligation catalogue (stopgap), ScubaGear omissions and Prowler
MANUAL checks, Prowler has no stale-report rule (workaround), Machine proof for krbtgt (PC-KRBTGT-AGE).

---

## Engine gaps that blocked or weakened proposals

1. **A failed handshake is "unknown", never a row.** A DC without LDAPS, an endpoint that is down, or a
   server offering only protocols the scan host has disabled all vanish into coverage. For DCs the
   absence *is* the finding. Needed: the `tls` runner returns a row with `reachable: false` and
   `failure` text (so `each: { field: reachable, op: eq, value: false }` works), or a store rule in
   `rules/keeper.yaml` over `coverage` (`scope = 'target' AND state = 'failed'` for the newest run of
   each tls system) turns failed targets into findings. The second needs no runner change.
2. **No per-target labels or expected issuer per target.** TLS-ISSUER-UNEXPECTED and
   DC-CERT-ISSUER-UNEXPECTED work per integration through one regex threshold; "this endpoint should be
   issued by that CA" needs a target option (`targets.list` entries as `host:port|issuer-pattern`, or a
   labels map).
3. **`validityDays` is not in the TLS row**, so TLS-VALIDITY-TOO-LONG stays an approximation (backlog).
4. **No cross-run or cross-row comparison** for TLS: the same key on many endpoints, a certificate that
   changed since the last scan, a thumbprint that moved to another host. `row_seen` holds the attributes
   per run, so a store rule could compare thumbprints between the two newest runs of a tls system - but
   `row_seen.attrs` of per-target runs must be confirmed to carry `thumbprint` before writing it.
5. **`emit` cannot set refs or category from a row.** Prowler's `unmapped.compliance` and Maester's
   `Tag` carry the frameworks each finding maps to; today every imported finding inherits the rule's
   static `refs`, so GRC evidence from imported tools is coarse. Needed: `emit.refs: "{unmapped.compliance}"`
   (array template) and `emit.category` from a field with a map.
6. **Newest file only, one row set per file.** One PingCastle XML per domain, one Prowler file per
   account, several tenants' Maester results cannot be read by one rule (backlog). A root-array file
   (Prowler) has no file-level row; PROWLER-REPORT-STALE leans on finding-key collapse instead.
7. **Thresholds are not bound into SQL** (`:threshold_<name>`), so every due date computed in SQL (the
   obligations, vendor review) reads the setting table directly and ignores a per-rule `threshold`
   override (backlog). Not fixable in a rule.
8. **`count` is absolute**, not a share of rows: "more than 10 % of tests skipped" or "more than a third
   of controls erroring" needs `count: { op: gt, pct: 10, where: ... }`.
9. **No obligation catalogue table.** OBL-ATTESTATION-UNKNOWN-ID hard-codes the id list; expected targets
   per obligation (every CA, every critical system) cannot be enumerated, so "never attested for CA #2"
   is invisible while CA #1 is attested.
10. **Foreign-key enforcement unknown** (`PRAGMA foreign_keys`): decides whether REG-VEN-REFERENCE-DANGLING
    can ever fire.
11. **Registers have no per-field as-of dates** (`seats_used` as of when?), no perpetual flag, no renewal
    state, no payment or suspension key-date kinds, no contract auto-extension flag (backlog). The
    proposals use `updated_at` as a stand-in.
12. **Every rule in a per-target file sees only that file's targets.** The TLS hygiene rules do not run
    on DCs, so the DC pack needs copies (DC-CERT-LEGACY-PROTOCOL, DC-CERT-WEAK-KEY-OR-SIGNATURE,
    DC-CERT-NO-SAN). A `targets` include/`extends` between files would avoid the duplication.
13. **TLS 1.3 and accepted-but-not-negotiated protocols** cannot be judged without per-version probing
    (backlog); TLS-PROTOCOL-NO-TLS13 is therefore priority 3 and info only.
