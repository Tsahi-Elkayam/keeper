# Backlog - certificates, registers, obligations and imported tools

Checks that `rules/certificates.yaml`, `rules/domain-controller-certificates.yaml`,
`rules/registers.yaml`, `rules/obligations.yaml`, `rules/pingcastle.yaml`, `rules/maester.yaml`,
`rules/scubagear.yaml` and `rules/prowler.yaml` cannot express yet. One line each: the check, what it
needs, and where it came from.

Source labels: `tls-runner`, `file-runner`, `store-runner`, `evaluator`, `loader` = the engine code
that sets the limit; `schema` = the review and register migrations and the register handler;
`obligations` = the legacy obligations catalogue; `pki` = the legacy PKI check catalogue;
`vmware` = the legacy certificate plugin; `tool-docs` = the tool's published output format;
`field` = a problem seen in a real estate (described generically).

## Certificates - not in the TLS row, or not expressible per row

- Exact validity length (notAfter - notBefore): TLS-VALIDITY-TOO-LONG approximates with daysLeft and the age of notBefore, so a long certificate is caught only once its remaining days or its age pass the limit - needs a `validityDays` row field. Source: tls-runner.
- "Self-signed on a production endpoint": a target has no environment label, so the rule applies to every target of the integration and lab endpoints need their own integration plus an override - needs per-target labels in the targets option. Source: tls-runner.
- Revoked certificates: the handshake uses no revocation check, so a revoked certificate passes - needs an opt-in revocation mode (CRL/OCSP reachable from the scan host). Source: tls-runner.
- Legacy protocol or weak suite *accepted* next to a modern one: only the negotiated protocol and suite are visible - needs per-version and per-suite probing. Source: tls-runner.
- A server that offers only protocols Keeper's own host has disabled fails the handshake and appears as a failed query (unknown), not as TLS-LEGACY-PROTOCOL - needs the runner to report "no common protocol" as a row. Source: tls-runner.
- A failed handshake is never a row: a domain controller that does not answer LDAPS at all (no usable certificate, so Schannel offers none) is only a failed target in coverage, although for DCs the absence is the finding - needs a `reachable: false` row with the failure text, or a store rule over `coverage` (scope target, state failed, newest run of each tls system). Source: tls-runner.
- TLS 1.3 support: the negotiated version also depends on Keeper's host TLS stack, so "no TLS 1.3" cannot be judged reliably - needs the probing above (a TLS-PROTOCOL-NO-TLS13 rule waits for it). Source: tls-runner.
- Weak signatures inside the chain: TLS-CHAIN-WEAK-SIGNATURE relies on the platform's HasWeakSignature chain status, which the scan host's crypto policy sets for MD5 but may not set for a SHA-1 intermediate - needs the signature algorithm of every chain certificate in the row. Source: tls-runner.
- Internal names in SANs (unqualified host names, .local, .lan, .corp and similar): forbidden for public CAs but normal on a private CA, so a rule fires on every internal certificate - needs the issuer classified as public or private (per target, or a public-issuer pattern). Source: tls-runner.
- The TLS hygiene checks exist twice: a per-target file sees only its own targets, so domain-controller-certificates.yaml repeats the protocol, key, SAN and issuer checks of certificates.yaml - needs a targets include or extends between files. Source: loader.
- Missing intermediate sent by the server: the chain is the one Keeper's host builds (it may fetch intermediates itself), so TLS-CHAIN-INCOMPLETE can miss it - needs the count of certificates the server presented. Source: pki (TLS sweep defect).
- IP-address SANs: `sans` holds DNS names only, so a certificate issued for IP addresses only is reported by TLS-NO-SAN - needs IP SANs in the row. Source: tls-runner.
- TLS interception per target: TLS-ISSUER-UNEXPECTED and DC-CERT-ISSUER-UNEXPECTED judge one expected-issuer pattern per rule (a threshold, which an override can change per rule and entity), so "this endpoint must be issued by that CA" for many different endpoints needs per-target expected issuers (an issuer pattern on each targets entry, or a labels map). Source: tls-runner; field (security agent cloud traffic intercepted, agent offline for weeks).
- Same certificate or key on many endpoints, and "certificate changed since the last scan" - needs cross-row and run-to-run comparison. Source: evaluator.
- OCSP stapling, HSTS, Certificate Transparency SCTs and key usage are not in the row. Source: tls-runner.
- Certificates no TLS scan reaches (appliance token-signing, federation, code-signing, CA certificates) can be tracked only as key dates (REG-KEY-CERTIFICATE-DUE). Source: vmware.

## Registers - schema and engine gaps

- Thresholds are not bound as SQL parameters: derived dates (REG-VEN-SENSITIVE-NO-REVIEW review_due, every obligation due_on) read `threshold.*` from the setting table with the default as fallback, so a per-rule threshold override changes the condition but not the date - bind thresholds as `:threshold_<name>`. Source: store-runner.
- Severity ranges are fixed in the rule files and cannot be tuned per tenant. Source: loader.
- No `payment` kind in key_date: payments are kind `other` recognised by a title pattern (threshold `registers.payment-title-pattern`) - add `payment` (and `suspension`) to key_date.kind and the handler's choices. Source: schema; field (two cloud accounts in payment arrears, one with a suspension date).
- Systems affected by a missed payment: key-date rules do not count the systems that depend on key_date.system_id the way REG-CON-ENDING-PLANNED does for contracts. Source: field (nobody knew which services would stop on suspension).
- No arrears or invoice register: past-due invoices and suspension notices live in finance systems and reach Keeper only as key dates typed in by hand. Source: field (arrears tracked in separate mail threads by different people).
- key_date has no done or recurrence fields: a passed date is reported until someone moves or deletes it, and recurring dates are rolled forward by hand. Source: schema.
- licence has no perpetual flag: REG-LIC-NO-EXPIRY exempts licences whose notes contain "perpetual". Source: schema.
- licence has no renewal state (quoted, ordered, paid): a renewal that was planned but never ordered shows only as expiring and then expired. Source: field (a licence ran out while its renewal was "planned"; no order existed).
- contract has no auto-renew or fall-back-to-list-price flag and no termination-notice date: an agreement that continues at list price unless renewed is warned about only through a price-change or contract key date. Source: field (marketplace agreements that fall back to public pricing at term end).
- Consumption commitments: seats/seats_used cover unit caps, but a usage forecast above a prepaid commitment (overage) cannot be expressed. Source: field (platform consumption forecast well above its subscription).
- Owners and notice recipients are free text: a licence, contract or key date owned by someone who has left, or whose vendor renewal notices still go to a departed person's mailbox, cannot be detected - needs owner as a directory reference joined to the entity table (user, gone_since) and a notice-recipient field. Source: field (renewal notices, budget and security alerts still addressed to a departed staff member).
- Dependants of a retiring tool: REG-CON-ENDING-PLANNED counts system_dependency rows only; the teams and uses that rely on a tool, and the replacement that should cover them, are not recorded. Source: field (a tool was not renewed while another team relied on it for ten uses its replacement did not cover).
- Duplicate purchases: REG-LIC-DUPLICATE-PRODUCT matches licences by product name only; the same product under another name, or overlapping contracts, are not matched. Source: field (a new offer for a product already under a running agreement).
- No purchase-order register: open orders and quotes waiting for a "needed or close" or seat-count decision are invisible. Source: field (open order and quote awaiting a decision).
- Cap increases requested from a vendor have no state: a promised increase that never arrived shows only once seats or seats_used are updated. Source: field (free-tier user cap exceeded while an increase was believed done).
- vendor has no legal-retention or data-export fields: a sole supplier holding records that must be kept for many years and migrated to any successor is prompted only through the exit_plan fix text. Source: field (sole supplier holding sensitive records under a short extension).
- No as-of date per field: REG-LIC-USAGE-STALE and REG-VEN-ROW-STALE judge the whole row's updated_at, so any save of the row (even an unchanged one) counts as a fresh reading of seats_used or of the vendor's facts - needs seats_used_on on licence and a reviewed_on on vendor. Source: schema.
- No cancellation terms: a licence that can be cancelled at any time needs an exception on REG-LIC-AUTORENEW-SHORT-NOTICE - needs a cancellation-notice (or cancellable-any-time) field on licence and contract. Source: schema.

## Obligations

- No obligation catalogue: OBL-ATTESTATION-UNKNOWN-ID finds attestations whose id maps to no rule only through the naming convention (obligation a.b-c -> rule OBL-A-B-C), and per-target obligations still know only the targets attested at least once - "never attested for the second CA" is invisible while the first CA is attested - needs an obligation table with its expected targets. Source: schema.
- `count: none` cannot use a threshold because the interval is not visible in SQL, so each obligation reads one aggregate row per target instead. Source: store-runner, evaluator.
- Machine proof belongs in other packs: PC-KRBTGT-AGE proves the krbtgt rotation from the PingCastle report (with the obligation's own threshold); an ldap rule on krbtgt pwdLastSet would prove it without PingCastle, and GPO backup output and system-state backup records still need backup integrations. This pack reads attestations only. Source: obligations (ProvedBy column).
- change.code-review is per change, but Keeper cannot see which scripts and automations run in production, or whether they are signed - needs an inventory source (scheduled tasks and automation accounts with Authenticode status, or a CI pipeline integration). Source: field (security required review, a secrets check, a staging run and a signature before identity scripts run in production).

## Imported tools

- Newest file wins: one PingCastle report per domain, one Prowler file per account, or several tenants cannot be read by one rule - needs an all-files mode. Source: file-runner.
- JSON items take the first match only: ScubaGear's JSON nests controls as Results.<product>[].Controls[], which cannot be flattened, so controls are read from ScubaResults.csv. Source: file-runner (RowValues.ItemsOf).
- No file-level row: stale-report rules read a small metadata object (PingCastle GenerationDate, ScubaGear MetaData) or the root object (Maester: the whole results file, tests included, becomes one row and is stored again in row_seen); Prowler's OCSF file is a bare array, so PROWLER-REPORT-STALE counts findings whose own event time is recent instead of reading a run time - needs one row per file (_file, _modified and the root's scalar fields). Source: file-runner.
- emit kind, category and refs are fixed per rule: a tool's own per-row category or framework mapping (Prowler unmapped.categories and unmapped.compliance, Maester tags) cannot set the Keeper category or refs, so every imported finding carries the rule's static refs; PingCastle is split into rules by XPath instead. Source: loader.
- No field-to-field comparison: a condition compares a field with a literal or a threshold, so "the Maester module that ran (CurrentVersion) is not the published one (LatestVersion)" cannot be written - needs a value that names another field. Source: evaluator.
- Built (engine stage 2): a share is `count: { percent: true, ... }` - "more than a tenth of the Maester tests skipped or not run"; the rules still use absolute limits. Source: evaluator.
- Built (engine stage 2): an exception can end - `keeper decide accept <key> --until <date>`; SCUBA-OMITTED and SCUBA-MANUAL-CHECK can now say to record the decision with an end date. Source: schema.
- PingCastle's domain name is on the report root, not on the risk rows, so evidence carries the file name; rule Details are exported only at the Full level. Source: file-runner, tool-docs.
- Stale data inside a tool (an inventory showing week-old data) is judged only by report age; tools with an API need their own pack. Source: field (inventory tool data a week behind).
- Many Maester tests carry no severity; their failures default to medium. Source: tool-docs.

## Proposals reviewed and not shipped

From `docs/proposals/certificates-registers-imports.md`; the rest of that document is now rules.

- PC-SCORE-STALE-OBJECTS, -PRIVILEGED, -TRUSTS, -ANOMALIES: a duplicate. The global score is the worst category score, so the worst category's rule restates PC-GLOBAL-SCORE, and each category's risk rules are already findings with points-based severity (PC-STALE-OBJECTS, PC-PRIVILEGED-ACCOUNTS, PC-TRUSTS, PC-ANOMALIES). If per-category targets are wanted, replace PC-GLOBAL-SCORE with them rather than add them. Source: pingcastle.yaml.
- MAESTER-VERSION-OUTDATED: needs the field-to-field comparison above. Source: evaluator.
- MAESTER-SKIPPED-MANY: needs the share-based count above; a fixed limit fires on tenants without the licences many tests need. Source: evaluator.
- REG-VEN-REFERENCE-DANGLING: cannot occur. The store opens with foreign keys on and contract.vendor_id and licence.vendor_id reference vendor, so a dangling vendor id is refused on write. Source: schema.
- TLS-SAN-INTERNAL-NAME: waits for the public/private issuer classification above. Source: tls-runner.
- TLS-PROTOCOL-NO-TLS13: waits for per-version probing (see TLS 1.3 support above). Source: tls-runner.

## Applications and business systems catalogue

From `docs/proposals/catalog-apps-business.md`. Shipped: the generic obligations (OBL-SYS-*, OBL-APP-*,
OBL-PRIVACY-DATABASE-RECORD, OBL-TEL-EMERGENCY-CALL-TEST), REG-KEY-SUPPORT-END-DUE and
REG-KEY-SYSTEM-INACTIVE, the TLS-target guidance in certificates.yaml, and the ServiceNow platform,
exposure and access rules. Source label `servicenow` = the ServiceNow section of that proposal; its
lines belong with the ServiceNow items in `infrastructure.md`, which this change did not edit.

### Registers and obligations

- Nothing writes `system_dependency`: REG-CON-ENDING-PLANNED counts dependants and OBL-SYS-RUNBOOK asks for dependencies and co-hosted systems, but no handler accepts dependency rows, so the count is 0 unless the table is edited by hand - needs a review.system-dependency handler. Source: schema.
- Per-system obligations know only attested targets: a system that was never attested for OBL-APP-BACKUP-VERIFIED (or any per-system duty) is covered by the single "-" row only. Joining every active system (as OBL-SYS-DECOMMISSION does for inactive ones) would demand every duty of every system - needs per-system applicability (which duties apply to which kind of system) on top of the obligation catalogue above. Source: schema.
- The severity maps of OBL-ATTESTATION-EXPIRED and OBL-ATTESTED-NO are hand-kept copies of each obligation rule's severity, and drift when a rule changes - needs the severity read from the `rule` table. (OBL-ATTESTATION-UNKNOWN-ID has no id list to maintain; it matches the rule catalogue by naming convention.) Source: loader.
- One-off obligations: OBL-SYS-DECOMMISSION departs from the template (a 'yes' never expires; targets include inactive systems; no "-" row). The day a system was retired is approximated by the last save of its system row - needs a retired_on date on `system`. Source: schema.
- Payments: since migration 005 the `payment` kind exists and REG-KEY-PAYMENT-DUE / -OVERDUE read it next to the old title pattern on kind `other`; a `suspension` kind is still missing (see the payment line above). Source: schema.
- Product versions against support dates: a support-end key date is typed in by hand even where a scan reads the running version (a release family, a firmware build) - needs a version-to-lifecycle table and version comparison. Source: evaluator.

### ServiceNow - not expressible yet

- Per-object filters: SNOW-DISCOVERY-SCHEDULE-STALE (newest discovery_status per active schedule) and SNOW-SCOPED-APP-NO-REPO (sys_repo_config per scoped app) put the parent's sys_id into `sysparm_query`, but `for_each` fills placeholders in the path only, and the must-exist would have to be judged per parent - needs for_each placeholders in params plus per-parent counts. Partial: SNOW-DISCOVERY-NONE-RECENT (no run at all in 7 days). Source: servicenow.
- Tenant values inside a query: SNOW-CONTENT-LEGACY-REFERENCE (text LIKE a tenant pattern), SNOW-PII-FIELD-NO-ACL (one ACL lookup per tenant-listed field), SNOW-VENDOR-USER-PRIVILEGED (a tenant marker on company or source) - needs thresholds in params (the gap in `infrastructure.md`). The last one could filter client-side, but a dot-walked field comes back under a literal key such as "user.company", which a field path cannot address - needs a quoted path segment. Source: servicenow; evaluator.
- Production or test: SNOW-TEST-INSTANCE-SENDS-MAIL and SNOW-DELEGATED-DEVELOPER-PROD are right on one kind of instance and wrong on the other - needs an environment label on the integration (the same gap as per-target labels for TLS above). Source: servicenow.
- List fields: SNOW-NOTIFICATION-INACTIVE-RECIPIENT dot-walks `recipient_users`, a list of sys_ids that encoded queries cannot dot-walk - needs a per-recipient lookup. Source: servicenow.

### ServiceNow - unverified details, rule not written

- SNOW-EMAIL-ACCOUNT-ERROR: the error and last-poll fields of sys_email_account are not confirmed. Source: servicenow.
- SNOW-UPGRADE-SKIPS-UNREVIEWED: the disposition and resolution codes of sys_upgrade_history_log are not confirmed; the proposed `resolution_status!=reviewed` likely matches every skip of every past upgrade. Source: servicenow.
- SNOW-DISCOVERY-SCHEDULE-PINNED-MID: the stored values of the MID selection field are not confirmed; a wrong value would pass silently. Source: servicenow.
- SNOW-CLONE-TO-TEST-STALE: the completion field of clone_instance is not confirmed. Source: servicenow.
- SNOW-TABLE-NO-CLEANUP and SNOW-AUDIT-FLUSH-RULE-SHORT: the unit of sys_auto_flush age and which tables rotate instead of flushing are not confirmed. Source: servicenow.
- SNOW-AUDIT-SECURITY-TABLES-OFF: which dictionary attribute marks a table as audited is not confirmed, and the proposed glide.sys.audit property was not found in the vendor's property lists. Source: servicenow.
- SNOW-DISCOVERY-AUTH-FAILURES and SNOW-DISCOVERY-UNCLASSIFIED-MANY: depend on log message wording and discovery_device_history fields; a LIKE over a large log table may also time out. Source: servicenow.
- SNOW-CATALOG-ITEM-OWNER-INACTIVE: the owner field of sc_cat_item depends on the release. Source: servicenow.
- SNOW-SCHEDULED-IMPORT-STALE: the proposed field (run_start) is when the schedule starts, not the last run. Source: servicenow.
- SNOW-MONITORING-EVENTS-NONE: em_event exists only with event management, and `monitoring` is not a base contact type. Source: servicenow.

### ServiceNow - reviewed and not shipped

- SNOW-GUEST-USER-UNLOCKED: wrong - public pages and the login page run as the guest user, so it must stay usable; replaced by SNOW-GUEST-USER-HAS-ROLE. Source: servicenow.
- SNOW-USER-LOCAL-LOGIN: wrong - an empty `source` does not mean a local password (users provisioned by a connector or SCIM have none either); SNOW-SSO-NOT-ENABLED and SNOW-LOCAL-MFA-OFF cover the risk. Source: servicenow.
- SNOW-INTEGRATION-USER-INTERACTIVE and -ADMIN: the internal-integration-user flag already blocks interactive sign-in, and a filter on a field older releases lack is ignored, which would report every user. Source: servicenow.
- SNOW-BASIC-AUTH-ALLOWED: shipped as SNOW-PROCESSOR-AUTH-NOT-REQUIRED - the glide.basicauth.required properties decide whether a processor demands credentials at all, not whether basic authentication is allowed. Source: servicenow.
- SNOW-LEGACY-WORKFLOW-ACTIVE: `published` is on wf_workflow_version, not wf_workflow, and an info list of legacy workflows is a migration plan, not a finding. Source: servicenow.
- SNOW-PUBLIC-PAGE-ACTIVE, SNOW-SP-PAGE-PUBLIC, SNOW-KB-ARTICLE-PUBLIC: the base system ships public pages, so the list is noise without an approved baseline - needs a diff against a tenant baseline. Source: servicenow.
- SNOW-ACL-RECENTLY-CHANGED, SNOW-ELEVATION-EVENT, SNOW-IMPERSONATION-EVENT, SNOW-LOCAL-LOGIN-EVENT: info lists; upgrades rewrite every base ACL, so the first needs the upgrade accounts filtered out. Source: servicenow.
- SNOW-ARCHIVE-RULE-NONE: the retention decision belongs to OBL-PRIVACY-DATABASE-RECORD. SNOW-MID-NOTIFICATION-INACTIVE: covered by OBL-SYS-ALERT-ROUTING. SNOW-CMDB-NO-RECONCILIATION-RULES and SNOW-CLONE-NO-DATA-EXCLUSION: the base system ships defaults, so "none" never fires. SNOW-EMAIL-FILTER-NONE: table not confirmed. Source: servicenow.
- SNOW-CMDB-APP-NO-OWNER: shipped for services as SNOW-CMDB-SERVICE-NO-OWNER; business applications carry no operational status and use other owner fields. The wf_context "faulted" sibling of SNOW-FLOW-ERRORS was left out with the legacy workflows. Source: servicenow.
- Corrected while writing: `{DAYS_AGO:n}` in `sysparm_query` (its ISO form is not the encoded-query date format) became relative encoded queries; SNOW-EVENT-QUEUE-BACKLOG counts events past their processing time, not all ready events; SNOW-ELEVATED-ROLE-HOLDER became a per-user count (SNOW-ELEVATED-ROLE-COUNT, and SNOW-IMPERSONATOR-ROLE-COUNT), because a high finding per holder buries the work queue; SNOW-SCHEDULED-JOB-OVERDUE dropped the unconfirmed state code; SNOW-RELEASE-OLD reports until the supported-family pattern is set, instead of passing with a stale default. Source: servicenow.

### ServiceNow - to confirm on the first real run

- The relative operators with the minute and dayofweek units (RELATIVEGT@dayofweek@ago@7, RELATIVELT@minute@ago@30) are accepted in `sysparm_query`; an ignored term widens the count and shows as a loud finding, not a pass.
- The Aggregate API without grouping answers `result` as one object carrying `stats.count` (an array would be read as rows too).
- Field names marked likely in the proposal: sys_cluster_state.status `online`, sys_trigger.next_action, ecc_agent.last_refreshed (refreshed by the heartbeat), ecc_agent_issue.state `resolved`, ecc_agent_property names containing check_cert, sys_store_app.update_available, sys_import_set_run.errors, sys_outbound_http_log.response_status, sysevent.process_on, problem.cause_notes, incident.major_incident_state.
- Property names: glide.login.no_blank_password and glide.authenticate.multifactor (the other hardening, attachment and session properties are in the vendor's high-security and security-properties lists).
- The integration account can read sys_properties, sys_user_has_role, the ecc_* tables, sysevent, syslog and sys_cluster_state; the Aggregate API refuses (403) when any row is hidden by an ACL, which makes those rules unknown.
