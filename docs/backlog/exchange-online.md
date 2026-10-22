# Backlog - Exchange Online

Legacy checks from `_archive\_health-20261020\Keeper\catalog\checks-EXO.csv` (146 rows; the
`(Restored1)` duplicates were ignored) that `rules/exchange-online.yaml` cannot express, one line each:
the check, what it needs, and the source CheckId.

`rules/exchange-online.yaml` reads through the `exchange-online` integration type, whose token is for the
Exchange Online REST endpoint (`https://outlook.office365.com/adminapi/beta/<tenant id>`). Every read is
one `POST /InvokeCommand` whose body names a **Get-** cmdlet and its read parameters; the type refuses any
non-Get cmdlet and any parameter that makes one do more than read (`GetMailboxLog`,
`NotificationEmailAddresses`, `IncludeCredential`). The 45 rules cover what that allows: the organisation
and transport config booleans (auditing, SMTP AUTH, modern auth, Direct Send, MailTips, MRM, Office 365
connectors), mail-flow and forwarding risk (remote domains, outbound-spam auto-forward, mailbox forwards,
transport-rule redirect/SCL-bypass/test-mode and new-since-last-scan), connectors and accepted domains
(partner TLS, weak outbound TLS, relay domains, new connectors), authentication policy and legacy
protocols (basic-auth policy, POP/IMAP per mailbox and plan, client access rules), RBAC (direct user
assignments, unscoped application assignments, ApplicationImpersonation and Application Access Policy
leftovers, add-in install roles), OWA and mobile policy, sharing and federation, groups, shared-mailbox
sent-items, retention/litigation hold/single-item recovery, DKIM, and restricted senders.

Source labels: `EXO-*` = the legacy CheckId; `field` = a problem seen in this estate. After the backlog:
the thresholds the rule file defines, and what to confirm on the first real run.

## Needs Security & Compliance (Purview) or a non-Get cmdlet

The audit, alert and retention catalogue lives behind the Security & Compliance endpoint (the `purview`
integration type, read through `Connect-IPPSSession`) or behind `Search-UnifiedAuditLog`, which is not a
`Get-` cmdlet and so is refused by the `exchange-online` type's command allow-list.

- Exchange audit records actually reach the unified audit log (a 24 h sample). Source: EXO-LOG-004.
- Audit (Premium) search and mail-access events recorded for priority / E5 accounts. Source: EXO-LOG-008.
- Exchange-related alert policies enabled and routed to a monitored mailbox (`Get-ProtectionAlert`, IPPS). Source: EXO-MON-001.
- Forwarding, inbox-rule, permission and mail-flow changes in 7 d, matched to who made them (`Search-UnifiedAuditLog`). Source: EXO-MON-003, EXO-MON-004.
- Who-made-the-change half of transport-rule and connector drift (the config diff is EXO-TRANSPORT-RULE-NEW / EXO-INBOUND/OUTBOUND-CONNECTOR-NEW; the actor needs the audit log). Source: EXO-CFG-006, EXO-CFG-012.
- Mailbox search / eDiscovery / import-export role holders (`Get-RoleGroupMember`, `Get-eDiscoveryCaseAdmin` via IPPS). Source: EXO-IAM-002.
- Every user and shared mailbox covered by a retention policy or hold; statutory mailboxes under a long-term hold (`Get-RetentionCompliancePolicy`, IPPS). Source: EXO-BCK-001, EXO-BCK-010.

## Needs Microsoft Graph (lives in the m365 / entra / hybrid packs)

Each reads a Graph resource the `exchange-online` type cannot reach; it belongs in a `graph` rule file, or
is already held tenant-wide there.

- Open Exchange Online service incidents / advisories and plan-for-change message-center notices (serviceAnnouncement). Source: EXO-HLT-001, EXO-LCM-009.
- Mailbox / archive / shared-mailbox capacity, inactive mailboxes, Outlook client versions (usage reports `getMailboxUsageDetail`, `getEmailAppUsage*`). Source: EXO-HLT-004, EXO-HLT-005, EXO-HLT-006, EXO-LCM-007, EXO-HYG-002.
- Directory objects with unresolved Exchange provisioning errors (`/users serviceProvisioningErrors`). Source: EXO-HLT-012.
- SMTP AUTH / legacy-protocol / EWS callers seen in sign-in and consent data (`/auditLogs/signIns`, `/servicePrincipals appRoleAssignedTo`, `oauth2PermissionGrants`). Source: EXO-LCM-006, EXO-LCM-010, EXO-AUT-006, EXO-IAM-005.
- Shared / room / equipment mailbox accounts: sign-in blocked and no interactive sign-ins (Graph `accountEnabled`, `signInActivity`). Source: EXO-IAM-011, EXO-IAM-012.
- Mailbox-permission holders who are disabled or departed; admin accounts in business DLs (Graph `accountEnabled`, `employeeLeaveDateTime`, `memberOf`). Source: EXO-IAM-009, EXO-IAM-016.
- Disabled accounts still holding a user mailbox or an Exchange-bearing / inactive licence; A1-faculty fit; shared-mailbox licensing (Graph `accountEnabled`, `assignedLicenses`). Source: EXO-HYG-001, EXO-CST-001, EXO-CST-002, EXO-CST-003, EXO-CST-004, EXO-CST-005, EXO-CST-006.
- System / vendor notices delivered to disabled or departed mailboxes (Graph join + message trace). Source: EXO-MON-006.
- App-enforced-restriction / approved-client Conditional Access half of the OWA and mobile checks (`/identity/conditionalAccess/policies`, Entra owns it). Source: EXO-CFG-017, EXO-CFG-030.

## Needs a per-mailbox or per-object read the engine cannot fan out as a read-POST yet

These use a `Get-` cmdlet that runs **per identity** (`-Identity <mailbox>`): a `for_each` over the mailbox
or group list that injects the identity into the `CmdletInput` body. `for_each` is documented for the
request path and params, not for a POST body, so these need that confirmed (or built) before they can be
written; the mailbox-statistics ones also need size-string parsing.

- Recoverable Items / archive / folder-item statistics near quota (`Get-MailboxStatistics`, `Get-MailboxFolderStatistics` per mailbox). Source: EXO-HLT-005, EXO-HLT-007, EXO-HLT-008.
- Full Access, Send As, Send on Behalf and folder-permission inventory (`Get-MailboxPermission`, `Get-RecipientPermission`, `Get-MailboxFolderPermission` per mailbox). Source: EXO-IAM-006, EXO-IAM-007, EXO-IAM-008, EXO-IAM-010, EXO-HYG-003.
- Inbox rules that forward, redirect, delete or hide mail; rules in error on shared mailboxes (`Get-InboxRule -Mailbox` per mailbox). Source: EXO-IAM-014, EXO-LOG-007.
- Calendar-processing safety on rooms; published calendars; junk safe-sender lists; auto-replies on resident-facing mailboxes (`Get-CalendarProcessing`, `Get-MailboxCalendarFolder`, `Get-MailboxJunkEmailConfiguration`, `Get-MailboxAutoReplyConfiguration` per mailbox). Source: EXO-CFG-025, EXO-CFG-021, EXO-CFG-034, EXO-HYG-007.
- Exchange admin role-group membership with a run-to-run diff (`Get-RoleGroupMember` per role group, then `_new`). Source: EXO-IAM-001.
- Dynamic distribution group membership resolves; large-audience groups restrict senders (`Get-DynamicDistributionGroupMember` / member counts per group). Source: EXO-CFG-023, EXO-CFG-024.
- Native EAS clients on outdated mobile OS (`Get-MobileDevice` plus an OS-string version comparison across platforms). Source: EXO-LCM-008.

## Needs a cross-row, cross-query or trend judgement the condition language cannot make

The data is reachable with a `Get-` cmdlet, but the test compares rows with each other, joins two queries,
or needs history across runs.

- Mail-flow, failed-delivery, queue, NDR-code, transport-rule-hit and outbound-volume trends against a baseline (`Get-MessageTraceV2`, `Get-MailflowStatusReport`, `Get-MailDetailTransportRuleReport` vs previous runs). Source: EXO-HLT-002, EXO-HLT-003, EXO-HLT-010, EXO-HLT-011, EXO-LOG-006, EXO-LOG-009, EXO-MON-007.
- Recipient counts by type, week-on-week (`Get-Recipient` grouped, vs previous run). Source: EXO-HLT-009.
- Security-relevant transport rules not shadowed by a higher-priority stop-processing rule (ordering across rows). Source: EXO-CFG-007.
- Message size limits consistent across transport, mailbox plans and mailboxes (cross-query comparison). Source: EXO-CFG-027.
- Journal rules point only at a contracted archive; no transport/connector route to an unknown external address (`Get-JournalRule` / connectors joined to `Get-AcceptedDomain` to classify internal vs external). Source: EXO-CFG-014, EXO-CFG-004 (external-classification half), EXO-CFG-013 (route half).
- onmicrosoft primary addresses and proxy addresses in non-accepted domains (`Get-Recipient` joined to `Get-AcceptedDomain`). Source: EXO-CFG-035.
- Enhanced Filtering set where MX points at a gateway; migration-batch and endpoint cleanup; hybrid remnants (join to MX/DNS or multi-cmdlet state). Source: EXO-CFG-011, EXO-LCM-012, EXO-LCM-001, EXO-HYG-011.

## Needs a tenant-specific list of named mailboxes, domains or an exception record

Generic rules state a condition the scan finds instances of; these are about a tenant's own named objects
(role mailboxes, gateways, exception records in `Config\keeper.psd1` or the README), so they are a
tenant-rules file in the Keeper home, not a generic rule here.

- Role / resident-facing / statutory / alert mailboxes resolve, accept mail, are triaged, and are under hold. Source: EXO-AVL-004, EXO-MON-005, EXO-IAM-019, EXO-IAM-020.
- postmaster and abuse addresses exist for every accepted domain; mail flow not dependent on a single smart host. Source: EXO-AVL-005, EXO-AVL-006.
- The DPO forwarding exception recorded and enforced narrowly (the allow-list threshold on EXO-MAILBOX-FORWARDING-SET is the generic half). Source: EXO-IAM-015.
- The police-encryption transport rule enforced with the right template (a tenant-specific rule scope and IRM state). Source: EXO-CFG-008.

## Needs a different integration entirely (LDAP / DNS / TLS / registry / on-prem)

- On-premises Exchange servers supported or removed; recipient-management tooling (LDAP Configuration partition, registry on the admin PC). Source: EXO-LCM-002, EXO-LCM-003.
- Autodiscover resolves to Exchange Online; EXO traffic not TLS-intercepted; connector / partner / hybrid certificate validity (DNS, TLS probe, on-prem `Get-ExchangeCertificate`). Source: EXO-AVL-001, EXO-AVL-007, EXO-PKI-003, EXO-PKI-004, EXO-PKI-005.
- Keepit Exchange backup coverage, archives in scope, restore drill (Keepit console). Source: EXO-BCK-005, EXO-BCK-006, EXO-BCK-007.
- Soft-deleted / inactive leaver mailboxes preserved in the 30-day window (`Get-Mailbox -SoftDeletedMailbox` / `-InactiveMailboxOnly` are Get cmdlets, but the judgement joins Keepit coverage and the leaver process). Source: EXO-BCK-003.

## Process / local-read / attestation only - no tenant API to read generically

- EWS and legacy-Exchange-token org posture needs a cmdlet parameter that changes output (`Get-AuthenticationPolicy -AllowLegacyExchangeTokens`) or an allow-list decision; EWS org state (`EwsEnabled` / `EwsApplicationAccessPolicy`) can be added once the intended posture is set. Source: EXO-AUT-008, EXO-AUT-009.
- Exchange Online module version and no Remote PowerShell sessions; workspace scripts off the retired message-trace cmdlets (local module and script reads). Source: EXO-LCM-004, EXO-LCM-005.
- Mail-flow configuration exported and stored; mail path and exceptions documented in the README; full forwarding sweep run within 30 d; stale mail contacts reviewed; admin/service mailboxes hidden from the GAL and non-admin PowerShell access (attestation, local reads, or an estate decision). Source: EXO-BCK-009, EXO-HYG-009, EXO-HYG-010, EXO-HYG-006, EXO-HYG-008, EXO-IAM-017.
- Purview Message Encryption / OME branding and IRM licensing decision recorded (`Get-IRMConfiguration` is a Get cmdlet, but the finding is a recorded decision, not a posture bit). Source: EXO-CFG-032.
- Public folders absent or not readable by Default/Anonymous; per-mailbox recipient-rate limits; protected-mailbox exclusive scopes (per-folder reads or tenant decisions). Source: EXO-CFG-028, EXO-CFG-033, EXO-IAM-018.

## Thresholds this rule file defines

- `exchange-online.allowed-forwarding-addresses` (default empty) - EXO-MAILBOX-FORWARDING-SET; the primary SMTP addresses allowed to forward (the documented dpo@ exception). Empty by default, so every forward is a finding until the tenant records its exceptions.
- `exchange-online.deleted-items-retention-min-days` (default 30) - EXO-DELETED-ITEMS-RETENTION-SHORT; the minimum RetainDeletedItemsFor in days.

## To confirm on the first real run (no live tenant has been read)

- `POST /adminapi/beta/<tenant id>/InvokeCommand` with `{ CmdletInput: { CmdletName: Get-*, Parameters: {...} } }` returns the cmdlet's result objects under the OData `value` array, with their PowerShell property names at the object root (`AuditDisabled`, `RequireTls`, `TlsSettings`, `AutoForwardingMode`, ...). Confirm the property names and that `Parameters: {}` is accepted for a parameterless cmdlet.
- Large scans (`Get-Mailbox`, `Get-CASMailbox`, `Get-DistributionGroup`, `Get-UnifiedGroup` with `ResultSize: Unlimited`) page under the runner's default `auto` paging (`@odata.nextLink`); confirm the endpoint returns a next link rather than a module-side continuation, and set `min_rows` on the mailbox scans once a floor is known.
- The `_new`-based drift rules (EXO-TRANSPORT-RULE-NEW, EXO-INBOUND/OUTBOUND-CONNECTOR-NEW) are n/a on the first scan (no earlier clean read) and only fire on the next one; they carry a 7 d refresh so a finding stays visible for a week.
- `TlsSettings` on an outbound connector that uses MX routing may come back empty rather than a value; EXO-OUTBOUND-CONNECTOR-WEAK-TLS fires only on the explicit `EncryptionOnly` value, so an empty one is n/a (no false positive), never a pass.
- `RetainDeletedItemsFor` and `LitigationHoldDuration` come back as a `d.hh:mm:ss` timespan string (the `duration-lt` op reads it); confirm the format against a real mailbox.
- `Get-ManagementRoleAssignment` with `RoleAssigneeType: User` returns `Role`, `RoleAssignee` and `CustomResourceScope`; confirm that end-user assignment-policy roles are named `My ...` so the `^My ` exclusion holds, and that service-principal rows expose `CustomResourceScope`.
