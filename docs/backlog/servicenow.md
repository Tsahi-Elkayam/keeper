# Backlog - ServiceNow (rules/servicenow.yaml)

Legacy ServiceNow health checks from the catalogue (`checks-SERVICENOW.csv`, ~107 rows: HLT, LCM,
LOG, AVL, CFG, IAM, AUT, PKI, BCK, MON, HYG, CST) that `rules/servicenow.yaml` cannot express yet,
one line each with the reason and the legacy CheckId. Source: the legacy `_health` catalogue.
`(Restored1)` rows ignored. The `servicenow` integration reads the Table API (`/api/now/table/<t>`)
and the Aggregate API (`/api/now/stats/<t>`) by HTTP GET only; anything needing a write, a join to
another system, a per-host agent, a time-series/trend read, or an attestation is out of reach here.

What this pass added (expressible through the Table/Aggregate API): privileged-role hygiene -
admin on inactive/locked accounts, elevated role on inactive accounts, bulk role grants to inactive
accounts, admin on web-service accounts, integration accounts that can also sign in
(SNOW-ADMIN-ROLE-INACTIVE-USER, SNOW-ADMIN-ROLE-LOCKED-USER, SNOW-ELEVATED-ROLE-INACTIVE-USER,
SNOW-ROLE-GRANT-TO-INACTIVE-USER, SNOW-INTEGRATION-USER-ADMIN, SNOW-INTEGRATION-USER-INTERACTIVE);
exposure - recently changed ACLs, public platform pages and public portal pages, basic-auth REST
messages and plain-HTTP SOAP messages (SNOW-ACL-CHANGED-RECENTLY, SNOW-PUBLIC-PAGE-ACTIVE,
SNOW-PORTAL-PAGE-PUBLIC, SNOW-REST-MESSAGE-BASIC-AUTH, SNOW-SOAP-MESSAGE-CLEARTEXT); platform and
retention - an inbound mail account in error and a flush rule deleting audit history
(SNOW-INBOUND-EMAIL-ACCOUNT-ERROR, SNOW-AUDIT-FLUSH-ACTIVE); lifecycle and change governance -
published legacy workflows, unsuccessfully closed changes, registered OAuth clients
(SNOW-LEGACY-WORKFLOW-ACTIVE, SNOW-CHANGE-CLOSED-UNSUCCESSFUL, SNOW-OAUTH-CLIENT-REGISTERED). These
join the hardening, SSO/MFA, REST/inbound-mail, IP-access and role-count rules already in the pack.
The items below are what is still open.

## Needs a join across systems (AD / Entra / AWS / the CMDB / Keeper's own store)

- Active ServiceNow users whose AD/Entra account is disabled, deleted or in the leaver OU. SERVICENOW-IAM-007.
- Active employees missing from the provisioning source group, so never provisioned. SERVICENOW-IAM-008.
- Vendor users' roles and expiry cross-checked against the directory's accountExpires. SERVICENOW-IAM-009.
- Entra SCIM provisioning job health for the ServiceNow app (status, quarantine, last success). SERVICENOW-IAM-006. Graph, not the Table API.
- The ServiceNow enterprise app requires assignment and is covered by an MFA Conditional Access policy. SERVICENOW-AUT-001. Graph.
- Entra SAML signing certificate expiry and the thumbprint ServiceNow trusts. SERVICENOW-PKI-002. Graph plus a cert-reference read.
- CMDB servers reconciled both ways with AD computers, live scans, EC2 and vCenter. SERVICENOW-CFG-004, SERVICENOW-CFG-006.
- Discovery IP ranges vs AD site subnets and AWS VPC CIDRs. SERVICENOW-CFG-009. Cross-system.
- External monitoring of the instance and MID hosts by PRTG/Dynatrace. SERVICENOW-MON-001. Other tools' APIs.
- Monitoring alerts from PRTG/Dynatrace/AWS reaching ServiceNow as events/incidents. SERVICENOW-MON-010.

## Needs a write, a per-host agent (WinRM/TLS), or a different protocol

- MID host disk/memory/CPU, JVM heap and wrapper/agent logs. SERVICENOW-HLT-011, SERVICENOW-BCK-005. WinRM to the MID hosts (cim/smb), not the Table API.
- MID server version matched to the instance build, plus MID host OS/Java currency. SERVICENOW-LCM-006. Build-string comparison and WinRM.
- Custom-URL certificate on the instance (validity, chain, SAN). SERVICENOW-PKI-001. Belongs to the tls protocol / rules/certificates.yaml.
- MID server instance-certificate chain and hostname validation settings in config.xml. SERVICENOW-PKI-003. WinRM read of the MID config; the instance-side override is partly covered by SNOW-MID-CERT-CHECK-DISABLED.
- Reachability probe of the login page, portal and REST API. SERVICENOW-HLT-001. An HTTP GET of a non-API page with status-code logic, outside the Table-API rule shape; node and queue health already cover the platform.

## Needs the m2m / dictionary join the Table API cannot do in one GET

- ACLs on sensitive tables with no role and no condition (the "open ACL"). SERVICENOW-IAM-014. Role assignment lives in sys_security_acl_role, a separate table; one GET cannot tell "no role". Partial: SNOW-ACL-CHANGED-RECENTLY flags recent edits to review.
- Assignment groups with an inactive manager or fewer than two active members. SERVICENOW-IAM-012. Member counts need sys_user_grmember joined per group; the inactive-manager half is covered by SNOW-GROUP-MANAGER-INACTIVE.
- Personal-identifier fields on sys_user/HR tables restricted to the roles that need them, and encrypted. SERVICENOW-IAM-016. Needs sys_dictionary plus field-level ACL join plus licensing state.
- Delegated-developer and studio access per scoped application. SERVICENOW-IAM-017. Needs the scope-privilege join.
- Notification recipients resolved to active users, flagging literal external addresses. SERVICENOW-CFG-014. Needs recipient-field resolution across users/groups.

## Needs a trend, an order-by-limit, or a per-group aggregate the engine shape does not give

- Largest-table growth and whether a flush/rotation rule covers each. SERVICENOW-HLT-008. Growth is a run-to-run trend; SNOW-AUDIT-FLUSH-ACTIVE covers the audit-deletion half.
- Oldest audit record is at least the retention period. SERVICENOW-LOG-007. Needs an order-by sys_created_on limit 1 read, not a count; SNOW-AUDIT-FLUSH-ACTIVE catches a short flush rule.
- Response-time percentile and slow-transaction share. SERVICENOW-HLT-007. p95 is a percentile; SNOW-TRANSACTION-SLOW covers the absolute slow-count.
- Duplicate CIs by serial number / by name per class. SERVICENOW-CFG-003. Needs a per-group count>1 over a possibly-empty key; the de-duplication-task backlog is covered by SNOW-CMDB-DEDUP-TASK-OLD.
- CMDB completeness and freshness as a percentage per class. SERVICENOW-CFG-001, SERVICENOW-CFG-002. Share-of-class; the per-CI gaps are covered one server at a time by the SNOW-CMDB-* rules.
- Discovery schedule ran-in-period and classified/identified device shares. SERVICENOW-CFG-008, SERVICENOW-CFG-011. Per-schedule status history and shares; SNOW-DISCOVERY-NONE-RECENT covers total absence.
- SLA breach rate, change-without-approval rate, emergency-change share, problem-link share. SERVICENOW-MON-003, SERVICENOW-MON-007, SERVICENOW-MON-008. Rates/shares; the absolute conditions behind them are covered (SNOW-SLA-BREACHED, SNOW-CHANGE-IMPLEMENTED-UNAPPROVED, SNOW-CHANGE-EMERGENCY-OPEN, SNOW-INCIDENT-P1-NO-PROBLEM).
- Upgrade skipped records not reviewed. SERVICENOW-LCM-003. The skipped/review-status semantics on sys_upgrade_history_log vary by release, so a plain count risks a false pass on a malformed query term; wait for a first real read.
- Catalog items unused for 12 months; category/group sprawl. SERVICENOW-HYG-003, SERVICENOW-HYG-004. Usage counts over a long window and near-duplicate-name detection.
- Live references to the retired SysAid system in knowledge/catalog/templates. SERVICENOW-HYG-005. Full-text search aggregate across several tables.
- Scheduled imports that did not run in their period. SERVICENOW-LOG-002 (schedule half). scheduled_import holds no last-run field; the error half is covered by SNOW-IMPORT-SET-ERRORS.

## Needs cross-instance (snow-t) data

- No in-progress update set in production, and every set applied to prod came from test. SERVICENOW-LCM-004. The in-progress half is covered by SNOW-UPDATE-SET-IN-PROGRESS-OLD; provenance needs sys_remote_update_set origin.
- Test instance runs the same family/patch and was cloned recently. SERVICENOW-LCM-007. Two-instance comparison.
- Clone hygiene - exclusions scrub sensitive data, test MIDs are separate, test access limited. SERVICENOW-CFG-022. Reads on both instances.
- Test instance does not send/read production mail. SERVICENOW-CFG-013. Per-instance property comparison.
- Pre-upgrade clone-and-rehearse record. SERVICENOW-BCK-004. Clone history vs upgrade history.

## Attestation / manual - no API fact to read

- Vendor availability and maintenance windows; outage fallback procedure. SERVICENOW-AVL-003, SERVICENOW-AVL-004.
- Vendor backup RPO/retention and restore path; own periodic export; customisations in source control. SERVICENOW-BCK-001, SERVICENOW-BCK-002, SERVICENOW-BCK-003.
- Security log export to the SIEM; scheduled security-log review. SERVICENOW-LOG-008, SERVICENOW-MON-012.
- OAuth client ownership and token lifespans (the credential tables are not read). SERVICENOW-IAM-015. Partial: SNOW-OAUTH-CLIENT-REGISTERED flags that clients exist.
- Discovery-credential tiering (no Domain Admin credential in Discovery). SERVICENOW-CFG-010. Credential tables are not read; needs an LDAP memberOf join.
- Platform ownership, platform documentation, tool-overlap routing rule. SERVICENOW-HYG-001, SERVICENOW-HYG-002, SERVICENOW-HYG-006.
- Ticket-data retention/archive rules and sensitive-pattern review; CMDB data-source governance. SERVICENOW-HYG-007, SERVICENOW-HYG-008.
- Integration/mutual-TLS certificate inventory in the instance store. SERVICENOW-PKI-004.
- Licences and cost - Marketplace agreement ends, fulfiller and ITOM units, budget line. SERVICENOW-CST-001..005. AWS Marketplace / Subscription Management / attestation.

## Thresholds this pass adds

Set as `threshold.<name>` in the Keeper home; the value in the rule applies when it is not set.

| Threshold | Default | Rule |
|---|---|---|
| servicenow.max-inactive-role-grants | 0 | SNOW-ROLE-GRANT-TO-INACTIVE-USER |
| servicenow.max-acl-changes | 0 | SNOW-ACL-CHANGED-RECENTLY |
| servicenow.max-legacy-workflows | 0 | SNOW-LEGACY-WORKFLOW-ACTIVE |
| servicenow.max-oauth-clients | 0 | SNOW-OAUTH-CLIENT-REGISTERED |

## To confirm on the first real run

- The dot-walked encoded-query terms (`user.active=false`, `user.locked_out=true`,
  `user.web_service_access_only=true`, `role.elevated_privilege=true`) filter on the instance; the
  read-only account needs read on sys_user_has_role, sys_user_role and sys_user, or the rule reads
  as unknown rather than passing.
- `sys_public` carries `page` as a reference (name shown with display_value) and `active`; baseline
  public pages (login and the like) exist, so review rather than assume every hit is a leak.
- `sp_page.public` is the boolean that opens a portal page to anonymous visitors.
- `change_request.close_code` spelling for unsuccessful outcomes varies by instance; the rule
  matches the substring "unsuccessful", so confirm the local close-code values on the first run.
- `sys_auto_flush.tablename` holds the cleaned table and `age` the retention; confirm the audit
  table names in use (sys_audit, sys_audit_delete, sys_audit_relation) match this instance.
