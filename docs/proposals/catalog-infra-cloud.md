# Proposals - infrastructure and cloud catalogue port

Status: proposal only. Nothing here is loaded or run; another model writes the YAML from these specs.
Source: the archived check catalogue for the virtualisation, backup, monitoring and cloud-provider
areas (VMware, Veeam, Rubrik, Druva, Keepit, PRTG, Dynatrace, SolarWinds, Grafana, Coralogix, Azure,
AWS, GCP, FSx, WorkSpaces and the known-issue lists beside them), mapped row by row against the
rules in `rules\`, `docs\proposals\infrastructure.md`, the other catalogue proposals and the
integration types in `IntegrationTypes.cs`. The per-row map holds tenant detail and lives outside the
repo. This document is tenant-free: no names, hosts, addresses, amounts or counts of the estate.
Tenant lists (approved regions, expected users, critical systems, required alerts) are
`threshold.<name>` settings, and an empty threshold makes the rule n/a.

Written 2026-10-20 without contacting any system. Vendor documentation was **not** fetched in this
pass, so **no entry is marked verified**: `likely` means the path and fields are the documented ones
as known to the author; `guess` means the shape must be tried on a real tenant first. A wrong path
or field is `unknown` or n/a, never a pass.

Engine facts relied on (from `docs/RULES.md`): `http` is GET-only with none / basic / bearer /
api-key-header / api-key-query / oauth-client-credentials / session-login auth, `for_each` (one
level), `{DAYS_AGO:n}`; `graphql` and `store` exist; `store` rules read `row_seen` of other packs;
a missing field is n/a and a failed query is unknown.

Entry format: **ID** (rule file) - what it catches and why; severity; source; condition; refs; fix;
confidence. Refs are canonical: `NIST-800-53:XX-n`, `CIS-Controls-v8:n.n`, `CIS-AWS:n.n`. Where a
query is shared by several entries the first entry defines it and later ones say "same read". A
`[gap: ...]` tag means the check is expressible in principle but needs the engine feature named in
the last section.

Totals behind this document (rows of the old catalogue): covered 409, proposed elsewhere 47,
duplicate 46, new 343 (334 distinct ids below), needs an integration 670, not automatable 225.

---

## Integrations to add

Ranked by the number of old rows each one unlocks. "Rows" counts rows whose only route is that
integration; rows already covered by a Prowler import or by a proposal that itself needs the same
integration are noted separately.

### 1. `aws` - AWS API with SigV4 (271 rows; 19 more already proposed in `catalog-network-security.md`)

There is no AWS integration. The generic `http` type cannot sign requests, and most AWS read APIs
are POST (JSON 1.0/1.1 with `X-Amz-Target`) or XML query calls (EC2, RDS, IAM, ELB, Auto Scaling).
This is the same `aws` type that `catalog-network-security.md` section 2 already assumes; this
section is its specification.

**Protocol.** A new `aws` protocol in the http runner family: SigV4 signing in process (no CLI, no
SDK process), service and region per rule, read-only action allow-list enforced by the runner.
Supports JSON-RPC style (`X-Amz-Target` / `Action=` query) and REST-JSON, parses JSON and XML into
rows, pages with `NextToken` / `Marker` / `nextToken` / `NextMarker`, and fans out over a tenant
list of accounts and approved regions (`threshold.aws.accounts`, `threshold.aws.regions`). Global
services answer from a fixed region (IAM, Organizations, Route 53, CloudFront, Health, Cost
Explorer, Budgets, Billing: us-east-1).

**Auth.** `aws-role` : static keys are accepted for a first run only. Preferred, in order:
(1) IAM Roles Anywhere with a certificate from the estate's own CA (no secret at rest, session
credentials of one hour); (2) one read-only identity that assumes a read-only role in each member
account with an external id (`sts:AssumeRole`; the role is rolled out to members by a StackSet);
(3) a long-lived access key of a dedicated IAM user restricted by a source-address condition. An
interactive SSO session cannot be used unattended. Secrets: `accessKeyId` + `secretAccessKey`, or the
client certificate and key (stored in the vault).

**Read-only enforcement in the runner.** Allow only actions that start with Describe, List, Get,
Search or Lookup, and refuse by name the data-plane reads that return content: `s3:GetObject*`,
`secretsmanager:GetSecretValue`, `ssm:GetParameter*` with decryption, `lambda:GetFunction` (it returns
a code URL), `kms:Decrypt`, `logs:StartQuery` and `logs:GetQueryResults` (a query start is
write-class), `cloudtrail:LookupEvents` is allowed but its payloads are reduced to the fields the
rule names.

**Permission policy (attach to the read-only role in every account; the payer and delegated-admin
accounts need the organisation-level actions too).** Prefer the AWS managed policies
`SecurityAudit` and `ViewOnlyAccess` as the base and add this custom policy for what they lack. The
list is explicit on purpose: wildcard `Get*` would include secret reads.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "KeeperReadOnly", "Effect": "Allow", "Resource": "*", "Action": [
      "health:DescribeEventsForOrganization", "health:DescribeAffectedAccountsForOrganization",
      "health:DescribeAffectedEntitiesForOrganization", "health:DescribeEventDetailsForOrganization",
      "health:DescribeHealthServiceStatusForOrganization", "health:DescribeEvents",
      "ec2:Describe*", "ec2:SearchTransitGatewayRoutes", "ec2:GetEbsEncryptionByDefault",
      "ec2:GetEbsDefaultKmsKeyId", "ec2:GetInstanceMetadataDefaults", "ec2:GetSerialConsoleAccessStatus",
      "ec2:GetSnapshotBlockPublicAccessState", "ec2:GetImageBlockPublicAccessState",
      "ssm:DescribeInstanceInformation", "ssm:DescribeInstancePatchStates", "ssm:DescribePatchBaselines",
      "ssm:GetDefaultPatchBaseline", "ssm:DescribePatchGroups", "ssm:DescribeMaintenanceWindows",
      "ssm:ListInventoryEntries", "ssm:DescribeActivations", "ssm:GetDocument", "ssm:DescribeParameters",
      "cloudwatch:GetMetricData", "cloudwatch:ListMetrics", "cloudwatch:DescribeAlarms",
      "cloudwatch:DescribeAlarmsForMetric", "autoscaling:Describe*",
      "elasticloadbalancing:Describe*", "rds:Describe*", "docdb:Describe*", "elasticache:Describe*",
      "servicequotas:GetServiceQuota", "servicequotas:GetAWSDefaultServiceQuota",
      "servicequotas:ListServiceQuotas", "trustedadvisor:List*", "trustedadvisor:Get*",
      "support:DescribeSeverityLevels", "support:DescribeCases", "support:DescribeTrustedAdvisorChecks",
      "lambda:ListFunctions", "lambda:ListVersionsByFunction", "lambda:ListFunctionUrlConfigs",
      "lambda:ListEventSourceMappings", "eks:List*", "eks:Describe*", "mgn:Describe*", "drs:Describe*",
      "appstream:Describe*", "appstream:ListAssociated*", "workspaces:Describe*",
      "ds:DescribeDirectories", "controltower:ListLandingZones", "controltower:GetLandingZone",
      "controltower:ListEnabledControls", "cloudformation:ListStacks", "cloudformation:DescribeStacks",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors",
      "cloudtrail:LookupEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams",
      "logs:DescribeMetricFilters", "route53resolver:List*", "route53:ListHostedZones",
      "route53:ListHostedZonesByVPC", "route53:GetHostedZone", "route53:GetDNSSEC",
      "route53:ListHealthChecks", "route53:GetHealthCheckStatus", "route53domains:ListDomains",
      "route53domains:GetDomainDetail", "organizations:List*", "organizations:Describe*",
      "account:ListRegions", "account:GetAlternateContact", "account:GetContactInformation",
      "tag:GetResources", "ram:GetResourceShares", "ram:ListPrincipals", "ram:ListResources",
      "iam:ListUsers", "iam:ListRoles", "iam:GetRole", "iam:ListPolicies", "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed", "iam:ListSAMLProviders",
      "iam:ListOpenIDConnectProviders", "iam:GetOpenIDConnectProvider", "iam:GetAccountSummary",
      "iam:GenerateCredentialReport", "iam:GetCredentialReport", "iam:GetAccountAuthorizationDetails",
      "iam:ListOrganizationsFeatures", "iam:SimulatePrincipalPolicy", "iam:ListInstanceProfilesForRole",
      "sso-admin:List*", "sso-admin:Describe*", "sso-admin:GetInlinePolicyForPermissionSet",
      "identitystore:ListUsers", "identitystore:DescribeUser", "identitystore:ListGroups",
      "accessanalyzer:ListAnalyzers", "accessanalyzer:ListFindingsV2", "acm:ListCertificates",
      "acm:DescribeCertificate", "acm-pca:ListCertificateAuthorities", "kms:ListKeys",
      "kms:DescribeKey", "kms:GetKeyRotationStatus", "kms:GetKeyPolicy", "kms:ListGrants",
      "backup:List*", "backup:Describe*", "backup:GetBackupPlan", "backup:GetBackupVaultAccessPolicy",
      "backup:GetBackupVaultNotifications", "dlm:GetLifecyclePolicies", "dlm:GetLifecyclePolicy",
      "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListFindings", "guardduty:GetFindings",
      "securityhub:DescribeHub", "securityhub:GetEnabledStandards", "securityhub:GetFindings",
      "securityhub:ListAutomationRules", "securityhub:ListEnabledProductsForImport",
      "inspector2:BatchGetAccountStatus", "inspector2:ListCoverage", "inspector2:ListFindings",
      "macie2:GetMacieSession", "macie2:ListClassificationJobs", "config:Describe*",
      "config:GetComplianceDetailsByConfigRule", "events:ListRules", "events:ListTargetsByRule",
      "events:DescribeRule", "sns:ListTopics", "sns:ListSubscriptionsByTopic", "sns:GetSMSAttributes",
      "budgets:ViewBudget", "budgets:DescribeBudgets", "ce:Get*", "ce:ListCostAllocationTags",
      "ce:ListCostCategoryDefinitions", "compute-optimizer:Get*", "savingsplans:Describe*",
      "directconnect:Describe*", "invoicing:ListInvoiceSummaries", "invoicing:ListInvoiceUnits",
      "invoicing:GetInvoiceUnit", "marketplace-agreement:SearchAgreements",
      "marketplace-agreement:DescribeAgreement", "marketplace-agreement:GetAgreementTerms",
      "cur:DescribeReportDefinitions", "bcm-data-exports:ListExports", "bcm-data-exports:GetExport",
      "tax:ListTaxRegistrations", "fsx:Describe*", "lightsail:GetInstances",
      "lightsail:GetInstancePortStates", "lightsail:GetRelationalDatabases", "ecr:DescribeRepositories",
      "ecr:GetLifecyclePolicy", "kinesisvideo:ListStreams", "kinesisvideo:DescribeStream",
      "application-autoscaling:Describe*", "resource-explorer-2:ListIndexes",
      "resource-explorer-2:GetDefaultView", "sms-voice:DescribeSpendLimits",
      "sms-voice:DescribeAccountLimits", "s3:ListAllMyBuckets", "s3:GetBucketLocation",
      "s3:GetBucketVersioning", "s3:GetLifecycleConfiguration", "s3:GetBucketLogging",
      "s3:GetEncryptionConfiguration", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
      "s3:GetAccountPublicAccessBlock", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketOwnershipControls",
      "wafv2:ListWebACLs", "wafv2:GetLoggingConfiguration", "wafv2:GetWebACLForResource",
      "cloudfront:ListDistributions", "cloudfront:GetDistributionConfig", "apigateway:GET",
      "transfer:ListServers", "transfer:DescribeServer", "elasticfilesystem:DescribeFileSystems",
      "redshift:DescribeClusters", "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
      "sqs:GetQueueAttributes", "sqs:ListQueues", "dynamodb:ListTables", "dynamodb:DescribeTable"
    ] },
    { "Sid": "NeverReadContent", "Effect": "Deny", "Resource": "*", "Action": [
      "s3:GetObject", "s3:GetObjectVersion", "secretsmanager:GetSecretValue", "ssm:GetParameter",
      "ssm:GetParameters", "ssm:GetParametersByPath", "lambda:GetFunction", "kms:Decrypt",
      "logs:StartQuery", "logs:GetLogEvents", "logs:FilterLogEvents", "dynamodb:GetItem",
      "dynamodb:Query", "dynamodb:Scan", "sqs:ReceiveMessage"
    ] }
  ]
}
```

Notes on the policy. `apigateway:GET` is the only way to read API Gateway configuration and it also
reads API keys: scope it with `Resource` to `arn:aws:apigateway:*::/restapis/*` and `/apis/*` and
exclude `/apikeys` and `/usageplans/*/keys`. `ec2:Describe*` and `rds:Describe*` are inventory reads
only. `cloudtrail:LookupEvents` returns event payloads that can carry request parameters: reduce to
the named fields. The payer account additionally needs `organizations:*` reads, the Cost Explorer,
Budgets, Invoicing, Marketplace Agreement, Tax and Cost and Usage Report reads; the Health
organisational view needs a Business or Enterprise support plan and a delegated administrator.

**Paging and cost.** Every list has a token; the runner stops at `maxPages` and reports a partial
result. Cost Explorer bills per request, so cost rules share one read per day (`refresh: 1d`) and
cost rows are cached. CloudWatch `GetMetricData` is billed per metric requested: the metric rules
batch up to the API limit per call and use daily refresh.

**Rows it unlocks.** 271 old rows have only this route. Another 114 rows are covered today only
through a Prowler import (a periodic file, not a live read); with `aws` they could be rewritten as
live rules, which is optional. The rule files it enables: `aws.yaml` (prefix `AWS-`, generic reads),
`aws-network.yaml` (already specified in `catalog-network-security.md`) and a thin `fsx.yaml`.

**Why first.** It is the largest single block, it covers the cloud estate where the only evidence
today is a periodic scanner file or a person's memory, and the other cloud packs (backup, desktops,
file services, cost) all route through it.

### 2. `vsphere-soap` - vSphere Web Services (112 rows)

The vSphere Automation REST API has no host detail (maintenance mode, version, lockdown, NTP,
syslog, advanced settings), no snapshots, no performance counters, no events, no alarms, no DRS rules
and no VM extra-config. All of it is in the Web Services (SOAP) API at `https://<vcenter>/sdk`, which
the `vcenter` type already authenticates against. Needs a `soap` protocol in the http runner family:
POST of a fixed set of read-only methods (`RetrieveServiceContent`, `RetrievePropertiesEx`,
`ContinueRetrievePropertiesEx`, `QueryEvents`, `QueryPerf`, `QueryAvailablePerfMetric`, the vSAN and
PBM read methods), XML to rows, session cookie from `Login` using the same account as `vcenter`
(role: Read-only on the root with propagation). Refuse every method outside the allow-list.
Per-host advanced settings come from `OptionManager.QueryOptions`, services from `ServiceSystem`,
firewall from `FirewallSystem`, multipathing from `StorageSystem`. Auth reuses `vcenter-session`.
Rows: all host-level, VM-config, event and performance checks (112). It also lets the existing
per-VM rules stop depending on the deprecated `/rest` base path.

### 3. `keepit` - Keepit REST API (60 rows)

XML responses and some list operations are PUT with a query body (backlog, "Keepit"). Needs an XML
body reader in the http runner and an allow-listed read-only PUT for the documented list/query
operations; auth is a token or an API user (basic) per the vendor; endpoint is the tenant region
host. Rows: connector state, snapshots, jobs, scope, retention, users and roles, tokens,
notifications, seats (60). Until it exists, the export of the console report to `imports\` and a
`file` rule is the interim route.

### 4. `gcp` - Google Cloud APIs (57 rows) and 5. `google-admin` - Cloud Identity / Admin SDK (13 rows)

`gcp`: REST on `*.googleapis.com` (Resource Manager v3, Cloud Billing, Service Usage, Monitoring,
Logging, API Keys v2, IAM, Recommender, Org Policy, Cloud Quotas, Billing Budgets, Essential
Contacts, Cloud Asset, Security Command Center, Compute and Cloud SQL where enabled). Several reads
are POST by design (`projects:getIamPolicy`, `entries:list`, `timeSeries` is GET) and must be
allow-listed. Auth: a service account via the JWT-bearer grant (`urn:ietf:params:oauth:grant-type:
jwt-bearer`, RS256-signed assertion) giving a one-hour access token, or workload identity
federation; the generic `oauth-client-credentials` kind cannot do either. Roles: `roles/viewer`,
`roles/iam.securityReviewer`, `roles/cloudasset.viewer`, `roles/billing.viewer`, `roles/recommender.viewer`
at organisation level. No key file on disk: the key goes in the vault. `google-admin`: Admin SDK
Directory, Reports and Alert Center plus the Cloud Identity API; needs domain-wide delegation of a
service account to a read-only admin with the read-only scopes, same JWT grant with a `sub` claim.
Rows: 57 and 13.

### 6. `rubrik-cdm` - Rubrik cluster REST (28 rows)

The existing `rubrik` type reaches only `*.my.rubrik.com` (the cloud tenant). The appliance's own
REST (`/api/v1`, `/api/v2`, `/api/internal`) lives on the cluster host. A `rubrik-cdm` http type with
an API token as bearer and a per-cluster endpoint covers disks, runway, hardware, NTP/DNS/SMTP/SNMP/
syslog, support tunnel, encryption, certificates and guest credentials (28). Internal endpoints change
between releases, so every one is `guess` until read on the running version.

### 7. `azure-query` - allow-listed read POSTs on the `azure` type (28 rows)

Azure Resource Graph (`POST /providers/Microsoft.ResourceGraph/resources`), Cost Management query
and Log Analytics workspace queries are POST by design. Allow-list exactly those paths in the `azure`
type (Log Analytics is a different host and token audience, `api.loganalytics.io`). Resource Graph
also removes the paging gap and the nested-fan-out gap for the cross-resource checks (network
gateways per resource group, recovery protected items, policy states, security assessments, patch
assessments, guest configuration). Auth unchanged (Entra certificate). Rows: 28.

### 8. `fsx-remote-admin` (17), 9. `coralogix` (17), 10. `prtg-config-export` (17)

* `fsx-remote-admin`: WinRM to the constrained PowerShell endpoint the file service exposes
  (`Invoke-Command -ConfigurationName` with the read-only `Get-FSx*` cmdlets). Needs a `winrm-endpoint`
  protocol that runs an allow-listed list of cmdlets and returns objects as rows; auth Kerberos
  (`negotiate`) as a member of the file-system administrators group. Rows: shadow copies, dedup,
  quotas, SMB sessions, shares, share access, SMB server configuration (17).
* `coralogix`: DataPrime query API (read-only POST with a team key as bearer) plus the data-usage API;
  one integration instance per team. Needs a per-instance team key and an allow-listed query-text
  field in `http`. Rows: ingestion freshness, volume baselines, parsing, sources, usage (17).
* `prtg-config-export`: the PRTG table API cannot list triggers, dependencies, maintenance, SNMP
  credentials, users or notification templates. Either the newer PRTG API v2 (read-only, when the
  installed version has it) or a scheduled, sanitised export of the configuration file to `imports\`
  that strips secret fields before it reaches Keeper (never copy the raw file: it holds hashes and
  community strings). Then `file` rules with `format: xml`. Rows: 17.

### 11. Smaller

* `veeam-aws` (15): Veeam Backup for AWS appliance REST on its own host, token POST; sessions,
  policies, workers, accounts, repositories, users. Same shape as the `veeam` type with a different
  token path.
* `dynatrace-account` (15): the Account Management API on `api.dynatrace.com` (OAuth client with
  account read scopes, `oauth-client-credentials` kind is enough, host allow-list to add): users,
  groups, permissions, subscriptions, cost. Already in `docs/backlog/infrastructure.md`.
* `veeam-one` (5): Veeam ONE REST (`/api/v2.x`, token POST, `oauth-password` kind).
* `bindplane` (5): the log-gateway management REST (`/v1/agents`, API key header).
* `azure-keyvault` (4): Key Vault data plane needs a token for the `vault.azure.net` audience; list
  secrets/keys/certificates metadata only (attributes, never values). Add a second audience to the
  `azure` type's certificate auth.
* `dynatrace-platform` (2): Grail bucket definitions and Documents API on `*.apps.dynatrace.com`
  with a platform token (bearer); the `dynatrace` type allows the host but only `api-key-header` auth.
* `power-platform-admin` (2): `api.bap.microsoft.com` environments and application users; Entra auth.
* `kubernetes` (1) and `redfish` (1): read-only Kubernetes API (pod image digest) and per-BMC Redfish
  (`/redfish/v1`, basic or session auth, one instance per BMC).

---

## New checks

### VMware vCenter (`rules\vmware.yaml`, integration `vcenter`)

Per-VM reads reuse the existing for_each over powered-on VMs: `for_each: { path: /api/vcenter/vm,
params: { power_states: POWERED_ON }, field: vm }`, and `/rest/vcenter/vm/{vm}` for the map-shaped VM
detail (maps arrive as `[{key, value}]`).

**VMW-CLUSTER-IMAGE-NONCOMPLIANT** - a cluster managed by a lifecycle image whose hosts drift from the
desired image; patches and firmware are not what the image says. Severity: medium. Source: GET
`/api/esx/settings/clusters/{cluster}/software/compliance` through for_each over `/api/vcenter/cluster`
(field `cluster`), `paging: none`, `key: "{parent.cluster}"`; fields `status`, `scan_time`. Condition:
`status` ne `COMPLIANT`. Refs: NIST-800-53:SI-2, NIST-800-53:CM-6. Fix: remediate the cluster against
the image, or record why a baseline-managed cluster is exempt. Confidence: likely (a cluster that is not
image-managed answers an error: the rule treats it as n/a).

**VMW-VM-HARDWARE-VERSION-OLD** - a powered-on VM whose virtual hardware version is below a floor; old
versions miss security features (secure boot, vTPM) and are first to fall out of support. Severity: low.
Source: GET `/api/vcenter/vm/{vm}/hardware` (per VM), `key: "{parent.vm}"`; fields `version`
(`VMX_15`), `upgrade_status`. Condition: numeric part of `version` lt the threshold
`vmware.min-hardware-version` (default 15) - match `^VMX_(\d|1[0-4])$`. Refs: NIST-800-53:SI-2,
NIST-800-53:CM-2. Fix: schedule the upgrade in a window with a snapshot. Confidence: likely.

**VMW-VM-TOOLS-UPGRADE-POLICY-MANUAL** - tools are never upgraded automatically on power cycle, so
outdated tools stay outdated. Severity: low. Source: same read as VMW-VM-TOOLS-OUTDATED
(`/api/vcenter/vm/{vm}/tools`); field `upgrade_policy`. Condition: `upgrade_policy` eq `MANUAL`.
Refs: NIST-800-53:SI-2. Fix: set `UPGRADE_AT_POWER_CYCLE` where reboots are routine. Confidence: likely.
The time-sync flag of the same old row is not in REST.

**VMW-VM-GUEST-OS-UNSUPPORTED** - a powered-on VM configured for a guest OS past vendor support.
Severity: high (security lens). Source: `/rest/vcenter/vm/{vm}`; field `value.guest_OS` (an enum such
as `WINDOWS_SERVER_2012_R2_64`). Condition: `value.guest_OS` match the threshold
`vmware.unsupported-guest-pattern` (default `WINDOWS_SERVER_20(08|12)|WINDOWS_7|WINDOWS_8|RHEL_6|
CENTOS_6|UBUNTU_16`). Refs: NIST-800-53:SA-22, NIST-800-53:SI-2, CIS-Controls-v8:2.2. Fix: upgrade or
isolate and record the exception. Confidence: likely (the configured type can differ from the running
OS; the guest identity read below is the truth when tools run).

**VMW-VM-LEGACY-DEVICES** - virtual devices that cost performance or support (E1000 / E1000E NICs, IDE
controllers, LSI Logic SAS on a modern guest). Severity: low. Source: `/rest/vcenter/vm/{vm}`; fields
`value.nics[].value.type`, `value.sata_adapters`, `value.scsi_adapters[].value.type`. Condition:
`value.nics[].value.type` in [E1000, E1000E] or `value.scsi_adapters[].value.type` in [LSILOGIC,
LSILOGICSAS]. Refs: NIST-800-53:CM-2. Fix: move to VMXNET3 / PVSCSI with tools installed. Confidence:
likely.

**VMW-VM-UNNEEDED-DEVICES** - floppy, serial, parallel or USB devices attached to a VM; each is an
escape or exfiltration path and a vMotion blocker. Severity: low (security lens). Source: same detail
read; fields `value.floppies`, `value.serial_ports`, `value.parallel_ports`, `value.usb_controllers`
(maps). Condition: any of those maps `notempty`. Refs: NIST-800-53:CM-7, CIS-Controls-v8:4.8. Fix:
remove the device; ISO images are already VMW-VM-ISO-CONNECTED. Confidence: likely.

**VMW-VM-HOT-ADD-ENABLED** - CPU or memory hot-add on a VM; hot-add disables vNUMA and widens the
attack surface of guest-initiated changes. Severity: low. Source: same detail read; fields
`value.cpu.hot_add_enabled`, `value.memory.hot_add_enabled`. Condition: either eq true. Refs:
NIST-800-53:CM-6. Fix: disable unless a workload needs it. Confidence: likely. Oversized vCPU against
host cores is an engine gap (cross-object).

**VMW-VM-NAME-GUEST-HOSTNAME-MISMATCH** - the VM inventory name differs from the guest's own host
name, so every inventory-to-directory join misses it. Severity: info. Source: GET
`/api/vcenter/vm/{vm}/guest/identity` per VM (needs tools running); fields `host_name`, with the VM
name from `parent.name`. Condition: `host_name` ne `{parent.name}` (case-insensitive, short name).
Refs: NIST-800-53:CM-8. Fix: rename one side. Confidence: guess (field-against-parent comparison and
the short-name rule must be tried).

**VMW-CONTENT-LIBRARY-SUBSCRIBED-EXTERNAL** - a content library subscribed to an external URL pulls
unreviewed images and templates into the environment. Severity: medium (security lens). Source: GET
`/api/content/library` for ids, then `/api/content/library/{library}` through for_each; fields `type`,
`subscription_info.subscription_url`, `subscription_info.authentication_method`. Condition: `type` eq
`SUBSCRIBED` and the URL does not match the threshold `vmware.library-allowed-hosts`. Refs:
NIST-800-53:CM-7, NIST-800-53:SA-12, CIS-Controls-v8:2.5. Fix: unsubscribe or pin to an approved
internal source. Confidence: likely.

### Veeam Backup & Replication (`rules\veeam.yaml`, integration `veeam`, header `x-api-version: 1.2-rev0`)

Job configuration shares the `/api/v1/jobs` read defined in `infrastructure.md`. All entries below
are `[gap]`-free unless tagged.

**VEEAM-SERVER-VERSION-OUTDATED** - the backup server build is below the minimum build the tenant
accepts (patched against known exploited flaws). Severity: high (security lens). Source: GET
`/api/v1/serverInfo`, `paging: none`, `key: vbrId`; field `buildVersion`. Condition: `buildVersion`
lt the threshold `veeam.min-build` (version ordering is an engine gap: use a regular expression of
acceptable builds, `veeam.accepted-build-pattern`). Refs: NIST-800-53:SI-2, NIST-800-53:RA-5,
CIS-Controls-v8:7.4. Fix: install the current cumulative patch. Confidence: likely.

**VEEAM-PROXY-UNAVAILABLE** - a backup proxy that is disabled or unreachable; jobs queue or fall back
to a slower path. Severity: high. Source: GET `/api/v1/backupInfrastructure/proxies`, `items: data`,
`key: id`, `name: name`; fields `server.isDisabled`, `status`. Condition: `server.isDisabled` eq true
or `status` ne `Available`. Refs: NIST-800-53:CP-9, NIST-800-53:SI-4. Fix: enable or repair the
proxy, or remove it from the infrastructure. Confidence: likely.

**VEEAM-PROXY-NETWORK-MODE-ONLY** - a VMware proxy restricted to the network transport mode, which
loads the production network and slows every backup. Severity: low. Source: same proxies read; field
`server.transportMode`. Condition: eq `Nbd`. Refs: NIST-800-53:CP-9. Fix: allow direct storage access
or hot-add where the design supports it. Confidence: guess (field name).

**VEEAM-SOBR-EXTENT-STATE** - a scale-out repository extent in maintenance, sealed or evacuating
state; capacity and placement silently change. Severity: high. Source: GET
`/api/v1/backupInfrastructure/scaleOutRepositories`, `items: data`; fields
`performanceTier.performanceExtents[].status`. Condition: any extent status in [Maintenance, Sealed,
Evacuating]. Refs: NIST-800-53:CP-9, NIST-800-53:CP-10. Fix: finish or revert the maintenance.
Confidence: likely.

**VEEAM-SOBR-OFFLOAD-FAILED** - offload of restore points to the capacity or archive tier failed in
the window. Severity: medium. Source: GET `/api/v1/sessions` with `typeFilter` for the offload session
types and `createdAfterFilter: {DAYS_AGO:1}`; fields `result.result`, `sessionType`. Condition:
`result.result` eq `Failed`. Refs: NIST-800-53:CP-9, NIST-800-53:CP-6. Fix: read the session log; check
the object storage credentials and endpoint. Confidence: guess (session type names).

**VEEAM-REPOSITORY-FILLING-FAST** - a repository on course to be full within the planning horizon.
Severity: high. Source: `store` rule over `row_seen` of the repository states read (usedSpaceGB per run,
last several runs). Condition: linear growth per day times a horizon of days exceeds the free space
(threshold `veeam.runway-days`). Refs: NIST-800-53:CP-9, NIST-800-53:SC-5. Fix: add capacity, shorten
retention or move a chain. Confidence: guess [gap: run-to-run arithmetic; a store query can do it].

**VEEAM-SESSION-WAITING-RESOURCES** - sessions waiting for a repository or a slot; the backup window is
being consumed by queueing. Severity: medium. Source: `/api/v1/sessions` with `stateFilter` WaitingSlot /
WaitingRepository (REST 1.2-rev1 and later). Condition: each row older than a threshold. Refs:
NIST-800-53:CP-9. Fix: add tasks, proxies or repository capacity. Confidence: guess (revision pin).

**VEEAM-TASKSESSION-FAILED** - per-object failure text of a failed session (corruption, snapshot,
application-aware, credentials, CBT, licence): the cause behind VEEAM-SESSION-FAILED. Severity: high.
Source: GET `/api/v1/sessions/{id}/taskSessions` through for_each over failed sessions; fields
`result.result`, `result.message`, `name`. Condition: `result.result` in [Failed, Warning]; severity
and a class label from a message regular-expression table in thresholds. Refs: NIST-800-53:CP-9,
NIST-800-53:SI-4. Fix: by class: re-run with app-aware credentials, consolidate the VM, reset CBT, fix
licence. Confidence: guess (result fields unconfirmed in the reference).

**VEEAM-RESTORE-SESSION-FAILED** - a restore or instant-recovery session failed in 30 days; the
restore path itself is not working. Severity: medium. Source: `/api/v1/sessions`, `typeFilter: Restore`,
`createdAfterFilter: {DAYS_AGO:30}`. Condition: `result.result` eq `Failed`. Refs: NIST-800-53:CP-4,
NIST-800-53:CP-9. Fix: repeat the restore to a test target and fix the cause. Confidence: likely.

**VEEAM-SESSION-HEALTHCHECK-FAILED** - a backup health check (recheck of stored restore points) found
errors. Severity: high. Source: `/api/v1/sessions` filtered to health-check sessions in 30 days.
Condition: `result.result` ne `Success`. Refs: NIST-800-53:CP-9, NIST-800-53:SI-7. Fix: run an active
full on the affected chain. Confidence: guess (type names).

**VEEAM-AGENT-OUTDATED / VEEAM-AGENT-COMPUTER-OFFLINE** - agent-protected computers on an old agent
build, or discovered but offline. Severity: low / medium. Source: the protection-group / discovered
computers routes of the REST API; fields `agentVersion`, `status`. Condition: version below the
accepted pattern; status Offline. Refs: NIST-800-53:SI-2, NIST-800-53:CP-9. Fix: update the agent;
bring the computer online or remove it. Confidence: guess (routes differ by revision).

**VEEAM-JOB-LEGACY-TYPE** - jobs of a type the vendor has deprecated (legacy copy or tape-style
types). Severity: low. Source: `/api/v1/jobs`; field `type`. Condition: `type` in the threshold list
`veeam.deprecated-job-types`. Refs: NIST-800-53:SA-22. Fix: migrate to the current job type.
Confidence: guess.

**VEEAM-JOB-INVENTORY-CHANGED** - a job added, removed, disabled or retargeted since the last run;
unreviewed change of what is protected. Severity: medium. Source: `store` rule over `row_seen`
history of `/api/v1/jobs` (name, type, isDisabled, target repository, include count). Condition:
a difference between the two newest runs. Refs: NIST-800-53:CM-3, NIST-800-53:CM-5. Fix: confirm it
against a change record. Confidence: guess [gap: run-to-run comparison].

**VEEAM-JOB-EXPLICIT-VM-LIST** - a job that names individual VMs instead of a container, folder or
tag; a new VM is never protected. Severity: medium. Source: `/api/v1/jobs`; field
`virtualMachines.includes[].type`. Condition: any include of type `VirtualMachine` and none of type
Folder / ResourcePool / Tag / Datastore / Cluster. Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.1.
Fix: select by tag or folder. Confidence: likely.

**VEEAM-JOB-SQL-LOG-TRUNCATION-OFF** - transaction logs are never truncated or backed up for VMs
running a database; the log fills the disk. Severity: medium. Source: `/api/v1/jobs`; the
application-aware settings under `guestProcessing.appAwareProcessing` (SQL transaction log mode).
Condition: mode is `Never` with app-aware enabled. Refs: NIST-800-53:CP-9. Fix: truncate on success or
back up logs on an interval. Confidence: guess (field path unconfirmed).

**VEEAM-REPOSITORY-PER-MACHINE-OFF** - a repository without per-machine backup files; one corrupt
chain affects every machine in the job. Severity: low. Source: repositories read of
`infrastructure.md`; field `repository.advancedSettings.perVmBackup`. Condition: eq false. Refs:
NIST-800-53:CP-9. Fix: enable per-machine chains (new chains start with the next full). Confidence:
likely.

**VEEAM-JOB-NO-PERIODIC-FULL-OR-HEALTHCHECK** - a job with neither a periodic full nor a backup health
check; silent corruption is never found. Severity: medium. Source: `/api/v1/jobs`; fields
`storage.advancedSettings.backupHealth.isEnabled`, `.syntheticFulls.isEnabled`, `.activeFulls.isEnabled`.
Condition: all three eq false on an enabled job. Refs: NIST-800-53:CP-9, NIST-800-53:SI-7. Fix: enable
the health check monthly at least. Confidence: likely.

**VEEAM-JOB-CBT-DISABLED** - changed block tracking off on a vSphere job; every run reads the full
disk. Severity: low. Source: `/api/v1/jobs`; field
`storage.advancedSettings.vSphere.changedBlockTracking.isEnabled`. Condition: eq false. Refs:
NIST-800-53:CP-9. Fix: enable it. Confidence: likely.

**VEEAM-JOB-EXCLUSIONS-PRESENT** - disks or VMs excluded from a job; a protection gap that someone
decided once. Severity: info (lists them for review). Source: `/api/v1/jobs`; field
`virtualMachines.excludes`. Condition: `notempty`. Refs: NIST-800-53:CP-9. Fix: confirm each exclusion
and its reason. Confidence: likely.

**VEEAM-JOB-GUEST-CREDENTIAL-MISSING** - application-aware processing is on but no guest credential is
set; processing fails or is skipped. Severity: medium. Source: `/api/v1/jobs`; fields
`guestProcessing.appAwareProcessing.isEnabled`, `guestProcessing.guestCredentials.credentialsId`.
Condition: enabled and the credential absent. Refs: NIST-800-53:CP-9, NIST-800-53:IA-5. Fix: assign a
dedicated least-privilege account. Confidence: likely.

**VEEAM-CREDENTIAL-STALE** - a stored credential not modified for a long time; unrotated service
secrets. Severity: low (security lens). Source: GET `/api/v1/credentials`, `items: data`, `key: id`;
fields `creationTime`, `modificationTime`, `username`, `type`. Condition: `modificationTime` age-gt
365 (threshold `veeam.credential-max-age-days`). Refs: NIST-800-53:IA-5, CIS-Controls-v8:5.2. Fix:
rotate in the vault and update the credential. Confidence: likely.

**VEEAM-GUEST-CREDENTIAL-PRIVILEGED** - a job's guest-processing account is a member of a
domain-wide admin group; a backup server compromise becomes a domain compromise. Severity: high
(security lens). Source: `store` rule joining the credentials read with Active Directory group
membership of the account. Condition: username resolves to a member of a protected group. Refs:
NIST-800-53:AC-6, CIS-Controls-v8:5.4. Fix: use a local or delegated service account with
backup-operator rights on the guest only. Confidence: guess.

**VEEAM-ROLE-ADMIN-BROAD** - the backup console role assignments give administrator to a broad group
or a shared account. Severity: high (security lens). Source: the users-and-roles routes (not
confirmed in REST 1.2; newer revisions have role assignments). Condition: administrator role assigned
to a group, or to an account matching the shared-account pattern. Refs: NIST-800-53:AC-6,
NIST-800-53:AC-2. Fix: named accounts only, least privilege. Confidence: guess.

**VEEAM-MALWARE-DETECTION-OFF** - inline entropy scan or suspicious-file detection is off. Severity:
medium (security lens). Source: the malware-detection settings route; fields per feature. Condition:
a feature disabled. Refs: NIST-800-53:SI-3, NIST-800-53:CP-9, MITRE-ATTACK:T1486. Fix: enable the
features. Confidence: guess.

**VEEAM-OBJECT-NO-GFS-POINT** - an object that should have long-term points has no weekly or monthly
restore point. Severity: medium. Source: `/api/v1/restorePoints` GFS flags per object. Condition: no
point flagged GFS within the threshold. Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.2. Fix: enable GFS
on the job or copy. Confidence: guess [gap: per-object newest/aggregate].

**VEEAM-BACKUP-CHAIN-BROKEN** - session warnings that name a missing or broken chain. Severity: high.
Source: sessions in 30 days with warning text matching chain / missing / incomplete. Condition: any
match. Refs: NIST-800-53:CP-9, NIST-800-53:SI-7. Fix: run an active full. Confidence: guess.

**VEEAM-NETWORK-TRAFFIC-ENCRYPTION-OFF** - backup traffic across sites or to object storage is not
encrypted in transit. Severity: medium (security lens). Source: network traffic rules (route not
confirmed in REST). Condition: a rule with encryption off for external ranges. Refs:
NIST-800-53:SC-8. Fix: enable encryption on the rule. Confidence: guess.

**VEEAM-FAILOVER-PLAN-MISSING** - no replica failover plan exists although replica jobs do. Severity:
medium. Source: failover plan routes of later REST revisions. Condition: replica jobs exist and
`count: none` of plans. Refs: NIST-800-53:CP-2, NIST-800-53:CP-10. Fix: define plans for the tier-one
systems and test them. Confidence: guess.

**VEEAM-WAN-ACCELERATOR-STATE** - a WAN accelerator that is unavailable (when used). Severity: low.
Source: GET `/api/v1/backupInfrastructure/wanAccelerators` (12.1+). Condition: `status` ne `Available`.
Refs: NIST-800-53:CP-9. Fix: repair the accelerator or remove it. Confidence: guess.

### PRTG (`rules\prtg.yaml`, integration `prtg`)

**PRTG-DEVICE-PING-ONLY** - a device whose only sensor is a ping, or whose host is a bare address;
availability is monitored but nothing about the service. Severity: low. Source: the devices table
read of `infrastructure.md` (`content=devices`). Condition: `totalsens_raw` eq 1 and a ping-type
sensor, or `host` matching an IPv4 literal. Refs: NIST-800-53:SI-4, CIS-Controls-v8:1.1. Fix: add a
service sensor; name devices by host name. Confidence: likely.

**PRTG-SENSOR-INTERVAL-SUBMINUTE** - sensors polling more often than a minute without reason (load and
licence cost) - or critical service sensors slower than five minutes. Severity: low. Source: sensors
table with the `interval` column (raw seconds). Condition: `interval_raw` lt 60 or gt 300 on a
critical-group sensor (threshold `prtg.interval-min`, `prtg.interval-max-critical`). Refs:
NIST-800-53:SI-4. Fix: change the interval. Confidence: likely.

**PRTG-PROBE-VERSION-MISMATCH** - a remote probe running a different version from the core; unsupported
combination. Severity: medium. Source: probes table (`content=probes`, column `version` if exposed).
Condition: probe version ne core version (from `getstatus.htm` `Version`). Refs: NIST-800-53:SI-2.
Fix: update the probe. Confidence: guess.

**PRTG-SENSOR-TYPE-DEPRECATED** - sensor types in use that the vendor has deprecated. Severity: low.
Source: GET `/api/sensortypesinuse.json`; field type name. Condition: in the threshold list
`prtg.deprecated-sensor-types`. Refs: NIST-800-53:SA-22. Fix: replace the sensor. Confidence: guess.

**PRTG-NOTIFICATION-DELIVERY-FAILED** - a notification (mail, SMS, HTTP) that PRTG failed to deliver
in 7 days; alerts did not arrive. Severity: high. Source: messages table (`content=messages`,
`filter_drel=7days`), rows of the notification type with an error status. Condition: each. Refs:
NIST-800-53:IR-6, NIST-800-53:SI-4. Fix: repair the mail path; send a test. Confidence: guess.

**PRTG-BACKGROUND-TASKS-HIGH** - background, correlation or auto-discovery tasks piling up on the core.
Severity: low. Source: `getstatus.htm` fields (undocumented, same caveat as PRTG-LOW-MEMORY). Condition:
above threshold across two runs. Refs: NIST-800-53:SI-4. Fix: reduce discovery scope or enlarge the
core. Confidence: guess.

**PRTG-SENSOR-FLAPPING** - sensors with many state changes in 30 days, the noise that trains people to
ignore alerts. Severity: low. Source: messages table of state changes. Condition: state changes per
sensor above a threshold. Refs: NIST-800-53:SI-4. Fix: tune limits or add dependencies. Confidence:
guess [gap: count per group].

### Dynatrace (`rules\dynatrace.yaml`, integration `dynatrace`)

**DT-SYNTHETIC-LOCATION-UNHEALTHY** - a private synthetic location with failing nodes or no capacity;
monitors scheduled there stop. Severity: medium. Source: GET `/api/v2/synthetic/locations`, params
`{ type: PRIVATE }`, `items: locations`, `key: entityId`; field `status`. Condition: `status` ne
`ENABLED`. Refs: NIST-800-53:SI-4. Fix: repair or replace the node. Confidence: likely.

**DT-EXTENSION-CONFIG-ERROR** - an extension monitoring configuration in an error state, so a source
reports nothing. Severity: medium. Source: GET `/api/v2/extensions` then
`/api/v2/extensions/{name}/monitoringConfigurations` and each `/status`. Condition: `status` in
[ERROR, UNKNOWN]. Refs: NIST-800-53:SI-4. Fix: fix credentials or reachability. Confidence: guess
[gap: two-level fan-out].

**DT-SELF-MONITORING-EVENT** - ingestion throttling or resource-contention events raised by the
platform itself. Severity: low. Source: GET `/api/v2/events` with `eventSelector` for the resource
contention event types and `from: {DAYS_AGO:7}`. Condition: any. Refs: NIST-800-53:SI-4. Fix: reduce
ingest or raise limits. Confidence: guess.

**DT-DEPRECATED-EXTENSION-1** - first-generation plugins still installed. Severity: low. Source: GET
`/api/config/v1/plugins`. Condition: `notempty`. Refs: NIST-800-53:SA-22. Fix: migrate to the current
extension framework. Confidence: guess (endpoint may be gone).

**DT-AUDIT-CONFIG-CHANGE-UNEXPECTED-USER** - configuration or token changes by a principal outside the
expected administrators. Severity: medium (security lens). Source: GET `/api/v2/auditlogs`, params
`{ filter: category("CONFIG","TOKEN"), from: now-30d }` as an ISO window; fields `user`, `eventType`,
`entityId`, `timestamp`. Condition: `user` notin the threshold list `dynatrace.expected-admins`.
Refs: NIST-800-53:AU-6, NIST-800-53:AC-2. Fix: review the change; revoke if unauthorised. Confidence:
likely (timestamps are epoch ms - not read, so the age uses the query window).

**DT-LOG-MASKING-RULES-MISSING** - no sensitive-data masking rule exists for ingested logs. Severity:
high (privacy). Source: GET `/api/v2/settings/objects`, params `{ schemaIds:
"builtin:logmonitoring.sensitive-data-masking-settings", scopes: environment }`, `items: items`.
Condition: `count: none`. Refs: NIST-800-53:SI-12, NIST-800-53:SC-28. Fix: add masking for national
ids, tokens and passwords before storage. Confidence: likely (needs `settings.read`).

**DT-RUM-PRIVACY-OFF** - user monitoring that does not mask IP addresses or user input. Severity:
medium (privacy). Source: settings objects for `builtin:preferences.privacy`; fields
`maskIpAddresses`, `dataCaptureOptIn`. Condition: either false. Refs: NIST-800-53:SI-12. Fix: enable
masking and opt-in. Confidence: likely.

**DT-REQUEST-ATTRIBUTE-SENSITIVE** - a captured request attribute whose name suggests a secret or
identifier. Severity: high. Source: GET `/api/config/v1/service/requestAttributes`; field `name`,
`dataSources`. Condition: `name` match `(?i)pass|token|secret|id_?num|ssn`. Refs: NIST-800-53:SC-28,
NIST-800-53:SI-12. Fix: stop capturing it or mask. Confidence: likely.

(DYNATRACE-AVL-001, the vendor status feed, maps to the already proposed VENDOR-STATUS-INCIDENT-OPEN.)

**DT-ACTIVEGATE-NETWORKZONE-SINGLE** - a network zone with fewer than two ActiveGates. Severity:
medium. Source: the ActiveGates read of the file; fields `networkZone`, `connected`. Condition: count
of connected gates per zone lt 2. Refs: NIST-800-53:CP-10. Fix: add a second gate. Confidence: likely
[gap: count per group].

**DT-HOST-NO-HOSTGROUP** - a monitored host in no host group, so zones, tags and ownership cannot be
derived. Severity: low. Source: GET `/api/v2/entities`, params `{ entitySelector: type(HOST), fields:
"+properties.hostGroupName" }`, `items: entities`, `key: entityId`. Condition: `properties.hostGroupName`
empty. Refs: NIST-800-53:CM-8. Fix: assign a host group in the agent installation. Confidence: likely.

**DT-AUTOTAG-RULES-MISSING** - no auto-tagging rules, so nothing carries system, environment or owner.
Severity: low. Source: settings objects `builtin:tags.auto-tagging`. Condition: `count: none`. Refs:
NIST-800-53:CM-8. Fix: add rules. Confidence: likely.

**DT-ALERTING-PROFILE-DEFAULT-ONLY** - one default alerting profile for everything; no routing by
severity or system. Severity: medium. Source: settings objects `builtin:alerting.profile`. Condition:
`count: { op: lt, value: 2 }`. Refs: NIST-800-53:IR-6. Fix: define profiles per tier. Confidence: likely.

**DT-MAINTENANCE-WINDOW-LONG** - an enabled maintenance window with no end or longer than a limit;
alerts are suppressed for weeks. Severity: medium. Source: settings objects
`builtin:alerting.maintenance-window`; fields `enabled`, `schedule.onceRecurrence.endTime`,
`schedule.recurrenceType`. Condition: enabled and once-window longer than the threshold
`dynatrace.maintenance-max-days`, or no end. Refs: NIST-800-53:SI-4. Fix: shorten or remove. Confidence:
likely.

**DT-ANOMALY-DETECTION-DISABLED** - anomaly detection switched off for services or disks at
environment scope. Severity: high. Source: settings objects `builtin:anomaly-detection.services` and
`.infrastructure-disks`. Condition: detection `enabled` eq false. Refs: NIST-800-53:SI-4. Fix:
re-enable; tune thresholds instead of switching off. Confidence: likely.

**DT-SYNTHETIC-MONITOR-DISABLED / DT-SYNTHETIC-FAILING** - no enabled synthetic monitor exists, or an
enabled one has failed continuously. Severity: medium. Source: GET `/api/v1/synthetic/monitors`
(`enabled`) and per monitor `/api/v2/synthetic/execution/{id}/FAILED`. Condition: `count: none` where
`enabled` eq true; failing: last success older than a day. Refs: NIST-800-53:SI-4, CP-10. Fix: repair
the script or target. Confidence: guess for the execution route.

**DT-PROCESS-MONITORING-EXCLUSIONS** - process monitoring rules that exclude key processes from
monitoring. Severity: medium. Source: settings objects for the process monitoring rule schema (id to
confirm). Condition: rule mode eq monitoring off for a process in the threshold list. Refs:
NIST-800-53:SI-4. Fix: remove the exclusion. Confidence: guess.

**DT-PROBLEM-OPEN-NO-COMMENT** - an open problem older than a day with no comment. Severity: medium.
Source: GET `/api/v2/problems/{problemId}/comments` through for_each over the open-problem read.
Condition: `totalCount` eq 0 and the problem older than 1 day. Refs: NIST-800-53:IR-4. Fix: acknowledge
with a note. Confidence: likely.

**DT-NOTIFICATION-FAILED / DT-NOTIFICATION-RECIPIENT-GONE** - problem notifications that fail, or sent
to recipients who left. Severity: high. Source: audit log / events for failed sends; notification
settings e-mail recipients joined to Entra in a `store` rule. Condition: any failure; recipient not an
enabled mailbox. Refs: NIST-800-53:IR-6. Fix: repair the channel; route to a group mailbox.
Confidence: guess.

**DT-VULNERABILITY-CRITICAL-OPEN** - open critical or high vulnerabilities detected in monitored
processes. Severity: high (security lens). Source: GET `/api/v2/securityProblems`, params
`{ securityProblemSelector: 'status("OPEN"),riskLevel("CRITICAL","HIGH")' }`, `items: securityProblems`.
Condition: `each: any`. Refs: NIST-800-53:RA-5, NIST-800-53:SI-2, CIS-Controls-v8:7.7. Fix: patch the
library or process. Confidence: likely (needs the licence and `securityProblems.read`).

**DT-PROBLEM-RECURRING** - the same entity and title opening again and again. Severity: low. Source:
problems over 30 days. Condition: count per entity and title above a threshold. Refs: NIST-800-53:IR-4.
Fix: root-cause or tune. Confidence: guess [gap: count per group].

**DT-CREDENTIAL-USER-TYPE-INVENTORY** - credential-vault entries of a user type whose account is
privileged. Severity: medium (security lens). Source: GET `/api/v2/credentials` metadata plus a store
join with Active Directory membership. Condition: owner or username resolves to a protected group.
Refs: NIST-800-53:AC-6, IA-5. Fix: use a dedicated low-privilege account. Confidence: guess.

**DT-HOST-NOT-SEEN-30D** - hosts not reporting for 30 days still listed. Severity: low. Source: HOST
entities `lastSeenTms`. Condition: older than 30 days. Refs: NIST-800-53:CM-8. Fix: remove from
scope. Confidence: likely [gap: epoch-millisecond dates].

### SolarWinds Orion (`rules\solarwinds.yaml`, integration `http`, auth basic)

Shared read: GET `/SolarWinds/InformationService/v3/Json/Query`, params `{ query: "<SWQL>" }`,
`items: results`, `paging: none`, base path on the SWIS port; a read account with the read-only
role. Every SWQL statement is a single SELECT. Confidence for all entries below: likely for the
Orion.Nodes / Engines / Accounts / AlertConfigurations entities (documented), guess where marked.

**SW-NODE-NONE** - the node table is empty or unreadable; every other SW rule is quiet. Severity:
medium. Source: `SELECT NodeID, Caption FROM Orion.Nodes`, `key: NodeID`. Condition: `count: none`.
Refs: NIST-800-53:CA-7. Fix: grant the account view of all nodes. 

**SW-ENGINE-DOWN** - a polling engine that has stopped checking in. Severity: high. Source: `SELECT
EngineID, ServerName, KeepAlive FROM Orion.Engines`. Condition: `KeepAlive` age-gt 10 minutes (use
0.007 days; threshold `solarwinds.engine-max-silence-days`). Refs: NIST-800-53:SI-4, CP-10. Fix:
restart the service; check the database link.

**SW-NODE-DOWN / SW-NODE-DOWN-LONG** - managed nodes Down or Unknown, and those down for over 30 days.
Severity: high / low. Source: `SELECT Caption, Status, StatusDescription, LastSync, UnManaged FROM
Orion.Nodes WHERE UnManaged = 0`. Condition: `Status` in [2, 0, 3]; long: `LastSync` age-gt 30.
Refs: NIST-800-53:SI-4, CM-8. Fix: repair or remove the node.

**SW-NODE-UNMANAGED-LONG** - nodes muted for longer than a week. Severity: medium. Source: `SELECT
Caption, UnManaged, UnManageFrom, UnManageUntil FROM Orion.Nodes WHERE UnManaged = 1`. Condition:
`UnManageFrom` age-gt 7. Refs: NIST-800-53:SI-4. Fix: remanage or document.

**SW-PLATFORM-VERSION-OUTDATED** - installed platform or module version below an accepted pattern.
Severity: high (security lens). Source: `SELECT Name, Version FROM Orion.InstalledModules`. Condition:
version not in the threshold pattern `solarwinds.accepted-version`. Refs: NIST-800-53:SI-2, RA-5.
Fix: upgrade after the vendor advisory check.

**SW-NODE-SNMP-V2C** - nodes polled with SNMP below v3. Severity: medium (security lens). Source:
`SELECT Caption, SNMPVersion FROM Orion.Nodes`. Condition: `SNMPVersion` lt 3. Refs: NIST-800-53:SC-8,
IA-5. Fix: move to v3 authPriv where the device supports it.

**SW-ALERT-DISABLED** - alert definitions disabled, or no enabled alert exists. Severity: medium.
Source: `SELECT AlertID, Name, Enabled FROM Orion.AlertConfigurations`. Condition: `Enabled` eq false;
and `count: { op: lt, value: 1, where: { field: Enabled, op: eq, value: true } }`. Refs:
NIST-800-53:SI-4, IR-6. Fix: enable or delete.

**SW-ALERT-SUPPRESSION-LONG** - alert suppressions older than a week. Severity: medium. Source: SWQL on
`Orion.AlertSuppression` (where available). Condition: `SuppressFrom` age-gt 7. Refs: NIST-800-53:SI-4.
Fix: lift or document. Confidence: guess.

**SW-NCM-CONFIG-BACKUP-STALE** - network device configuration not downloaded recently (when NCM is
used). Severity: medium. Source: NCM schema last successful download per node. Condition: age-gt 2.
Refs: NIST-800-53:CP-9, CM-2. Fix: fix the credential or reachability. Confidence: guess.

**SW-NCM-INSECURE-PROTOCOL** - NCM connection profiles using Telnet or clear protocols. Severity: high
(security lens). Source: NCM connection profile tables. Condition: protocol in [Telnet, TFTP, FTP].
Refs: NIST-800-53:SC-8, CM-7. Fix: use SSH. Confidence: guess.

**SW-ACCOUNT-ADMIN-MANY / SW-ACCOUNT-IDLE-OR-LEFT** - too many administrator accounts; accounts idle
for 90 days or whose directory identity is gone. Severity: medium. Source: `SELECT AccountID, Enabled,
AllowAdmin, AccountType, LastLogin FROM Orion.Accounts`; second part a `store` join with AD and Entra.
Condition: count of `AllowAdmin` eq 1 above `solarwinds.max-admins`; `LastLogin` age-gt 90; disabled
identity. Refs: NIST-800-53:AC-2, AC-6, CIS-Controls-v8:5.3, 5.4. Fix: remove or disable.

**SW-CREDENTIAL-PRIVILEGED** - a stored Windows/WMI credential that is a domain admin. Severity: high
(security lens). Source: `Orion.Credential` names and types (never secrets) joined with AD group
membership. Condition: account in a protected group. Refs: NIST-800-53:AC-6. Fix: least-privilege
monitoring account. Confidence: guess.

**SW-ACTION-RECIPIENT-LEFT / SW-ALERT-UNACKNOWLEDGED** - alert e-mail actions to people who left;
triggered alerts nobody acknowledged. Severity: high / medium. Source: `Orion.Actions` recipient
addresses joined to Entra; `Orion.AlertHistory` for 30 days. Condition: recipient not an enabled
mailbox; triggered without acknowledgement. Refs: NIST-800-53:IR-6, IR-4. Fix: route to a group.
Confidence: guess.

**SW-LICENCE-NEAR-LIMIT** - licensed elements near the limit. Severity: medium. Source: the licence
usage tables (names to confirm). Condition: used above 90% of licensed. Refs: NIST-800-53:SA-4. Fix:
prune nodes or extend. Confidence: guess.

### Grafana (`rules\grafana.yaml`, integration `http`, auth bearer with a viewer service-account token; server-admin reads need an admin token; confidence is likely unless an entry says guess)

**GRAFANA-HEALTH-DATABASE-FAILING** - the health endpoint reports the database not ok. Severity: high.
Source: GET `/api/health`, `paging: none`, `key: "-"`; field `database`. Condition: `database` ne `ok`.
Refs: NIST-800-53:SI-4. Fix: check the database and storage. Confidence: likely.

**GRAFANA-DATASOURCE-UNHEALTHY** - a data source whose health check fails; panels and alerts on it are
blind. Severity: medium. Source: GET `/api/datasources/uid/{uid}/health` through for_each over
`/api/datasources` (field `uid`). Condition: `status` ne `OK`. Refs: NIST-800-53:SI-4. Fix: repair the
credential or endpoint. Confidence: likely.

**GRAFANA-ALERT-RULE-ERROR** - alert rules that evaluate with an error or no data. Severity: medium.
Source: GET `/api/prometheus/grafana/api/v1/rules`; `items: data.groups[].rules[]` (array walk),
fields `health`, `lastError`. Condition: `health` ne `ok`. Refs: NIST-800-53:SI-4. Fix: fix the query.
Confidence: guess (nested array items).

**GRAFANA-VERSION-OUTDATED** - version below the accepted pattern (security advisories). Severity:
high. Source: `/api/health` field `version`. Condition: not in `grafana.accepted-version-pattern`.
Refs: NIST-800-53:SI-2, RA-5. Fix: upgrade. Confidence: likely.

**GRAFANA-PLUGIN-UNSIGNED** - installed plugins whose signature is missing or invalid. Severity:
medium (security lens). Source: GET `/api/plugins`, params `{ embedded: "0" }`; field `signature`.
Condition: `signature` ne `internal` and ne `valid`. Refs: NIST-800-53:SI-7, CM-7. Fix: remove or
replace. Confidence: likely.

**GRAFANA-DASHBOARD-NOT-PROVISIONED** - dashboards and alert rules edited in the UI only; no
version-controlled copy. Severity: low. Source: alert-rule provisioning `provenance` field; dashboards
`provisioned`. Condition: provenance empty. Refs: NIST-800-53:CM-2, CP-9. Fix: provision from Git.
Confidence: guess.

**GRAFANA-DATABASE-SQLITE** - the configuration database is an embedded file (lost with its
container). Severity: medium. Source: GET `/api/admin/settings`; field `database.type`. Condition:
eq `sqlite3`. Refs: NIST-800-53:CP-9, CP-10. Fix: external database with backups. Confidence: likely.

**GRAFANA-ANONYMOUS-ACCESS-ON** - anonymous access enabled. Severity: high (security lens). Source:
`/api/admin/settings`; field `auth.anonymous.enabled`. Condition: eq true. Refs: NIST-800-53:AC-3,
AC-14, CIS-Controls-v8:6.1. Fix: disable. Confidence: likely.

**GRAFANA-PUBLIC-DASHBOARD-EXISTS** - dashboards or snapshots shared publicly. Severity: high
(security lens). Source: GET `/api/dashboards/public-dashboards` and `/api/dashboard/snapshots`.
Condition: `each: any` (snapshots with `external` true). Refs: NIST-800-53:AC-3, AC-22. Fix: remove or
approve. Confidence: likely.

**GRAFANA-SELF-SIGNUP-ON** - self sign-up on, or new users auto-assigned Editor or Admin. Severity:
high (security lens). Source: `/api/admin/settings`; `users.allow_sign_up`, `users.auto_assign_org_role`.
Condition: sign-up true, or role in [Editor, Admin]. Refs: NIST-800-53:AC-2, AC-6. Fix: disable, Viewer.
Confidence: likely.

**GRAFANA-INSECURE-COOKIE-OR-EMBEDDING** - embedding allowed, cookies not Secure/SameSite, transport
security headers off. Severity: medium (security lens). Source: `/api/admin/settings` security section.
Condition: any weak value. Refs: NIST-800-53:SC-8, SC-23. Fix: set strict values. Confidence: likely.

**GRAFANA-CONTACT-POINT-NONE** - no contact point or notification policy routes alerts anywhere.
Severity: high. Source: GET `/api/v1/provisioning/contact-points`. Condition: `count: none`. Refs:
NIST-800-53:IR-6. Fix: add a monitored group. Confidence: likely.

**GRAFANA-LOCAL-LOGIN-ENABLED** - the local login form and built-in admin remain next to SSO. Severity:
medium (security lens). Source: `/api/admin/settings`; `auth.disable_login_form`. Condition: eq false
while an SSO provider is enabled. Refs: NIST-800-53:IA-2, AC-2. Fix: disable and vault the admin.
Confidence: likely.

**GRAFANA-ADMIN-MANY** - more server administrators than allowed. Severity: medium. Source: GET
`/api/users` (server admin); field `isGrafanaAdmin`. Condition: count of true gt `grafana.max-admins`.
Refs: NIST-800-53:AC-6. Fix: reduce.

**GRAFANA-USER-IDLE / GRAFANA-EXTERNAL-USER** - users idle for 90 days; users outside the municipal
domain. Severity: low / medium. Source: GET `/api/users/search`; `lastSeenAt`, `email`. Condition:
`lastSeenAt` age-gt 90; `email` notmatch `grafana.internal-domain-pattern`. Refs: NIST-800-53:AC-2.
Fix: remove or time-bound.

**GRAFANA-SERVICE-ACCOUNT-TOKEN-NO-EXPIRY** - service-account tokens without expiry, and legacy API
keys. Severity: medium (security lens). Source: GET `/api/serviceaccounts/search` then
`/api/serviceaccounts/{id}/tokens`; also `/api/auth/keys`. Condition: `expiration` absent; any legacy
key. Refs: NIST-800-53:IA-5. Fix: rotate with expiry.

**GRAFANA-FOLDER-EDITABLE-BY-ALL** - a folder that every user can edit. Severity: low. Source:
`/api/folders/{uid}/permissions` through for_each. Condition: a role-based Editor permission for
`Viewer` or `Editor` base roles on a sensitive folder. Refs: NIST-800-53:AC-6. Fix: team permissions.
Confidence: guess.

**GRAFANA-DASHBOARD-STALE** - dashboards untouched for a year. Severity: info. Source: GET
`/api/search?type=dash-db`; field `updated`. Condition: age-gt 365. Refs: NIST-800-53:CM-8. Fix:
archive.

---

### Azure (`rules\azure.yaml`, integration `azure`)

Reads follow the existing file. "Per-subscription" means `path: /subscriptions/{subscriptionId}/
providers/<provider>/<type>` with `for_each: { path: /subscriptions, params: { api-version:
"2022-12-01" }, paging: none, field: subscriptionId, max: 500 }`, `key: id`, `name: name`, and the
`api-version` named for the provider. ARM pages with `nextLink`, which the runner does not follow yet
(backlog), so a large subscription is judged on its first page. Unless an entry says otherwise its
confidence is likely for the path and the fields it names, and refs are given only when they differ from
the neighbouring entry. Entries tagged `[gap: ...]` need the engine feature in the last section; a
tag `[store]` means a `store` rule over `row_seen` of this pack and another.

#### Identity and RBAC

**AZ-OWNER-COUNT** - a subscription with too many (or too few) Owner role holders; the owner set is the
subscription's blast radius. Severity: medium (security). Source: per-subscription
`Microsoft.Authorization/roleAssignments`, `api-version 2022-04-01`, `$filter: atScope()`; fields
`properties.roleDefinitionId` (Owner id `8e3af657-a8ff-443c-a75c-2fe8c4bcb635`), `properties.principalType`.
Condition: count of Owner assignments per subscription gt `azure.max-owners` (default 3) or lt 2
[gap: count per parent]. Refs: NIST-800-53:AC-6, CIS-Controls-v8:5.4. Fix: move people to scoped roles
and PIM. 

**AZ-PRIVILEGED-ROLE-PERMANENT** - Owner, Contributor, User Access Administrator or RBAC Administrator
held permanently instead of through PIM. Severity: high (security). Source: per-subscription
`roleAssignmentScheduleInstances`, `2020-10-01`; fields `properties.assignmentType`, `roleDefinitionId`.
Condition: `assignmentType` eq `Assigned` and the role id in the privileged list. Refs:
NIST-800-53:AC-2, AC-6, CIS-Controls-v8:5.4. Fix: make the assignment eligible.

**AZ-PIM-ELIGIBLE-NO-END** - eligible assignments with no end date or more than a year ahead. Severity:
medium. Source: `roleEligibilityScheduleInstances`, `2020-10-01`. Condition: `properties.endDateTime`
absent or `until-lt` fails the 365-day window. Refs: NIST-800-53:AC-2. Fix: set expiry and re-certify.

**AZ-PIM-POLICY-WEAK** - PIM settings for a privileged role that do not require MFA, justification or
approval, or allow long activation. Severity: medium (security). Source: `roleManagementPolicies` with
`roleManagementPolicyAssignments` per subscription; the `rules[]` array (rule ids `Enablement_EndUser_
Assignment`, `Expiration_EndUser_Assignment`, `Approval_EndUser_Assignment`). Condition: required
enablement lacks MultiFactorAuthentication / Justification; maximum duration above 8 hours [gap:
element-wise conditions on `rules[]`]. Refs: NIST-800-53:AC-2, IA-2. Fix: tighten the role policy.
Confidence: guess.

**AZ-ROLE-ASSIGNED-TO-USER-DIRECT** - roles granted to individual users rather than groups. Severity:
low. Source: role assignments per subscription, `properties.principalType`. Condition: eq `User` where
`properties.scope` is a subscription or resource group. Refs: NIST-800-53:AC-2. Fix: assign to a group.

**AZ-ROLE-ASSIGNMENT-DELETED-PRINCIPAL** - assignments whose principal no longer exists in Entra
(left behind by deletions); a reused object id inherits the access. Severity: low. Source: [store] join
of role assignment `principalId` with Entra user / group / service-principal ids from the entra pack.
Condition: principal id absent from all three. Refs: NIST-800-53:AC-2. Fix: remove. Confidence: guess.

**AZ-ROLE-ASSIGNMENT-PRIVILEGED-CHANGED** - a privileged assignment appeared or disappeared since the
last run. Severity: high (security). Source: [store] over `row_seen` history of role assignments
(privileged role ids). Condition: set difference of the two newest runs. Refs: NIST-800-53:AC-2, CM-3,
AU-6. Fix: confirm against a change or PIM record. Confidence: guess [gap: run-to-run comparison].

**XS-AZURE-ROLE-HOLDER-DISABLED / XS-AZURE-ROLE-HOLDER-GUEST / XS-AZURE-ROLE-HOLDER-MAILBOX** - an
Azure role held by a disabled or departed account; by a guest (B2B) user; by an everyday mail-enabled
account instead of a dedicated admin account. Severity: high / medium / medium (security). Source:
[store] join of role assignments (`principalId`, `principalType` User) with Entra users (`accountEnabled`,
`userType`, `mail`, `assignedLicenses`). Condition: disabled; `userType` eq Guest; mailbox-licensed with
a write role. Refs: NIST-800-53:AC-2, AC-6, PS-4, CIS-Controls-v8:5.3, 5.4, 6.2. Fix: revoke, use a
dedicated admin account.

**AZ-ROLE-FOREIGN-PRINCIPAL** - assignments to principals of another tenant, including partner admin
agents. Severity: high (security). Source: role assignments; `properties.principalType` eq
`ForeignGroup`, or a service principal whose home tenant differs. Condition: either. Refs:
NIST-800-53:AC-2, AC-20, CIS-Controls-v8:5.1. Fix: remove or document the relationship.

**AZ-LIGHTHOUSE-DELEGATION** - delegated resource management to a partner tenant. Severity: high
(security). Source: per-subscription `Microsoft.ManagedServices/registrationAssignments`,
`2022-10-01`, `$expandRegistrationDefinition=true`; fields `properties.registrationDefinition.properties.
managedByTenantId`, `authorizations[]`. Condition: `each: any`. Refs: NIST-800-53:AC-20, AC-6. Fix:
confirm contract and scope; remove if unused.

**AZ-WORKLOAD-IDENTITY-PRIVILEGED** - a service principal or managed identity with Owner, Contributor
or User Access Administrator at subscription or management-group scope. Severity: high (security).
Source: role assignments; `principalType` eq `ServicePrincipal`, privileged role ids. Condition: both.
Refs: NIST-800-53:AC-6, IA-9, CIS-Controls-v8:5.4. Fix: scope to the resources it needs.

**AZ-MANAGED-IDENTITY-UNUSED** - a user-assigned managed identity with no role assignment. Severity:
low. Source: per-subscription `Microsoft.ManagedIdentity/userAssignedIdentities` joined [store] to role
assignments. Condition: principal id has no assignment. Refs: NIST-800-53:AC-2, CM-8. Fix: delete.
Confidence: guess.

**AZ-CLASSIC-ADMIN-PRESENT** - classic co-administrators (retired model) still present. Severity:
medium (security). Source: per-subscription `Microsoft.Authorization/classicAdministrators`,
`2015-07-01`. Condition: entries beyond the account administrator. Refs: NIST-800-53:AC-6. Fix: replace
with RBAC.

**AZ-ROLE-RUNCOMMAND-PERMISSION** - role definitions (built-in and custom) that allow running commands as
SYSTEM on VMs (run command, extension writes, serial console). Severity: medium (security). Source:
`Microsoft.Authorization/roleDefinitions` per subscription, `2022-04-01`; `properties.permissions[].
actions`. Condition: contains `Microsoft.Compute/virtualMachines/runCommand/action` or `.../extensions/
write`; paired [store] with assignments to list holders. Refs: NIST-800-53:AC-6, MITRE-ATTACK:T1059.
Fix: restrict to named operators.

**AZ-KEYVAULT-DATA-ROLE-HUMAN / AZ-STORAGE-DATA-ROLE-BROAD** - Key Vault administrator / officer roles
or storage data roles granted to people, broad groups or guests. Severity: medium (security). Source:
role assignments at vault or storage scope and above; role names matching `Key Vault .* (Administrator|
Officer)` / `Storage .* Data .*`. Condition: principal type User or a group above a size threshold.
Refs: NIST-800-53:AC-6, SC-28. Fix: assign to a managed identity; keep human access eligible only.
Confidence: guess.

**AZ-BILLING-ROLE-ASSIGNMENT-REVIEW** - billing roles listed for review. Severity: info. Source: GET
`/providers/Microsoft.Billing/billingAccounts/{billingAccount}/billingRoleAssignments`, `2024-04-01`
via for_each over `billingAccounts`. Condition: `each: any`. Refs: NIST-800-53:AC-2, AC-6. Fix: confirm
holders against the finance owner. Confidence: likely.

**AZ-SP-ROLE-UNUSED** - a service principal holding Azure roles that has not signed in for 90 days.
Severity: low. Source: [store] join of role assignments with Graph beta
`/reports/servicePrincipalSignInActivities`. Condition: `lastSignInActivity` age-gt 90. Refs:
NIST-800-53:AC-2. Fix: remove the role. Confidence: guess.

**AZ-AUTOMATION-CREDENTIAL-STALE** - credentials in automation accounts not rotated for a year. Severity:
medium (security). Source: `Microsoft.Automation/automationAccounts` per subscription then
`/credentials` (names and `lastModifiedTime` only). Condition: age-gt 365. Refs: NIST-800-53:IA-5. Fix:
rotate or use a managed identity. [gap: two-level fan-out]

**AZ-VM-LOGIN-EXTENSION-MISSING** - privileged VMs without the Entra login extension, so sign-in is
local only. Severity: medium (security). Source: VM extensions (child resources). Condition: no
`AADLoginForWindows` / `AADSSHLoginForLinux`. Refs: NIST-800-53:IA-2. Confidence: guess [gap: two-level
fan-out].

#### Subscription and tenant

**AZ-SUBSCRIPTION-NONPROD-OFFER** - a subscription on a trial, student, developer or expiring offer.
Severity: medium. Source: `/subscriptions`; `subscriptionPolicies.quotaId`. Condition: match
`MSDN|FreeTrial|Sponsored|Education|AzurePass` (threshold `azure.nonprod-offers`). Refs:
NIST-800-53:CM-2, SA-4. Fix: move production to an enterprise or customer-agreement subscription.

**AZ-SUBSCRIPTION-TENANT-TRANSFER-OPEN** - subscriptions may leave or enter the tenant without
restriction. Severity: medium (security). Source: GET `/providers/Microsoft.Subscription/policies/
default`, `2021-10-01`; `properties.blockSubscriptionsLeavingTenant`, `blockSubscriptionsIntoTenant`.
Condition: either false. Refs: NIST-800-53:AC-3, CM-3. Fix: block both and list exempt principals.

**AZ-RESOURCE-OUTSIDE-APPROVED-REGION** - resources located outside the approved regions. Severity:
medium. Source: per-subscription GET `/subscriptions/{subscriptionId}/resources`, `2021-04-01`;
`location`, `type`. Condition: `location` notin `azure.approved-regions`. Refs: NIST-800-53:SA-9,
CM-8. Fix: move or record the exception.

**AZ-RESOURCE-TYPE-NOT-APPROVED** - resource types in use that are not on the approved-services list
(a procurement or government list). Severity: medium. Source: same resources read. Condition: `type`
notin `azure.approved-resource-types`. Refs: NIST-800-53:SA-4, SA-9. Fix: procure or remove.

**AZ-RESOURCEGROUP-MISSING-TAGS** - resource groups lacking mandatory tags (owner, environment, system,
cost centre). Severity: low. Source: per-subscription `/resourcegroups`, `2021-04-01`; `tags`.
Condition: any key of `azure.required-tags` absent. Refs: NIST-800-53:CM-8, CIS-Controls-v8:1.1. Fix:
tag, enforce with policy.

**AZ-RESOURCE-LOCK-MISSING** - no delete lock on subscription-critical resources. Severity: medium.
Source: per-subscription `Microsoft.Authorization/locks`, `2020-05-01`. Condition: no lock of level
CanNotDelete over resources on the critical list `azure.locked-resource-ids`. Refs: NIST-800-53:CP-9.
Confidence: guess.

**AZ-POLICY-ASSIGNMENT-NONE** - a subscription with no policy assignment at all. Severity: medium.
Source: per-subscription `Microsoft.Authorization/policyAssignments`, `2022-06-01`. Condition: `count:
none` per subscription [gap: count per parent]. Refs: NIST-800-53:CM-6, CA-7. Fix: assign the security
benchmark initiative.

**AZ-POLICY-EXEMPTION-NO-EXPIRY** - policy exemptions without an expiry date or category. Severity:
low. Source: `policyExemptions`, `2022-07-01-preview`; `properties.expiresOn`. Condition: absent.
Refs: NIST-800-53:CA-5. Fix: add expiry and reason.

**AZ-RETIRED-SKU-IN-USE** - resource SKUs the vendor has retired: Basic public IP, Basic load balancer,
Application Gateway v1, unmanaged disks. Severity: high. Source: per-subscription `publicIPAddresses`
(`sku.name`), `loadBalancers` (`sku.name`), `applicationGateways` (`properties.sku.tier`), VM
`properties.storageProfile.osDisk.vhd`. Condition: `Basic`, `Standard` tier v1 gateways, vhd present.
Refs: NIST-800-53:SA-22. Fix: migrate before the retirement date.

**AZ-IMAGE-STALE** - custom images and gallery versions older than 180 days. Severity: low. Source:
per-subscription `Microsoft.Compute/images`, `galleries/images/versions`; `properties.publishingProfile.
publishedDate`. Condition: age-gt 180. Refs: NIST-800-53:SI-2. Fix: rebuild from a patched base.

**AZ-SAAS-SUBSCRIPTION-RENEWAL** - SaaS marketplace subscriptions with an upcoming term end or no
auto-renew. Severity: medium. Source: GET `/providers/Microsoft.SaaS/resources`, `2018-03-01-beta`.
Condition: term end `until-lt` 60. Refs: NIST-800-53:SA-4. Fix: decide with procurement. Confidence:
guess.

**AZ-BILLING-INVOICE-OVERDUE** - an invoice past due. Severity: high. Source: GET `/providers/
Microsoft.Billing/billingAccounts/{billingAccount}/invoices`, `2024-04-01`, params `periodStartDate`,
`periodEndDate` ({DAYS_AGO:365} to {TODAY}), for_each over `billingAccounts`; `properties.status`.
Condition: eq `OverDue`. Refs: none (financial continuity). Fix: route to treasury.

**AZ-BUDGET-MISSING / AZ-COST-ANOMALY-ALERT-MISSING** - a subscription with no budget; none with a
cost-anomaly alert. Severity: medium. Source: per-subscription `Microsoft.Consumption/budgets`,
`2023-05-01`; `Microsoft.CostManagement/scheduledActions`, `kind` eq `InsightAlert`. Condition:
`count: none` per subscription [gap: count per parent]. Refs: NIST-800-53:SA-2. Fix: create with
notification recipients that are monitored.

**AZ-ADVISOR-COST-RECOMMENDATION** - cost recommendations listed with savings. Severity: low. Source:
per-subscription `Microsoft.Advisor/recommendations`, `2023-01-01`, `$filter: Category eq 'Cost'`.
Condition: `each: any`. Refs: NIST-800-53:SA-2. Fix: act or dismiss with a reason.

**AZ-HYBRID-BENEFIT-NOT-APPLIED** - Windows VMs paying the licence-included rate where the tenant holds
Software Assurance. Severity: low. Source: per-subscription VMs; `properties.licenseType`,
`storageProfile.imageReference.offer`. Condition: Windows image and `licenseType` ne `Windows_Server`
when `azure.sa-covered` is true. Refs: NIST-800-53:SA-4. Confidence: guess (the entitlement is a register
fact).

#### Compute and platform

**AZ-RESOURCE-HEALTH-UNAVAILABLE** - resources reporting Unavailable, Degraded or Unknown. Severity:
high. Source: per-subscription `Microsoft.ResourceHealth/availabilityStatuses`, `2022-10-01`;
`properties.availabilityState`. Condition: ne `Available`. Refs: NIST-800-53:SI-4, CP-10. Fix: read the
status reason. (Backlog: expressible, paging gap.)

**AZ-QUOTA-NEAR-LIMIT** - regional vCPU, public IP or NIC quotas near their limit. Severity: medium.
Source: `Microsoft.Compute/locations/{location}/usages` and the network equivalent;
`currentValue`, `limit`. Condition: `currentValue` gt `limit` times 0.9. Refs: NIST-800-53:CP-2, SC-5.
Fix: request an increase. [gap: subscription x location fan-out and field-versus-field arithmetic]

**AZ-STORAGE-CAPACITY-HIGH / AZ-STORAGE-NO-TRANSACTIONS** - storage near a quota; accounts with no
transactions in 90 days. Severity: medium / low. Source: `Microsoft.Insights/metrics` per storage
account (`UsedCapacity`, `Transactions`). Condition: thresholds. Refs: NIST-800-53:SC-5, CM-8. Fix:
grow or retire. Confidence: guess [gap: nested fan-out].

**AZ-APPSERVICE-STOPPED** - web apps in a stopped state. Severity: medium. Source: per-subscription
`Microsoft.Web/sites`, `2023-12-01`; `properties.state`. Condition: ne `Running`. Refs:
NIST-800-53:CP-10. Fix: start or delete.

**AZ-APPSERVICE-HTTPS-ONLY-OFF** - apps that accept HTTP. Severity: high (security). Source: sites;
`properties.httpsOnly`. Condition: eq false. Refs: NIST-800-53:SC-8, CIS-Controls-v8:3.10. Fix: enable.
Site config (TLS version, FTP, debugging, always-on) needs `config/web` per site [gap: nested
fan-out] and is **AZ-APPSERVICE-ALWAYS-ON-OFF** (low) and **AZ-APPSERVICE-RUNTIME-EOL** (medium: runtime
stack version past end of support, threshold list).

**AZ-APPSERVICE-PLAN-EMPTY** - plans with no apps still billing. Severity: low. Source: `Microsoft.Web/
serverfarms`; `properties.numberOfSites`. Condition: eq 0. Refs: NIST-800-53:CM-8. Fix: delete.

**AZ-APPSERVICE-CERT-EXPIRING / AZ-APPSERVICE-CERT-KV-SYNC** - web certificates near expiry; Key
Vault-referenced certificates out of sync. Severity: high / low. Source: `Microsoft.Web/certificates`,
`2023-12-01`; `properties.expirationDate`, `properties.keyVaultSecretStatus`. Condition: `until-lt` 30
(`azure.cert-notice-days`); status ne `Initialized`. Refs: NIST-800-53:SC-17, SI-2. Fix: renew.

**AZ-ARC-MACHINE-DISCONNECTED** - Arc-enabled servers disconnected or expired. Severity: medium.
Source: `Microsoft.HybridCompute/machines`, `2024-03-31-preview`; `properties.status`. Condition: in
[Disconnected, Expired]. Refs: NIST-800-53:SI-4, CM-8. Fix: reconnect the agent. 

**AZ-ARC-ESU-MISSING** - extended-security-update licences absent for end-of-support Windows servers.
Severity: high (security). Source: `Microsoft.HybridCompute/licenses` and machine licence profiles.
Condition: end-of-support OS without a linked licence. Refs: NIST-800-53:SI-2, SA-22. Confidence:
guess.

**AZ-MACHINE-OS-UNSUPPORTED** - Azure VMs and Arc machines on operating systems past end of support.
Severity: high (security). Source: VM `instanceView` (`osName`, `osVersion`; list with `statusOnly=true`
does not include them: use `$expand=instanceView`) and Arc `properties.osName/osVersion`. Condition:
match the unsupported-OS threshold pattern shared with `AZ-VM-SIZE-RETIRING`. Refs: NIST-800-53:SA-22,
SI-2. Fix: upgrade or isolate.

**AZ-VM-SIZE-RETIRING** - VM sizes on the vendor's retirement list. Severity: medium. Source: VMs;
`properties.hardwareProfile.vmSize`. Condition: match `azure.retiring-vm-sizes`. Refs: NIST-800-53:SA-22.
Fix: resize.

**AZ-VM-PATCH-MODE-MANUAL** - VMs with no managed patching mode. Severity: medium. Source: VMs;
`properties.osProfile.windowsConfiguration.patchSettings.patchMode`, linux equivalent. Condition: ne
`AutomaticByPlatform` and ne `AutomaticByOS`. Refs: NIST-800-53:SI-2. Fix: enable update management.

**AZ-VM-BOOT-DIAGNOSTICS-OFF** - boot diagnostics off. Severity: low. Source: VMs;
`properties.diagnosticsProfile.bootDiagnostics.enabled`. Condition: not true. Refs: NIST-800-53:SI-4.

**AZ-VM-ENCRYPTION-AT-HOST-OFF / AZ-VM-TRUSTED-LAUNCH-OFF** - VMs without encryption at host, or
without trusted launch (secure boot, vTPM). Severity: medium / low (security). Source: VMs;
`properties.securityProfile.encryptionAtHost`, `.securityType`, `.uefiSettings.*`. Condition: not true;
`securityType` ne `TrustedLaunch` on generation-2 VMs. Refs: NIST-800-53:SC-28, SI-7. Fix: enable on
re-deploy.

**AZ-VM-NO-ZONE-OR-AVSET** - VMs in no zone, availability set or scale set. Severity: medium. Source:
VMs; `zones`, `properties.availabilitySet.id`, `properties.virtualMachineScaleSet.id`. Condition: all
three absent. Refs: NIST-800-53:CP-10. Fix: place or accept single-instance risk with a record.

**AZ-VMSS-AUTO-REPAIR-OFF** - scale sets without automatic repairs. Severity: low. Source:
`virtualMachineScaleSets`; `properties.automaticRepairsPolicy.enabled`. Condition: not true.
Confidence: guess.

**AZ-SNAPSHOT-OLD** - disk snapshots older than 90 days. Severity: low. Source:
`Microsoft.Compute/snapshots`; `properties.timeCreated`. Condition: age-gt 90. Refs: NIST-800-53:CM-8.
Fix: delete or archive.

**AZ-RESOURCE-GROUP-EMPTY** - empty resource groups. Severity: low. Source: resource groups against
resources [store join]. Condition: no resource. Refs: NIST-800-53:CM-8. [gap: join]

**AZ-DEVTEST-SHUTDOWN-MISSING** - development or test VMs with no auto-shutdown schedule. Severity: low.
Source: `Microsoft.DevTestLab/schedules` per subscription joined to VMs by tag. Condition: VM tagged
non-production with no schedule. Refs: NIST-800-53:CM-8. Confidence: guess.

**AZ-AKS-VERSION-UNSUPPORTED** - managed Kubernetes clusters on a version outside support. Severity:
high (presence-gated). Source: `Microsoft.ContainerService/managedClusters`, `2024-02-01`;
`properties.kubernetesVersion`. Condition: not in `azure.supported-aks-versions`. Refs:
NIST-800-53:SI-2. Fix: upgrade.

**AZ-DB-ENGINE-EXTENDED-SUPPORT** - managed databases on engine versions in paid extended support or
past end of life. Severity: medium (presence-gated). Source: flexible server lists
(`Microsoft.DBforPostgreSQL`, `Microsoft.DBforMySQL`, `Microsoft.Sql/managedInstances`);
`properties.version`. Condition: match the threshold list. Refs: NIST-800-53:SA-22. Confidence: guess.

**AZ-AUTOMATION-RETIRED-FEATURE** - run-as accounts or retired runbook runtimes. Severity: medium
(presence-gated). Source: automation accounts; runbooks `properties.runbookType`. Condition: in the
retired list. Refs: NIST-800-53:SA-22. Confidence: guess [gap: two-level fan-out].

**AZ-DATABRICKS-PUBLIC-NETWORK-ACCESS** - workspaces reachable from the internet or not VNet-injected.
Severity: medium (presence-gated). Source: `Microsoft.Databricks/workspaces`;
`properties.publicNetworkAccess`, `properties.parameters.enableNoPublicIp.value`. Condition: `Enabled`;
false. Refs: NIST-800-53:SC-7. 

#### Network

**AZ-NSG-MGMT-PORT-INTERNET** - a network security group that allows management ports (RDP, SSH, WinRM,
SMB, RPC, SQL) from the internet. Severity: critical (security). Source: per-subscription
`Microsoft.Network/networkSecurityGroups`, `2023-11-01`; `properties.securityRules[].properties`
(`direction`, `access`, `sourceAddressPrefix`, `destinationPortRange(s)`). Condition: Inbound, Allow,
source in [`*`, `Internet`, `0.0.0.0/0`] and a port in the management list - all on the same rule
element [gap: same-element conditions and port ranges]. Refs: NIST-800-53:SC-7, AC-17, CIS-Controls-
v8:12.2, MITRE-ATTACK:T1133. Fix: Bastion or just-in-time access; narrow the source.

**AZ-NSG-ANY-INTERNET** - rules that allow any port, UDP or wide ranges from the internet. Severity:
high (security). Source and gap as above. Condition: Allow from Internet with port `*` or a range wider
than a limit. Refs as above.

**AZ-PUBLIC-IP-NEW** - a public address appeared since the last run. Severity: medium (security).
Source: [store] over `row_seen` history of public IP addresses. Condition: new id. Refs:
NIST-800-53:CM-3, SC-7. Fix: confirm the need. Confidence: guess.

**AZ-SUBNET-NO-NSG / AZ-SUBNET-DEFAULT-OUTBOUND** - subnets without an NSG (excluding gateway and
bastion subnets); subnets relying on implicit default outbound access. Severity: medium / low. Source:
per-subscription `virtualNetworks`; `properties.subnets[]` (`networkSecurityGroup`,
`defaultOutboundAccess`). Condition: `networkSecurityGroup` absent and name not in the exempt list;
`defaultOutboundAccess` absent or true. Refs: NIST-800-53:SC-7. Fix: attach an NSG; add explicit
egress.

**AZ-VNET-PEERING-DISCONNECTED** - a peering not Connected. Severity: high. Source: `virtualNetworks`;
`properties.virtualNetworkPeerings[].properties.peeringState`. Condition: ne `Connected`. Refs:
NIST-800-53:CP-10, SC-7. Fix: re-sync or recreate.

**AZ-VNET-ADDRESS-OVERLAP** - virtual network address spaces that overlap each other or the on-premises
ranges. Severity: medium. Source: `virtualNetworks`; `properties.addressSpace.addressPrefixes`.
Condition: pairwise CIDR overlap [gap: address arithmetic across rows]. Refs: NIST-800-53:SC-7, CM-2.

**AZ-VNET-DDOS-OFF** - networks fronting public services without DDoS protection. Severity: low.
Source: `virtualNetworks`; `properties.enableDdosProtection`. Condition: false where a public IP is
attached [store]. Refs: NIST-800-53:SC-5.

**AZ-NETWORK-WATCHER-MISSING** - no Network Watcher in a region in use. Severity: low. Source: per-
subscription `Microsoft.Network/networkWatchers`; locations of resources. Condition: region without one
[gap: count per group].

**AZ-FLOW-LOGS-MISSING** - virtual networks without flow logs, traffic analytics or enough retention.
Severity: medium. Source: `networkWatchers/{w}/flowLogs`. Condition: absent or `retentionPolicy.days` lt
90. Refs: NIST-800-53:AU-2, AU-11, CIS-Controls-v8:8.2. [gap: two-level fan-out]

**AZ-APPGW-WAF-DETECTION-ONLY** - application gateways whose WAF is in detection mode or off. Severity:
high (security). Source: per-subscription `applicationGateways`;
`properties.webApplicationFirewallConfiguration.firewallMode`, `.enabled`. Condition: not `Prevention`.
Refs: NIST-800-53:SC-7, SI-10. Fix: move to prevention after tuning.

**AZ-SQL-SERVER-WEAK-AUTH** - SQL servers with SQL authentication allowed, TLS below 1.2 or public
network access. Severity: high (security). Source: per-subscription `Microsoft.Sql/servers`,
`2023-05-01-preview`; `properties.administrators.azureADOnlyAuthentication`, `minimalTlsVersion`,
`publicNetworkAccess`. Condition: false; lt 1.2; `Enabled`. Refs: NIST-800-53:IA-2, SC-8, SC-7.

**AZ-ACR-ADMIN-USER-ENABLED** - container registries with the shared admin user, or public network
access. Severity: medium (security). Source: `Microsoft.ContainerRegistry/registries`;
`properties.adminUserEnabled`, `publicNetworkAccess`. Condition: true; `Enabled`. Refs:
NIST-800-53:IA-2, SC-7.

**AZ-PAAS-LOCAL-AUTH-ENABLED** - Cosmos DB, Service Bus, Event Hubs and similar with key-based local
authentication on. Severity: low. Source: per-provider lists; `properties.disableLocalAuth`. Condition:
false. Refs: NIST-800-53:IA-2. Confidence: guess.

**AZ-FILES-SMB-WEAK** - Azure Files allowing old SMB versions, weak channel encryption or NTLMv2.
Severity: medium (security). Source: storage accounts then `fileServices/default`;
`properties.protocolSettings.smb`. Condition: versions include 2.1 or 3.0, channel encryption lacks
AES-256-GCM. Refs: NIST-800-53:SC-8. [gap: two-level fan-out]

**AZ-STORAGE-LRS-ONLY** - storage accounts on locally redundant storage only. Severity: low. Source:
`Microsoft.Storage/storageAccounts`, `2023-05-01`; `sku.name`. Condition: `Standard_LRS` or
`Premium_LRS` on accounts in `azure.critical-storage`. Refs: NIST-800-53:CP-9, CP-6.

**AZ-STORAGE-PUBLIC-NETWORK-DEFAULT-ALLOW** - storage with the firewall default Allow and public
network access on. Severity: medium (security). Source: storage accounts;
`properties.networkAcls.defaultAction`, `publicNetworkAccess`. Condition: `Allow`; `Enabled`. Refs:
NIST-800-53:SC-7.

**AZ-KEYVAULT-PUBLIC-NETWORK-ACCESS** - vaults reachable from all networks. Severity: medium (security).
Source: `Microsoft.KeyVault/vaults`, `2023-07-01`; `properties.publicNetworkAccess`,
`networkAcls.defaultAction`. Condition: `Enabled` and `Allow`. Refs: NIST-800-53:SC-7.

**AZ-KEYVAULT-ACCESS-POLICY-MODEL** - vaults still on legacy access policies. Severity: medium
(security). Source: vaults; `properties.enableRbacAuthorization`. Condition: false. Refs:
NIST-800-53:AC-3, AC-6. Fix: switch to RBAC.

**AZ-KEYVAULT-DELETED-PENDING-PURGE** - soft-deleted vaults awaiting purge. Severity: low. Source:
GET `/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/deletedVaults`, `2023-07-01`;
`properties.scheduledPurgeDate`. Condition: `each: any` with a deadline. Refs: NIST-800-53:SC-12.

#### Logging, monitoring and Defender

**AZ-ACTIVITY-LOG-DIAGNOSTIC-MISSING** - subscription activity log not exported to a workspace or
storage with the required categories. Severity: high (security). Source: per-subscription GET
`/subscriptions/{subscriptionId}/providers/microsoft.insights/diagnosticSettings`, `2021-05-01-preview`;
`logs[].category`. Condition: none exports Administrative, Security, Policy, Alert. Refs:
NIST-800-53:AU-2, AU-4, AU-12, CIS-Controls-v8:8.2. 

**AZ-ENTRA-DIAGNOSTIC-SETTINGS-MISSING / AZ-INTUNE-DIAGNOSTIC-SETTINGS-MISSING** - Entra sign-in and
audit logs (and Intune logs) not exported. Severity: high / low. Source: GET `/providers/
microsoft.aadiam/diagnosticSettings`, `2017-04-01-preview`; `/providers/microsoft.intune/
diagnosticSettings`. Condition: `count: none` or lacking SignInLogs, AuditLogs. Refs: NIST-800-53:AU-2,
AU-6.

**AZ-RESOURCE-DIAGNOSTIC-SETTINGS-MISSING** - key vaults, recovery vaults and other resource types with
no diagnostic setting. Severity: medium. Source: `{resourceId}/providers/Microsoft.Insights/
diagnosticSettings` per resource. Condition: `count: none` per resource. Refs: NIST-800-53:AU-2, AU-12.
[gap: two-level fan-out]

**AZ-LAW-INGESTION-CAPPED / AZ-LAW-RETENTION-SHORT** - a workspace at its daily cap, or retention below
365 days for audit data. Severity: high / medium. Source: per-subscription `Microsoft.OperationalInsights/
workspaces`, `2022-10-01`; `properties.workspaceCapping`, `properties.retentionInDays`. Condition:
`dailyQuotaGb` set and ingestion stopped (needs a query for the stop); `retentionInDays` lt 365. Refs:
NIST-800-53:AU-4, AU-11. Table-level retention needs `workspaces/{w}/tables` [gap: nested].

**AZ-ACTIVITY-LOG-PRIVILEGE-CHANGE** - role, policy or network changes in the activity log in the last
7 days. Severity: info (listing for review). Source: per-subscription `Microsoft.Insights/eventtypes/
management/values`, `2015-04-01`, `$filter: eventTimestamp ge {DAYS_AGO:7}`; `operationName.value`,
`caller`. Condition: operation matches `roleAssignments/write|delete`, `policyAssignments/delete`,
`securityRules/write`. Refs: NIST-800-53:AU-6, CM-5. **AZ-ACTIVITY-LOG-REPEATED-FAILURE** - the same
operation failing repeatedly (low) [gap: count per group].

**AZ-DEFENDER-SERVERS-EXTENSIONS-OFF / AZ-DEFENDER-MDE-INTEGRATION-OFF** - Defender for Servers paid but
agentless scanning off; the endpoint-detection integration off. Severity: medium (security). Source:
`pricings/VirtualMachines`, `2024-01-01`; `properties.extensions[]` (`name`, `isEnabled`);
`Microsoft.Security/settings`, `2022-05-01`, name `WDATP`; `properties.enabled`. Condition: tier Standard
with an extension false; enabled false. Refs: NIST-800-53:SI-3, SI-4, CIS-Controls-v8:10.1.

**AZ-DEFENDER-MULTICLOUD-CONNECTOR-MISSING / AZ-DEFENDER-CONTINUOUS-EXPORT-MISSING /
AZ-DEFENDER-SECURITY-CONTACT-MISSING** - no cloud connector for the other clouds in use; no export of
alerts and recommendations; no security contact. Severity: low / medium / medium. Source:
`Microsoft.Security/securityConnectors`, `2023-10-01-preview`; `Microsoft.Security/automations`,
`2023-12-01-preview`; `securityContacts`, `2023-12-01-preview` (`properties.emails`,
`notificationsByRole`). Condition: `count: none` / emails empty. Refs: NIST-800-53:SI-4, IR-6.

**AZ-DEFENDER-ALERT-OPEN / AZ-DEFENDER-RECOMMENDATION-HIGH-UNHEALTHY / AZ-SECURE-SCORE-LOW** - active
high or medium alerts; unhealthy high-severity recommendations; a secure score below a target.
Severity: high / medium / low. Source: per-subscription `Microsoft.Security/alerts`, `2022-01-01`
(`properties.status`, `severity`); `assessments`, `2021-06-01` (`properties.status.code`,
`metadata.severity`); `secureScores`, `2020-01-01` (`properties.score.percentage`). Condition: Active or
InProgress; Unhealthy and High; score lt `azure.secure-score-min`. Refs: NIST-800-53:SI-4, RA-5. The
score is a trend, not a task: report it as info unless a target is set.

**AZ-ACTIVITY-LOG-ALERT-MISSING / AZ-SERVICE-HEALTH-ALERT-MISSING / AZ-RESOURCE-HEALTH-ALERT-MISSING /
AZ-ACTION-GROUP-NO-RECEIVER / AZ-METRIC-ALERT-NONE / AZ-ALERT-NEW-UNHANDLED** - no activity-log alert on
policy / NSG / firewall changes; none for service health; none for resource health on critical
resources; action groups with no working receiver; no metric or log alerts on production; fired alerts
left in New. Severity: medium. Source: per-subscription `Microsoft.Insights/activityLogAlerts`
(`2020-10-01`, `properties.condition.allOf`, `enabled`), `actionGroups` (`2023-01-01`, receivers),
`metricAlerts`, `scheduledQueryRules`; `Microsoft.AlertsManagement/alerts` (`properties.essentials.
alertState`). Condition: required category absent; receivers empty or status not Enabled; counts zero
[gap: count per parent]; `alertState` eq New and older than a day. Refs: NIST-800-53:SI-4, IR-6, AU-6.

**AZ-APPINSIGHTS-CLASSIC** - application insights components not workspace-based. Severity: low.
Source: `Microsoft.Insights/components`; `properties.WorkspaceResourceId`. Condition: absent. Refs:
NIST-800-53:SI-4. 

**AZ-SENTINEL-NOT-ONBOARDED** - no SIEM onboarding on the audit workspace. Severity: medium. Source:
`workspaces/{w}/providers/Microsoft.SecurityInsights/onboardingStates`. Condition: `count: none`.
Confidence: guess [gap: two-level fan-out].

#### Backup

**AZ-BACKUP-VAULT-SOFT-DELETE-OFF / AZ-BACKUP-VAULT-LRS / AZ-BACKUP-VAULT-PUBLIC-NETWORK /
AZ-BACKUP-VAULT-ALERTS-OFF** - recovery vaults without always-on soft delete or immutability; on local
redundancy only; reachable from public networks; without failure alerts. Severity: high / medium / low
/ medium (security for the first). Source: per-subscription `Microsoft.RecoveryServices/vaults`,
`2023-04-01`; `properties.securitySettings.softDeleteSettings`, `immutabilitySettings`,
`properties.publicNetworkAccess`, `properties.monitoringSettings.azureMonitorAlertSettings`;
redundancy from `backupstorageconfig/vaultstorageconfig` [gap: nested]. Condition: soft delete not
AlwaysON; immutability Disabled; `Enabled`; alerts for job failures false. Refs: NIST-800-53:CP-9, CP-6,
SC-7, CIS-Controls-v8:11.4.

**AZ-BACKUP-POLICY-RETENTION-SHORT** - policies whose retention is below the records requirement.
Severity: medium. Source: `vaults/{v}/backupPolicies`, `2023-04-01`; `properties.retentionPolicy`.
Condition: daily / weekly / monthly / yearly below `azure.backup-min-retention`. Refs: NIST-800-53:CP-9.
[gap: two-level fan-out]

**AZ-FILESHARE-SOFT-DELETE-OFF / AZ-BLOB-SOFT-DELETE-OFF / AZ-SQL-LTR-MISSING** - file shares, blobs
and databases without soft delete / versioning / long-term retention. Severity: medium. Source:
`storageAccounts/{a}/fileServices/default` (`shareDeleteRetentionPolicy`), `blobServices/default`
(`deleteRetentionPolicy`, `isVersioningEnabled`), SQL `databases/{d}/backupLongTermRetentionPolicies/
default`. Condition: disabled or absent. Refs: NIST-800-53:CP-9, SI-12. [gap: two-level fan-out]

### Rubrik Security Cloud (`rules\rubrik.yaml`, system `rubrik`, integration `rubrik`)

The `rubrik` type and its GraphQL runner exist, but no rule file reads it, so the whole backup estate
behind it is invisible to the store and to the cross-system backup joins (`XS-VM-NO-BACKUP`,
`XS-SYSTEM-CRITICAL-NO-BACKUP`, `XS-DC-IMAGE-ONLY-BACKUP`). The first job of this file is to feed
`row_seen` with the protected objects. The schema is visible only in the tenant's API explorer, so
**every field name below is a guess to confirm there**; a wrong name is a GraphQL error (unknown),
never a pass. Queries are cursor-paged (`after`, `pageInfo { hasNextPage endCursor }`, `first: 500`)
with inline literals. Where an entry says "snappables" it means the protected-object connection
(`snappableConnection` / `vSphereVmNewConnection` family) with `effectiveSlaDomain`, `slaAssignment`,
`protectionStatus`, `latestSnapshot`, `snapshotConnection { count }`, `archivalComplianceStatus`,
`replicationComplianceStatus`. Refs unless stated: NIST-800-53:CP-9, and CIS-Controls-v8:11.2 for the
protection entries. Confidence: guess for all entries of this section unless stated.

**RBK-CLUSTER-DISCONNECTED** - a cluster not connected to the cloud tenant or silent for hours; its
data is not managed. Severity: critical. Source: `clusterConnection { nodes { id name status
lastConnectionTime version pauseStatus } }`, `key: id`. Condition: `status` ne connected, or
`lastConnectionTime` age-gt 0.1 days. Refs: NIST-800-53:CP-9, SI-4. Fix: check the cluster's outbound
path and proxy.

**RBK-NODE-UNHEALTHY / RBK-CLUSTER-PAUSED / RBK-CLUSTER-STORAGE-HIGH** - a node not OK; a cluster
paused (nothing backs up); storage above 80% used. Severity: high. Source: the cluster nodes with
`status`, `pauseStatus` and capacity metrics. Condition: not OK; paused true; used percentage gt
`rubrik.storage-max-percent`. Refs: NIST-800-53:CP-9, SC-5. Fix: replace the node; resume; add
capacity or shorten retention.

**RBK-ACTIVITY-STUCK** - activities running or queued for over a day. Severity: medium. Source:
`activitySeriesConnection(filters: { lastActivityStatus: [RUNNING, QUEUED] }) { nodes { objectName
lastActivityType startTime progress } }`. Condition: `startTime` age-gt 1. Fix: cancel and investigate.

**RBK-BACKUP-ACTIVITY-FAILED / RBK-ARCHIVE-ACTIVITY-FAILED / RBK-REPLICATION-ACTIVITY-FAILED /
RBK-RECOVERY-ACTIVITY-FAILED / RBK-BACKUP-ACTIVITY-CANCELED** - failed (or cancelled) backup, archive,
replication and recovery activities in the window. Severity: high / high / high / medium / medium.
Source: `activitySeriesConnection(filters: { lastActivityStatus: [FAILURE], lastActivityType:
[BACKUP|ARCHIVE|REPLICATION|RECOVERY], startTimeGt: <7 days ago> })`; relative-date macros are documented for http and graph
only, so the graphql document needs the same macro (engine gap 12) or a filter on the returned
`startTime` with `age-lt`. Condition: `each: any`. Refs add NIST-800-53:SI-4.
Fix: read the activity message; the first failure per object is the one that matters.

**RBK-ACTIVITY-WARNING-RECURRING** - the same warning on the same object over many runs. Severity:
low. Source: warning activities for 30 days. Condition: count per object and message above a limit
[gap: count per group].

**RBK-BACKUP-DURATION-LONG** - a backup that runs longer than its SLA frequency window. Severity:
medium. Source: successful backup activities (`startTime`, `lastUpdated`). Condition: duration gt the
frequency [gap: arithmetic between two fields]. Fix: add resources or change the window.

**RBK-SYSTEM-EVENT-FAILURE** - cluster, hardware or configuration events at failure or warning.
Severity: high. Source: activities of system object types. Condition: status in [FAILURE, WARNING].

**RBK-LOGIN-FAILURES / RBK-AUDIT-CONFIG-CHANGE / RBK-AUDIT-SNAPSHOT-DELETED** - failed sign-ins; SLA,
retention, role and user changes; snapshot deletions or expirations by a person. Severity: medium /
medium / high (security). Source: audit log connection with `startTimeGt` of 7 or 30 days and an
event-type filter (enum names to confirm). Condition: failures above a threshold; change events by a
user outside `rubrik.expected-admins`; any manual snapshot deletion. Refs: NIST-800-53:AU-6, AC-2,
CP-9, MITRE-ATTACK:T1490. Fix: review with the change record.

**RBK-VCENTER-DISCONNECTED / RBK-VCENTER-REFRESH-STALE** - a registered vCenter whose connection is
down or whose inventory is not refreshed. Severity: critical / high. Source: `vSphereVCenterConnection
{ nodes { id name connectionStatus lastRefreshTime } }`. Condition: not connected; `lastRefreshTime`
age-gt 1. Fix: re-enter credentials or trust the new certificate.

**RBK-VCENTER-NOT-REGISTERED** - a vCenter in the virtualisation pack that Rubrik does not know,
without a recorded decision. Severity: medium. Source: [store] join of the vmware pack's vCenter
instances with these rows. Condition: absent from Rubrik and not in `rubrik.not-protected-vcenters`.
Fix: register it or record the decision.

**RBK-ARCHIVE-TARGET-DISCONNECTED / RBK-ARCHIVE-TARGET-GROWTH** - an archival or replication target not
connected; a target growing faster than planned. Severity: critical / medium. Source: `targets { nodes
{ name targetType status consumedBytes } }`. Condition: `status` ne connected; growth between runs
above a threshold [gap: run-to-run]. Fix: restore the credentials or network path.

**RBK-REPLICATION-TARGET-DOWN / RBK-ARCHIVAL-LAG / RBK-REPLICATION-LAG** - replication partner
unreachable; objects whose newest archived or replicated copy is older than their SLA allows. Severity:
high. Source: replication pairs; snappables with the compliance fields. Condition: status; compliance
`OutOfCompliance`. Fix: check the link; run on-demand.

**RBK-HOST-DISCONNECTED** - a registered host whose backup agent is disconnected (also covers the 30-day
variant: `lastConnection` age-gt 30 as a second rule). Severity: high. Source: `physicalHosts { nodes
{ name connectionStatus { connectivity } } }`. Condition: ne connected. Fix: restart the agent or
remove the host.

**RBK-CDM-VERSION-UNSUPPORTED / RBK-UPGRADE-PENDING-LONG / RBK-HARDWARE-MODEL-EOL / RBK-RBS-AGENT-OUTDATED**
- cluster software out of support; an available upgrade pending over 90 days; appliance generation past
support; agents behind the cluster. Severity: high / medium / medium / medium. Source: cluster `version`,
`upgradeStatus`, hardware model; host agent version. Condition: not in `rubrik.accepted-version-pattern`;
pending age; model in `rubrik.eol-models`; version ne cluster. Refs: NIST-800-53:SI-2, SA-22. Fix: plan
the upgrade.

**RBK-LIVE-MOUNT-LEFT-RUNNING** - a live mount left running; it holds a snapshot and a datastore.
Severity: medium. Source: live mount connection. Condition: older than 3 days. Fix: unmount.

**RBK-SLA-FREQUENCY-TOO-LOW / RBK-SLA-RETENTION-SHORT / RBK-SLA-NO-ARCHIVAL / RBK-SLA-NO-REPLICATION /
RBK-SLA-BACKUP-WINDOW-MISSING** - policy domains whose snapshot frequency exceeds the RPO, retention is
under the record-keeping minimum, no archival or replication is configured, or no backup window is set.
Severity: high / medium / high / medium / low. Source: `slaDomains { nodes { name frequencies
retention archivalSpecs replicationSpecs backupWindows numProtectedObjects } }`. Condition: frequency
gt `rubrik.rpo-hours`; retention lt `rubrik.min-retention-days`; specs empty on domains protecting
objects. Fix: set the policy to the tier.

**RBK-SLA-NOT-RETENTION-LOCKED / RBK-SLA-RETENTION-LOCK-GOVERNANCE / RBK-OBJECT-NOT-IMMUTABLE** -
production domains without retention lock; locks in governance rather than compliance mode; objects
without an immutable copy (lock plus object lock on the archive target). Severity: high (security).
Source: `slaDomains` lock fields; [store] join with the target's lock for the last. Condition: lock
false / mode ne compliance. Refs: NIST-800-53:CP-9, SI-7, MITRE-ATTACK:T1490. Fix: enable the lock.

**RBK-SLA-UNUSED** - a domain with no protected objects. Severity: low. Source: `slaDomains`
`numProtectedObjects`. Condition: eq 0. Fix: delete.

**RBK-OBJECT-DO-NOT-PROTECT / RBK-OBJECT-UNPROTECTED** - objects assigned Do Not Protect; objects with
no domain at all. Severity: medium / high. Source: snappables with the SLA-assignment filter.
Condition: assignment `DoNotProtect`; protection status Unprotected. Fix: protect, or record a reason.

**RBK-OBJECT-OUT-OF-COMPLIANCE / RBK-OBJECT-COMPLIANCE-UNKNOWN / RBK-SNAPSHOT-STALE / RBK-SNAPSHOT-MISSED /
RBK-OBJECT-NO-SNAPSHOT / RBK-OBJECT-NO-ARCHIVE-COPY / RBK-OBJECT-NO-REPLICA** - protected objects out
of compliance; compliance not available (unknown); newest snapshot older than the frequency; missed
snapshots in 7 days; none at all; no archive or replica copy for tier-one objects. Severity: critical /
high / high / high / high / high / medium. Source: snappables. Condition: compliance not `InCompliance`;
`NotAvailable`; `latestSnapshot` age-gt frequency; missed count gt 0; `snapshotConnection.count` eq 0;
archive / replica fields empty on objects in `rubrik.tier1-objects`. Fix: re-run, then find the cause.

**RBK-RETENTION-NOT-HONOURED** - the oldest snapshot or count disagrees with the SLA retention (too many
kept - cost; too few - risk). Severity: low. Source: snappables with `oldestSnapshot`. Condition: outside
tolerance.

**RBK-MSSQL-LOG-BACKUP-OFF / RBK-MSSQL-LOG-BACKUP-FAILED** - database objects protected without
transaction-log backup, or whose log backups fail. Severity: high. Source: SQL database objects (log
backup frequency) and activities of type LOG_BACKUP. Condition: frequency absent; failed. Fix: set a
log frequency; fix the failure.

**RBK-HOST-NO-FILESET** - a registered host without any fileset assignment. Severity: medium. Source:
physical hosts with fileset counts. Condition: eq 0.

**RBK-VM-CRASH-CONSISTENT-ONLY** - database or directory VMs protected crash-consistent only. Severity:
high. Source: VM objects `snapshotConsistencyMandate`. Condition: `CRASH_CONSISTENT` on VMs in
`rubrik.app-consistent-vms`. Refs: NIST-800-53:CP-9. Fix: enable app-consistent snapshots with guest
credentials.

**RBK-BACKUP-VERIFICATION-OFF / RBK-RELIC-OBJECT / RBK-SNAPSHOT-ON-DEMAND-FOREVER** - no automated
restore verification; relic objects (source deleted) still holding snapshots; on-demand snapshots with
no expiry. Severity: low. Source: verification settings; snappables filtered to relic; snapshots by
type. Condition: off; `isRelic` true; on-demand with forever retention. Fix: review and prune.

**RBK-SSO-NOT-ENFORCED / RBK-USER-NO-MFA / RBK-LOCAL-USER-PRESENT / RBK-ADMIN-ROLE-HOLDER /
RBK-CUSTOM-ROLE-BROAD / RBK-USER-STALE-OR-LEFT / RBK-SSO-GROUP-MAPPING** - sign-in not federated; users
without MFA; local (non-SSO) accounts; holders of the administrator role; custom roles equivalent to
administrator; users idle 90 days or whose directory account is disabled; SSO groups mapped to roles
containing unintended people. Severity: high / high / medium / high / medium / medium / medium
(security). Source: org security policy; `userConnection { nodes { email roles lastLogin
isSsoUser totpStatus } }`; `roleConnection { nodes { name permissions } }`; SSO groups; the last two
join Entra [store]. Condition: policy lacks SSO; MFA not enabled; not SSO user; role name Administrator;
permissions include user / role management and snapshot deletion; `lastLogin` age-gt 90; disabled
member. Refs: NIST-800-53:IA-2, AC-2, AC-6, CIS-Controls-v8:5.3, 5.4, 6.3. Fix: enforce SSO and MFA,
trim roles.

**RBK-SERVICE-ACCOUNT-INVENTORY / RBK-SERVICE-ACCOUNT-SECRET-OLD** - service accounts with roles and
last use; secrets older than a year. Severity: low / medium (security). Source: `serviceAccounts`.
Condition: no recent login; `createdAt` / rotation age-gt 365. Refs: NIST-800-53:IA-5, AC-2.

**RBK-QUORUM-AUTH-OFF** - two-person authorisation for destructive actions off. Severity: high
(security). Source: quorum authorisation settings. Condition: disabled. Refs: NIST-800-53:AC-5,
CP-9, MITRE-ATTACK:T1490. Fix: enable for retention reduction, lock removal and snapshot deletion.

**RBK-LEGAL-HOLD-INVENTORY** - snapshots under legal hold, each needing a request. Severity: info.
Source: snapshots filtered to legal hold. Condition: `each: any`.

**RBK-RADAR-OFF / RBK-ANOMALY-OPEN / RBK-THREAT-MONITORING-OFF / RBK-SENSITIVE-DISCOVERY-OFF /
RBK-EVENT-CRITICAL-OPEN / RBK-ADDON-LICENCE-UNUSED / RBK-LICENCE-OVER-ENTITLEMENT** - anomaly detection
off on production objects; anomaly events from the last week untriaged; threat monitoring or sensitive
data discovery off where licensed; critical events open; licensed add-ons not enabled; usage above the
entitlement. Severity: high / high / medium / low / medium / low / medium. Source: anomaly, threat and
discovery settings; anomaly event connection (7 days); event connection (severity critical, status
open); licence usage. Condition: off; unresolved; usage gt entitlement. Refs: NIST-800-53:SI-4, SI-3,
CP-9, MITRE-ATTACK:T1486, CIS-Controls-v8:10.1.

### Druva (`rules\druva.yaml`, integration `http`, auth `oauth-client-credentials`)

Druva Cloud Platform REST with an API client; **every endpoint below is to confirm against the vendor
reference** (the old catalogue marked each as such), so confidence is guess for all. The product's
state is "if live": rules must be quiet when the tenant is empty. Console-only settings are not
automatable and are in the map, not here.

**DRUVA-STORAGE-QUOTA-HIGH** - storage consumed above 90% of purchased. Severity: medium. Source:
platform storage report. Condition: used gt quota times 0.9. Refs: NIST-800-53:SC-5, CP-9.

**DRUVA-BACKUP-JOB-LONG / DRUVA-BACKUP-FAILED / DRUVA-BACKUP-WITH-ERRORS** - backups over 24 hours;
failed in 7 days; completed with errors. Severity: medium / high / medium. Source: backup activity
report. Condition: duration; status Failed; status with errors. Refs: NIST-800-53:CP-9, SI-4.

**DRUVA-CLIENT-OUTDATED / DRUVA-DEVICE-DISABLED / DRUVA-DEVICE-RESTORE-POINTS-FEW** - client version
below support; devices disabled or preserved; too few restore points. Severity: medium / low / medium.
Source: devices. Condition: `clientVersion` not in pattern; status; restore-point count lt 2. Refs:
NIST-800-53:SI-2, CP-9.

**DRUVA-USER-BACKUP-STALE / DRUVA-USER-COVERAGE-GAP / DRUVA-ENDPOINT-COVERAGE-GAP** - users whose last
successful backup is older than a day; users in the assigned Entra group not backed up; active
workstations without a Druva device. Severity: high. Source: users and devices; [store] joins with the
Entra and SCCM / Intune packs. Condition: age; absent. Refs: NIST-800-53:CP-9, CIS-Controls-v8:11.1.

**DRUVA-PROFILE-RETENTION-SHORT / DRUVA-PROFILE-SCHEDULE-LONG** - profiles whose retention is under the
records minimum or whose backup interval exceeds the RPO. Severity: medium. Source: profiles. Condition:
thresholds `druva.min-retention-days`, `druva.rpo-hours`.

**DRUVA-ADMIN-INVENTORY / DRUVA-ADMIN-ACCOUNT-DISABLED** - administrators and roles; administrators
whose directory account is disabled. Severity: medium (security). Source: administrators joined to
Entra [store]. Condition: count above a limit; disabled. Refs: NIST-800-53:AC-2, AC-6, PS-4.

### Coralogix (`rules\coralogix.yaml`, integration `http` for the management APIs; DataPrime rows need the `coralogix` integration)

Management APIs are REST under the team's API domain with a bearer API key; **paths are to confirm**,
so confidence is guess for all entries. One integration instance per team.

**CX-ALERT-DEFINITION-ERROR** - alert definitions disabled by error or stuck. Severity: medium. Source:
alert definitions list with `enabled` and evaluation status. Condition: error state. Refs:
NIST-800-53:SI-4. 

**CX-ALERT-COVERAGE-GAP / CX-NO-DATA-ALERT-MISSING** - required alerts (error spikes, failed sign-ins,
security events, pipeline health) absent; a critical source with no no-data alert. Severity: high.
Source: alert definitions against `coralogix.required-alerts` and the source list. Condition: required
name or type absent. Refs: NIST-800-53:SI-4, AU-6. Fix: create the alert.

**CX-ALERT-SNOOZED-LONG / CX-ALERT-UNACKNOWLEDGED** - alerts muted for over 7 days or without an end;
alerts that fired and were not acknowledged or linked to an incident. Severity: medium. Source: alert
definitions (snooze), alert history 30 days with [store] join to ServiceNow incidents. Condition: age;
no incident. Refs: NIST-800-53:IR-4, SI-4.

**CX-NOTIFICATION-RECIPIENT-GONE / CX-WEBHOOK-SECRET-IN-URL** - alert recipients who left; outbound
webhook URLs carrying tokens in the query string. Severity: high / high (security). Source: outbound
integrations list; e-mail recipients joined to Entra. Condition: not an enabled mailbox; `url` match
`[?&](token|key|secret|sig)=`. Refs: NIST-800-53:IR-6, IA-5. Fix: group mailbox; header-based secret.

**CX-TCO-RETENTION-SHORT / CX-TCO-POLICY-HIGH-VALUE-IN-WRONG-TIER** - retention below the audit minimum
for security logs; high-value sources in a cheap tier or bulk debug logs in the frequent tier. Severity:
medium. Source: TCO policies per team. Condition: retention lt `coralogix.min-security-retention-days`;
tier mismatch against a source table. Refs: NIST-800-53:AU-11, CIS-Controls-v8:8.10.

**CX-PARSING-RULE-DISABLED / CX-DASHBOARD-PUBLIC-LINK** - parsing rule groups disabled; custom
dashboards shared by public link. Severity: low / high (security). Source: parsing rules; custom
dashboards list. Condition: `enabled` false; public-link flag. Refs: NIST-800-53:AU-3, AC-22.

**CX-USER-LEFT / CX-ADMIN-MANY / CX-EXTERNAL-USER / CX-API-KEY-INVENTORY** - users whose Entra account is
disabled; too many team administrators; users outside the municipal domain without an end date; API
keys with owner, permissions and last use. Severity: high / medium / medium / medium (security). Source:
SCIM `GET /scim/Users` and the users / roles / keys APIs; [store] join with Entra. Condition: disabled;
admin count gt `coralogix.max-admins`; domain notmatch; key owner gone or unused 90 days. Refs:
NIST-800-53:AC-2, AC-6, IA-5, PS-4.

### Cross-system, endpoint and vendor-status rules

**XS-BACKUP-DOUBLE-PROTECTED** (`rules\cross-system.yaml`) - an object protected by two backup products
(licence and storage paid twice) or two SaaS backup tenants for the same workload. Severity: low.
Source: `store` join of backup objects across the veeam, rubrik, keepit and druva packs on the object
name. Condition: present in two or more where `xs.double-protection-allowed` does not list it. Refs:
NIST-800-53:CP-9. Fix: pick one owner product, or record a deliberate second copy. Confidence: guess.

**XS-AZURE-ROLE-HOLDER-DISABLED / -GUEST / -MAILBOX, XS-AZURE-OWNER-TAG-LEFT** - see the identity
section of Azure above; the Owner-tag variant joins resource-group and subscription `Owner` tag values
to Entra `accountEnabled` (low). Confidence: guess.

**ENTRA-SP-NO-RECENT-SIGNIN** (`rules\entra.yaml`) - an enterprise application for a SaaS backup or
monitoring product with no sign-in in 90 days (the product is probably unused or the app is a
leftover). Severity: low. Source: Graph `/auditLogs/signIns`, `filter: appId eq '<id>' and
createdDateTime ge {DAYS_AGO:90}` per app from a threshold list `entra.watch-apps`. Condition: `count:
none`. Refs: NIST-800-53:AC-2, CM-8. Fix: remove the app and its SCIM job. Confidence: guess.

**AWS-NOTICE-MAILBOX-UNTRIAGED** (`rules\m365.yaml`) - the shared mailbox that receives cloud-provider
notices has a large unread count. Severity: medium. Source: Graph `/users/{id}/mailFolders/inbox`,
`select: unreadItemCount, totalItemCount`, `Mail.Read` on that mailbox only. Condition:
`unreadItemCount` gt `m365.notice-mailbox-max-unread`. Refs: NIST-800-53:IR-6, SI-5. Fix: assign an
owner and a triage rule (no forwarding). Confidence: likely.

**SNOW-INCIDENT-RECURRING-CI** (`rules\servicenow.yaml`) - incidents against the same configuration
item recurring over six months without a problem record. Severity: low. Source: incident table
grouped by `cmdb_ci` (the Aggregate API `/api/now/stats/incident`, `sysparm_group_by=cmdb_ci`).
Condition: count gt 3 and no linked problem. Refs: NIST-800-53:IR-4. Fix: open a problem record.
Confidence: guess [gap: aggregate response shape].

**WINSRV-EVT-VEEAM-LOG-ERRORS** (`rules\windows-server.yaml`) - error events in the backup product's
own Windows event log channel on its servers. Severity: medium. Source: `eventlog` protocol, `log:
"Veeam Backup"`, `days: 7`, targets the backup servers and proxies by tenant list. Condition: `level`
error or critical. Refs: NIST-800-53:SI-4, AU-6. Fix: read the event text. Confidence: likely (the
channel exists where the product is installed; a missing channel returns no rows).

**HTTP-ENDPOINT-DOWN** (`rules\endpoints.yaml`, a new small pack) - a public web endpoint that stops
answering with a success status (portal, console, service pages). Severity: high for listed
production endpoints, medium otherwise. Source: needs an `http` target list in the way the `tls` type
has one: `targets: { threshold: endpoints.urls }`, GET the URL with auth `none`, row fields `status`,
`elapsedMs`, `finalHost`. Condition: `status` ge 400 or no answer; elapsed above a limit. Refs:
NIST-800-53:SI-4, CP-10, CIS-Controls-v8:13.1. Fix: depends on the endpoint. Confidence: likely [gap:
http target list]. Used by three old rows; page-content checks (HTML parsing for library versions or
keys) are deliberately not part of it.

**VENDOR-STATUS-INCIDENT-OPEN** - already proposed in `catalog-network-security.md` (vendor status page JSON through `http` auth `none`). Five old rows (cloud provider, backup and monitoring vendors) map to it; no new entry. Feed shapes differ per vendor and some offer only RSS, so confidence stays guess.

---

## Engine gaps met while writing these

Ordered by the number of new checks each one blocks. Items already in `docs/backlog/infrastructure.md`
are marked (backlog).

1. **Count or aggregate per group / per parent** (backlog): per-subscription "none exists" rules, owner
   counts, recurring problems, flapping sensors, network zones with one gateway, incidents per item.
   `count` judges the whole row set; a `group: <field>` on `count` would unblock about twenty entries.
2. **Two-level fan-out**: ARM child resources (storage account > file service, vault > policies,
   workspace > tables, automation account > credentials, network watcher > flow logs), Dynatrace
   extensions > configurations > status. `for_each` is one level (backlog, "Nested per-object
   requests").
3. **Same-element conditions on arrays** (backlog): NSG rule direction + access + source + port on the
   same `securityRules[]` element, PIM policy `rules[]`, and port-range containment.
4. **Run-to-run comparison**: job inventory changed, privileged assignment changed, repository growth,
   public IP new, archive target growth. A `store` rule can read two `row_seen` runs, but the
   engine has no helper for "newest versus previous"; a documented SQL pattern would do.
5. **Field-versus-field arithmetic across rows**: quota used versus limit within a row is covered by
   `value: { field }`; percent used of capacity from two different rows, duration from two timestamps,
   vCPU against host cores are not.
6. **Epoch-millisecond and OLE dates** (backlog): Dynatrace entity timestamps, audit-log timestamps,
   PRTG `lastcheck_raw`.
7. **Address arithmetic**: overlapping CIDR ranges across virtual networks and with on-premises ranges.
8. **Paging tokens the runner does not follow** (backlog): ARM `nextLink`, Dynatrace `nextPageKey`.
9. **Read-only POST for query endpoints**: Azure Resource Graph and Cost Management, Log Analytics,
   Google `getIamPolicy` and logging `entries:list`, AWS JSON-RPC reads, Coralogix DataPrime.
   An allow-list per integration (path or action + verb), enforced in the runner like the GraphQL
   mutation refusal.
10. **Targets for `http`**: a list of URLs (the way `tls` takes endpoints) for the endpoint-down rule.
11. **Version ordering**: `veeam`, `grafana`, `solarwinds`, `rubrik` minimum-version rules fall back to a
    regular expression of accepted versions (backlog in the other catalogue passes).
12. **Relative-date macros in graphql documents**: `{DAYS_AGO:n}` works in http and graph text only;
    the Rubrik activity and audit queries want it inside the document.
