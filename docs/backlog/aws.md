# Backlog - AWS

What `rules/aws.yaml` cannot express yet, one line each: the check, what it needs, and its source.
`rules/aws.yaml` holds 336 rules covering IAM (root, password policy, users, keys, MFA, roles and their
trust, policy documents including admin, wildcard and privilege-escalation grants), S3 per bucket,
EC2/EBS/VPC (security-group ports, NACLs, flow logs, snapshots, AMIs, launch templates, account-level
blocks), RDS/Aurora/DocumentDB/Neptune, Redshift, ElastiCache, CloudTrail, Config, GuardDuty, Security
Hub, Inspector, Access Analyzer, KMS, Lambda, ECS task definitions, EKS, ECR, DynamoDB, ACM, Secrets
Manager, SSM, Backup, CloudFront, WAF, SNS, Auto Scaling, ELB, CloudWatch (alarms and the CIS metric
filters), CloudFormation, Organizations, Route 53 and CodeBuild.

Source labels: `AWS-*` = the legacy CheckId (`_archive\_health-20261020\Keeper\catalog\checks-AWS.csv`);
`FSBP:` / `CIS-AWS:` = the public control id the gap corresponds to; `field` = seen in this estate;
`request` = asked for directly. After the backlog: the thresholds the rule file defines, and what to
confirm on the first real run.

## Moved into rules in the 22.10 pass

Two runner behaviours, already in the code but not used before, unblocked most of these:

- A list of plain strings is rows of `{ value }` (`RowValues.ItemsOf`), so `for_each` walks it with
  `field: value` - GuardDuty detectors, EKS clusters, DynamoDB tables, ECS task-definition families.
- A json/rest-json read with no `items` is the whole answer as one row per account and region (or per
  object under `for_each`), so "none here" is judged per place - GuardDuty, Config, Access Analyzer,
  Security Hub standards, CloudTrail per account, and a VPC's flow logs (EC2 answer element as the row).

| Was parked as | Now |
|---|---|
| GuardDuty per region and per detector (AWS-MON-001..003) | AWS-GUARDDUTY-NOT-ENABLED, -DETECTOR-SUSPENDED, six protection-plan rules, -HIGH-SEVERITY-FINDINGS |
| Security Hub standards (AWS-MON-004/005) | AWS-SECURITYHUB-FSBP-OFF, -CIS-OFF, -STANDARD-FAILED, -CRITICAL-FINDINGS (a region with Security Hub off is still unknown, below) |
| Inspector enabled and critical findings (AWS-MON-006) | AWS-INSPECTOR-EC2/ECR/LAMBDA/LAMBDA-CODE-SCAN-OFF, -CRITICAL-FINDINGS, -COVERAGE-INACTIVE |
| Config recorder in every region/account (AWS-CFG-030) | AWS-CONFIG-NO-RECORDER (+ NOT-ALL-RESOURCES, RULE-NONCOMPLIANT, NO-AGGREGATOR) |
| CloudTrail multi-region trail per account (AWS-LOG-001) | AWS-CLOUDTRAIL-ACCOUNT-NO-MULTI-REGION, AWS-CLOUDTRAIL-NO-S3-DATA-EVENTS |
| Access Analyzer per region (AWS-IAM-029) | AWS-ACCESS-ANALYZER-REGION-NONE, -NO-UNUSED-ACCESS |
| Every VPC has a flow log (AWS-LOG-010) | AWS-VPC-NO-FLOW-LOG |
| EKS version/endpoint/logging (AWS-HLT-017, AWS-LCM-009, AWS-AUT-022, AWS-LOG-016) | AWS-EKS-* (7 rules) |
| DynamoDB PITR (AWS-BCK-007 DynamoDB part) | AWS-DYNAMODB-PITR-OFF, -DELETION-PROTECTION-OFF, -AWS-OWNED-KEY |
| Public EBS/RDS snapshots (AWS-AUT-014) | AWS-EBS-SNAPSHOT-PUBLIC (RestorableBy all, no fan-out), AWS-RDS-SNAPSHOT-PUBLIC, AWS-RDS-CLUSTER-SNAPSHOT-PUBLIC |
| IAM admin/wildcard policies, privilege escalation (AWS-IAM-011..014, -031..034) | AWS-IAM-POLICY-* (22 rules over GetAccountAuthorizationDetails, text patterns - limits below) |
| Role trust with wildcard/external principal, role last used (AWS-IAM-025..027, -040) | AWS-IAM-ROLE-TRUST-*, AWS-IAM-ROLE-UNUSED, -ADMIN-ATTACHED |
| IAM-user MFA (credential-report part of AWS-IAM-005) | AWS-IAM-USER-NO-MFA (ListMFADevices per user) |
| NACL ingress from the internet (AWS-AUT-004) | AWS-NACL-ADMIN-FROM-INTERNET, AWS-NACL-UNUSED |
| ElastiCache encryption, failover (AWS-AVL-013, AWS-AUT-019 part) | AWS-ELASTICACHE-* (7 rules) |
| DocumentDB/Neptune encryption, backups, deletion, logs (AWS-LCM-011, AWS-AVL-014 part) | AWS-RDS-CLUSTER-* - DocumentDB and Neptune are answered by the `rds` API (DescribeDBClusters) |
| Unattached EIPs/volumes/ENIs, unused NACLs (AWS-HYG-002..006 part) | AWS-EIP-UNATTACHED, AWS-EBS-VOLUME-UNATTACHED, AWS-ENI-UNUSED, AWS-NACL-UNUSED (a state field, no join) |
| CIS metric filters (AWS-MON-008, filter half) | AWS-CW-METRIC-FILTER-*-MISSING (15 rules; the alarm half is below) |
| EC2 reservation expiry (AWS-CST-013 EC2 part) | AWS-EC2-RESERVATION-EXPIRING |

Also corrected: the Backup REST reads now pass the page token as `nextToken` (the REST query-string
name), not `NextToken`.

## Not in the runner's service allow-list

The `aws` runner signs only the services in `AwsServices.Known`. These checks read a service it does not
know, so no rule can be written until the service (and its read actions) is added to the runner.

- AWS Health open issues, scheduled changes and lifecycle notices (health DescribeEventsForOrganization). Needs `health`. Source: AWS-HLT-001, AWS-HLT-002, AWS-LCM-012, AWS-MON-020.
- Service quotas near their limit (service-quotas, cloudwatch AWS/Usage). Needs `service-quotas`. Source: AWS-HLT-013, AWS-HLT-014.
- Trusted Advisor checks; support plan and cases (support). Needs `support`/`trustedadvisor`. Source: AWS-HLT-015, AWS-MON-015, AWS-LCM-022, AWS-HYG-016.
- WorkSpaces and AppStream fleets, images, directories. Needs `workspaces`, `appstream`. Source: AWS-LCM-015, AWS-LCM-016, AWS-AVL-015, AWS-AVL-016, AWS-AUT-027, AWS-CST-026, AWS-CST-027.
- OpenSearch domains: encryption at rest and node-to-node, fine-grained access, public/VPC access, audit logs, TLS policy, version. Needs `es`. Source: AWS-AUT-019 (OpenSearch part).
- SQS queues: encryption, public queue policy. Needs `sqs` (the SNS/SQS pair; SNS rules exist).
- EFS: encryption at rest, backup policy, access points with root path, mount targets in public subnets. Needs `efs`. Source: AWS-PKI-009, AWS-BCK-007 (EFS part); CIS-AWS:2.4.1.
- API Gateway: authorisation, access logging, execution logging, client certificate, WAF, TLS policy. Needs `apigateway`/`apigatewayv2`. Source: AWS-AUT-023, AWS-LOG-012, AWS-LCM-017 (API part).
- Account-level S3 Block Public Access. Needs `s3control`. A bucket with no public-access block at all yields no row for AWS-S3-PUBLIC-ACCESS-BLOCK-WEAK (see "absence under for_each"). Source: AWS-AUT-010; FSBP:S3.1.
- Account alternate and security contacts, opted-in regions. Needs `account`. Source: AWS-CFG-009, AWS-CFG-010, AWS-IAM-003; CIS-AWS:1.1, 1.2.
- IAM Identity Center permission sets, assignments, admin sets (sso-admin). The known `sso` service is the user portal, not the admin API. Needs `sso-admin`. Source: AWS-IAM-018..022, AWS-IAM-044.
- GuardDuty / Security Hub / Inspector organisation configuration (auto-enable for new accounts, delegated admin): their DescribeOrganizationConfiguration paths are not in the REST allow-list. Needs those operations added. Source: AWS-MON-001..006 (org part).
- EMR (block public access, security configurations, Kerberos), DMS (public replication instances, SSL), SageMaker (notebook root access, direct internet, encryption), Kinesis/Firehose encryption, MSK (TLS, public access), Amazon MQ (public brokers, auto minor upgrade), Glue (security configurations, connection SSL), Cognito (MFA, advanced security), SES (identity policies), Network Firewall (policy and logging), Elastic Beanstalk (managed updates, logs), AppSync (logging, auth), Step Functions (logging), Bedrock (guardrails, invocation logging), Redshift Serverless, FSx, Directory Service, CodePipeline/CodeArtifact. Each needs its service.
- Public domain registration expiry/auto-renew. Needs `route53domains`. Source: AWS-AVL-011.
- Route 53 Resolver query logs and endpoints. Needs `route53resolver`. Source: AWS-LOG-014, AWS-CFG-017.
- Control Tower landing zone and controls. Needs `controltower`. Source: AWS-LCM-020, AWS-CFG-026.
- MGN/DRS source servers, Direct Connect state, Private CA, DLM policies, Kinesis Video retention, Lightsail, Transfer Family, RAM shares, Macie, EventBridge routing, Compute Optimizer, Budgets, CUR/Data Exports, Marketplace agreements, Savings Plans, SMS spend limit, invoicing/billing/tax, licence manager. Each needs its service. Source: AWS-LCM-013, AWS-AVL-007, AWS-PKI-014, AWS-BCK-005, AWS-CST-042, AWS-AUT-024, AWS-AUT-026, AWS-CFG-015, AWS-MON-007, AWS-MON-010, AWS-MON-017, AWS-BCK-018, AWS-CST-016..019, AWS-CST-002, AWS-CST-003, AWS-CST-034, AWS-CST-031, AWS-CST-032, AWS-CST-015, AWS-CST-029, AWS-AVL-001, AWS-CST-030, AWS-CST-033, AWS-CST-038, AWS-CST-022.
- Classic Load Balancers: the known `elasticloadbalancing` service is the v2 API (2015-12-01); classic ELBs answer the 2012-06-01 version. Needs a second service entry. FSBP:ELB.2..ELB.9 (classic part).
- Cost Explorer spend, anomalies and rightsizing: `ce` is known and billed daily; each check is a per-tenant value or arithmetic (below). Source: AWS-CST-001, AWS-CST-004..042.

## Engine and runner gaps - the service is known, the rule cannot be written yet

### Absence under for_each (missing: empty yields no row)

`missing: empty` turns "this bucket has no such setting" into no rows, which no condition can see. The
runner would need to emit a marker row (`_missing: true`) for an object whose setting is absent.

- S3 bucket with no public access block at all (AWS-S3-PUBLIC-ACCESS-BLOCK-WEAK sees only weak ones). FSBP:S3.8.
- S3 bucket with no bucket policy, so no TLS-only statement (AWS-S3-NO-TLS-ENFORCEMENT judges only buckets that have a policy). CIS-AWS:2.1.1, FSBP:S3.5.
- S3 lifecycle (FSBP:S3.13, S3.10), replication, object lock (FSBP:S3.15), ownership controls absent on old buckets (FSBP:S3.12).
- ECR repository with no lifecycle policy (FSBP:ECR.3); backup vault with no access policy denying deletes.
- An account with no IAM password policy (GetAccountPasswordPolicy answers NoSuchEntity on a single, non-for_each read). Source: AWS-IAM-008; FSBP:IAM.7 (absent part).
- A region where Security Hub is off: DescribeHub/GetEnabledStandards answer InvalidAccessException, which reads as a failed (unknown) place, never "not enabled". Source: AWS-MON-004; FSBP:SecurityHub.1.

### for_each cannot pass an ARN, a name with '/', or a list

Only plain ids (letters, digits, `. _ : -`) go into a path or param, and a `{placeholder}` fills a
string param only - never a list.

- ELB v2 listeners and attributes: HTTPS/TLS policy, HTTP-to-HTTPS redirect, deletion protection, access logs, drop invalid headers, desync mitigation, cross-zone (DescribeListeners / DescribeLoadBalancerAttributes need the load-balancer ARN). Source: AWS-LCM-017 (ELB part); FSBP:ELB.1, ELB.3..ELB.6, ELB.8, ELB.12, ELB.14.
- WAF logging and associations (GetLoggingConfiguration / ListResourcesForWebACL take the web ACL ARN). Source: AWS-AUT-017, AWS-AUT-018; FSBP:WAF.11.
- ACM DescribeCertificate: transparency logging, renewal status, InUseBy (certificate ARN). Source: AWS-PKI-002, AWS-PKI-003.
- Access Analyzer findings (ListFindings/ListFindingsV2 need the analyzer ARN in the body). Source: AWS-IAM-029, AWS-IAM-030.
- Route 53 per hosted zone: DNSSEC signing, query logging per zone (the zone Id is `/hostedzone/<id>`). AWS-ROUTE53-NO-QUERY-LOGGING is whole-estate. Source: FSBP:Route53.2.
- ECS clusters and services: Container Insights, services assigning public IPs (ListClusters returns ARNs; DescribeClusters/DescribeServices take a list). FSBP:ECS.2, ECS.12.
- CodeBuild projects: privileged mode, plain-text environment credentials, logging, artifact encryption, Bitbucket URLs with credentials (BatchGetProjects takes a list of names). FSBP:CodeBuild.1..5.
- Secrets Manager policies and ECR repository policies of objects whose names contain '/' (e.g. `team/app`) are skipped by AWS-SECRET-POLICY-PUBLIC / AWS-ECR-REPO-POLICY-PUBLIC (the read is then partial, never a pass); IAM users whose names contain `+=,@` likewise for the per-user reads. Source: AWS-IAM-006.
- CloudTrail logging status of a trail homed in another region, and the trail's S3 bucket (public? access-logged? - the bucket is usually in another account and region). Source: AWS-LOG-003; FSBP:CloudTrail.6, CloudTrail.7; CIS-AWS:3.4.

### Two levels of for_each (the aws runner allows one)

- IAM access keys unused for 45 days / never used (ListUsers -> ListAccessKeys -> GetAccessKeyLastUsed). Source: AWS-IAM-006, AWS-IAM-007; CIS-AWS:1.12 (keys part).
- EKS managed node groups: AMI release, remote access, public subnets (ListClusters -> ListNodegroups -> DescribeNodegroup).
- RDS `rds.force_ssl` / `require_secure_transport` parameters: one level is enough (DescribeDBInstances -> DescribeDBParameters, as AWS-REDSHIFT-REQUIRE-SSL-OFF does) but each group pages through hundreds of parameters with no server-side filter; deferred for cost. Source: AWS-AUT-019 (RDS part).

### Text patterns over policy documents (what AWS-IAM-POLICY-* and the *-POLICY-PUBLIC rules do not see)

- Action wildcards that cover an escalation action (`iam:Put*`, `iam:Attach*`, `iam:*Policy`), Resource ARNs ending in `*`, and statements whose Condition object comes before Action/Resource (the pattern stops at the statement's first closing brace).
- Every stored version of a customer-managed policy is matched, not only the default (a non-default version can be reactivated, so this errs on the side of reporting).
- The public-principal rules for KMS, Lambda, ECR, SNS and Secrets Manager pass any policy that has a Condition anywhere; a public statement next to a conditioned one is missed. NotPrincipal is not evaluated.
- Combinations that make an escalation (ec2:RunInstances + iam:PassRole, lambda:CreateFunction + InvokeFunction + PassRole) are reported as their PassRole part only.
- Own-account versus foreign-account principals: AWS-IAM-ROLE-TRUST-NO-EXTERNAL-ID cannot compare the trusted account id with `_account`, so same-account and in-organisation trusts appear and need a recorded exception.
- A list of the organisation's account ids (`aws.org-account-ids`, comma-separated) cannot be compared with the principals inside a policy's JSON text: no operator extracts the ids, and a threshold cannot be spliced into a pattern. AWS-KMS-KEY-POLICY-FOREIGN-ACCOUNT therefore takes the whole pattern as its required setting (`aws.kms.foreign-account-pattern`, a negative lookahead over the organisation's ids). Bare 12-digit principals (`"AWS": "123456789012"`) match only if the tenant's pattern covers that form; an organisation-wide list (ListAccounts) joined against parsed principals would replace it.
- Full authorisation analysis (effective permissions after SCPs and boundaries; SimulatePrincipalPolicy is not a plain read).

### Dates the engine cannot read, or arithmetic it cannot do

- JSON-protocol timestamps that arrive as fractional epoch numbers (ACM NotAfter, Secrets Manager LastAccessedDate/LastRotatedDate, KMS ValidTo, EKS createdAt) read n/a when fractional. Not written for that reason: KMS imported key material expiry. Source: AWS-PKI-003, AWS-HYG-010.
- Secret rotation overdue (LastRotatedDate older than the rotation interval: two fields and date arithmetic). FSBP:SecretsManager.2, SecretsManager.4 (overdue part).
- RDS/ElastiCache/Redshift reservation end (StartTime + Duration). Source: AWS-CST-013..015.
- Instances stopped for more than N days (the time is inside stateTransitionReason text); maintenance windows outside working hours (`ddd:hh:mm` strings). Source: AWS-AVL-018, AWS-AVL-019; FSBP:EC2.4.
- CloudWatch metric statistics (utilisation, 5XX rates, idle resources, tunnel throughput) - no time-series condition. Source: AWS-HLT-006..011, AWS-HLT-019, AWS-HYG-007, AWS-CST-018, AWS-CST-020, AWS-CST-021.
- CloudTrail event history over a window (root use, failed sign-ins, destructive calls) - event-stream questions for a log pipeline. Source: AWS-LOG-007..009, AWS-LOG-024..026, AWS-IAM-040.
- Budgets, savings-plan utilisation, tag coverage, cost ratios. Source: AWS-CST-003, AWS-CST-013, AWS-CST-014, AWS-CFG-013.

### Joins across resources or systems

- CIS metric filter -> CloudWatch alarm -> SNS subscriber (the alarm half of CIS-AWS:4.1..4.15; AWS-CW-METRIC-FILTER-* checks the filter only). Source: AWS-MON-008.
- Security groups attached to nothing (FSBP:EC2.22), instances not managed by SSM (FSBP:SSM.1 coverage), resources with no backup plan, newest recovery point per resource. Source: AWS-CFG-021, AWS-HYG-001, AWS-BCK-001, AWS-BCK-002, AWS-BCK-007.
- "Toxic combinations": a public instance with an admin port open and a privileged role; a public bucket with sensitive data.
- IAM users with neither console nor key use in 90 days (password last used + every key's last use). CIS-AWS:1.12.
- AD computer objects of terminated instances; AWS servers in PRTG/Dynatrace/backup products; SSM inventory against the Windows estate pack. Source: AWS-HYG-009, AWS-MON-018, AWS-AVL-012, AWS-BCK-010, AWS-BCK-011, AWS-LCM-001, AWS-LCM-002, AWS-LCM-014, AWS-LCM-018, AWS-LCM-019, AWS-HYG-013.

## Secret-, credential- or content-returning reads the runner refuses or masks

- IAM credential report (one base64 CSV blob, not rows). Root last used, password-enabled users. Source: AWS-IAM-004, AWS-IAM-009, AWS-LOG-008 (root part); CIS-AWS:1.7.
- Secrets in environment variables and user data: Lambda/ECS environments, CodeBuild variables and EC2 user data come back as "set", so their names (AWS_SECRET_ACCESS_KEY, DB_PASSWORD) cannot be judged. By design. FSBP:ECS.8, CodeBuild.2. Source: AWS-IAM-037.
- Session Manager preferences (encryption, logging) live in the SSM-SessionManagerRunShell document's content (GetDocument), which is document content.
- AWS-derived secrets in the workspace/mail: a local content scan, not an API state. Source: AWS-IAM-038.

## Process-only / attestation (no API state to read)

- Break-glass path documented and tested; DR region strategy; RTO/RPO per system; change procedure; architecture documentation; support tier; cost-allocation sign-off; evidence freshness; script defects and signing. Source: AWS-IAM-035, AWS-AVL-012, AWS-BCK-021, AWS-HYG-015, AWS-CFG-024, AWS-LCM-022, AWS-CST-036, AWS-MON-019, AWS-HYG-018, AWS-BCK-013, AWS-BCK-020.
- Account purpose/owner tags vs documentation, data residency, OU structure, CIDR overlap with on-premises. Source: AWS-CFG-003, AWS-CFG-016, AWS-CFG-019, AWS-CFG-022, AWS-CFG-028.
- Root/notification mailbox triage (Microsoft 365 pack); public endpoint certificate checks (`rules/certificates.yaml`, tls protocol). Source: AWS-MON-016, AWS-HLT-018, AWS-PKI-004.

## Thresholds

Set as `threshold.<name>` in the Keeper home; the value in the rule applies when it is not set.

| Threshold | Default | Rule |
|---|---|---|
| aws.iam.access-key-max-age-days | 90 | AWS-IAM-ACCESS-KEY-OLD |
| aws.iam.password-min-length | 14 | AWS-IAM-PASSWORD-POLICY-WEAK |
| aws.iam.password-reuse-count | 24 | AWS-IAM-PASSWORD-REUSE-ALLOWED |
| aws.iam.password-max-age-days | 90 | AWS-IAM-PASSWORD-NO-EXPIRY |
| aws.iam.unused-credential-days | 45 | AWS-IAM-USER-PASSWORD-UNUSED |
| aws.iam.unused-role-days | 90 | AWS-IAM-ROLE-UNUSED |
| aws.iam.server-cert-notice-days | 30 | AWS-IAM-SERVER-CERT-EXPIRY |
| aws.kms.max-rotation-days | 365 | AWS-KMS-ROTATION-PERIOD-LONG |
| aws.ebs.snapshot-max-age-days | 365 | AWS-EBS-SNAPSHOT-OLD |
| aws.ec2.previous-generation-pattern | `^(t1\|m1\|m2\|m3\|c1\|c3\|cc2\|cg1\|cr1\|g2\|hi1\|hs1\|i2\|r3)\.` | AWS-EC2-PREVIOUS-GENERATION |
| aws.ec2.imds-max-hops | 1 | AWS-EC2-IMDS-HOP-LIMIT |
| aws.ec2.reservation-notice-days | 30 | AWS-EC2-RESERVATION-EXPIRING |
| aws.rds.min-backup-retention-days | 7 | AWS-RDS-BACKUP-RETENTION-SHORT, AWS-RDS-CLUSTER-BACKUP-RETENTION-SHORT |
| aws.rds.ca-notice-days | 60 | AWS-RDS-CA-CERT-EXPIRY |
| aws.rds.maintenance-notice-days | 30 | AWS-RDS-MAINTENANCE-FORCED-SOON |
| aws.redshift.min-snapshot-retention-days | 7 | AWS-REDSHIFT-SNAPSHOT-RETENTION-SHORT |
| aws.acm.notice-days | 30 | AWS-ACM-CERT-EXPIRY |
| aws.secrets.unused-days | 90 | AWS-SECRET-UNUSED |
| aws.secrets.max-rotation-days | 90 | AWS-SECRET-ROTATION-INTERVAL-LONG |
| aws.backup.min-retention-days | 7 | AWS-BACKUP-PLAN-SHORT-RETENTION |
| aws.lambda.deprecated-runtime-pattern | *(required; the inline pattern is a starting point)* | AWS-LAMBDA-RUNTIME-DEPRECATED |
| aws.eks.min-version | *(required; inline 1.31 is a starting point)* | AWS-EKS-VERSION-OLD |
| aws.kms.foreign-account-pattern | *(required; a regex matching an account ARN whose id is not the organisation's, e.g. `arn:aws:iam::(?!(?:<id1>\|<id2>):)[0-9]{12}:`)* | AWS-KMS-KEY-POLICY-FOREIGN-ACCOUNT |
| aws.cloudfront.weak-tls-pattern | `^(SSLv3\|TLSv1\|TLSv1_2016\|TLSv1\.1_2016)$` | AWS-CLOUDFRONT-WEAK-TLS |

## To confirm on the first real run

Nothing in `rules/aws.yaml` has run against an account yet. The validator checks syntax, the allow-list
and REST paths; it does not check AWS's answer shapes. In order of doubt:

- **GetAccountAuthorizationDetails** (AWS-IAM-POLICY-*, -ROLE-*, -GROUP-*): the union XPath returns one row per policy/user/group/role across pages; the documents are URL-encoded as expected; `RoleLastUsed.LastUsedDate` is present for used roles. The regexes were tested offline against encoded and raw sample documents only.
- **Rows without items** (GuardDuty ListDetectors, Config recorders, Access Analyzer, Security Hub GetEnabledStandards, CloudTrail DescribeTrails, DescribeMetricFilters, DynamoDB DescribeContinuousBackups, Backup ListBackupSelections): one row per account and region (per object). DescribeMetricFilters with more than 50 filters in an account pages into a second row with the same key - the first page's row can then report a filter as missing that is on page two.
- **XML response elements as rows**: `//DescribeFlowLogsResponse`, `//GetSnapshotBlockPublicAccessStateResponse`, `//GetImageBlockPublicAccessStateResponse`, `//GetSerialConsoleAccessStatusResponse`, `//GetInstanceMetadataDefaultsResponse`, `//ListMFADevicesResult`, `//GetGroupResult`, `//ListEntitiesForPolicyResult`, `//DescribeLoggingStatusResult`, `//GetTopicAttributesResult/Attributes`.
- **EC2 query params**: `RestorableBy.1: all` on DescribeSnapshots returns only public snapshots; `LaunchTemplateVersion.1: $Default` without a template id returns every template's default version; the Client VPN set is `clientVpnEndpoint/item`.
- **REST bodies**: GuardDuty ListFindings criterion keys (`gte`, `eq`), Security Hub GetFindings filters, Inspector filterCriteria - a wrong key is an API error (unknown), not a silent pass.
- **Lambda `Environment`** is absent (not an empty object) on functions without variables; otherwise AWS-LAMBDA-ENV-NO-CMK reports every function.
- **IAM SSO-reserved roles** (path `/aws-reserved/sso.amazonaws.com/`) carry permission-set policies inline: admin permission sets will appear under AWS-IAM-POLICY-ADMIN, which is accurate but may want an exception per set.
- **Access Analyzer per region** flags member accounts that rely on an organisation analyzer in the delegated administrator; **AWS-IAM-ROLE-TRUST-NO-EXTERNAL-ID** flags same-account trusts. Both say so in their why.
- The earlier items still stand: ACM `ListCertificates` summary carries NotAfter/Type/InUse/KeyAlgorithm; S3 per-bucket reads resolve each bucket's region via `BucketRegion`; GetBucketVersioning returns an empty configuration when never enabled; KMS rotation on asymmetric keys reads false (AWS-KMS-ROTATION-DISABLED may list them).
