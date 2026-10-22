# Backlog - Google Cloud

What `rules/gcp.yaml` (167 rules) does not cover yet, and why. Every GCP rule reads one thing: Cloud Asset
Inventory `ListAssets` (`GET /assets`, one asset type and one content type per query - RESOURCE, IAM_POLICY,
ORG_POLICY or ACCESS_POLICY) with a `cloud-platform.read-only` token. Anything that needs another Google API,
a second asset type joined to the first, or a condition the engine cannot write is listed here with the
reason. CIS ids are the CIS Google Cloud Platform Foundation Benchmark; `CIS-GKE` the CIS GKE Benchmark.

## Not in Cloud Asset Inventory - needs another API or another integration

The `gcp` type reads only `cloudasset.googleapis.com/.../assets`; these live elsewhere.

- **Security Command Center findings** (vulnerabilities, threats, Security Health Analytics results, posture violations): the SCC API (`securitycenter.googleapis.com`), a different host. Would be its own integration type or a `file` import of an SCC export.
- **Google Workspace / Cloud Identity users**: MFA enforced for every user (CIS 1.2), security keys for admins (CIS 1.3), inactive users, super-admins used for daily work. Admin SDK / Cloud Identity APIs, a different host and a domain-wide-delegated identity.
- **Cloud SQL users**: MySQL root (or any user) without a password or allowed from any host (CIS 6.1.1, root host restriction). `sqladmin ... /instances/{i}/users` is a per-instance call to the SQL Admin host, not an asset.
- **Access Transparency (CIS 2.14) and Access Approval (CIS 2.15)**: organisation settings read through `accessapproval.googleapis.com` and the Access Transparency settings page; not asset types.
- **Service account and key last use, unused service accounts (90 days)**: Policy Intelligence (Activity Analysis) and IAM Recommender APIs.
- **Secrets in Cloud Functions / Cloud Run environment variables (CIS 1.18)**: the runner deliberately returns environment variables as "set", so a rule cannot tell a secret from a region name. Needs a name-only view of the variables (names without values) from the runner.
- **API key strings and their exposure**: `GetKeyString` hands over the secret - refused by design.
- **Firestore / Firebase security rules** (read/write for all users): Firebase Rules API.
- **Firewall Insights** (shadowed, unused, overly permissive rules by hit count) and **VPC flow log contents**: Recommender / Logging read APIs.
- **OS patch state of VMs (CIS 4.12)**: Cloud Asset `OS_INVENTORY` content type (or VM Manager), which the `gcp` type does not offer - RULES.md lists only the four content types above. Adding `OS_INVENTORY` and `RELATIONSHIP` to the type would open patch-level and relationship rules.
- **IAM deny policies and Principal Access Boundary policies**: IAM v2 APIs, not part of the IAM_POLICY content.

## Engine gaps - ListAssets has the data, a rule cannot express it

### Joins between two asset types

A rule reads one asset type; it cannot look up a second.

- Log sink destination bucket has a locked retention policy (CIS 2.3): `LogSink.destination` -> `Bucket.retentionPolicy.isLocked`. GCP-BUCKET-RETENTION-UNLOCKED flags every unlocked retention policy instead.
- Log-based metric has an alert policy on it (second half of CIS 2.4-2.11): `LogMetric.name` -> `AlertPolicy.conditions[].conditionThreshold.filter`. The pack checks each metric exists and, separately, that some log-based alert exists (GCP-MONITORING-NO-LOG-ALERT).
- Every VPC network is covered by a DNS policy with logging (CIS 2.12): `Network` -> `Policy.networks[]`. The pack flags policies attached with logging off, and the absence of any logging policy.
- Effective OS Login / serial port / project SSH keys per VM: instance metadata, project `commonInstanceMetadata` and the organisation constraint together. Each layer is a separate rule today.
- Effective audit-log configuration per project (organisation + folders + project) and effective organisation policy per project (inheritance, `inheritFromParent`, `restoreDefault`). Rules read the organisation's own policy and flag project/folder overrides.
- Toxic combinations: an internet-exposed VM running as a privileged service account; a service account with an admin role that also has a user-managed key; a public Cloud Run service whose identity is the default service account.
- GKE / Cloud Run / Composer / Dataflow workloads whose identity is a default service account holding Editor (needs the project IAM policy beside the workload).

### One member across two bindings

`element` judges one array element at a time; it cannot say "the same member appears in binding A and in
binding B".

- Separation of duties for service accounts (CIS 1.8): a member holding both Service Account Admin and Service Account User.
- Separation of duties for KMS (CIS 1.11): a member holding both Cloud KMS Admin and an encrypter/decrypter role.

### Numbers inside text

- Firewall port ranges that cover a sensitive port ("20-30" covers 22): the port rules match a listed port exactly; a range from the internet is GCP-FIREWALL-INTERNET-PORT-RANGE. Needs a "range contains" op.
- Ingress allowed only from the IAP range (35.235.240.0/20) and health-check ranges (CIS 3.10): source ranges are CIDRs; `in-cidr` takes an address. Needs a CIDR-within-CIDR op.
- Google durations ("7776000s"): `duration-gt` does not read the seconds form, so the KMS 90-day rotation check is a fixed regular expression with no tenant threshold, and secret rotation periods longer than 90 days are not judged. Reading `<n>s` as seconds in `TryDays` would fix both.

### Per-project must-exist

`count` is judged over the whole scope, and `count: by` only groups rows that exist. "Every project has X"
cannot be written:

- a sink exporting all logs per project not covered by an aggregated organisation sink (CIS 2.2);
- the CIS log metrics and alerts per project (CIS 2.4-2.11) - at organisation scope one project having them passes all;
- essential contacts per project or folder (CIS 1.16);
- Cloud Asset API enabled per project (CIS 2.13 - the scan itself proves it only for the scanning project).

## Deferred - expressible, left out of the first pack

Left out to keep the first pack near its size target, or because the field names could not be confirmed
without a live read. Each is a candidate for the next round once a real organisation has been scanned.

- Compute: guest attributes, nested virtualization (instance and org constraint), instance-level SSH keys, deletion protection, preemptible/Spot for production, old snapshots, uploaded (user-provided) service account keys, disabled service accounts.
- Network: auto-mode networks, flow-log sampling below 1.0 / metadata excluded (CIS 3.8 detail), public DNS zone query logging, Cloud NAT logging, egress allow-all rules, Cloud Armor default-allow and missing preconfigured WAF rules, VPC Service Controls perimeters (ACCESS_POLICY content: ingress/egress rules that allow all identities or all resources).
- Storage: lifecycle rules, bucket admin roles granted to users, static-website buckets without index/error pages.
- Cloud SQL: high availability, CMEK, IAM database authentication, password validation policy, Postgres `log_*_stats` flags, MySQL/SQL Server audit.
- GKE (CIS GKE): intranode visibility and VPC-native (5.6.1/5.6.2), Container-Optimized OS (5.5.1), node secure boot and integrity monitoring (5.5.6/5.5.7), GKE metadata server per node pool (5.4.2), Google Groups for RBAC (5.8.3), Kubernetes dashboard add-on (5.10.1 - field shape unconfirmed on current clusters), GKE Sandbox (5.10.3), node boot disk CMEK (5.9.1), default network.
- Cloud Functions 2nd gen (`cloudfunctions.googleapis.com/Function`: runtime, ingress) - the asset type name and fields are unconfirmed; 2nd-gen functions are judged as Cloud Run services meanwhile. 1st-gen default service account.
- Organisation constraints: `cloudfunctions.allowedIngressSettings`, `run.allowedIngress`, `compute.disableGuestAttributesAccess`, `compute.disableNestedVirtualization`, `ainotebooks.*`, `compute.restrictXpnProjectLienRemoval`, `cloudbuild` default service account.
- BigQuery table CMEK (CIS 7.2): `bigquery.googleapis.com/Table` can be millions of rows; needs a volume test first.
- Other services in the topic list without a rule yet: AlloyDB, Bigtable, Spanner deletion protection, Memorystore (Redis AUTH, in-transit encryption, old versions), Filestore, Composer, Data Fusion, Dataflow, Vertex AI notebooks/Workbench, Looker, Workflows, Cloud Scheduler, App Engine (CIS 4.10 HTTPS), Certificate Manager, Artifact Registry CMEK and remote repositories, Pub/Sub CMEK, Secret Manager CMEK / replication / expiry, Dataproc image version, Kerberos and component gateway.

## Confirm on the first real run

The pack has been validated (syntax, ids, ops) but never run against an organisation.

- **Asset types**: that ListAssets answers for `apikeys.googleapis.com/Key`, `essentialcontacts.googleapis.com/Contact`, `monitoring.googleapis.com/AlertPolicy`, `logging.googleapis.com/LogMetric`, `dns.googleapis.com/Policy`, `compute.googleapis.com/Project` and `iam.googleapis.com/Role`, and IAM_POLICY for `compute.googleapis.com/Image`, `bigquery.googleapis.com/Dataset`, `run.googleapis.com/Service`, `artifactregistry.googleapis.com/Repository`, `secretmanager.googleapis.com/Secret`. An unsupported type should be an API error (unknown, never a pass) - if ListAssets instead returns zero rows for it, the each-rules on it read nothing silently; a supported type with none in scope is zero rows - which makes the count rules (GCP-CONTACTS-*, GCP-MONITORING-METRIC-*, GCP-LOGGING-NO-FULL-SINK) fire.
- **Omitted booleans**: rules treat a missing boolean as false where Google's JSON drops false values (`any: [absent, eq false]`). Check a few rows that the shapes (`shieldedInstanceConfig`, `logConfig.enable`, `privateIpGoogleAccess`, `uniformBucketLevelAccess.enabled`) match.
- **Cloud Run representation**: GCP-RUN-INGRESS-ALL accepts both the v1 (Knative annotation `run.googleapis.com/ingress`) and v2 (`ingress`) shapes; confirm which the asset carries.
- **ORG_POLICY rows**: whether an organisation with no policies returns a row at all (GCP-ORGPOLICY-NONE assumes not), and whether constraints set through the v2 Org Policy API (including `managed` constraints) appear in the v1 `orgPolicy[]` view the rules read.
- **Scope**: at folder or project scope the organisation rules read nothing (GCP-SCOPE-NOT-ORGANIZATION, info) and GCP-ORGPOLICY-NONE fires; scan at the organisation.
- **Volume**: `pageSize: 1000` with cursor paging over large organisations (Disk, Firewall, ServiceAccountKey); watch for read time and the runner's page cap.
- **Thresholds** to set per tenant: `gcp.iam.external-member-pattern` (required), `gcp.gke.min-version` (required); defaults exist for `gcp.iam.sa-key-max-age-days` (90), `gcp.apikeys.max-age-days` (90), `gcp.iam.max-project-owners` (3), `gcp.compute.stopped-days` (30), `gcp.compute.unattached-days` (14), `gcp.certificates.notice-days` (45), `gcp.sql.outdated-version-pattern`, `gcp.functions.deprecated-runtime-pattern` (review both lists against Google's current support schedules).
