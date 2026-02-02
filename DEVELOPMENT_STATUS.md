# Nuvu Scan - Development Status

**Multi-Cloud Data Asset Control** - Designed from the ground up to support AWS, GCP, Azure, and Databricks.

## ✅ Completed (v2.0.0)

### Core Architecture
- ✅ Cloud-agnostic base interface (`CloudProviderScan`)
- ✅ Normalized asset categories enum (now includes `DATA_PIPELINE`, `DATA_SHARING`)
- ✅ Cloud-agnostic data models (`Asset`, `ScanResult`, `ScanConfig`)
- ✅ Provider module structure for future multi-cloud support
- ✅ Modern Python packaging with `uv` and `pyproject.toml`
- ✅ Python 3.10+ support (removed EOL versions 3.8, 3.9)

### AWS Provider Implementation

#### S3 Bucket Collector
- ✅ Lists all buckets across all regions
- ✅ Gets bucket metadata (size, storage class, tags)
- ✅ Detects public access and policy status
- ✅ Estimates costs (storage + requests)
- ✅ Flags risks (empty buckets, PII naming, public access)
- ✅ Infers ownership from tags
- ✅ Last activity tracking via CloudTrail

#### Glue Data Catalog Collector (Enhanced in v2.0.0)
- ✅ **Databases & Tables**
  - Lists databases and tables
  - Detects empty tables and databases
  - Links databases to their crawlers for activity tracking
  - Table update time tracking
  - External table (Spectrum) detection
- ✅ **Glue Crawlers** (NEW)
  - Lists all crawlers with status (READY, RUNNING)
  - Schedule expression and state (SCHEDULED, unscheduled)
  - Last crawl time and status
  - Tables created/updated/deleted counts
  - Risk flags: `stale_crawler` (>90 days), `no_schedule`, `never_run`
- ✅ **Glue ETL Jobs** (NEW)
  - Lists all ETL jobs
  - Job type, Glue version, allocated capacity
  - Last run status and time
  - Cost estimation based on DPU hours
  - Risk flags: `stale_job`, `never_run`, `failed_job`
- ✅ **Glue Connections** (NEW)
  - Lists JDBC connections
  - Connection type and masked JDBC URLs
  - Risk flags: `external_connection` (non-AWS databases)

#### Athena Workgroup Collector
- ✅ Lists workgroups
- ✅ Analyzes query history (last 90 days)
- ✅ Detects idle workgroups
- ✅ Flags high failure rates
- ✅ Last activity tracking from query stats

#### Redshift Collector (Major Enhancement in v2.0.0)
- ✅ **Provisioned Clusters** (Enhanced)
  - Lists all clusters across ALL regions (auto-discovery)
  - Node type, count, encryption status
  - CloudWatch-based activity tracking (DatabaseConnections, CPUUtilization)
  - Cluster age calculation
  - VPC and public accessibility detection
  - **Reservation coverage analysis** - checks if covered by reserved nodes
  - **WLM configuration analysis** - queue count, auto WLM, unlimited queues
  - Potential reservation savings calculation (40% estimate)
  - **Performance metrics from CloudWatch** (NEW)
    - CPU utilization max/avg (24h)
    - Queries completed (24h)
    - Disk space usage percentage
    - Query duration and queue time
    - Performance recommendations (right-sizing)
  - Risk flags: `publicly_accessible`, `unencrypted`, `low_activity`, `potentially_unused`, `no_reservation_long_running`, `default_wlm_only`, `unlimited_wlm_queue`, `low_cpu_utilization`
- ✅ **Redshift Serverless** (Enhanced)
  - Namespaces with encryption status
  - Workgroups with base capacity and cost estimation
  - **RPU utilization metrics from CloudWatch** (NEW)
    - RPU max/avg (24h and 7d)
    - Queries completed/failed (24h)
    - Query duration metrics
    - Utilization recommendations for capacity right-sizing
  - Risk flags: `publicly_accessible`, `low_rpu_utilization`, `high_query_failure_rate`
- ✅ **Redshift Datashares** (NEW)
  - Lists all datashares (inbound and outbound)
  - Consumer account identification
  - Cross-account and cross-region detection
  - Public consumer allowance check
  - Risk flags: `cross_account_sharing`, `cross_region_sharing`, `allows_public_consumers`
- ✅ **Redshift Snapshots** (NEW)
  - Lists all snapshots (manual and automated)
  - Snapshot size and storage cost estimation
  - Snapshot age tracking
  - Orphan snapshot detection (source cluster deleted)
  - Risk flags: `old_snapshot` (>90 days), `very_old_snapshot` (>365 days), `large_snapshot` (>1TB), `orphan_snapshot`
- ✅ **Redshift Reserved Nodes** (NEW)
  - Lists all reserved nodes (active and retired)
  - Node type, count, offering type
  - Remaining duration calculation
  - Expiration tracking
  - Annual and monthly cost calculation
  - Risk flags: `reservation_expired`, `reservation_expiring_soon`, `reservation_retired`

#### IAM Roles Collector
- ✅ Lists IAM roles with data-access permissions
- ✅ Detects unused roles (90+ days)
- ✅ Flags overly permissive policies
- ✅ Infers ownership from tags and role names
- ✅ Last activity tracking from `RoleLastUsed`

#### MWAA (Managed Workflows for Apache Airflow) Collector
- ✅ Lists MWAA environments across regions
- ✅ Collects environment details (status, version, worker counts)
- ✅ Estimates costs based on environment class
- ✅ Infers ownership from tags
- ✅ Last activity tracking from `LastUpdate`

#### Cost Explorer Integration
- ✅ Retrieves actual costs from AWS Cost Explorer API
- ✅ Service-level cost breakdown
- ✅ Monthly cost estimates based on last 30 days
- ✅ Cost summary asset in scan results

### GCP Provider Implementation

#### GCS (Google Cloud Storage) Collector
- ✅ Lists all buckets
- ✅ Gets bucket metadata (size, storage class, labels)
- ✅ Detects public access
- ✅ Estimates costs
- ✅ Flags risks (empty buckets, public access)
- ✅ Infers ownership from labels
- ✅ Last activity tracking from bucket update time

#### BigQuery Collector
- ✅ Lists datasets and tables
- ✅ Analyzes query job history (last 90 days)
- ✅ Tracks query costs (including public datasets)
- ✅ Creates dedicated asset for query costs
- ✅ Estimates costs with 1 TB free tier consideration
- ✅ Detailed usage metrics (TB processed, monthly estimates)
- ✅ Last activity tracking from query stats

#### Dataproc Collector
- ✅ Lists Dataproc clusters
- ✅ Collects cluster details and job history
- ✅ Estimates costs
- ✅ Last activity tracking from job stats

#### Pub/Sub Collector
- ✅ Lists topics and subscriptions
- ✅ Collects topic metadata
- ✅ Estimates costs
- ✅ Last activity tracking

#### IAM Service Accounts Collector
- ✅ Lists service accounts
- ✅ Checks for data-access roles
- ✅ Flags overly permissive roles
- ✅ Infers ownership from display names and email patterns
- ✅ Last activity tracking from update time

#### Gemini API Collector
- ✅ Checks if Gemini API is enabled
- ✅ Retrieves actual costs from BigQuery billing export
- ✅ Fallback to Cloud Monitoring API for usage detection
- ✅ Last activity tracking from billing data

### CLI
- ✅ Command-line interface with `nuvu scan --provider <aws|gcp>`
- ✅ Support for multiple output formats:
  - HTML (default) - Beautiful interactive report with governance insights
  - JSON - Machine-readable format
  - CSV - Spreadsheet-friendly format
- ✅ Credential handling:
  - AWS: env vars, CLI args, AWS profiles, IAM role assumption
  - GCP: JSON key files, `GOOGLE_APPLICATION_CREDENTIALS`, JSON content
- ✅ Region filtering support (AWS)
- ✅ Project ID support (GCP)
- ✅ **Nuvu Cloud API push** (`--push --api-key`)
- ✅ **Collector Filtering** (NEW)
  - `--collectors` / `-c` option to run specific collectors
  - `--list-collectors` to show available collectors
  - AWS collectors: `s3`, `glue`, `athena`, `redshift`, `iam`, `mwaa`
  - GCP collectors: `gcs`, `bigquery`, `dataproc`, `pubsub`, `iam`, `gemini`
  - Omit option for full scan (all collectors)
- ✅ **Progress Logging** - Real-time status updates during collection

### Enhanced HTML Reports (v2.0.0)
- ✅ **Scan Scope Section** (NEW) - Shows which collectors and regions were scanned
- ✅ **Executive Summary** with key metrics
- ✅ **Cost Optimization Section**
  - Snapshot cost analysis with old snapshot flagging
  - Reserved node status and expiration tracking
  - Potential savings calculation
- ✅ **Governance Insights Section**
  - Stale/unused crawlers and ETL jobs
  - Cross-account data sharing alerts
  - WLM configuration review
  - **Cluster Performance table** (NEW) - CPU, queries, disk, recommendations
  - **Serverless Workgroup Utilization table** (NEW) - RPU metrics, recommendations
- ✅ Improved styling with insight boxes (warning, alert, info)
- ✅ Potential savings card in summary
- ✅ **Footer with nuvu-scan attribution** and GitHub repository link

### New Asset Categories (v2.0.0)
- ✅ `DATA_PIPELINE` - ETL jobs, crawlers, workflows
- ✅ `DATA_SHARING` - Datashares, cross-account sharing

### New Asset Types (v2.0.0)
| Asset Type | Service | Description |
|------------|---------|-------------|
| `glue_crawler` | Glue | Crawler status, schedule, last run |
| `glue_job` | Glue | ETL job status, DPU allocation |
| `glue_connection` | Glue | JDBC connections to external DBs |
| `redshift_datashare` | Redshift | Cross-account data sharing |
| `redshift_snapshot` | Redshift | Manual and automated snapshots |
| `redshift_reserved_node` | Redshift | Reserved capacity purchases |
| `redshift_serverless_workgroup` | Redshift | Serverless workgroup details |

### New Risk Flags (v2.0.0)
| Category | Flag | Description |
|----------|------|-------------|
| Glue | `stale_crawler` | Crawler hasn't run in 90+ days |
| Glue | `no_schedule` | Crawler has no schedule configured |
| Glue | `never_run` | Crawler or job has never been executed |
| Glue | `stale_job` | ETL job hasn't run in 90+ days |
| Glue | `failed_job` | Last job run failed |
| Glue | `external_connection` | JDBC connection to non-AWS database |
| Redshift | `cross_account_sharing` | Datashare shared to another AWS account |
| Redshift | `cross_region_sharing` | Datashare shared across regions |
| Redshift | `allows_public_consumers` | Datashare allows public consumers |
| Redshift | `old_snapshot` | Snapshot older than 90 days |
| Redshift | `very_old_snapshot` | Snapshot older than 365 days |
| Redshift | `large_snapshot` | Snapshot larger than 1TB |
| Redshift | `orphan_snapshot` | Source cluster no longer exists |
| Redshift | `no_reservation_long_running` | Cluster running 90+ days without reservation |
| Redshift | `reservation_expired` | Reserved node has expired |
| Redshift | `reservation_expiring_soon` | Reserved node expires within 30 days |
| Redshift | `default_wlm_only` | Cluster using only default WLM queue |
| Redshift | `unlimited_wlm_queue` | WLM queue with no concurrency limit |
| Redshift | `low_cpu_utilization` | Cluster CPU never exceeds 20% (right-sizing opportunity) |
| Redshift Serverless | `low_rpu_utilization` | RPU usage below 50% of base capacity |
| Redshift Serverless | `high_query_failure_rate` | >10% of queries failing |

### Cost Tracking & Reporting
- ✅ Asset-level cost estimation for all resources
- ✅ AWS Cost Explorer API integration for actual costs
- ✅ GCP Cloud Billing API integration (Gemini costs)
- ✅ BigQuery query cost tracking (including public datasets)
- ✅ Redshift snapshot storage cost estimation
- ✅ Potential reservation savings calculation
- ✅ Cost summary assets showing service-level breakdowns

### Usage & Activity Tracking
- ✅ Last activity timestamp for all assets (`last_activity_at`)
- ✅ Days since last use calculation
- ✅ **CloudWatch metrics for Redshift** (DatabaseConnections, CPUUtilization)
- ✅ CloudTrail integration for AWS (S3, Redshift)
- ✅ Crawler run times for Glue database/table activity
- ✅ Query history analysis (Athena, BigQuery)
- ✅ Job history analysis (Dataproc, Glue ETL)

### Package & Distribution
- ✅ Modern Python packaging with `pyproject.toml` and `uv`
- ✅ Comprehensive README.md with setup instructions
- ✅ IAM policy file (`aws-iam-policy.json`) with 60+ read-only actions
- ✅ GitHub Actions CI/CD workflows
- ✅ Package structure ready for PyPI

## 🧪 Tested

### AWS (v2.0.0 Test Results)
- ✅ Discovered 2,344 assets in single-region scan (us-west-2)
  - 90 S3 buckets
  - 1,013 Glue assets (94 databases, 904 tables, 10 crawlers, 2 jobs, 3 connections)
  - 1 Athena workgroup
  - 1,141 Redshift assets (5 clusters, 2 namespaces, 2 workgroups, 12 datashares, 1,096 snapshots, 24 reserved nodes)
  - 95 IAM roles
  - 3 MWAA environments
- ✅ Snapshot cost totaling $88,684.92/month identified
- ✅ Reserved node status correctly identified (active vs retired)
- ✅ Cross-account datashares flagged correctly
- ✅ WLM configuration analysis working
- ✅ CloudWatch-based activity tracking working
- ✅ HTML report with Cost Optimization and Governance sections

### GCP
- ✅ Discovered GCS buckets, BigQuery datasets, Dataproc clusters, Pub/Sub topics
- ✅ IAM service accounts scanning
- ✅ Gemini API cost tracking from billing export
- ✅ BigQuery query cost tracking (including public datasets)

## 🔒 IAM Permissions Required

### AWS
The complete IAM policy is available in `aws-iam-policy.json`. Key permission groups:

| Permission Group | Actions | Purpose |
|-----------------|---------|---------|
| S3 | 9 actions | Bucket metadata, public access, encryption |
| Glue Data Catalog | 6 actions | Databases, tables, partitions |
| Glue Crawlers | 4 actions | Crawler status, metrics |
| Glue ETL Jobs | 5 actions | Job status, run history |
| Glue Connections | 2 actions | JDBC connections |
| Athena | 4 actions | Workgroups, query history |
| Redshift Clusters | 4 actions | Cluster metadata, logging |
| Redshift Snapshots | 3 actions | Snapshot inventory |
| Redshift Reserved Nodes | 3 actions | Reservation status |
| Redshift WLM | 2 actions | Parameter groups |
| Redshift Datashares | 3 actions | Cross-account sharing |
| Redshift Serverless | 5 actions | Namespaces, workgroups |
| IAM | 8 actions | Role policies, data access |
| MWAA | 3 actions | Airflow environments |
| CloudWatch | 3 actions | Metrics for activity tracking |
| CloudTrail | 1 action | Last activity detection |
| Cost Explorer | 5 actions | Actual cost reporting |
| STS | 1 action | Account identity |

**Total: 66 read-only actions** following the principle of least privilege.

### GCP
Required IAM roles for the service account:
- `roles/storage.objectViewer` - Cloud Storage
- `roles/bigquery.dataViewer` + `roles/bigquery.jobUser` - BigQuery
- `roles/dataproc.viewer` - Dataproc
- `roles/pubsub.subscriber` - Pub/Sub
- `roles/iam.serviceAccountViewer` - IAM service accounts
- `roles/serviceusage.serviceUsageViewer` - API status
- `roles/billing.costsViewer` - Cost Explorer (optional)
- `roles/monitoring.viewer` - Cloud Monitoring

## 📋 TODO for Full v2

### Additional AWS Collectors
- [ ] OpenSearch collector
- [ ] EMR collector
- [ ] SageMaker collector
- [ ] Bedrock collector
- [ ] MSK (Kafka) collector
- [ ] Kinesis collector
- [ ] DataSync/Transfer Family collector
- [ ] EBS Volumes & Snapshots collector
- [ ] VPC Endpoints collector
- [ ] Lake Formation collector
- [ ] Step Functions collector
- [ ] EventBridge collector

### Redshift Deep Governance (Phase 2)
- [ ] Schema-level inventory via Redshift Data API
- [ ] Table-level inventory with column metadata
- [ ] PII detection via column naming heuristics
- [ ] Permission matrix visualization
- [ ] Usage-based stale table detection (STL_SCAN)

### Additional GCP Collectors
- [ ] Cloud SQL collector
- [ ] Cloud Spanner collector
- [ ] Bigtable collector
- [ ] Firestore collector
- [ ] Vertex AI collector
- [ ] Dataflow collector
- [ ] Cloud Composer collector

### Enhancements
- [ ] Parallel collection for faster scans
- [ ] Progress bars with ETA
- [ ] PDF report export
- [ ] Cost alerts and thresholds
- [ ] Asset dependency mapping
- [ ] Realized savings tracking (scan-over-scan comparison)

## 🚀 Next Steps

1. **Redshift Deep Governance** - Schema/table level inventory without data access
2. **Azure Provider** - Blob Storage, Data Lake, Synapse, Databricks
3. **Databricks Provider** - Workspace discovery, Unity Catalog
4. **Enterprise Features** - RBAC, audit logging, compliance reporting
