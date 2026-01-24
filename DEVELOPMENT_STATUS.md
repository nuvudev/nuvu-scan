# Nuvu Scan - Development Status

**Multi-Cloud Data Asset Control** - Designed from the ground up to support AWS, GCP, Azure, and Databricks.

## ✅ Completed (v1.2.0)

### Core Architecture
- ✅ Cloud-agnostic base interface (`CloudProviderScan`)
- ✅ Normalized asset categories enum
- ✅ Cloud-agnostic data models (`Asset`, `ScanResult`, `ScanConfig`)
- ✅ Provider module structure for future multi-cloud support
- ✅ Modern Python packaging with `uv` and `pyproject.toml`
- ✅ Python 3.10+ support (removed EOL versions 3.8, 3.9)

### AWS Provider Implementation
- ✅ AWS Scanner implementing `CloudProviderScan` interface
- ✅ **S3 Bucket Collector**
  - Lists all buckets across all regions
  - Gets bucket metadata (size, storage class, tags)
  - Detects public access and policy status
  - Estimates costs (storage + requests)
  - Flags risks (empty buckets, PII naming, public access)
  - Infers ownership from tags
  - Last activity tracking via CloudTrail
- ✅ **Glue Data Catalog Collector**
  - Lists databases and tables
  - Detects empty tables
  - Estimates costs
  - Last activity tracking
- ✅ **Athena Workgroup Collector**
  - Lists workgroups
  - Analyzes query history (last 90 days)
  - Detects idle workgroups
  - Flags high failure rates
  - Last activity tracking from query stats
- ✅ **Redshift Collector**
  - Lists provisioned clusters
  - Lists serverless namespaces and workgroups
  - Estimates costs based on node type
  - Last activity tracking
- ✅ **IAM Roles Collector**
  - Lists IAM roles with data-access permissions
  - Detects unused roles (90+ days)
  - Flags overly permissive policies
  - Infers ownership from tags and role names
  - Last activity tracking from `RoleLastUsed`
- ✅ **MWAA (Managed Workflows for Apache Airflow) Collector**
  - Lists MWAA environments across regions
  - Collects environment details (status, version, worker counts)
  - Estimates costs based on environment class
  - Infers ownership from tags
  - Last activity tracking from `LastUpdate`
- ✅ **Cost Explorer Integration**
  - Retrieves actual costs from AWS Cost Explorer API
  - Service-level cost breakdown
  - Monthly cost estimates based on last 30 days
  - Cost summary asset in scan results

### GCP Provider Implementation
- ✅ GCP Scanner implementing `CloudProviderScan` interface
- ✅ **GCS (Google Cloud Storage) Collector**
  - Lists all buckets
  - Gets bucket metadata (size, storage class, labels)
  - Detects public access
  - Estimates costs
  - Flags risks (empty buckets, public access)
  - Infers ownership from labels
  - Last activity tracking from bucket update time
- ✅ **BigQuery Collector**
  - Lists datasets and tables
  - Analyzes query job history (last 90 days)
  - Tracks query costs (including public datasets)
  - Creates dedicated asset for query costs
  - Estimates costs with 1 TB free tier consideration
  - Detailed usage metrics (TB processed, monthly estimates)
  - Last activity tracking from query stats
- ✅ **Dataproc Collector**
  - Lists Dataproc clusters
  - Collects cluster details and job history
  - Estimates costs
  - Last activity tracking from job stats
- ✅ **Pub/Sub Collector**
  - Lists topics and subscriptions
  - Collects topic metadata
  - Estimates costs
  - Last activity tracking
- ✅ **IAM Service Accounts Collector**
  - Lists service accounts
  - Checks for data-access roles (Owner, Editor, Storage Admin, BigQuery Admin, etc.)
  - Flags overly permissive roles
  - Infers ownership from display names and email patterns
  - Last activity tracking from update time
- ✅ **Gemini API Collector**
  - Checks if Gemini API is enabled
  - Retrieves actual costs from BigQuery billing export
  - Fallback to Cloud Monitoring API for usage detection
  - Last activity tracking from billing data
  - Automatic cost retrieval (no manual input required)

### CLI
- ✅ Command-line interface with `nuvu scan --provider <aws|gcp>`
- ✅ Support for multiple output formats:
  - HTML (default) - Beautiful interactive report
  - JSON - Machine-readable format
  - CSV - Spreadsheet-friendly format
- ✅ Credential handling:
  - AWS: env vars, CLI args, AWS profiles
  - GCP: JSON key files, `GOOGLE_APPLICATION_CREDENTIALS`, JSON content
- ✅ Region filtering support (AWS)
- ✅ Project ID support (GCP)

### Cost Tracking & Reporting
- ✅ Asset-level cost estimation for all resources
- ✅ AWS Cost Explorer API integration for actual costs
- ✅ GCP Cloud Billing API integration (Gemini costs)
- ✅ BigQuery query cost tracking (including public datasets)
- ✅ Cost summary assets showing service-level breakdowns
- ✅ Notes explaining non-data asset costs

### Usage & Activity Tracking
- ✅ Last activity timestamp for all assets (`last_activity_at`)
- ✅ Days since last use calculation
- ✅ Usage metrics with `last_used` and `days_since_last_use`
- ✅ CloudTrail integration for AWS (S3, Redshift)
- ✅ Query history analysis (Athena, BigQuery)
- ✅ Job history analysis (Dataproc)

### Package & Distribution
- ✅ Modern Python packaging with `pyproject.toml` and `uv`
- ✅ Removed legacy `setup.py` and `requirements.txt`
- ✅ Comprehensive README.md with setup instructions
- ✅ IAM policy file (`aws-iam-policy.json`) for AWS credentials
- ✅ GitHub Actions CI/CD workflows
- ✅ Package structure ready for PyPI

## 🧪 Tested

### AWS
- ✅ Discovered S3 buckets, Athena workgroups, Glue databases, Redshift clusters
- ✅ IAM roles scanning with data-access permission detection
- ✅ MWAA environments discovery
- ✅ Cost Explorer integration showing actual costs ($25.55 in test account)
- ✅ Last activity tracking working
- ✅ Risk flagging working (public access, empty buckets, unused roles)
- ✅ HTML, JSON, and CSV output formats working

### GCP
- ✅ Discovered GCS buckets, BigQuery datasets, Dataproc clusters, Pub/Sub topics
- ✅ IAM service accounts scanning
- ✅ Gemini API cost tracking from billing export
- ✅ BigQuery query cost tracking (including public datasets)
- ✅ Last activity tracking working
- ✅ Cost estimation working

## 📋 TODO for Full v1

### Additional AWS Collectors
- [ ] OpenSearch collector
- [ ] EMR collector
- [ ] SageMaker collector
- [ ] Bedrock collector
- [ ] Glue Jobs collector
- [ ] MSK (Kafka) collector
- [ ] Kinesis collector
- [ ] DataSync/Transfer Family collector
- [ ] EBS Volumes & Snapshots collector
- [ ] VPC Endpoints collector
- [ ] Lake Formation collector

### Additional GCP Collectors
- [ ] Cloud SQL collector
- [ ] Cloud Spanner collector
- [ ] Bigtable collector
- [ ] Firestore collector
- [ ] Cloud Functions collector
- [ ] Vertex AI collector
- [ ] Dataflow collector

### Enhancements
- [ ] Better CloudTrail integration for more accurate last activity
- [ ] More accurate cost estimation using AWS Pricing API
- [ ] Enhanced ownership heuristics (CloudTrail event analysis)
- [ ] Progress indicators for long scans
- [ ] Parallel collection for faster scans
- [ ] Error handling and retry logic improvements
- [ ] Cost alerts and thresholds
- [ ] Asset dependency mapping

### IAM Policy & Security
- ✅ IAM policy file created (`aws-iam-policy.json`)
- ✅ Policy documented in README

## 🔒 IAM Permissions Required

### AWS
The complete IAM policy is available in `aws-iam-policy.json`. The policy includes read-only permissions for:

- **S3**: List buckets, get metadata, check public access, list objects
- **Glue**: List databases and tables, get tags
- **Athena**: List workgroups, get query history
- **Redshift**: Describe clusters, list serverless namespaces
- **IAM**: List roles, get policies (for data-access analysis)
- **MWAA**: List environments, get environment details
- **CloudWatch**: Get metrics for usage tracking
- **CloudTrail**: Lookup events for last activity detection
- **Cost Explorer**: Get cost and usage data (optional, for actual cost reporting)
- **STS**: Get caller identity

**Total: 40 read-only actions** following the principle of least privilege.

### GCP
Required IAM roles for the service account:

- `roles/storage.objectViewer` - For Cloud Storage
- `roles/bigquery.dataViewer` + `roles/bigquery.jobUser` - For BigQuery
- `roles/dataproc.viewer` - For Dataproc
- `roles/pubsub.subscriber` - For Pub/Sub
- `roles/iam.serviceAccountViewer` - For IAM service accounts
- `roles/serviceusage.serviceUsageViewer` - For checking API status (Gemini, etc.)
- `roles/billing.costsViewer` - For Cost Explorer (optional, for actual costs)
- `roles/monitoring.viewer` - For Cloud Monitoring (fallback for Gemini costs)

See README.md for detailed setup instructions.

## 🚀 Next Steps

1. **Azure Provider** - Implement Azure scanner with collectors for:
   - Azure Blob Storage
   - Azure Data Lake Storage
   - Azure Synapse Analytics
   - Azure Databricks
   - Azure Data Factory

2. **Databricks Provider** - Implement Databricks scanner with:
   - Workspace discovery
   - Cluster and job tracking
   - Cost tracking via underlying cloud accounts

3. **SaaS UI** - Build the Nuvu Control Plane (nuvu.dev) with:
   - Multi-tenant architecture
   - Dashboard and chat agent
   - Automated scanning schedules
   - Email and Slack notifications

4. **Enterprise Features**:
   - Credential encryption and secure storage
   - Role-based access control
   - Audit logging
   - Compliance reporting
