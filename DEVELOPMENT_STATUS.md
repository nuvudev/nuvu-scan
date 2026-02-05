# Nuvu Scan - Development Status

**Multi-Cloud Data Asset Scanner** - Open-source scanner designed to discover and inventory cloud data assets across AWS, GCP, Azure, and Databricks.

> **Note**: nuvu-scan is a read-only scanner that collects asset metadata. For governance, policy enforcement, and decision-making, see [nuvu-cloud](https://github.com/nuvudev/nuvu-cloud).

## ✅ Available Collectors (v2.1.0)

### AWS Collectors (18 collectors)

| Collector | Command Flag | What It Scans | Key Metrics |
|-----------|--------------|---------------|-------------|
| **S3** | `s3` | Buckets, policies, encryption | Size, public access, versioning |
| **Glue** | `glue` | Databases, tables, crawlers, jobs, connections | Table counts, crawl status, job runs |
| **Athena** | `athena` | Workgroups, query history | Query stats, failure rates |
| **Redshift** | `redshift` | Clusters, serverless, snapshots, datashares, reserved nodes | CPU, connections, WLM, costs |
| **IAM** | `iam` | Roles, users, groups, access keys | Permissions, MFA, key age, last used |
| **MWAA** | `mwaa` | Apache Airflow environments | Environment class, worker counts |
| **EC2/VPC** | `ec2` | Security groups, VPCs, instances, EBS volumes, Elastic IPs | Open ports, public IPs, volume encryption |
| **KMS** | `kms` | Customer-managed encryption keys | Rotation status, key state |
| **RDS** | `rds` | RDS instances, Aurora clusters, snapshots | Encryption, multi-AZ, backup retention |
| **DynamoDB** | `dynamodb` | DynamoDB tables | PITR, encryption, capacity mode |
| **Lambda** | `lambda` | Lambda functions | Runtime, code size, VPC config |
| **Secrets Manager** | `secrets` | Secrets | Rotation, last accessed, age |
| **AWS Backup** | `backup` | Backup vaults, backup plans | Recovery points, lifecycle |
| **EKS** | `eks` | EKS clusters, node groups | K8s version, endpoint access |
| **SNS/SQS** | `sns_sqs` | SNS topics, SQS queues | Encryption, DLQ, message counts |
| **Lake Formation** | `lakeformation` | Data lake settings, permissions, LF-Tags | Permission grants, admin count |
| **CloudTrail** | `cloudtrail` | CloudTrail trails | Multi-region, encryption, logging status |
| **CloudWatch** | `cloudwatch` | CloudWatch log groups | Retention, encryption, size |

### GCP Collectors (6 collectors)

| Collector | Command Flag | What It Scans | Key Metrics |
|-----------|--------------|---------------|-------------|
| **GCS** | `gcs` | Cloud Storage buckets | Size, public access, lifecycle |
| **BigQuery** | `bigquery` | Datasets, tables, query history | Table sizes, query costs |
| **Dataproc** | `dataproc` | Dataproc clusters | Cluster config, job history |
| **Pub/Sub** | `pubsub` | Topics, subscriptions | Message counts |
| **IAM** | `iam` | Service accounts | Roles, permissions |
| **Gemini** | `gemini` | Gemini API usage | API costs |

## 📋 Usage

### Basic Scan
```bash
# Scan all AWS collectors
nuvu-scan aws

# Scan all GCP collectors
nuvu-scan gcp --credentials /path/to/key.json
```

### Selective Scanning
```bash
# Scan specific collectors
nuvu-scan aws --collectors s3,rds,iam,kms

# List available collectors
nuvu-scan aws --list-collectors
```

### Output Formats
```bash
# HTML report (default)
nuvu-scan aws -o report.html

# JSON output
nuvu-scan aws -o assets.json

# CSV output
nuvu-scan aws -o assets.csv
```

### Push to Nuvu Cloud
```bash
# Push results to nuvu-cloud for governance
nuvu-scan aws --push --api-key YOUR_API_KEY
```

## 🔒 IAM Permissions

The complete IAM policy is in `aws-iam-policy.json` (60+ permission statements).

### Permission Categories

| Category | Services | Example Actions |
|----------|----------|-----------------|
| **Storage** | S3, EBS | `s3:GetBucket*`, `ec2:DescribeVolumes` |
| **Compute** | EC2, Lambda, EKS | `ec2:DescribeInstances`, `lambda:ListFunctions` |
| **Database** | RDS, DynamoDB, Redshift | `rds:DescribeDB*`, `dynamodb:DescribeTable` |
| **Data Analytics** | Glue, Athena, Lake Formation | `glue:GetTables`, `athena:ListWorkGroups` |
| **Security** | IAM, KMS, Secrets Manager | `iam:ListRoles`, `kms:DescribeKey` |
| **Networking** | VPC, Security Groups | `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs` |
| **Messaging** | SNS, SQS | `sns:GetTopicAttributes`, `sqs:GetQueueAttributes` |
| **Observability** | CloudWatch, CloudTrail | `logs:DescribeLogGroups`, `cloudtrail:DescribeTrails` |
| **Resilience** | AWS Backup | `backup:ListBackupVaults`, `backup:ListBackupPlans` |
| **Cost** | Cost Explorer | `ce:GetCostAndUsage` |

All permissions are **read-only** following the principle of least privilege.

## 📊 Asset Types Collected

### Compute
- EC2 instances, EBS volumes, Elastic IPs
- Lambda functions
- EKS clusters, node groups

### Storage
- S3 buckets
- EBS volumes

### Databases
- RDS instances, Aurora clusters
- DynamoDB tables
- Redshift clusters (provisioned & serverless)

### Data Catalog
- Glue databases, tables, crawlers, jobs
- Lake Formation settings, permissions, LF-Tags

### Security
- IAM roles, users, groups, access keys
- KMS keys
- Secrets Manager secrets
- Security groups, VPCs

### Observability
- CloudWatch log groups
- CloudTrail trails

### Messaging
- SNS topics
- SQS queues

### Backup
- AWS Backup vaults and plans

## 🏷️ Risk Flags

nuvu-scan identifies potential issues by flagging assets:

| Category | Example Flags |
|----------|---------------|
| **Security** | `unencrypted`, `publicly_accessible`, `mfa_disabled`, `open_to_internet` |
| **Access** | `unused_role`, `old_key`, `overly_permissive`, `public_access` |
| **Operations** | `no_backups`, `stale_crawler`, `deprecated_runtime`, `logging_disabled` |
| **Cost** | `unattached_volume`, `old_snapshot`, `unused_eip` |
| **Compliance** | `no_retention_policy`, `rotation_disabled`, `pitr_disabled` |

## 🧪 Testing

```bash
# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=nuvu_scan
```

## 📦 Installation

```bash
# From PyPI
pip install nuvu-scan

# From source
git clone https://github.com/nuvudev/nuvu-scan
cd nuvu-scan
uv sync
```

## 📋 Roadmap

### Additional AWS Collectors
- [ ] OpenSearch collector
- [ ] EMR collector
- [ ] SageMaker collector
- [ ] Bedrock collector
- [ ] MSK (Kafka) collector
- [ ] Kinesis collector
- [ ] Step Functions collector
- [ ] EventBridge collector

### Additional GCP Collectors
- [ ] Cloud SQL collector
- [ ] Cloud Spanner collector
- [ ] Bigtable collector
- [ ] Firestore collector
- [ ] Vertex AI collector
- [ ] Dataflow collector
- [ ] Cloud Composer collector

### Azure Provider
- [ ] Blob Storage collector
- [ ] Data Lake collector
- [ ] Synapse collector
- [ ] Azure Databricks collector

### Databricks Provider
- [ ] Workspace discovery
- [ ] Unity Catalog

### Enhancements
- [ ] Parallel collection for faster scans
- [ ] Progress bars with ETA
- [ ] Incremental scanning (delta detection)
- [ ] Schema-level inventory (Redshift Data API)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
