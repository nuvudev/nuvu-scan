# Nuvu Scan - Development Status

**Multi-Cloud Data Asset Control** - Designed from the ground up to support AWS, GCP, Azure, and Databricks.

## ✅ Completed (v0.1.0)

### Core Architecture
- ✅ Cloud-agnostic base interface (`CloudProviderScan`)
- ✅ Normalized asset categories enum
- ✅ Cloud-agnostic data models (`Asset`, `ScanResult`, `ScanConfig`)
- ✅ Provider module structure for future multi-cloud support

### AWS Provider Implementation
- ✅ AWS Scanner implementing `CloudProviderScan` interface
- ✅ S3 Bucket Collector
  - Lists all buckets
  - Gets bucket metadata (size, storage class, tags)
  - Detects public access
  - Estimates costs
  - Flags risks (empty buckets, PII naming, public access)
  - Infers ownership from tags
- ✅ Glue Data Catalog Collector
  - Lists databases and tables
  - Detects empty tables
  - Estimates costs
- ✅ Athena Workgroup Collector
  - Lists workgroups
  - Analyzes query history
  - Detects idle workgroups
  - Flags high failure rates
- ✅ Redshift Collector
  - Lists provisioned clusters
  - Lists serverless namespaces
  - Estimates costs based on node type

### CLI
- ✅ Command-line interface with `nuvu scan --provider aws`
- ✅ Support for multiple output formats:
  - HTML (default) - Beautiful interactive report
  - JSON - Machine-readable format
  - CSV - Spreadsheet-friendly format
- ✅ Credential handling (env vars, CLI args, AWS profiles)
- ✅ Region filtering support

### Package & Distribution
- ✅ Setup.py configuration
- ✅ Requirements.txt
- ✅ README.md
- ✅ Package structure ready for PyPI

## 🧪 Tested

Successfully tested with AWS credentials:
- ✅ Discovered 3 S3 buckets
- ✅ Discovered 1 Athena workgroup
- ✅ Cost estimation working
- ✅ Risk flagging working (public access, empty buckets)
- ✅ HTML and JSON output formats working

## 📋 TODO for Full v1

### Additional AWS Collectors Needed
- [ ] OpenSearch collector
- [ ] EMR collector
- [ ] SageMaker collector
- [ ] Bedrock collector
- [ ] Glue Jobs collector
- [ ] MSK (Kafka) collector
- [ ] Kinesis collector
- [ ] DataSync collector
- [ ] EBS Volumes & Snapshots collector
- [ ] IAM Roles collector
- [ ] VPC Endpoints collector
- [ ] Lake Formation collector

### Enhancements
- [ ] Better usage detection (CloudTrail integration for last access)
- [ ] More accurate cost estimation (AWS Pricing API integration)
- [ ] Enhanced ownership heuristics (CloudTrail event analysis)
- [ ] Progress indicators for long scans
- [ ] Parallel collection for faster scans
- [ ] Error handling and retry logic improvements

### IAM Policy Verification
- [ ] Test with minimal readonly IAM policy
- [ ] Document exact permissions needed
- [ ] Create IAM policy template for clients
- [ ] Verify all collectors work with readonly access

## 🔒 IAM Permissions Required

Based on current implementation, the following AWS services are accessed:

### S3
- `s3:ListAllMyBuckets`
- `s3:GetBucketLocation`
- `s3:ListBucket`
- `s3:GetBucketTagging`
- `s3:GetBucketPolicyStatus`
- `s3:GetPublicAccessBlock`
- `s3:GetObject` (for size calculation)

### Glue
- `glue:GetDatabases`
- `glue:GetTables`
- `glue:GetTags`

### Athena
- `athena:ListWorkGroups`
- `athena:GetWorkGroup`
- `athena:ListQueryExecutions`
- `athena:GetQueryExecution`

### Redshift
- `redshift:DescribeClusters`
- `redshift-serverless:ListNamespaces`
- `redshift-serverless:ListWorkgroups`

### CloudWatch (for future usage metrics)
- `cloudwatch:GetMetricStatistics`
- `cloudwatch:ListMetrics`

**Note**: Current implementation uses admin credentials for testing. The readonly IAM policy from the PRD should be tested and verified to ensure all collectors work correctly with minimal permissions.
