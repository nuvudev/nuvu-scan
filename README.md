# Nuvu Scan

**Take Control of Your Cloud Data Estate**
Discover, govern, and optimize your cloud data assets across **AWS and GCP** — reduce wasted spend, enforce compliance, and gain full visibility into unused, idle, or risky resources.

---

## Why Nuvu Scan?

Cloud data estates grow fast, and without visibility, organizations face:

- **Wasted cloud spend**: Idle storage, orphaned databases, and underutilized clusters cost millions.
- **Security & compliance gaps**: Public buckets, exposed PII, and misconfigured permissions.
- **Operational confusion**: Who owns which assets? Which datasets are stale or unused?

**Nuvu Scan solves these problems by giving you:**

- **Full Asset Visibility**: Discover every bucket, table, cluster, and service across your cloud accounts.
- **Cost Insights**: Identify idle or orphaned resources and quantify their impact on your cloud bill.
- **Automated Risk Detection**: Highlight security risks, compliance issues, and PII exposure.
- **Ownership Tracking**: Infer owners from metadata to enforce accountability.
- **Actionable Reporting**: Generate reports in HTML, CSV, or JSON to share with your team or integrate into workflows.

---

## Installation

```bash
pip install nuvu-scan
```

## Usage

### Optional: Push results to Nuvu Cloud

Nuvu Scan is fully open-source and runs standalone — no account required.
If you want dashboards, team workflows, and long‑term history, you can optionally push results to Nuvu Cloud.

```bash
# Push results to Nuvu Cloud (optional)
nuvu scan --provider aws --push --api-key your_nuvu_api_key

# Or use environment variable
export NUVU_API_KEY=your_nuvu_api_key
nuvu scan --provider aws --push

# Custom cloud URL (defaults to https://nuvu.dev)
nuvu scan --provider aws --push --nuvu-cloud-url https://nuvu.dev
```

What this means for open‑source users:
- You can keep everything local and export JSON/CSV/HTML.
- No cloud credentials are ever sent to Nuvu Cloud — only scan results.
- The data collected is identical whether you run locally or push.

### AWS Scanning

**Prerequisites:** Create an IAM user or role with the read-only policy from `aws-iam-policy.json`. See the [AWS Setup](#aws-v1---available-now) section below for detailed instructions.

Nuvu Scan supports three AWS authentication methods:

#### 1. Access Key + Secret Key (Standard Credentials)

```bash
# Via environment variables
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
nuvu scan --provider aws

# Via CLI arguments
nuvu scan --provider aws \
  --access-key-id your-key \
  --secret-access-key your-secret

# Output to JSON
nuvu scan --provider aws --output-format json --output-file report.json

# Scan specific regions
nuvu scan --provider aws --region us-east-1 --region eu-west-1
```

#### 2. Access Key + Secret Key + Session Token (Temporary Credentials)

For temporary credentials (e.g., from AWS SSO, assumed roles, or STS):

```bash
# Via environment variables
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_SESSION_TOKEN=your-session-token
nuvu scan --provider aws

# Via CLI arguments
nuvu scan --provider aws \
  --access-key-id your-key \
  --secret-access-key your-secret \
  --session-token your-session-token
```

#### 3. IAM Role Assumption

Assume an IAM role using your credentials (or default credentials if running on EC2/Lambda):

```bash
# Assume role with explicit credentials
nuvu scan --provider aws \
  --access-key-id your-key \
  --secret-access-key your-secret \
  --role-arn arn:aws:iam::123456789012:role/MyRole

# Assume role from default credentials (EC2/Lambda IAM role)
nuvu scan --provider aws \
  --role-arn arn:aws:iam::123456789012:role/MyRole

# With external ID (for enhanced security)
nuvu scan --provider aws \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --external-id your-external-id

# Custom session name and duration
nuvu scan --provider aws \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name my-scan-session \
  --role-duration-seconds 7200
```

**Note:** You can combine methods 2 and 3 (use temporary credentials to assume a role):

```bash
nuvu scan --provider aws \
  --access-key-id your-key \
  --secret-access-key your-secret \
  --session-token your-session-token \
  --role-arn arn:aws:iam::123456789012:role/MyRole
```

### GCP Scanning

```bash
# Scan GCP project (uses GOOGLE_APPLICATION_CREDENTIALS environment variable)
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
nuvu scan --provider gcp --gcp-project your-project-id

# Or specify credentials file directly
nuvu scan --provider gcp --gcp-credentials /path/to/service-account-key.json --gcp-project your-project-id

# Output to JSON
nuvu scan --provider gcp --gcp-project your-project-id --output-format json --output-file gcp-report.json
```

### Selective Scanning (Collectors)

Run focused scans on specific services instead of a full scan:

```bash
# List available collectors for a provider
nuvu scan --provider aws --list-collectors
# Output: athena, glue, iam, mwaa, redshift, s3

nuvu scan --provider gcp --list-collectors
# Output: bigquery, dataproc, gcs, gemini, iam, pubsub

# Scan only Redshift
nuvu scan --provider aws -c redshift --region us-west-2

# Scan multiple specific collectors
nuvu scan --provider aws -c redshift -c glue --region us-west-2

# Scan only S3 buckets
nuvu scan --provider aws -c s3 --output-format html

# Full scan (default - all collectors)
nuvu scan --provider aws  # Runs all collectors

# GCP: Scan only BigQuery
nuvu scan --provider gcp -c bigquery --gcp-project your-project
```

**Benefits of selective scanning:**
- **Faster scans** - Focus on services you care about
- **Reduced API calls** - Only query the services you need
- **Targeted reports** - Generate reports for specific areas

---

## Features

- **Asset Discovery**: Automatically discovers cloud data assets:
  - **AWS**: S3 buckets, Glue databases/tables, Athena workgroups, Redshift clusters, and more
  - **GCP**: GCS buckets, BigQuery datasets/tables, Dataproc clusters, Pub/Sub topics, and more
- **Cost Estimation**: Estimates monthly costs for all discovered assets (in USD)
  - **AWS**: Includes actual costs from AWS Cost Explorer API. Note: Some costs shown may be for services that are not data assets (e.g., domain registration, email services, DNS). Individual asset costs are estimates based on resource usage.
  - **GCP**: Estimates based on resource usage and actual costs from Cloud Billing API where available
- **Risk Detection**: Flags public access, PII exposure, and other security risks
- **Ownership Inference**: Attempts to identify asset owners from tags, labels, and metadata
- **Multiple Output Formats**: HTML (default), JSON, and CSV reports

## Output Formats

- **HTML**: Beautiful, interactive report with summary statistics
- **JSON**: Machine-readable format for integration with other tools
- **CSV**: Spreadsheet-friendly format for analysis

## Cloud Provider Support

### AWS (v1 - Available Now)
Nuvu requires read-only access to your AWS account. The tool uses the following AWS services:

- **S3**: List buckets, get bucket metadata, check public access
- **Glue**: List databases and tables
- **Athena**: List workgroups and query history
- **Redshift**: Describe clusters and serverless namespaces
- **IAM**: List roles and policies (for data-access permission analysis)
- **MWAA**: List Managed Workflows for Apache Airflow environments
- **CloudWatch**: Get metrics for usage tracking
- **CloudTrail**: Lookup events for last activity detection
- **Cost Explorer**: Get cost and usage data (optional, for actual cost reporting)

**Setting Up IAM Credentials:**

1. **Create an IAM User or Role** with the read-only policy:
   ```bash
   # Option 1: Create IAM user
   aws iam create-user --user-name nuvu-scan-readonly

   # Option 2: Create IAM role (for EC2/ECS/Lambda)
   aws iam create-role --role-name nuvu-scan-readonly --assume-role-policy-document file://trust-policy.json
   ```

2. **Attach the IAM Policy**:
   ```bash
   # For IAM user
   aws iam put-user-policy --user-name nuvu-scan-readonly --policy-name NuvuScanReadOnly --policy-document file://aws-iam-policy.json

   # For IAM role
   aws iam put-role-policy --role-name nuvu-scan-readonly --policy-name NuvuScanReadOnly --policy-document file://aws-iam-policy.json
   ```

3. **Create Access Keys** (for IAM user only):
   ```bash
   aws iam create-access-key --user-name nuvu-scan-readonly
   ```

4. **Use the credentials** (choose one of the three methods below):

   **Method 1: Standard Credentials (Access Key + Secret Key)**
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key-id
   export AWS_SECRET_ACCESS_KEY=your-secret-access-key
   nuvu scan --provider aws
   ```

   **Method 2: Temporary Credentials (Access Key + Secret Key + Session Token)**

   If you're using AWS SSO, assumed roles, or other temporary credentials:
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key-id
   export AWS_SECRET_ACCESS_KEY=your-secret-access-key
   export AWS_SESSION_TOKEN=your-session-token
   nuvu scan --provider aws
   ```

   **Method 3: IAM Role Assumption**

   To assume a role (useful for cross-account access or when using a role with more permissions):
   ```bash
   # With explicit credentials
   nuvu scan --provider aws \
     --access-key-id your-access-key-id \
     --secret-access-key your-secret-access-key \
     --role-arn arn:aws:iam::123456789012:role/MyRole

   # From default credentials (e.g., EC2 instance role)
   nuvu scan --provider aws \
     --role-arn arn:aws:iam::123456789012:role/MyRole

   # With external ID (if required by the role)
   nuvu scan --provider aws \
     --role-arn arn:aws:iam::123456789012:role/MyRole \
     --external-id your-external-id
   ```

The IAM policy file (`aws-iam-policy.json`) is included in this repository and contains all the read-only permissions required by Nuvu Scan. This policy follows the principle of least privilege and only grants read-only access to the services needed for scanning.

**Authentication Method Selection Guide:**

- **Use Method 1** (Access Key + Secret Key) for permanent IAM user credentials
- **Use Method 2** (Access Key + Secret Key + Session Token) when you have temporary credentials from AWS SSO, STS, or assumed roles
- **Use Method 3** (Role Assumption) for cross-account access, when you need to use a role with different permissions, or when running on EC2/Lambda with an IAM role

### GCP (v2 - Available Now)
Nuvu requires read-only access to your GCP project via a Service Account. The tool uses the following GCP services:

- **Cloud Storage (GCS)**: List buckets, get bucket metadata, IAM policies
- **BigQuery**: List datasets/tables, query history, job information
- **Dataproc**: List clusters, job history
- **Pub/Sub**: List topics and subscriptions

**Required IAM Roles:**
- `roles/storage.objectViewer` - For Cloud Storage
- `roles/bigquery.dataViewer` + `roles/bigquery.jobUser` - For BigQuery
- `roles/dataproc.viewer` - For Dataproc
- `roles/pubsub.subscriber` - For Pub/Sub
- `roles/serviceusage.serviceUsageViewer` - For checking API status (Gemini, etc.)

**Optional (for actual costs):**
- Enable BigQuery billing export for automatic cost tracking
- Or grant `roles/billing.billingAccountViewer` for Cloud Billing API access

**Setup Instructions:**

1. **Create a Service Account:**
   - Go to [GCP Console → IAM & Admin → Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts)
   - Create a new service account (e.g., `nuvu-scan-readonly`)
   - Attach the read-only roles listed above

2. **Create and Download JSON Key:**
   - Click on the service account → "Keys" tab
   - Click "Add Key" → "Create new key" → Select "JSON"
   - Download the JSON key file

3. **Enable Required APIs:**
   - Cloud Storage API
   - BigQuery API
   - Dataproc API
   - Pub/Sub API

4. **Test the Scan:**
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
   nuvu scan --provider gcp --gcp-project your-project-id
   ```

5. **Optional: Enable Automatic Cost Tracking:**
   To get actual costs for services like Gemini API, enable BigQuery billing export:
   - Go to [GCP Console → Billing → Billing Export](https://console.cloud.google.com/billing/export)
   - Enable BigQuery export
   - Costs will be automatically retrieved from the billing export

### Azure, Databricks (Coming Soon)
Multi-cloud support is built into the architecture. Additional providers will be added in future releases.

## License

Apache 2.0

## Website

Visit [https://nuvu.dev](https://nuvu.dev) for the SaaS version with continuous monitoring.

---

## Development

### Prerequisites

- Python 3.10+ (Python 3.8 and 3.9 are EOL)
- [uv](https://github.com/astral-sh/uv) - Fast Python package installer and resolver

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/nuvudev/nuvu-scan.git
cd nuvu-scan

# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies (uv automatically creates .venv)
uv sync --dev
```

**Note**: With `uv`, you don't need to manually activate a virtual environment! `uv run` automatically uses the `.venv` created by `uv sync`.

### Running Tests

```bash
# Run all tests (uv automatically uses .venv)
uv run pytest

# Run with coverage
uv run pytest --cov=nuvu_scan --cov-report=html

# Run specific test file
uv run pytest tests/test_s3_collector.py
```

### Code Quality

```bash
# Format code with black
uv run black .

# Lint with ruff
uv run ruff check .

# Type checking with mypy
uv run mypy nuvu_scan
```

### Building the Package

```bash
# Build distribution packages (uses pyproject.toml)
uv build

# This creates:
# - dist/nuvu_scan-{version}.tar.gz (source distribution)
# - dist/nuvu_scan-{version}-py3-none-any.whl (wheel)
```

**Note**: `uv` uses `pyproject.toml` (PEP 621 standard) - no `setup.py` needed!

### Running Locally

```bash
# Use uv run (automatically uses .venv, no activation needed)
uv run nuvu scan --provider aws

# Or install in development mode (optional)
uv pip install -e .
nuvu scan --provider aws
```

### Testing GCP Scanning

To test GCP scanning with your credentials:

```bash
# Set up GCP credentials
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json

# Run GCP scan
uv run nuvu scan --provider gcp --gcp-project your-project-id

# Or specify credentials file directly
uv run nuvu scan --provider gcp \
  --gcp-credentials /path/to/service-account-key.json \
  --gcp-project your-project-id

# Output to JSON for inspection
uv run nuvu scan --provider gcp \
  --gcp-project your-project-id \
  --output-format json \
  --output-file gcp-scan-results.json
```

**Troubleshooting:**

- **Permission Denied**: Ensure the service account has the required IAM roles listed above
- **API Not Enabled**: Enable the required APIs in [GCP Console → APIs & Services](https://console.cloud.google.com/apis/library)
- **Project ID Not Found**: Verify the project ID matches your service account's project

## Contributing

We welcome contributions! Here's how to get started:

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/your-username/nuvu-scan.git
cd nuvu-scan

# Add upstream remote
git remote add upstream https://github.com/nuvudev/nuvu-scan.git
```

### 2. Create a Branch

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Or a bugfix branch
git checkout -b fix/your-bug-description
```

### 3. Make Changes

- Follow the existing code style (enforced by black and ruff)
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass: `uv run pytest`
- Run code quality checks: `uv run black . && uv run ruff check .`

### 4. Commit and Push

```bash
# Commit your changes
git add .
git commit -m "Description of your changes"

# Push to your fork
git push origin feature/your-feature-name
```

### 5. Create a Pull Request

- Go to https://github.com/nuvudev/nuvu-scan
- Click "New Pull Request"
- Select your branch
- Fill out the PR template
- Wait for review and CI checks to pass

### Adding a New Cloud Provider

To add support for a new cloud provider (e.g., Azure):

1. **Create provider module structure:**
   ```bash
   mkdir -p nuvu_scan/core/providers/azure/collectors
   ```

2. **Implement CloudProviderScan interface:**
   - Create `nuvu_scan/core/providers/azure/azure_scanner.py`
   - Inherit from `CloudProviderScan`
   - Implement `list_assets()`, `get_usage_metrics()`, `get_cost_estimate()`

3. **Create service collectors:**
   - One collector per service (e.g., `blob_storage.py`, `synapse.py`)
   - Follow the pattern from AWS/GCP collectors

4. **Register in CLI:**
   - Update `nuvu_scan/cli/commands/scan.py` to support `--provider azure`
   - Add provider to choices

5. **Add tests:**
   - Create tests in `tests/providers/azure/`
   - Mock API responses

6. **Update documentation:**
   - Update README.md
   - Add provider-specific IAM/permissions docs

### Project Structure

```
nuvu-scan/
├── nuvu_scan/              # Main package
│   ├── core/               # Core scanning engine
│   │   ├── base.py         # CloudProviderScan interface
│   │   ├── providers/       # Provider implementations
│   │   │   ├── aws/        # AWS provider (v1)
│   │   │   │   └── collectors/  # S3, Glue, Athena, Redshift
│   │   │   ├── gcp/        # GCP provider (v2)
│   │   │   │   └── collectors/  # GCS, BigQuery, Dataproc, Pub/Sub
│   │   │   └── azure/      # Azure provider (future)
│   │   └── models/         # Data models
│   └── cli/                # CLI interface
│       ├── commands/       # CLI commands
│       └── formatters/     # Output formatters
├── tests/                  # Test suite
├── .github/
│   └── workflows/         # CI/CD workflows
├── pyproject.toml         # Project configuration (uv)
└── README.md
```

### Release Process

Releases are automated via GitHub Actions:

1. **Create a release tag:**
   ```bash
   git tag -a v0.1.0 -m "Release v0.1.0"
   git push origin v0.1.0
   ```

2. **Create GitHub Release:**
   - Go to https://github.com/nuvudev/nuvu-scan/releases
   - Click "Draft a new release"
   - Select the tag
   - Add release notes
   - Publish

3. **Automated Publishing:**
   - GitHub Actions will automatically:
     - Build the package
     - Publish to PyPI
     - Use trusted publishing (no API tokens needed)

### CI/CD

The project uses GitHub Actions for:

- **CI** (`.github/workflows/ci.yml`):
  - Runs on every push and PR
  - Tests on Python 3.10-3.13
  - Runs linters (ruff, black)
  - Runs type checker (mypy)
  - Runs test suite
  - Uploads coverage reports

- **Publish** (`.github/workflows/publish.yml`):
  - Triggers on GitHub releases
  - Builds package
  - Publishes to PyPI using trusted publishing

### Questions?

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Join discussions in pull requests
