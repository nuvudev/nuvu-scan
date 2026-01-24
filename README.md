# Nuvu Scan

Multi-Cloud Data Asset Control CLI - Discover and analyze your cloud data infrastructure across AWS, GCP, Azure, and Databricks.

## Installation

```bash
pip install nuvu-scan
```

## Usage

```bash
# Scan AWS account (uses default credentials)
nuvu scan --provider aws

# Specify credentials via environment variables
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
nuvu scan --provider aws

# Output to JSON
nuvu scan --provider aws --output-format json --output-file report.json

# Scan specific regions
nuvu scan --provider aws --region us-east-1 --region eu-west-1
```

## Features

- **Asset Discovery**: Automatically discovers S3 buckets, Glue databases/tables, Athena workgroups, Redshift clusters, and more
- **Cost Estimation**: Estimates monthly costs for all discovered assets
- **Risk Detection**: Flags public access, PII exposure, and other security risks
- **Ownership Inference**: Attempts to identify asset owners from tags and metadata
- **Multiple Output Formats**: HTML (default), JSON, and CSV reports

## Output Formats

- **HTML**: Beautiful, interactive report with summary statistics
- **JSON**: Machine-readable format for integration with other tools
- **CSV**: Spreadsheet-friendly format for analysis

## Cloud Provider Support

### AWS (v1 - Available Now)
Nuvu requires read-only access to your AWS account. The tool uses the following AWS services:

- S3 (list buckets, get bucket metadata)
- Glue (list databases, tables)
- Athena (list workgroups, query history)
- Redshift (describe clusters, namespaces)
- CloudWatch (metrics)
- CloudTrail (audit logs)

See the [IAM Policy Documentation](IAM_POLICY.md) for the exact permissions required.

### GCP, Azure, Databricks (Coming Soon)
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
git clone https://github.com/flexilogix/nuvu-scan.git
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

## Contributing

We welcome contributions! Here's how to get started:

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/your-username/nuvu-scan.git
cd nuvu-scan

# Add upstream remote
git remote add upstream https://github.com/flexilogix/nuvu-scan.git
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

- Go to https://github.com/flexilogix/nuvu-scan
- Click "New Pull Request"
- Select your branch
- Fill out the PR template
- Wait for review and CI checks to pass

### Adding a New Cloud Provider

To add support for a new cloud provider (e.g., GCP):

1. **Create provider module structure:**
   ```bash
   mkdir -p nuvu_scan/core/providers/gcp/collectors
   ```

2. **Implement CloudProviderScan interface:**
   - Create `nuvu_scan/core/providers/gcp/gcp_scanner.py`
   - Inherit from `CloudProviderScan`
   - Implement `list_assets()`, `get_usage_metrics()`, `get_cost_estimate()`

3. **Create service collectors:**
   - One collector per service (e.g., `gcs.py`, `bigquery.py`)
   - Follow the pattern from AWS collectors

4. **Register in CLI:**
   - Update `nuvu_scan/cli/commands/scan.py` to support `--provider gcp`
   - Add provider to choices

5. **Add tests:**
   - Create tests in `tests/providers/gcp/`
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
│   │   │   ├── gcp/        # GCP provider (future)
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
   - Go to https://github.com/flexilogix/nuvu-scan/releases
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
  - Tests on Python 3.8-3.12
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
