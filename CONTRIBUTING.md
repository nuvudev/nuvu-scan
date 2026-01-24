# Contributing to Nuvu Scan

Thank you for your interest in contributing to Nuvu Scan! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Set up development environment** (see README.md)
4. **Create a branch** for your changes

## Development Workflow

### 1. Setup

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/your-username/nuvu-scan.git
cd nuvu-scan
uv sync --dev  # Creates .venv automatically, no activation needed!
```

### 2. Make Changes

- Write clear, readable code
- Follow existing code style (enforced by black and ruff)
- Add tests for new functionality
- Update documentation

### 3. Test Your Changes

```bash
# Run all tests (uv automatically uses .venv)
uv run pytest

# Run with coverage
uv run pytest --cov=nuvu_scan

# Check code quality
uv run black .
uv run ruff check .
uv run mypy nuvu_scan
```

**Note**: No need to activate `.venv` - `uv run` handles it automatically!

### 4. Commit

Use clear, descriptive commit messages:

```bash
git commit -m "Add GCP BigQuery collector"
git commit -m "Fix S3 bucket size calculation"
```

### 5. Push and Create PR

```bash
git push origin feature/your-feature
```

Then create a pull request on GitHub.

## Adding a New Cloud Provider

See the detailed guide in README.md under "Adding a New Cloud Provider".

## Adding a New AWS Service Collector

1. Create collector file: `nuvu_scan/core/providers/aws/collectors/{service}.py`
2. Implement collection logic
3. Add to `aws_scanner.py` collectors list
4. Add tests in `tests/providers/aws/`
5. Update documentation

## Testing Guidelines

- Write tests for all new functionality
- Aim for >80% code coverage
- Use mocks for AWS API calls
- Test error handling
- Test edge cases

## Code Style

- **Formatting**: Use `black` (line length: 100)
- **Linting**: Use `ruff`
- **Type hints**: Add type hints where helpful
- **Docstrings**: Add docstrings for public functions/classes

## Pull Request Process

1. Ensure all tests pass
2. Ensure code quality checks pass
3. Update documentation if needed
4. Fill out PR template completely
5. Request review from maintainers
6. Address review feedback
7. Wait for approval and merge

## Release Process

Releases are managed by maintainers:

1. Version bump in `pyproject.toml`
2. Create git tag
3. Create GitHub release
4. Automated PyPI publishing via GitHub Actions

## Questions?

- Open an issue for questions
- Check existing issues/PRs
- Ask in PR comments

Thank you for contributing! 🎉
