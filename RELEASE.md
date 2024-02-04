# Release Process

## Prerequisites

1. **PyPI Account Setup**:
   - Create account on [PyPI](https://pypi.org)
   - Enable trusted publishing for the repository:
     - Go to PyPI → Account Settings → API tokens
     - Add a new "Trusted Publisher"
     - Select "GitHub" as the publisher
     - Repository: `flexilogix/nuvu-scan`
     - Workflow filename: `.github/workflows/publish.yml`
     - Environment: (leave empty for default)

2. **GitHub Repository**:
   - Ensure repository is public (for PyPI trusted publishing)
   - Or configure repository secrets if using API tokens

## Release Steps

### 1. Update Version

Update version in `pyproject.toml`:

```toml
[project]
version = "0.2.0"  # Bump version
```

### 2. Update Changelog

Update `CHANGELOG.md` (if maintained) or release notes.

### 3. Commit and Tag

```bash
git add pyproject.toml
git commit -m "Bump version to 0.2.0"
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main
git push origin v0.2.0
```

### 4. Create GitHub Release

1. Go to https://github.com/flexilogix/nuvu-scan/releases
2. Click "Draft a new release"
3. Select tag: `v0.2.0`
4. Title: `v0.2.0`
5. Add release notes describing changes
6. Click "Publish release"

### 5. Automated Publishing

The GitHub Actions workflow (`.github/workflows/publish.yml`) will automatically:
- Build the package using `uv build`
- Publish to PyPI using trusted publishing
- No manual API tokens needed!

### 6. Verify

Check PyPI: https://pypi.org/project/nuvu-scan/

Install and test:
```bash
pip install --upgrade nuvu-scan
nuvu --version
```

## Manual Publishing (Alternative)

If trusted publishing is not set up, you can publish manually:

```bash
# Build
uv build

# Publish (requires PyPI API token)
uv publish --token pypi-...
```

## Versioning

Follow [Semantic Versioning](https://semver.org/):
- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backward compatible
- **PATCH** (0.0.1): Bug fixes, backward compatible
