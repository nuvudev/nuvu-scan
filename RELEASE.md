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

### 3. Commit and Create PR

**If you have direct push access to main:**
```bash
git add pyproject.toml
git commit -m "Bump version to 1.3.2"
git push origin main
```

**If you need to create a PR (recommended for contributors):**
```bash
# Create a release branch
git checkout -b release/v1.3.2

# Update version and commit
git add pyproject.toml
git commit -m "Bump version to 1.3.2"

# Push branch and create PR
git push origin release/v1.3.2
# Then create a PR on GitHub: release/v1.3.2 -> main
```

### 4. Automated Release (Recommended)

**The GitHub Actions workflow will automatically create a release when your PR is merged to main!**

The `.github/workflows/release.yml` workflow:
- ✅ Triggers automatically when `pyproject.toml` is changed on main
- ✅ Detects if the version was bumped
- ✅ Creates a git tag automatically
- ✅ Creates a GitHub release
- ✅ Triggers the PyPI publish workflow

**No manual steps required!** Just merge your PR with the version bump, and the release will be created automatically.

### 4a. Manual Tag Creation (Alternative)

**If you prefer to create the tag manually (or if automation is disabled):**

```bash
# Make sure you're on main and up to date
git checkout main
git pull origin main

# Create and push the tag
git tag -a v1.3.2 -m "Release v1.3.2"
git push origin v1.3.2
```

**Note:** If you don't have permission to push tags, ask a maintainer to create the tag after the PR is merged. Alternatively, you can create the tag through the GitHub web interface when creating the release.

### 5. Automated Release & Publishing

**The release workflow (`.github/workflows/release.yml`) automatically:**
- Detects version bump in `pyproject.toml`
- Creates a git tag when version is bumped
- Creates a GitHub release with release notes
- Builds the package using `uv build`
- Publishes to PyPI using trusted publishing
- No manual API tokens needed!

**Complete automation:** Merge PR → Release created → PyPI published! 🚀

**Note:** All steps happen in a single workflow, ensuring reliable execution order and avoiding workflow trigger issues.

### 5a. Manual Release (Alternative)

If you need to create a release manually:

1. Go to https://github.com/flexilogix/nuvu-scan/releases
2. Click "Draft a new release"
3. Select tag: `v1.3.2` (or create new tag)
4. Title: `v1.3.2`
5. Add release notes describing changes
6. Click "Publish release"

### 7. Verify

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
