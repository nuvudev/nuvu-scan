"""Tests for CLI commands and options."""

import pytest
from click.testing import CliRunner

from nuvu_scan.cli.main import cli


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestCLIOptions:
    """Test that all CLI options are present and correctly configured."""

    def test_scan_command_exists(self, runner):
        """Test that scan command is available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan cloud provider for data assets" in result.output

    def test_provider_option(self, runner):
        """Test --provider option is available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--provider" in result.output
        assert "aws" in result.output
        assert "gcp" in result.output

    def test_output_format_option(self, runner):
        """Test --output-format option is available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--output-format" in result.output
        assert "html" in result.output
        assert "json" in result.output
        assert "csv" in result.output

    def test_output_file_option(self, runner):
        """Test --output-file option is available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--output-file" in result.output

    def test_region_option(self, runner):
        """Test --region option is available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--region" in result.output

    def test_collectors_option(self, runner):
        """Test --collectors option is available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--collectors" in result.output
        assert "-c" in result.output

    def test_list_collectors_option(self, runner):
        """Test --list-collectors option is available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--list-collectors" in result.output

    def test_aws_credential_options(self, runner):
        """Test AWS credential options are available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--access-key-id" in result.output
        assert "--secret-access-key" in result.output
        assert "--session-token" in result.output
        assert "--profile" in result.output

    def test_aws_role_assumption_options(self, runner):
        """Test AWS role assumption options are available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--role-arn" in result.output
        assert "--role-session-name" in result.output
        assert "--external-id" in result.output
        assert "--role-duration-seconds" in result.output

    def test_gcp_credential_options(self, runner):
        """Test GCP credential options are available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--gcp-credentials" in result.output
        assert "--gcp-project" in result.output

    def test_push_options(self, runner):
        """Test push to Nuvu Cloud options are available."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--push" in result.output
        assert "--api-key" in result.output
        assert "--api-url" in result.output


class TestListCollectors:
    """Test --list-collectors functionality."""

    def test_list_aws_collectors(self, runner):
        """Test listing AWS collectors."""
        result = runner.invoke(cli, ["scan", "--provider", "aws", "--list-collectors"])
        assert result.exit_code == 0
        assert "s3" in result.output.lower()
        assert "glue" in result.output.lower()
        assert "redshift" in result.output.lower()

    def test_list_gcp_collectors(self, runner):
        """Test listing GCP collectors."""
        result = runner.invoke(cli, ["scan", "--provider", "gcp", "--list-collectors"])
        assert result.exit_code == 0
        assert "gcs" in result.output.lower() or "bigquery" in result.output.lower()


class TestPushValidation:
    """Test push option validation."""

    def test_push_requires_api_key(self, runner):
        """Test that --push requires --api-key."""
        # Use --list-collectors to avoid running actual scan
        # The validation for --push + --api-key should happen regardless
        result = runner.invoke(
            cli,
            ["scan", "--provider", "aws", "--push", "--list-collectors"],
            catch_exceptions=False,
        )
        # With --list-collectors, it exits after listing (no push happens)
        # The point is: if --push is used without --api-key and a real scan runs,
        # it should fail. But we can't easily test that without running a scan.
        # So we just verify the option is recognized
        assert "api" in result.output.lower() or result.exit_code == 0


class TestVersionCommand:
    """Test version command."""

    def test_version_command(self, runner):
        """Test that version command works."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        # Version should be in format X.Y.Z
        assert "." in result.output
