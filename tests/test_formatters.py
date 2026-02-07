"""Tests for output formatters."""

import json

import pytest

from nuvu_scan.cli.formatters.csv import CSVFormatter
from nuvu_scan.cli.formatters.html import HTMLFormatter
from nuvu_scan.cli.formatters.json import JSONFormatter
from nuvu_scan.core.base import Asset, NormalizedCategory, ScanResult


@pytest.fixture
def sample_assets():
    """Create sample assets for testing."""
    return [
        Asset(
            provider="aws",
            asset_type="s3_bucket",
            normalized_category=NormalizedCategory.OBJECT_STORAGE,
            service="S3",
            region="us-east-1",
            arn="arn:aws:s3:::test-bucket-1",
            name="test-bucket-1",
            size_bytes=1024000,
            cost_estimate_usd=10.50,
            risk_flags=["public", "unencrypted"],
            tags={"Environment": "production"},
        ),
        Asset(
            provider="aws",
            asset_type="redshift_cluster",
            normalized_category=NormalizedCategory.DATA_WAREHOUSE,
            service="Redshift",
            region="us-west-2",
            arn="arn:aws:redshift:us-west-2:123456789:cluster:my-cluster",
            name="my-cluster",
            cost_estimate_usd=500.00,
            risk_flags=[],
            tags={"Team": "analytics"},
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_assets):
    """Create a sample scan result."""
    return ScanResult(
        provider="aws",
        account_id="123456789012",
        assets=sample_assets,
        total_cost_estimate_usd=510.50,
        scan_timestamp="2026-02-01T12:00:00Z",
    )


class TestJSONFormatter:
    """Test JSON formatter output."""

    def test_json_format_valid(self, sample_scan_result):
        """Test that JSON output is valid JSON."""
        formatter = JSONFormatter()
        output = formatter.format(sample_scan_result)

        # Should be valid JSON
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_json_contains_assets(self, sample_scan_result):
        """Test that JSON contains assets."""
        formatter = JSONFormatter()
        output = formatter.format(sample_scan_result)
        parsed = json.loads(output)

        assert "assets" in parsed
        assert len(parsed["assets"]) == 2

    def test_json_contains_metadata(self, sample_scan_result):
        """Test that JSON contains scan metadata."""
        formatter = JSONFormatter()
        output = formatter.format(sample_scan_result)
        parsed = json.loads(output)

        assert "provider" in parsed
        assert parsed["provider"] == "aws"
        assert "account_id" in parsed
        assert "total_cost_estimate_usd" in parsed

    def test_json_asset_fields(self, sample_scan_result):
        """Test that JSON assets have required fields."""
        formatter = JSONFormatter()
        output = formatter.format(sample_scan_result)
        parsed = json.loads(output)

        asset = parsed["assets"][0]
        required_fields = [
            "provider",
            "asset_type",
            "normalized_category",
            "region",
            "arn",
            "name",
        ]
        for field in required_fields:
            assert field in asset, f"Missing field: {field}"


class TestHTMLFormatter:
    """Test HTML formatter output."""

    def test_html_format_valid(self, sample_scan_result):
        """Test that HTML output is valid HTML structure."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        assert "<html" in output.lower()
        assert "</html>" in output.lower()
        assert "<body" in output.lower()

    def test_html_contains_assets(self, sample_scan_result):
        """Test that HTML contains asset information."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        assert "test-bucket-1" in output
        assert "my-cluster" in output

    def test_html_contains_risk_flags(self, sample_scan_result):
        """Test that HTML highlights risk flags."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        # Should mention public or unencrypted risks
        assert "public" in output.lower() or "unencrypted" in output.lower()

    def test_html_contains_cost(self, sample_scan_result):
        """Test that HTML shows cost information."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        # Should show cost somewhere
        assert "cost" in output.lower() or "$" in output

    def test_html_contains_privacy_message(self, sample_scan_result):
        """Test that HTML contains the privacy/no-data-accessed message."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        # Should contain privacy reassurance
        assert "No data accessed" in output
        assert "metadata" in output.lower()
        assert "read-only" in output.lower()

    def test_html_contains_nuvu_cloud_cta(self, sample_scan_result):
        """Test that HTML contains Nuvu Cloud call-to-action."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        # Should contain CTA with link
        assert "nuvu.dev" in output.lower()
        assert "--push" in output
        assert "--api-key" in output

    def test_html_no_remediation_recommendations(self, sample_scan_result):
        """Test that HTML does not contain remediation recommendations."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        # Should NOT contain recommendation language
        assert "Consider downsizing" not in output
        assert "Consider upgrading" not in output
        assert "Plan for renewal" not in output
        assert "Review for security compliance" not in output

    def test_html_no_cost_optimization_title(self, sample_scan_result):
        """Test that HTML does not use 'Cost Optimization Opportunities' title."""
        formatter = HTMLFormatter()
        output = formatter.format(sample_scan_result)

        # Should NOT use the old savings-focused section title
        assert "Cost Optimization Opportunities" not in output


class TestCSVFormatter:
    """Test CSV formatter output."""

    def test_csv_format_valid(self, sample_scan_result):
        """Test that CSV output has proper structure."""
        formatter = CSVFormatter()
        output = formatter.format(sample_scan_result)

        lines = output.strip().split("\n")
        # Should have header + data rows
        assert len(lines) >= 3  # header + 2 assets

    def test_csv_has_header(self, sample_scan_result):
        """Test that CSV has header row."""
        formatter = CSVFormatter()
        output = formatter.format(sample_scan_result)

        header = output.split("\n")[0].lower()
        assert "name" in header
        assert "provider" in header

    def test_csv_contains_assets(self, sample_scan_result):
        """Test that CSV contains asset data."""
        formatter = CSVFormatter()
        output = formatter.format(sample_scan_result)

        assert "test-bucket-1" in output
        assert "my-cluster" in output
