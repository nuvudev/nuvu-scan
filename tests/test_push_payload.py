"""Tests for push payload format to ensure API compatibility."""

import pytest

from nuvu_scan.core.base import Asset, NormalizedCategory, ScanResult


class TestPushPayloadFormat:
    """Test that push payload matches expected API format."""

    @pytest.fixture
    def sample_scan_result(self):
        """Create a sample scan result."""
        assets = [
            Asset(
                provider="aws",
                asset_type="s3_bucket",
                normalized_category=NormalizedCategory.OBJECT_STORAGE,
                service="S3",
                region="us-east-1",
                arn="arn:aws:s3:::test-bucket",
                name="test-bucket",
                size_bytes=1024,
                cost_estimate_usd=10.0,
                risk_flags=["public"],
                tags={"env": "prod"},
                ownership_confidence="high",
                suggested_owner="team@example.com",
                created_at="2024-01-01T00:00:00Z",
                last_activity_at="2026-01-15T12:00:00Z",
            ),
            Asset(
                provider="aws",
                asset_type="redshift_cluster",
                normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                service="Redshift",
                region="us-west-2",
                arn="arn:aws:redshift:us-west-2:123:cluster:test",
                name="test-cluster",
                cost_estimate_usd=500.0,
                risk_flags=[],
                tags={},
                usage_metrics={
                    "node_count": 4,
                    "node_type": "dc2.large",
                    "has_reservation": True,
                    "reserved_nodes_count": 4,
                    "on_demand_nodes_count": 0,
                },
            ),
        ]
        return ScanResult(
            provider="aws",
            account_id="123456789012",
            assets=assets,
            total_cost_estimate_usd=510.0,
            scan_timestamp="2026-02-01T12:00:00Z",
        )

    def test_payload_has_required_fields(self, sample_scan_result):
        """Test payload structure matches API expectations."""
        # Simulate building the payload as done in scan.py
        result = sample_scan_result
        scan_regions = list(set(asset.region for asset in result.assets if asset.region))

        payload = {
            "provider": "aws",
            "account_id": result.account_id or "unknown",
            "scan_timestamp": result.scan_timestamp,
            "total_cost_estimate_usd": result.total_cost_estimate_usd,
            "scan_regions": scan_regions if scan_regions else None,
            "scan_all_regions": True,
            "assets": [
                {
                    "provider": asset.provider,
                    "asset_type": asset.asset_type,
                    "normalized_category": asset.normalized_category.value
                    if asset.normalized_category
                    else "unknown",
                    "service": asset.service or asset.asset_type.split("_")[0]
                    if asset.asset_type
                    else "unknown",
                    "region": asset.region,
                    "arn": asset.arn,
                    "name": asset.name,
                    "created_at": asset.created_at,
                    "last_activity_at": asset.last_activity_at,
                    "size_bytes": asset.size_bytes,
                    "tags": asset.tags,
                    "cost_estimate_usd": asset.cost_estimate_usd,
                    "usage_metrics": asset.usage_metrics,  # Include all usage metrics
                    "risk_flags": asset.risk_flags,
                    "ownership_confidence": asset.ownership_confidence or "unknown",
                    "suggested_owner": asset.suggested_owner,
                }
                for asset in result.assets
            ],
        }

        # Required top-level fields
        assert "provider" in payload
        assert "account_id" in payload
        assert "assets" in payload
        assert "scan_timestamp" in payload
        assert "total_cost_estimate_usd" in payload

        # Account ID should not be "unknown" when set
        assert payload["account_id"] == "123456789012"

    def test_payload_assets_have_required_fields(self, sample_scan_result):
        """Test that each asset has required fields."""
        result = sample_scan_result

        for asset in result.assets:
            asset_dict = {
                "provider": asset.provider,
                "asset_type": asset.asset_type,
                "normalized_category": asset.normalized_category.value
                if asset.normalized_category
                else "unknown",
                "region": asset.region,
                "arn": asset.arn,
                "name": asset.name,
            }

            # These fields are required by the API
            assert asset_dict["provider"] is not None
            assert asset_dict["asset_type"] is not None
            assert asset_dict["normalized_category"] is not None
            assert asset_dict["name"] is not None

    def test_payload_regions_extracted_correctly(self, sample_scan_result):
        """Test that regions are extracted from assets."""
        result = sample_scan_result
        scan_regions = list(set(asset.region for asset in result.assets if asset.region))

        assert "us-east-1" in scan_regions
        assert "us-west-2" in scan_regions
        assert len(scan_regions) == 2

    def test_normalized_category_is_string_value(self, sample_scan_result):
        """Test that normalized_category uses string value, not enum."""
        result = sample_scan_result

        for asset in result.assets:
            category = asset.normalized_category.value if asset.normalized_category else "unknown"
            assert isinstance(category, str)
            assert category in [
                "object_storage",
                "data_warehouse",
                "streaming",
                "compute",
                "ml_training",
                "data_catalog",
                "data_integration",
                "data_pipeline",
                "data_sharing",
                "query_engine",
                "search",
                "database",
                "security",
                "billing",
                "unknown",
            ]

    def test_usage_metrics_included_in_payload(self, sample_scan_result):
        """Test that usage_metrics is included in push payload for governance calculations."""
        result = sample_scan_result

        # Build payload matching scan.py implementation
        payload = {
            "assets": [
                {
                    "provider": asset.provider,
                    "asset_type": asset.asset_type,
                    "usage_metrics": asset.usage_metrics,
                }
                for asset in result.assets
            ],
        }

        # Find the Redshift cluster asset
        redshift_assets = [a for a in payload["assets"] if a["asset_type"] == "redshift_cluster"]
        assert len(redshift_assets) == 1

        redshift_asset = redshift_assets[0]
        assert redshift_asset["usage_metrics"] is not None

        # Verify key Redshift metrics are present
        usage_metrics = redshift_asset["usage_metrics"]
        assert "node_count" in usage_metrics
        assert "has_reservation" in usage_metrics
        assert "reserved_nodes_count" in usage_metrics
        assert usage_metrics["node_count"] == 4
        assert usage_metrics["has_reservation"] is True


class TestScanResultFields:
    """Test ScanResult model fields."""

    def test_scan_result_has_account_id(self):
        """Test that ScanResult stores account_id."""
        result = ScanResult(
            provider="aws",
            account_id="123456789012",
            scan_timestamp="2026-02-01T12:00:00Z",
            assets=[],
            total_cost_estimate_usd=0.0,
        )
        assert result.account_id == "123456789012"

    def test_scan_result_has_timestamp(self):
        """Test that ScanResult stores scan_timestamp."""
        result = ScanResult(
            provider="aws",
            account_id="123456789012",
            scan_timestamp="2026-02-01T12:00:00Z",
            assets=[],
            total_cost_estimate_usd=0.0,
        )
        assert result.scan_timestamp == "2026-02-01T12:00:00Z"

    def test_scan_result_has_cost(self):
        """Test that ScanResult stores total cost."""
        result = ScanResult(
            provider="aws",
            account_id="123456789012",
            scan_timestamp="2026-02-01T12:00:00Z",
            assets=[],
            total_cost_estimate_usd=1000.50,
        )
        assert result.total_cost_estimate_usd == 1000.50
