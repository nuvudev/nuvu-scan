"""Tests for core base classes."""

from nuvu_scan.core.base import (
    Asset,
    NormalizedCategory,
    ScanConfig,
)


def test_normalized_category_enum():
    """Test that normalized categories are defined."""
    assert NormalizedCategory.OBJECT_STORAGE == "object_storage"
    assert NormalizedCategory.DATA_WAREHOUSE == "data_warehouse"
    assert NormalizedCategory.STREAMING == "streaming"


def test_asset_creation():
    """Test Asset model creation."""
    asset = Asset(
        provider="aws",
        asset_type="s3_bucket",
        normalized_category=NormalizedCategory.OBJECT_STORAGE,
        service="S3",
        region="us-east-1",
        arn="arn:aws:s3:::test-bucket",
        name="test-bucket",
    )

    assert asset.provider == "aws"
    assert asset.asset_type == "s3_bucket"
    assert asset.normalized_category == NormalizedCategory.OBJECT_STORAGE
    assert asset.tags == {}
    assert asset.risk_flags == []


def test_scan_config():
    """Test ScanConfig creation."""
    config = ScanConfig(
        provider="aws",
        credentials={"access_key_id": "test", "secret_access_key": "test"},
    )

    assert config.provider == "aws"
    assert config.credentials["access_key_id"] == "test"
    assert config.regions == []
