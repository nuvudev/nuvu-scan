"""Tests for cloud provider scanners."""

from unittest.mock import MagicMock, patch

import pytest

from nuvu_scan.core.base import NormalizedCategory, ScanConfig


class TestAWSScanner:
    """Test AWS scanner functionality."""

    @pytest.fixture
    def mock_boto3_session(self):
        """Create a mock boto3 session."""
        with patch("nuvu_scan.core.providers.aws.aws_scanner.boto3") as mock_boto3:
            mock_session = MagicMock()
            mock_boto3.Session.return_value = mock_session

            # Mock STS for account ID
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
            mock_session.client.return_value = mock_sts

            yield mock_boto3, mock_session

    def test_scanner_initialization(self, mock_boto3_session):
        """Test that AWS scanner initializes correctly."""
        from nuvu_scan.core.providers.aws import AWSScanner

        config = ScanConfig(
            provider="aws",
            credentials={
                "access_key_id": "test-key",
                "secret_access_key": "test-secret",
            },
        )

        scanner = AWSScanner(config)
        assert scanner is not None

    def test_scanner_with_regions(self, mock_boto3_session):
        """Test scanner with specific regions."""
        from nuvu_scan.core.providers.aws import AWSScanner

        config = ScanConfig(
            provider="aws",
            credentials={
                "access_key_id": "test-key",
                "secret_access_key": "test-secret",
            },
            regions=["us-east-1", "us-west-2"],
        )

        scanner = AWSScanner(config)
        assert scanner.config.regions == ["us-east-1", "us-west-2"]

    def test_scanner_with_collectors(self, mock_boto3_session):
        """Test scanner with specific collectors."""
        from nuvu_scan.core.providers.aws import AWSScanner

        config = ScanConfig(
            provider="aws",
            credentials={
                "access_key_id": "test-key",
                "secret_access_key": "test-secret",
            },
            collectors=["s3", "redshift"],
        )

        scanner = AWSScanner(config)
        assert scanner.config.collectors == ["s3", "redshift"]


class TestScanConfig:
    """Test ScanConfig functionality."""

    def test_config_with_role_arn(self):
        """Test ScanConfig with role assumption."""
        config = ScanConfig(
            provider="aws",
            credentials={
                "access_key_id": "test-key",
                "secret_access_key": "test-secret",
                "role_arn": "arn:aws:iam::123456789012:role/TestRole",
            },
        )

        assert "role_arn" in config.credentials
        assert config.credentials["role_arn"] == "arn:aws:iam::123456789012:role/TestRole"

    def test_config_with_session_token(self):
        """Test ScanConfig with session token."""
        config = ScanConfig(
            provider="aws",
            credentials={
                "access_key_id": "test-key",
                "secret_access_key": "test-secret",
                "session_token": "test-session-token",
            },
        )

        assert "session_token" in config.credentials

    def test_config_collectors_list(self):
        """Test ScanConfig with collectors list."""
        config = ScanConfig(
            provider="aws",
            credentials={},
            collectors=["s3", "glue", "redshift"],
        )

        assert config.collectors == ["s3", "glue", "redshift"]


class TestNormalizedCategories:
    """Test that all expected normalized categories exist."""

    def test_object_storage_category(self):
        """Test object storage category."""
        assert NormalizedCategory.OBJECT_STORAGE == "object_storage"

    def test_data_warehouse_category(self):
        """Test data warehouse category."""
        assert NormalizedCategory.DATA_WAREHOUSE == "data_warehouse"

    def test_streaming_category(self):
        """Test streaming category."""
        assert NormalizedCategory.STREAMING == "streaming"

    def test_data_pipeline_category(self):
        """Test data pipeline (ETL) category."""
        assert NormalizedCategory.DATA_PIPELINE == "data_pipeline"

    def test_data_catalog_category(self):
        """Test data catalog category."""
        assert NormalizedCategory.DATA_CATALOG == "data_catalog"

    def test_query_engine_category(self):
        """Test query engine category."""
        assert NormalizedCategory.QUERY_ENGINE == "query_engine"

    def test_data_integration_category(self):
        """Test data integration category."""
        assert NormalizedCategory.DATA_INTEGRATION == "data_integration"

    def test_security_category(self):
        """Test security category."""
        assert NormalizedCategory.SECURITY == "security"
