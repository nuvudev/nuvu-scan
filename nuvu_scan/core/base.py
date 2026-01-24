"""
Abstract base class for cloud provider scanners.

This interface ensures all cloud providers (AWS, GCP, Azure, Databricks)
implement the same scanning contract, enabling provider-agnostic usage.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class NormalizedCategory(str, Enum):
    """Normalized asset categories across all cloud providers."""

    OBJECT_STORAGE = "object_storage"
    DATA_WAREHOUSE = "data_warehouse"
    STREAMING = "streaming"
    COMPUTE = "compute"
    ML_TRAINING = "ml_training"
    DATA_CATALOG = "data_catalog"
    DATA_INTEGRATION = "data_integration"
    QUERY_ENGINE = "query_engine"
    SEARCH = "search"
    DATABASE = "database"


@dataclass
class Asset:
    """Cloud-agnostic asset model."""

    provider: str  # aws, gcp, azure, databricks
    asset_type: str  # Provider-specific type (e.g., "s3_bucket", "gcs_bucket")
    normalized_category: NormalizedCategory
    service: str  # Provider-specific service name (e.g., "S3", "GCS", "Blob")
    region: str  # Normalized region/zone
    arn: str  # Provider-specific resource identifier
    name: str
    created_at: Optional[str] = None
    last_activity_at: Optional[str] = None
    size_bytes: Optional[int] = None
    tags: Dict[str, str] = None
    cost_estimate_usd: Optional[float] = None
    usage_metrics: Dict[str, Any] = None
    risk_flags: List[str] = None
    ownership_confidence: str = "unknown"  # high, medium, unknown
    suggested_owner: Optional[str] = None
    underlying_cloud_account_id: Optional[str] = None  # For Databricks

    def __post_init__(self):
        if self.tags is None:
            self.tags = {}
        if self.usage_metrics is None:
            self.usage_metrics = {}
        if self.risk_flags is None:
            self.risk_flags = []


@dataclass
class ScanConfig:
    """Configuration for scanning a cloud provider."""

    provider: str
    credentials: Dict[str, Any]  # Provider-specific credentials
    regions: List[str] = None  # None means all regions
    account_id: Optional[str] = None

    def __post_init__(self):
        if self.regions is None:
            self.regions = []


@dataclass
class ScanResult:
    """Results from a cloud provider scan."""

    provider: str
    account_id: str
    scan_timestamp: str
    assets: List[Asset]
    total_cost_estimate_usd: float
    summary: Dict[str, Any] = None

    def __post_init__(self):
        if self.summary is None:
            self.summary = {}


class CloudProviderScan(ABC):
    """
    Abstract base class for cloud provider scanners.

    All cloud providers must implement this interface to ensure
    consistent scanning behavior across providers.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.provider = config.provider

    @abstractmethod
    def list_assets(self) -> List[Asset]:
        """
        Discover and list all assets in the cloud provider.

        Returns:
            List of Asset objects representing discovered resources.
        """
        pass

    @abstractmethod
    def get_usage_metrics(self, asset: Asset) -> Dict[str, Any]:
        """
        Get usage metrics for a specific asset.

        Args:
            asset: The asset to analyze

        Returns:
            Dictionary of usage metrics (e.g., last_access, read_count, etc.)
        """
        pass

    @abstractmethod
    def get_cost_estimate(self, asset: Asset) -> float:
        """
        Estimate monthly cost for an asset in USD.

        Args:
            asset: The asset to estimate cost for

        Returns:
            Estimated monthly cost in USD
        """
        pass

    def scan(self) -> ScanResult:
        """
        Execute a full scan of the cloud provider.

        This is the main entry point that orchestrates:
        1. Asset discovery
        2. Usage analysis
        3. Cost estimation
        4. Risk flagging

        Returns:
            ScanResult containing all discovered assets and analysis
        """
        from datetime import datetime

        # Discover assets
        assets = self.list_assets()

        # Analyze each asset
        total_cost = 0.0
        for asset in assets:
            # Get usage metrics
            asset.usage_metrics = self.get_usage_metrics(asset)

            # Estimate cost
            asset.cost_estimate_usd = self.get_cost_estimate(asset)
            total_cost += asset.cost_estimate_usd or 0.0

        # Build summary
        summary = self._build_summary(assets)

        return ScanResult(
            provider=self.provider,
            account_id=self.config.account_id or "unknown",
            scan_timestamp=datetime.utcnow().isoformat(),
            assets=assets,
            total_cost_estimate_usd=total_cost,
            summary=summary,
        )

    def _build_summary(self, assets: List[Asset]) -> Dict[str, Any]:
        """Build summary statistics from assets."""
        total_assets = len(assets)
        assets_by_category = {}
        assets_by_service = {}
        unused_count = 0
        no_owner_count = 0
        risky_count = 0

        for asset in assets:
            # Count by category
            cat = asset.normalized_category.value
            assets_by_category[cat] = assets_by_category.get(cat, 0) + 1

            # Count by service
            assets_by_service[asset.service] = assets_by_service.get(asset.service, 0) + 1

            # Count unused (no activity in 90+ days)
            if asset.last_activity_at:
                from datetime import datetime, timedelta

                last_activity = datetime.fromisoformat(
                    asset.last_activity_at.replace("Z", "+00:00")
                )
                if datetime.utcnow() - last_activity.replace(tzinfo=None) > timedelta(days=90):
                    unused_count += 1
            else:
                unused_count += 1

            # Count no owner
            if asset.ownership_confidence == "unknown":
                no_owner_count += 1

            # Count risky
            if asset.risk_flags:
                risky_count += 1

        return {
            "total_assets": total_assets,
            "assets_by_category": assets_by_category,
            "assets_by_service": assets_by_service,
            "unused_count": unused_count,
            "no_owner_count": no_owner_count,
            "risky_count": risky_count,
        }
