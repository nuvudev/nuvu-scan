"""
AWS provider scanner implementation.

Implements CloudProviderScan interface for AWS cloud provider.
"""

from typing import Any

import boto3

from nuvu_scan.core.base import Asset, CloudProviderScan, ScanConfig

from .collectors.athena import AthenaCollector
from .collectors.glue import GlueCollector
from .collectors.redshift import RedshiftCollector

# Import collectors
from .collectors.s3 import S3Collector


class AWSScanner(CloudProviderScan):
    """AWS cloud provider scanner."""

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.session = self._create_session()
        self.collectors = self._initialize_collectors()

    def _create_session(self) -> boto3.Session:
        """Create boto3 session from credentials."""
        credentials = self.config.credentials

        if "access_key_id" in credentials and "secret_access_key" in credentials:
            return boto3.Session(
                aws_access_key_id=credentials["access_key_id"],
                aws_secret_access_key=credentials["secret_access_key"],
                region_name=credentials.get("region", "us-east-1"),
            )
        elif "profile" in credentials:
            return boto3.Session(profile_name=credentials["profile"])
        else:
            # Use default credentials (environment, IAM role, etc.)
            return boto3.Session()

    def _initialize_collectors(self) -> list:
        """Initialize all AWS service collectors."""
        collectors = []

        # Initialize collectors for each service
        collectors.append(S3Collector(self.session, self.config.regions))
        collectors.append(GlueCollector(self.session, self.config.regions))
        collectors.append(AthenaCollector(self.session, self.config.regions))
        collectors.append(RedshiftCollector(self.session, self.config.regions))

        # TODO: Add more collectors as needed
        # collectors.append(OpenSearchCollector(self.session, self.config.regions))
        # collectors.append(EMRCollector(self.session, self.config.regions))
        # collectors.append(SageMakerCollector(self.session, self.config.regions))
        # etc.

        return collectors

    def list_assets(self) -> list[Asset]:
        """Discover all AWS assets across all collectors."""
        all_assets = []

        for collector in self.collectors:
            try:
                assets = collector.collect()
                all_assets.extend(assets)
            except Exception as e:
                # Log error but continue with other collectors
                print(f"Error collecting from {collector.__class__.__name__}: {e}")
                continue

        return all_assets

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for an AWS asset."""
        # Delegate to appropriate collector based on service
        for collector in self.collectors:
            if hasattr(collector, "get_usage_metrics"):
                try:
                    return collector.get_usage_metrics(asset)
                except Exception:
                    continue

        # Default: return empty metrics
        return {}

    def get_cost_estimate(self, asset: Asset) -> float:
        """Estimate monthly cost for an AWS asset."""
        # Delegate to appropriate collector based on service
        for collector in self.collectors:
            if hasattr(collector, "get_cost_estimate"):
                try:
                    return collector.get_cost_estimate(asset)
                except Exception:
                    continue

        # Default: return 0 if no cost estimation available
        return 0.0
