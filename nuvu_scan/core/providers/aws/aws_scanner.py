"""
AWS provider scanner implementation.

Implements CloudProviderScan interface for AWS cloud provider.
"""

from typing import Any

import boto3

from nuvu_scan.core.base import Asset, CloudProviderScan, NormalizedCategory, ScanConfig

from .collectors.athena import AthenaCollector
from .collectors.cost_explorer import CostExplorerCollector
from .collectors.glue import GlueCollector
from .collectors.iam import IAMCollector
from .collectors.mwaa import MWAACollector
from .collectors.redshift import RedshiftCollector

# Import collectors
from .collectors.s3 import S3Collector


class AWSScanner(CloudProviderScan):
    """AWS cloud provider scanner."""

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.session = self._create_session()
        self.collectors = self._initialize_collectors()
        self.cost_explorer = CostExplorerCollector(self.session, self.config.regions)

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
        collectors.append(IAMCollector(self.session, self.config.regions))
        collectors.append(MWAACollector(self.session, self.config.regions))

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

        # Add a summary asset with actual costs from Cost Explorer
        try:
            from datetime import datetime, timedelta

            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=30)
            service_costs = self.cost_explorer.get_service_costs(start_date, end_date)

            if service_costs:
                total_actual_cost = sum(service_costs.values())
                # Convert to monthly estimate
                days_in_period = (end_date - start_date).days
                if days_in_period > 0:
                    daily_avg = total_actual_cost / days_in_period
                    monthly_estimate = daily_avg * 30

                    # Create a summary asset
                    cost_summary_asset = Asset(
                        provider="aws",
                        asset_type="cost_summary",
                        normalized_category=NormalizedCategory.SECURITY,  # Using security as placeholder
                        service="Cost Explorer",
                        region="global",
                        arn="arn:aws:ce::cost-summary",
                        name="AWS Cost Summary (Last 30 Days)",
                        created_at=None,
                        last_activity_at=datetime.utcnow().isoformat(),
                        tags={},
                        cost_estimate_usd=monthly_estimate,
                        risk_flags=[],
                        ownership_confidence="unknown",
                        suggested_owner=None,
                        usage_metrics={
                            "actual_costs_30d": service_costs,
                            "total_actual_cost_30d": total_actual_cost,
                            "estimated_monthly_cost": monthly_estimate,
                            "note": "Actual costs from AWS Cost Explorer API. Note: Some costs shown are for services that are not data assets (e.g., domain registration, email services, DNS). Individual asset costs below are estimates based on resource usage.",
                        },
                    )
                    all_assets.append(cost_summary_asset)
        except Exception as e:
            # If Cost Explorer fails, continue without summary
            import sys
            print(
                f"INFO: Could not get Cost Explorer summary: {e}",
                file=sys.stderr,
            )

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
        # First, try to get actual cost from Cost Explorer API
        try:
            # Map service names to Cost Explorer service names
            service_mapping = {
                "S3": "Amazon Simple Storage Service",
                "Athena": "Amazon Athena",
                "Glue": "AWS Glue",
                "Redshift": "Amazon Redshift",
                "MWAA": "Amazon Managed Workflows for Apache Airflow",
            }

            cost_explorer_service = service_mapping.get(asset.service)
            if cost_explorer_service:
                # Get service-level cost from Cost Explorer
                service_cost = self.cost_explorer.get_monthly_cost_for_service(
                    cost_explorer_service
                )
                if service_cost > 0:
                    # If we have service-level cost, we can use it as a baseline
                    # For now, we'll use the collector's estimate if available,
                    # but if it's 0 and we have service cost, we'll use a portion
                    # This is a heuristic - ideally we'd have per-resource costs
                    pass  # Continue to collector-based estimation

        except Exception:
            # If Cost Explorer fails, fall back to collector-based estimation
            pass

        # Delegate to appropriate collector based on service for detailed estimation
        for collector in self.collectors:
            if hasattr(collector, "get_cost_estimate"):
                try:
                    estimated_cost = collector.get_cost_estimate(asset)
                    if estimated_cost > 0:
                        return estimated_cost
                except Exception:
                    continue

        # Default: return 0 if no cost estimation available
        return 0.0
