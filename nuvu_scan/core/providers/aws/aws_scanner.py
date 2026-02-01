"""
AWS provider scanner implementation.

Implements CloudProviderScan interface for AWS cloud provider.
"""

from typing import Any

import boto3

from nuvu_scan.core.base import (
    Asset,
    CloudProviderScan,
    NormalizedCategory,
    ScanConfig,
)

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
        # Auto-detect account ID if not provided
        if not self.config.account_id:
            self.config.account_id = self._get_account_id()
        self.collectors = self._initialize_collectors()
        self.cost_explorer = CostExplorerCollector(self.session, self.config.regions)

    def _get_account_id(self) -> str:
        """Get the AWS account ID using STS."""
        try:
            sts_client = self.session.client("sts")
            return sts_client.get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    def _create_session(self) -> boto3.Session:
        """
        Create boto3 session from credentials.

        Supports multiple authentication methods:
        1. Access Key + Secret Key (with optional session token)
        2. AWS Profile
        3. IAM Role assumption (role_arn)
        4. Default credentials (environment, IAM role, etc.)
        """
        credentials = self.config.credentials

        # Method 1: Access Key + Secret Key (with optional session token)
        if "access_key_id" in credentials and "secret_access_key" in credentials:
            session_kwargs = {
                "aws_access_key_id": credentials["access_key_id"],
                "aws_secret_access_key": credentials["secret_access_key"],
                "region_name": credentials.get("region", "us-east-1"),
            }

            # Add session token if provided (for temporary credentials)
            if "session_token" in credentials:
                session_kwargs["aws_session_token"] = credentials["session_token"]

            session = boto3.Session(**session_kwargs)

            # Method 1b: If role_arn is provided, assume the role
            if "role_arn" in credentials:
                session = self._assume_role(session, credentials)

            return session

        # Method 2: AWS Profile
        elif "profile" in credentials:
            session = boto3.Session(profile_name=credentials["profile"])

            # If role_arn is provided with profile, assume the role
            if "role_arn" in credentials:
                session = self._assume_role(session, credentials)

            return session

        # Method 3: Role assumption from default credentials
        elif "role_arn" in credentials:
            # Start with default credentials and assume role
            default_session = boto3.Session()
            return self._assume_role(default_session, credentials)

        # Method 4: Use default credentials (environment, IAM role, etc.)
        else:
            return boto3.Session()

    def _assume_role(self, session: boto3.Session, credentials: dict) -> boto3.Session:
        """
        Assume an IAM role and return a new session with temporary credentials.

        Args:
            session: The base boto3 session to use for assuming the role
            credentials: Credentials dict containing role_arn and optional parameters

        Returns:
            A new boto3.Session with temporary credentials from the assumed role
        """
        import boto3
        from botocore.exceptions import ClientError

        role_arn = credentials["role_arn"]
        role_session_name = credentials.get("role_session_name", "nuvu-scan-session")
        external_id = credentials.get("external_id")
        duration_seconds = credentials.get("duration_seconds", 3600)  # Default 1 hour

        try:
            sts_client = session.client("sts")

            assume_role_kwargs = {
                "RoleArn": role_arn,
                "RoleSessionName": role_session_name,
                "DurationSeconds": duration_seconds,
            }

            if external_id:
                assume_role_kwargs["ExternalId"] = external_id

            response = sts_client.assume_role(**assume_role_kwargs)
            credentials_data = response["Credentials"]

            # Create a new session with the temporary credentials
            return boto3.Session(
                aws_access_key_id=credentials_data["AccessKeyId"],
                aws_secret_access_key=credentials_data["SecretAccessKey"],
                aws_session_token=credentials_data["SessionToken"],
                region_name=credentials.get("region", "us-east-1"),
            )
        except ClientError as e:
            raise ValueError(f"Failed to assume role {role_arn}: {str(e)}") from e

    def _resolve_regions(self) -> list[str]:
        """Resolve regions to scan. If none provided, scan all enabled regions."""
        try:
            ec2 = self.session.client("ec2", region_name="us-east-1")
            response = ec2.describe_regions(AllRegions=False)
            regions = [region["RegionName"] for region in response.get("Regions", [])]
            if regions:
                return regions
        except Exception:
            pass
        return ["us-east-1"]

    def _get_account_id(self) -> str:
        """Get AWS account ID from STS get_caller_identity."""
        try:
            sts_client = self.session.client("sts", region_name="us-east-1")
            identity = sts_client.get_caller_identity()
            return identity.get("Account", "unknown")
        except Exception:
            # If we can't get account ID, return "unknown"
            return "unknown"

    # Map of collector names to their classes for filtering
    COLLECTOR_MAP = {
        "s3": S3Collector,
        "glue": GlueCollector,
        "athena": AthenaCollector,
        "redshift": RedshiftCollector,
        "iam": IAMCollector,
        "mwaa": MWAACollector,
    }

    @classmethod
    def get_available_collectors(cls) -> list[str]:
        """Return list of available collector names."""
        return list(cls.COLLECTOR_MAP.keys())

    def _initialize_collectors(self) -> list:
        """Initialize AWS service collectors based on config."""
        collectors = []

        # Get requested collectors from config
        requested = self.config.collectors if self.config.collectors else []

        # Normalize to lowercase
        requested_lower = [c.lower() for c in requested]

        # If no specific collectors requested, use all
        if not requested_lower:
            for collector_cls in self.COLLECTOR_MAP.values():
                collectors.append(collector_cls(self.session, self.config.regions))
        else:
            # Filter to only requested collectors
            for name, collector_cls in self.COLLECTOR_MAP.items():
                if name in requested_lower:
                    collectors.append(collector_cls(self.session, self.config.regions))

            # Warn about unknown collectors
            known = set(self.COLLECTOR_MAP.keys())
            unknown = set(requested_lower) - known
            if unknown:
                import sys

                print(f"Warning: Unknown collectors ignored: {', '.join(unknown)}", file=sys.stderr)
                print(f"Available collectors: {', '.join(sorted(known))}", file=sys.stderr)

        return collectors

    def list_assets(self) -> list[Asset]:
        """Discover all AWS assets across all collectors."""
        all_assets = []
        import sys

        collector_names = [c.__class__.__name__ for c in self.collectors]
        print(f"Scanning with collectors: {', '.join(collector_names)}", file=sys.stderr)

        for i, collector in enumerate(self.collectors, 1):
            collector_name = collector.__class__.__name__
            print(
                f"[{i}/{len(self.collectors)}] Collecting from {collector_name}...", file=sys.stderr
            )
            try:
                assets = collector.collect()
                all_assets.extend(assets)
                print(
                    f"[{i}/{len(self.collectors)}] {collector_name}: Found {len(assets)} assets",
                    file=sys.stderr,
                )
            except Exception as e:
                # Log error but continue with other collectors
                print(f"Error collecting from {collector_name}: {e}", file=sys.stderr)
                continue

        # Add a summary asset with actual costs from Cost Explorer
        try:
            from datetime import datetime, timedelta

            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=30)
            service_costs = self.cost_explorer.get_service_costs(start_date, end_date)

            if service_costs:
                total_actual_cost = sum(service_costs.values())
                # Use the actual 30-day cost as monthly estimate
                # This represents the actual spend, not an extrapolation
                monthly_estimate = total_actual_cost

                # Create a summary asset
                cost_summary_asset = Asset(
                    provider="aws",
                    asset_type="cost_summary",
                    normalized_category=NormalizedCategory.BILLING,
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
                        "note": "Actual costs from AWS Cost Explorer API for the last 30 days. This represents real spend, not estimates. Note: Some costs shown are for services that are not data assets (e.g., domain registration, email services, DNS). Individual asset costs below may be estimates based on resource usage.",
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
        """Estimate monthly cost for an AWS asset.

        First tries to get actual cost from Cost Explorer API.
        Falls back to collector-based estimates if Cost Explorer data is not available.
        """
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
                # Get service-level cost from Cost Explorer (last 30 days actual cost)
                service_cost = self.cost_explorer.get_monthly_cost_for_service(
                    cost_explorer_service
                )
                if service_cost > 0:
                    # We have actual service-level cost from Cost Explorer
                    # For now, we'll still use collector estimates for individual assets
                    # because Cost Explorer doesn't provide per-resource costs without tags
                    # But we could potentially distribute service cost across assets proportionally
                    # For now, prefer collector estimates which are more accurate per-resource
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
