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
            raise ValueError(f"Failed to assume role {role_arn}: {str(e)}")

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
