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

from .collectors.apigateway import APIGatewayCollector
from .collectors.athena import AthenaCollector
from .collectors.backup import BackupCollector
from .collectors.cloudfront import CloudFrontCollector
from .collectors.cloudtrail import CloudTrailCollector
from .collectors.cloudwatch import CloudWatchLogsCollector
from .collectors.cost_explorer import CostExplorerCollector
from .collectors.dynamodb import DynamoDBCollector
from .collectors.ec2 import EC2Collector
from .collectors.ecs import ECSCollector
from .collectors.eks import EKSCollector
from .collectors.elasticache import ElastiCacheCollector
from .collectors.elb import ELBCollector
from .collectors.glue import GlueCollector
from .collectors.iam import IAMCollector
from .collectors.kinesis import KinesisFirehoseCollector
from .collectors.kms import KMSCollector
from .collectors.lakeformation import LakeFormationCollector
from .collectors.lambda_collector import LambdaCollector
from .collectors.misc_services import EFSCollector, StepFunctionsCollector, SystemsManagerCollector
from .collectors.mwaa import MWAACollector
from .collectors.rds import RDSCollector
from .collectors.redshift import RedshiftCollector
from .collectors.route53 import Route53Collector
from .collectors.s3 import S3Collector
from .collectors.secrets import SecretsManagerCollector
from .collectors.security_services import SecurityServicesCollector
from .collectors.sns_sqs import SNSSQSCollector

# New collectors for comprehensive coverage
from .collectors.vpc_costs import VPCCostsCollector


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
        # Original collectors
        "s3": S3Collector,
        "glue": GlueCollector,
        "athena": AthenaCollector,
        "redshift": RedshiftCollector,
        "iam": IAMCollector,
        "mwaa": MWAACollector,
        "ec2": EC2Collector,
        "kms": KMSCollector,
        "rds": RDSCollector,
        "dynamodb": DynamoDBCollector,
        "lambda": LambdaCollector,
        "secrets": SecretsManagerCollector,
        "backup": BackupCollector,
        "eks": EKSCollector,
        "sns_sqs": SNSSQSCollector,
        "lakeformation": LakeFormationCollector,
        "cloudtrail": CloudTrailCollector,
        "cloudwatch": CloudWatchLogsCollector,
        # New collectors for comprehensive coverage
        "vpc_costs": VPCCostsCollector,
        "elb": ELBCollector,
        "elasticache": ElastiCacheCollector,
        "route53": Route53Collector,
        "kinesis": KinesisFirehoseCollector,
        "apigateway": APIGatewayCollector,
        "cloudfront": CloudFrontCollector,
        "ecs": ECSCollector,
        "security": SecurityServicesCollector,
        "ssm": SystemsManagerCollector,
        "stepfunctions": StepFunctionsCollector,
        "efs": EFSCollector,
    }

    @classmethod
    def get_available_collectors(cls) -> list[str]:
        """Return list of available collector names."""
        return list(cls.COLLECTOR_MAP.keys())

    # Collectors that require account_id as a parameter
    COLLECTORS_NEEDING_ACCOUNT_ID = {
        "vpc_costs",
        "elb",
        "elasticache",
        "route53",
        "kinesis",
        "apigateway",
        "cloudfront",
        "ecs",
        "security",
        "ssm",
        "stepfunctions",
        "efs",
    }

    def _initialize_collectors(self) -> list:
        """Initialize AWS service collectors based on config."""
        collectors = []

        # Get requested collectors from config
        requested = self.config.collectors if self.config.collectors else []

        # Normalize to lowercase
        requested_lower = [c.lower() for c in requested]

        def create_collector(name, collector_cls):
            """Create a collector with appropriate parameters."""
            if name in self.COLLECTORS_NEEDING_ACCOUNT_ID:
                return collector_cls(self.session, self.config.regions, self.config.account_id)
            else:
                return collector_cls(self.session, self.config.regions)

        # If no specific collectors requested, use all
        if not requested_lower:
            for name, collector_cls in self.COLLECTOR_MAP.items():
                collectors.append(create_collector(name, collector_cls))
        else:
            # Filter to only requested collectors
            for name, collector_cls in self.COLLECTOR_MAP.items():
                if name in requested_lower:
                    collectors.append(create_collector(name, collector_cls))

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
        # Only include costs for services related to the scanned collectors
        print("Fetching cost data from AWS Cost Explorer...", file=sys.stderr)
        try:
            from datetime import datetime, timedelta

            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=30)

            # Get comprehensive cost data including Savings Plans
            cost_data = self.cost_explorer.get_all_costs_with_savings(start_date, end_date)
            service_costs = cost_data["service_costs"]
            savings_plans = cost_data["savings_plans"]
            print("  → Cost data retrieved", file=sys.stderr)
            if savings_plans.get("total_savings", 0) > 0:
                print(
                    f"  → Savings Plans: ${savings_plans['total_savings']:.2f} saved ({savings_plans['utilization_percent']:.1f}% utilization)",
                    file=sys.stderr,
                )

            if service_costs:
                # Map collectors to AWS service names in Cost Explorer
                collector_to_services = {
                    # Original collectors
                    "s3": ["Amazon Simple Storage Service"],
                    "glue": ["AWS Glue"],
                    "athena": ["Amazon Athena"],
                    "redshift": ["Amazon Redshift"],
                    "iam": [],  # IAM is free
                    "mwaa": ["Amazon Managed Workflows for Apache Airflow"],
                    "ec2": [
                        "Amazon Elastic Compute Cloud - Compute",
                        "EC2 - Other",
                        "Amazon EC2 Container Registry (ECR)",
                    ],
                    "kms": ["AWS Key Management Service"],
                    "rds": ["Amazon Relational Database Service"],
                    "dynamodb": ["Amazon DynamoDB"],
                    "lambda": ["AWS Lambda"],
                    "secrets": ["AWS Secrets Manager"],
                    "backup": ["AWS Backup"],
                    "eks": [
                        "Amazon Elastic Kubernetes Service",
                        "Amazon Elastic Container Service for Kubernetes",
                    ],
                    "sns_sqs": [
                        "Amazon Simple Notification Service",
                        "Amazon Simple Queue Service",
                    ],
                    "lakeformation": ["AWS Lake Formation"],
                    "cloudtrail": ["AWS CloudTrail"],
                    "cloudwatch": ["AmazonCloudWatch", "CloudWatch Events"],
                    # New collectors
                    "vpc_costs": ["Amazon Virtual Private Cloud"],
                    "elb": ["Amazon Elastic Load Balancing"],
                    "elasticache": ["Amazon ElastiCache"],
                    "route53": ["Amazon Route 53"],
                    "kinesis": ["Amazon Kinesis Firehose", "Amazon Kinesis"],
                    "apigateway": ["Amazon API Gateway"],
                    "cloudfront": ["Amazon CloudFront"],
                    "ecs": ["Amazon Elastic Container Service"],
                    "security": [
                        "Amazon GuardDuty",
                        "Amazon Inspector",
                        "AWS Security Hub",
                        "AWS Config",
                    ],
                    "ssm": ["AWS Systems Manager"],
                    "stepfunctions": ["AWS Step Functions"],
                    "efs": ["Amazon Elastic File System"],
                }

                # Filter costs based on active collectors
                active_collector_names = (
                    [name.lower() for name in self.config.collectors]
                    if self.config.collectors
                    else list(collector_to_services.keys())
                )

                # Build list of relevant AWS service names
                relevant_services = set()
                for collector_name in active_collector_names:
                    services = collector_to_services.get(collector_name, [])
                    relevant_services.update(services)

                # Filter service_costs to only include relevant services
                if self.config.collectors:  # Only filter if specific collectors requested
                    filtered_costs = {
                        svc: cost for svc, cost in service_costs.items() if svc in relevant_services
                    }
                    total_actual_cost = sum(filtered_costs.values())
                    display_costs = filtered_costs
                    scope_note = f"Filtered to collectors: {', '.join(self.config.collectors)}"
                else:
                    # Full scan - show all costs
                    total_actual_cost = sum(service_costs.values())
                    display_costs = service_costs
                    scope_note = "Full scan - all services"

                # Use the actual 30-day cost as monthly estimate
                monthly_estimate = total_actual_cost

                # Create a summary asset
                cost_summary_asset = Asset(
                    provider="aws",
                    asset_type="cost_summary",
                    normalized_category=NormalizedCategory.BILLING,
                    service="Cost Explorer",
                    region="global",
                    arn="arn:aws:ce::cost-summary",
                    name=f"AWS Cost Summary - {scope_note}",
                    created_at=None,
                    last_activity_at=datetime.utcnow().isoformat(),
                    tags={},
                    cost_estimate_usd=monthly_estimate,
                    risk_flags=[],
                    ownership_confidence="unknown",
                    suggested_owner=None,
                    usage_metrics={
                        "actual_costs_30d": display_costs,
                        "total_actual_cost_30d": total_actual_cost,
                        "estimated_monthly_cost": monthly_estimate,
                        "scope": scope_note,
                        "note": "Actual costs from AWS Cost Explorer API for the last 30 days.",
                        # Savings Plans data
                        "savings_plans": {
                            "total_savings": savings_plans.get("total_savings", 0),
                            "utilization_percent": savings_plans.get("utilization_percent", 0),
                            "coverage_percent": savings_plans.get("coverage_percent", 0),
                            "amortized_commitment": savings_plans.get("amortized_commitment", 0),
                            "on_demand_equivalent": savings_plans.get("on_demand_equivalent", 0),
                        },
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

        Uses collector-based estimates for individual assets.
        Service-level actual costs from Cost Explorer are already included
        in the cost_summary asset and used for reporting.
        """
        # Use the cost already set by the collector during collection
        # This avoids making Cost Explorer API calls for each asset
        if asset.cost_estimate_usd is not None and asset.cost_estimate_usd > 0:
            return asset.cost_estimate_usd

        # Delegate to appropriate collector based on service for estimation
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
