"""
MWAA (Managed Workflows for Apache Airflow) collector for AWS.

Collects MWAA environments, their metadata, usage, and cost estimates.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class MWAACollector:
    """Collects MWAA environments and their metadata."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []

    def collect(self) -> list[Asset]:
        """Collect all MWAA environments."""
        assets = []

        # MWAA is available in specific regions
        # Check common regions if not specified
        regions_to_check = self.regions or [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-west-2",
            "eu-central-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
        ]

        for region in regions_to_check:
            try:
                mwaa_client = self.session.client("mwaa", region_name=region)

                # List all MWAA environments
                try:
                    response = mwaa_client.list_environments()

                    for env_name in response.get("Environments", []):
                        try:
                            # Get environment details
                            env_details = mwaa_client.get_environment(Name=env_name)

                            environment = env_details.get("Environment", {})
                            if not environment:
                                continue

                            # Extract environment information
                            name = environment.get("Name", env_name)
                            status = environment.get("Status", "UNKNOWN")
                            created_at = environment.get("CreatedAt")
                            last_updated = environment.get("LastUpdate", {}).get("CreatedAt")
                            airflow_version = environment.get("AirflowVersion", "Unknown")
                            environment_class = environment.get("EnvironmentClass", "Unknown")
                            max_workers = environment.get("MaxWorkers", 0)
                            min_workers = environment.get("MinWorkers", 0)
                            webserver_url = environment.get("WebserverUrl", "")

                            # Get tags
                            tags = self._get_environment_tags(mwaa_client, env_name, region)

                            # Infer ownership
                            ownership = self._infer_ownership(tags, name)

                            # Estimate cost
                            cost_estimate = self._estimate_cost(
                                environment_class, min_workers, max_workers
                            )

                            # Check for risk flags
                            risk_flags = self._check_risks(environment, tags)

                            # Create asset
                            asset = Asset(
                                provider="aws",
                                asset_type="mwaa_environment",
                                normalized_category=NormalizedCategory.DATA_PIPELINE,
                                service="MWAA",
                                region=region,
                                arn=f"arn:aws:airflow:{region}:{self._get_account_id()}:environment/{env_name}",
                                name=name,
                                created_at=created_at.isoformat() if created_at else None,
                                last_activity_at=last_updated.isoformat() if last_updated else None,
                                tags=tags,
                                cost_estimate_usd=cost_estimate,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "status": status,
                                    "airflow_version": airflow_version,
                                    "environment_class": environment_class,
                                    "min_workers": min_workers,
                                    "max_workers": max_workers,
                                    "webserver_url": webserver_url,
                                    "last_used": last_updated.isoformat() if last_updated else None,
                                    "days_since_last_use": self._calculate_days_since_last_use(
                                        last_updated
                                    ),
                                },
                            )

                            assets.append(asset)

                        except ClientError as e:
                            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                                continue
                            print(f"Error getting MWAA environment {env_name}: {e}")
                            continue
                        except Exception as e:
                            print(f"Error processing MWAA environment {env_name}: {e}")
                            continue

                except ClientError as e:
                    if e.response["Error"]["Code"] == "AccessDeniedException":
                        # MWAA might not be available in this region or no permissions
                        continue
                    print(f"Error listing MWAA environments in {region}: {e}")
                    continue

            except Exception:
                # MWAA client might not be available in this region
                continue

        return assets

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            sts_client = self.session.client("sts", region_name="us-east-1")
            return sts_client.get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    def _get_environment_tags(self, mwaa_client, env_name: str, region: str) -> dict[str, str]:
        """Get tags for MWAA environment."""
        try:
            # Get environment ARN from environment details
            env_details = mwaa_client.get_environment(Name=env_name)
            environment = env_details.get("Environment", {})
            arn = environment.get("Arn", "")

            if not arn:
                return {}

            response = mwaa_client.list_tags_for_resource(ResourceArn=arn)
            tags = {}
            # Tags are returned as a dict, not a list
            for key, value in response.get("Tags", {}).items():
                tags[key] = value
            return tags
        except Exception:
            return {}

    def _infer_ownership(self, tags: dict[str, str], name: str) -> dict[str, str]:
        """Infer ownership from tags or naming."""
        owner = None
        confidence = "unknown"

        # Check tags for owner
        if "owner" in tags:
            owner = tags["owner"]
            confidence = "high"
        elif "Owner" in tags:
            owner = tags["Owner"]
            confidence = "high"
        elif "team" in tags:
            owner = tags["team"]
            confidence = "medium"
        elif "Team" in tags:
            owner = tags["Team"]
            confidence = "medium"
        elif "project" in tags:
            owner = tags["project"]
            confidence = "medium"

        # Try to infer from name
        if not owner:
            # Common patterns: team-name-env, project-name-airflow
            parts = name.split("-")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def _estimate_cost(
        self, environment_class: str, min_workers: int, max_workers: int
    ) -> float:
        """Estimate monthly cost for MWAA environment."""
        # MWAA pricing (as of 2024):
        # - mw1.small: $0.49/hour per environment + $0.055/hour per worker
        # - mw1.medium: $0.49/hour per environment + $0.11/hour per worker
        # - mw1.large: $0.49/hour per environment + $0.22/hour per worker

        base_hourly = 0.49  # Base cost per hour for environment
        hours_per_month = 730  # ~30.4 days

        # Worker pricing based on environment class
        worker_pricing = {
            "mw1.small": 0.055,
            "mw1.medium": 0.11,
            "mw1.large": 0.22,
        }

        worker_hourly = worker_pricing.get(environment_class.lower(), 0.11)

        # Estimate based on average workers (midpoint between min and max)
        avg_workers = (min_workers + max_workers) / 2 if max_workers > 0 else min_workers
        if avg_workers == 0:
            avg_workers = 1  # At least 1 worker

        # Calculate monthly cost
        base_monthly = base_hourly * hours_per_month
        worker_monthly = worker_hourly * avg_workers * hours_per_month

        return base_monthly + worker_monthly

    def _check_risks(self, environment: dict, tags: dict[str, str]) -> list[str]:
        """Check for risk flags in MWAA environment."""
        risks = []

        # Check if environment is in a problematic state
        status = environment.get("Status", "")
        if status in ["CREATING", "DELETING", "UPDATING"]:
            risks.append("environment_in_transition")

        # Check for missing owner
        if not tags.get("owner") and not tags.get("Owner"):
            risks.append("no_owner")

        # Check for public access (if webserver is publicly accessible)
        # Note: MWAA webserver access is controlled via VPC and security groups
        # This is a simplified check
        network_config = environment.get("NetworkConfiguration", {})
        if not network_config:
            risks.append("network_config_missing")

        # Check for old Airflow version (potential security risk)
        airflow_version = environment.get("AirflowVersion", "")
        if airflow_version and airflow_version.startswith("1."):
            risks.append("outdated_airflow_version")

        return risks

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get detailed usage metrics for a MWAA environment."""
        return asset.usage_metrics or {}

    def _calculate_days_since_last_use(self, last_updated) -> int | None:
        """Calculate days since last use."""
        from datetime import datetime

        if not last_updated:
            return None

        try:
            if isinstance(last_updated, datetime):
                days = (datetime.utcnow() - last_updated.replace(tzinfo=None)).days
            else:
                last_used = datetime.fromisoformat(last_updated.isoformat().replace("Z", "+00:00"))
                days = (datetime.utcnow() - last_used.replace(tzinfo=None)).days
            return days
        except Exception:
            return None

    def get_cost_estimate(self, asset: Asset) -> float:
        """Get cost estimate for MWAA environment."""
        return asset.cost_estimate_usd or 0.0
