"""
CloudWatch Logs collector for AWS.

Collects CloudWatch log groups for observability governance.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class CloudWatchLogsCollector:
    """Collects AWS CloudWatch log groups."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []
        self._account_id: str | None = None

    def _get_all_regions(self) -> list[str]:
        """Get all enabled AWS regions."""
        try:
            ec2 = self.session.client("ec2", region_name="us-east-1")
            response = ec2.describe_regions(AllRegions=False)
            return [r["RegionName"] for r in response.get("Regions", [])]
        except ClientError:
            return ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        if self._account_id:
            return self._account_id
        try:
            sts = self.session.client("sts")
            self._account_id = sts.get_caller_identity()["Account"]
            return self._account_id
        except ClientError:
            return ""

    def collect(self) -> list[Asset]:
        """Collect all CloudWatch log groups."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for CloudWatch log groups...", file=sys.stderr)

        for region in regions:
            try:
                logs = self.session.client("logs", region_name=region)
                paginator = logs.get_paginator("describe_log_groups")

                for page in paginator.paginate():
                    for log_group in page.get("logGroups", []):
                        log_group_name = log_group.get("logGroupName", "")
                        log_group_arn = log_group.get("arn", "")

                        # Get retention
                        retention_days = log_group.get("retentionInDays")

                        # Get storage
                        stored_bytes = log_group.get("storedBytes", 0)

                        # Get creation time
                        creation_time = log_group.get("creationTime")
                        created_at = None
                        if creation_time:
                            created_at = datetime.fromtimestamp(
                                creation_time / 1000, tz=timezone.utc
                            )

                        # Check encryption
                        kms_key_id = log_group.get("kmsKeyId")
                        encrypted = bool(kms_key_id)

                        # Get tags
                        tags = {}
                        try:
                            tags_response = logs.list_tags_log_group(logGroupName=log_group_name)
                            tags = tags_response.get("tags", {})
                        except ClientError:
                            pass

                        ownership = self._infer_ownership(tags, log_group_name)

                        # Build risk flags
                        risk_flags = []
                        if retention_days is None:
                            risk_flags.append("no_retention_policy")
                        elif retention_days > 365:
                            risk_flags.append("long_retention")
                        if not encrypted:
                            risk_flags.append("unencrypted")
                        if stored_bytes > 100 * 1024 * 1024 * 1024:  # >100GB
                            risk_flags.append("large_log_group")

                        # Estimate cost (~$0.03/GB-month for storage, ingestion varies)
                        stored_gb = stored_bytes / (1024**3)
                        monthly_cost = stored_gb * 0.03

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="cloudwatch_log_group",
                                normalized_category=NormalizedCategory.SECURITY,
                                service="CloudWatch Logs",
                                region=region,
                                arn=log_group_arn,
                                name=log_group_name,
                                created_at=created_at.isoformat() if created_at else None,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                size_bytes=stored_bytes,
                                cost_estimate_usd=monthly_cost,
                                usage_metrics={
                                    "log_group_name": log_group_name,
                                    "retention_days": retention_days,
                                    "stored_bytes": stored_bytes,
                                    "stored_gb": round(stored_gb, 2),
                                    "encrypted": encrypted,
                                    "kms_key_id": kms_key_id,
                                    "metric_filter_count": log_group.get("metricFilterCount", 0),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting CloudWatch log groups in {region}: {e}")

        print(f"  → Found {len(assets)} CloudWatch log groups", file=sys.stderr)
        return assets

    def _infer_ownership(self, tags: dict[str, str], name: str) -> dict[str, str]:
        """Infer ownership from tags."""
        owner = None
        confidence = "unknown"

        for key in ["owner", "Owner", "team", "Team", "created-by", "CreatedBy"]:
            if key in tags:
                owner = tags[key]
                confidence = "high" if key.lower() == "owner" else "medium"
                break

        # Try to infer from log group name (e.g., /aws/lambda/function-name)
        if not owner and name.startswith("/aws/lambda/"):
            parts = name.split("/")
            if len(parts) >= 4:
                owner = parts[3]  # Function name
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for CloudWatch log group."""
        return asset.usage_metrics or {}
