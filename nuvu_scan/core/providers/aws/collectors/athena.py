"""
Amazon Athena collector.

Collects Athena workgroups and query history across all regions.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class AthenaCollector:
    """Collects Amazon Athena resources across all regions."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []

    def collect(self) -> list[Asset]:
        """Collect Athena workgroups from all regions."""
        import sys

        assets = []

        # If no regions specified, get all enabled regions
        regions_to_check = self.regions if self.regions else self._get_all_regions()

        print(
            f"  → Checking {len(regions_to_check)} regions for Athena workgroups...",
            file=sys.stderr,
        )

        for region in regions_to_check:
            try:
                athena_client = self.session.client("athena", region_name=region)
                response = athena_client.list_work_groups()

                for wg_info in response.get("WorkGroups", []):
                    wg_name = wg_info["Name"]

                    try:
                        # Get workgroup details
                        wg_details = athena_client.get_work_group(WorkGroup=wg_name)

                        # Get query statistics
                        query_stats = self._get_query_stats(athena_client, wg_name)

                        risk_flags = []
                        if query_stats.get("idle_days", 0) > 90:
                            risk_flags.append("idle_workgroup")
                        if (
                            query_stats.get("failed_queries", 0)
                            > query_stats.get("total_queries", 1) * 0.5
                        ):
                            risk_flags.append("high_failure_rate")

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="athena_workgroup",
                                normalized_category=NormalizedCategory.QUERY_ENGINE,
                                service="Athena",
                                region=region,
                                arn=f"arn:aws:athena:{region}::workgroup/{wg_name}",
                                name=wg_name,
                                created_at=(
                                    wg_details.get("WorkGroup", {})
                                    .get("CreationTime", "")
                                    .isoformat()
                                    if wg_details.get("WorkGroup", {}).get("CreationTime")
                                    else None
                                ),
                                last_activity_at=query_stats.get("last_query_time"),
                                risk_flags=risk_flags,
                                usage_metrics={
                                    **query_stats,
                                    "last_used": query_stats.get("last_query_time"),
                                    "days_since_last_use": query_stats.get("idle_days"),
                                },
                            )
                        )
                    except ClientError:
                        continue

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                if error_code == "AccessDeniedException":
                    print(
                        f"  ⚠️  No permission to list Athena workgroups in {region}. "
                        "Add 'athena:ListWorkGroups' to IAM policy.",
                        file=sys.stderr,
                    )
                # Skip other errors silently (region not enabled, etc.)

        if assets:
            print(f"  → Found {len(assets)} Athena workgroups", file=sys.stderr)
        return assets

    def _get_all_regions(self) -> list[str]:
        """Get all enabled AWS regions."""
        try:
            ec2 = self.session.client("ec2", region_name="us-east-1")
            response = ec2.describe_regions(AllRegions=False)
            return [r["RegionName"] for r in response.get("Regions", [])]
        except ClientError:
            # Fallback to common regions
            return ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    def _get_query_stats(self, athena_client, workgroup_name: str) -> dict[str, Any]:
        """Get query statistics for a workgroup."""
        stats = {"total_queries": 0, "failed_queries": 0, "last_query_time": None, "idle_days": 0}

        try:
            # List recent queries (limit to avoid long scan times)
            paginator = athena_client.get_paginator("list_query_executions")

            query_count = 0
            for page in paginator.paginate(
                WorkGroup=workgroup_name, PaginationConfig={"MaxItems": 100}
            ):
                for query_id in page.get("QueryExecutionIds", []):
                    query_count += 1
                    if query_count > 50:  # Limit for performance
                        break

                    try:
                        query_info = athena_client.get_query_execution(QueryExecutionId=query_id)
                        execution = query_info.get("QueryExecution", {})
                        status = execution.get("Status", {})

                        stats["total_queries"] += 1

                        if status.get("State") == "FAILED":
                            stats["failed_queries"] += 1

                        # Get last query time
                        completion_time = status.get("CompletionDateTime")
                        if completion_time:
                            if (
                                not stats["last_query_time"]
                                or completion_time > stats["last_query_time"]
                            ):
                                stats["last_query_time"] = completion_time.isoformat()
                    except ClientError:
                        continue

                if query_count > 50:
                    break

            # Calculate idle days
            if stats["last_query_time"]:
                last_query = datetime.fromisoformat(stats["last_query_time"].replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                stats["idle_days"] = (now - last_query).days
            else:
                stats["idle_days"] = 999  # Never used

        except ClientError:
            pass

        return stats

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for Athena workgroup."""
        return asset.usage_metrics or {}

    def get_cost_estimate(self, asset: Asset) -> float:
        """Estimate cost for Athena workgroup."""
        # Athena: $5 per TB scanned
        # For idle workgroups, cost is minimal (just storage)
        # Estimate based on query activity
        query_count = asset.usage_metrics.get("total_queries", 0)
        if query_count == 0:
            return 0.0

        # Rough estimate: $0.10 per query on average
        return query_count * 0.10
