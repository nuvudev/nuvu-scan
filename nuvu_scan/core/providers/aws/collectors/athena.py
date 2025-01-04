"""
Amazon Athena collector.

Collects Athena workgroups and query history.
"""

from datetime import datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class AthenaCollector:
    """Collects Amazon Athena resources."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or ["us-east-1"]
        self.athena_client = session.client("athena", region_name="us-east-1")

    def collect(self) -> list[Asset]:
        """Collect Athena workgroups."""
        import sys
        
        assets = []

        try:
            # List workgroups
            print("  → Listing Athena workgroups...", file=sys.stderr)
            response = self.athena_client.list_work_groups()

            for wg_info in response.get("WorkGroups", []):
                wg_name = wg_info["Name"]

                try:
                    # Get workgroup details
                    wg_details = self.athena_client.get_work_group(WorkGroup=wg_name)
                    wg_details.get("WorkGroup", {}).get("Configuration", {})

                    # Get query statistics
                    query_stats = self._get_query_stats(wg_name)

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
                            region="us-east-1",
                            arn=f"arn:aws:athena:us-east-1::workgroup/{wg_name}",
                            name=wg_name,
                            created_at=(
                                wg_details.get("WorkGroup", {}).get("CreationTime", "").isoformat()
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
            print(f"Error collecting Athena resources: {e}")

        return assets

    def _get_query_stats(self, workgroup_name: str) -> dict[str, Any]:
        """Get query statistics for a workgroup."""
        stats = {"total_queries": 0, "failed_queries": 0, "last_query_time": None, "idle_days": 0}

        try:
            # List recent queries
            paginator = self.athena_client.get_paginator("list_query_executions")
            datetime.utcnow() - timedelta(days=90)

            for page in paginator.paginate(WorkGroup=workgroup_name):
                for query_id in page.get("QueryExecutionIds", []):
                    try:
                        query_info = self.athena_client.get_query_execution(
                            QueryExecutionId=query_id
                        )
                        execution = query_info.get("QueryExecution", {})
                        status = execution.get("Status", {})

                        stats["total_queries"] += 1

                        if status.get("State") == "FAILED":
                            stats["failed_queries"] += 1

                        # Get last query time
                        completion_time = execution.get("Status", {}).get("CompletionDateTime")
                        if completion_time:
                            if (
                                not stats["last_query_time"]
                                or completion_time > stats["last_query_time"]
                            ):
                                stats["last_query_time"] = completion_time.isoformat()
                    except ClientError:
                        continue

            # Calculate idle days
            if stats["last_query_time"]:
                last_query = datetime.fromisoformat(stats["last_query_time"].replace("Z", "+00:00"))
                stats["idle_days"] = (datetime.utcnow() - last_query.replace(tzinfo=None)).days
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
