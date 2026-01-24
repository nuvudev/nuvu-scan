"""
BigQuery collector.

Collects BigQuery datasets, tables, and query history.
"""

from datetime import datetime, timedelta
from typing import Any

from google.cloud import bigquery

from nuvu_scan.core.base import Asset, NormalizedCategory


class BigQueryCollector:
    """Collects BigQuery datasets, tables, and query jobs."""

    def __init__(self, credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.client = bigquery.Client(credentials=credentials, project=project_id)

    def collect(self) -> list[Asset]:
        """Collect BigQuery datasets, tables, and query jobs."""
        assets = []

        import sys

        # First, collect datasets and tables
        try:
            datasets = list(self.client.list_datasets())

            for dataset_ref in datasets:
                try:
                    dataset = self.client.get_dataset(dataset_ref.dataset_id)

                    # Get dataset metadata
                    dataset_id = dataset.dataset_id
                    created_at = dataset.created.isoformat() if dataset.created else None
                    location = dataset.location or "US"
                    labels = dataset.labels or {}

                    # List tables in dataset
                    tables = list(self.client.list_tables(dataset_id))

                    # Calculate total size
                    total_size = 0
                    for table_ref in tables:
                        try:
                            table = self.client.get_table(table_ref.table_id)
                            total_size += table.num_bytes or 0
                        except Exception:
                            continue

                    # Get query statistics
                    query_stats = self._get_query_stats(dataset_id)

                    # Build risk flags
                    risk_flags = []
                    if len(tables) == 0:
                        risk_flags.append("empty_dataset")
                    if total_size == 0:
                        risk_flags.append("no_data")

                    # Infer ownership
                    ownership = self._infer_ownership(labels, dataset_id)

                    # Estimate cost (BigQuery charges for storage and queries)
                    cost_estimate = self._estimate_cost(total_size, query_stats)

                    asset = Asset(
                        provider="gcp",
                        asset_type="bigquery_dataset",
                        normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                        service="BigQuery",
                        region=location,
                        arn=f"bigquery:{self.project_id}:{dataset_id}",
                        name=f"{self.project_id}.{dataset_id}",
                        created_at=created_at,
                        last_activity_at=query_stats.get("last_query_time"),
                        size_bytes=total_size,
                        tags=labels,
                        cost_estimate_usd=cost_estimate,
                        risk_flags=risk_flags,
                        ownership_confidence=ownership["confidence"],
                        suggested_owner=ownership["owner"],
                        usage_metrics={
                            "table_count": len(tables),
                            "total_queries": query_stats.get("total_queries", 0),
                            "last_used": query_stats.get("last_query_time"),
                            "days_since_last_use": self._calculate_days_since_last_use(
                                query_stats.get("last_query_time")
                            ),
                            "failed_queries": query_stats.get("failed_queries", 0),
                            "last_query_time": query_stats.get("last_query_time"),
                        },
                    )

                    assets.append(asset)

                except Exception as e:
                    print(f"Error processing dataset {dataset_ref.dataset_id}: {e}")
                    continue

        except Exception as e:
            import sys

            print(
                f"ERROR: Error listing BigQuery datasets: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

        # Also collect query jobs as a separate asset if there are queries but no datasets
        # This captures costs from querying public datasets
        try:
            query_jobs_asset = self._collect_query_jobs()
            if query_jobs_asset:
                assets.append(query_jobs_asset)
        except Exception as e:
            import sys

            print(
                f"ERROR: Error collecting BigQuery query jobs: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

        return assets

    def _collect_query_jobs(self) -> Asset | None:
        """Collect BigQuery query jobs as an asset (for tracking query costs)."""
        import sys

        try:
            # List recent query jobs (last 90 days)
            cutoff_date = datetime.utcnow() - timedelta(days=90)
            jobs = list(
                self.client.list_jobs(
                    max_results=1000,
                    all_users=True,
                    min_creation_time=cutoff_date,
                )
            )

            if len(jobs) == 0:
                return None

            # Calculate query statistics
            total_queries = len(jobs)
            failed_queries = sum(1 for job in jobs if job.errors)
            total_bytes_processed = sum(
                job.total_bytes_processed or 0 for job in jobs if job.total_bytes_processed
            )

            # Find most recent query
            last_query = None
            for job in jobs:
                if job.created:
                    if not last_query or job.created > last_query:
                        last_query = job.created

            # Calculate cost based on bytes processed
            # BigQuery pricing: $5 per TB processed (first 1TB free per month)
            # IMPORTANT: Free tier resets monthly, so we need to estimate per-month costs

            total_tb = total_bytes_processed / (1024**4)  # Convert to TB

            # Calculate monthly average
            daily_avg_tb = total_tb / 90  # Average TB per day over 90 days
            monthly_estimate_tb = daily_avg_tb * 30  # Estimate monthly from 90-day average

            # BigQuery free tier: First 1TB per month is free
            # Cost calculation: If total > 1TB over 90 days, calculate realistic monthly costs
            # Strategy: Assume usage is spread across 3 months, calculate billable amount per month

            query_cost = 0.0
            worst_case_monthly_tb = total_tb  # Worst case: all in one month

            if total_tb > 1.0:
                # Total exceeds 1TB over 90 days (~3 months)
                # Key insight: If total > 1TB, at least one month likely exceeded the 1TB free tier
                # BigQuery free tier: 1TB per month (resets monthly)
                # If we processed 1.76 TB over 90 days, usage is likely concentrated in some months

                excess_tb = total_tb - 1.0  # Total TB over the free tier

                # Realistic calculation: Assume usage varies month-to-month
                # If excess is 0.76 TB over 3 months, it's likely that:
                # - At least 1-2 months had usage > 1TB (exceeding free tier)
                # - Calculate cost assuming excess is distributed across months that exceeded

                # Strategy: Assume 1.5 months on average exceeded the free tier
                # This accounts for variable usage patterns
                estimated_billable = excess_tb / 1.5  # Average billable TB per month
                query_cost = estimated_billable * 5.0  # $5 per TB

                # Ensure minimum cost if total > 1TB (at least some usage exceeded free tier)
                if query_cost < 1.0:
                    query_cost = 1.0
            else:
                # Total is under 1TB, so likely all within free tier
                query_cost = 0.0

            # Also calculate absolute worst case: all usage in one month
            max_single_month_cost = max(0, (total_tb - 1.0)) * 5.0 if total_tb > 1.0 else 0.0

            # Only create asset if there are significant queries
            if total_queries < 5:
                return None

            return Asset(
                provider="gcp",
                asset_type="bigquery_queries",
                normalized_category=NormalizedCategory.QUERY_ENGINE,
                service="BigQuery",
                region="US",  # Queries can be from any location
                arn=f"bigquery:{self.project_id}:queries",
                name=f"{self.project_id} - Query Jobs",
                created_at=None,
                last_activity_at=last_query.isoformat() if last_query else None,
                size_bytes=total_bytes_processed,
                tags={},
                cost_estimate_usd=query_cost,
                risk_flags=[],
                ownership_confidence="unknown",
                suggested_owner=None,
                usage_metrics={
                    "total_queries_90d": total_queries,
                    "failed_queries_90d": failed_queries,
                    "total_bytes_processed_90d": total_bytes_processed,
                    "total_tb_processed_90d": round(total_tb, 2),
                    "estimated_monthly_tb": round(monthly_estimate_tb, 2),
                    "worst_case_monthly_tb": round(worst_case_monthly_tb, 2),
                    "estimated_monthly_cost": query_cost,
                    "max_single_month_cost": max_single_month_cost,
                    "last_used": last_query.isoformat() if last_query else None,
                    "days_since_last_use": self._calculate_days_since_last_use(
                        last_query.isoformat() if last_query else None
                    ),
                    "note": "Costs are estimates. Free tier is 1TB/month. If usage is concentrated, costs may be higher. For accurate costs, enable Cloud Billing API access.",
                },
            )

        except Exception as e:
            import sys

            print(
                f"WARNING: Could not collect BigQuery query jobs: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return None

    def _get_query_stats(self, dataset_id: str) -> dict[str, Any]:
        """Get query statistics for a dataset."""
        stats = {
            "total_queries": 0,
            "failed_queries": 0,
            "last_query_time": None,
        }

        try:
            # List recent queries for this dataset
            # Note: This requires bigquery.jobs.list permission
            query_jobs = self.client.list_jobs(
                max_results=100,
                all_users=True,
                min_creation_time=datetime.utcnow() - timedelta(days=90),
            )

            last_query = None
            for job in query_jobs:
                if job.job_type == "query":
                    # Check if query references this dataset
                    if dataset_id in (job.query or ""):
                        stats["total_queries"] += 1
                        if job.errors:
                            stats["failed_queries"] += 1

                        # Track most recent query
                        if job.created:
                            if not last_query or job.created > last_query:
                                last_query = job.created

            if last_query:
                stats["last_query_time"] = last_query.isoformat()

        except Exception as e:
            # If we can't get query stats, continue without them
            print(f"Could not get query stats for dataset {dataset_id}: {e}")

        return stats

    def _infer_ownership(self, labels: dict[str, str], dataset_id: str) -> dict[str, str]:
        """Infer ownership from labels or naming."""
        owner = None
        confidence = "unknown"

        # Check labels
        if "owner" in labels:
            owner = labels["owner"]
            confidence = "high"
        elif "team" in labels:
            owner = labels["team"]
            confidence = "medium"
        elif "project" in labels:
            owner = labels["project"]
            confidence = "medium"

        # Try to infer from dataset name
        if not owner:
            parts = dataset_id.split("_")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def _estimate_cost(self, size_bytes: int, query_stats: dict[str, Any]) -> float:
        """Estimate monthly cost for BigQuery dataset."""
        cost = 0.0

        # Storage cost: $0.020 per GB/month (first 10GB free)
        if size_bytes > 0:
            size_gb = size_bytes / (1024**3)
            storage_gb = max(0, size_gb - 10)  # First 10GB free
            cost += storage_gb * 0.020

        # Query cost: $5 per TB processed (first 1TB free per month)
        # We don't have exact query data, so we'll estimate based on query count
        # This is a rough estimate
        query_count = query_stats.get("total_queries", 0)
        if query_count > 0:
            # Assume average query processes 100MB (very rough estimate)
            estimated_tb = (query_count * 100 / 1024 / 1024) / 1000
            query_tb = max(0, estimated_tb - 1)  # First 1TB free
            cost += query_tb * 5.0

        return cost

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for BigQuery dataset."""
        return asset.usage_metrics or {}

    def _calculate_days_since_last_use(self, last_activity: str | None) -> int | None:
        """Calculate days since last use."""
        from datetime import datetime

        if not last_activity:
            return None

        try:
            last_used = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
            days = (datetime.utcnow() - last_used.replace(tzinfo=None)).days
            return days
        except Exception:
            return None

    def get_cost_estimate(self, asset: Asset) -> float:
        """Get cost estimate for BigQuery asset."""
        # For query jobs asset, cost is already calculated and stored in usage_metrics
        if asset.asset_type == "bigquery_queries":
            return asset.usage_metrics.get("estimated_monthly_cost", 0.0) if asset.usage_metrics else 0.0

        # For datasets, use the cost_estimate_usd that was set during collection
        return asset.cost_estimate_usd or 0.0
