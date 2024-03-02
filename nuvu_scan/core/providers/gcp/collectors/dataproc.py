"""
Dataproc collector.

Collects Dataproc clusters and job history.
"""

from datetime import datetime
from typing import Any

from google.cloud import dataproc_v1

from nuvu_scan.core.base import Asset, NormalizedCategory


class DataprocCollector:
    """Collects Dataproc clusters and jobs."""

    def __init__(self, credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.cluster_client = dataproc_v1.ClusterControllerClient(credentials=credentials)
        self.job_client = dataproc_v1.JobControllerClient(credentials=credentials)

    def collect(self) -> list[Asset]:
        """Collect Dataproc clusters."""
        assets = []

        try:
            # List clusters in all regions
            # Dataproc clusters are regional, so we need to check common regions
            regions = ["us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1"]

            for region in regions:
                try:
                    parent = f"projects/{self.project_id}/regions/{region}"
                    clusters = self.cluster_client.list_clusters(request={"parent": parent})

                    for cluster in clusters:
                        try:
                            cluster_name = cluster.cluster_name
                            created_at = (
                                cluster.status.state_start_time.isoformat()
                                if cluster.status.state_start_time
                                else None
                            )

                            # Get job history
                            job_stats = self._get_job_stats(cluster_name, region)

                            # Build risk flags
                            risk_flags = []
                            if cluster.status.state.name == "ERROR":
                                risk_flags.append("error_state")
                            if job_stats.get("idle_days", 0) > 30:
                                risk_flags.append("idle_cluster")

                            # Infer ownership from labels
                            labels = cluster.labels or {}
                            ownership = self._infer_ownership(labels, cluster_name)

                            # Estimate cost
                            cost_estimate = self._estimate_cost(cluster)

                            asset = Asset(
                                provider="gcp",
                                asset_type="dataproc_cluster",
                                normalized_category=NormalizedCategory.COMPUTE,
                                service="Dataproc",
                                region=region,
                                arn=f"dataproc:{self.project_id}:{region}:{cluster_name}",
                                name=cluster_name,
                                created_at=created_at,
                                last_activity_at=job_stats.get("last_job_time"),
                                tags=labels,
                                cost_estimate_usd=cost_estimate,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "status": cluster.status.state.name,
                                    "total_jobs": job_stats.get("total_jobs", 0),
                                    "failed_jobs": job_stats.get("failed_jobs", 0),
                                    "idle_days": job_stats.get("idle_days", 0),
                                    "last_used": job_stats.get("last_job_time"),
                                    "days_since_last_use": job_stats.get("idle_days", 0),
                                },
                            )

                            assets.append(asset)

                        except Exception as e:
                            print(f"Error processing cluster {cluster.cluster_name}: {e}")
                            continue

                except Exception:
                    # Region might not have Dataproc API enabled, continue
                    continue

        except Exception as e:
            print(f"Error listing Dataproc clusters: {e}")

        return assets

    def _get_job_stats(self, cluster_name: str, region: str) -> dict[str, Any]:
        """Get job statistics for a cluster."""
        stats = {
            "total_jobs": 0,
            "failed_jobs": 0,
            "last_job_time": None,
            "idle_days": 0,
        }

        try:
            parent = f"projects/{self.project_id}/regions/{region}"
            jobs = self.job_client.list_jobs(
                request={
                    "parent": parent,
                    "cluster_name": cluster_name,
                    "page_size": 100,
                }
            )

            last_job = None
            for job in jobs:
                stats["total_jobs"] += 1
                if job.status.state.name == "ERROR":
                    stats["failed_jobs"] += 1

                # Track most recent job
                if job.status.state_start_time:
                    if not last_job or job.status.state_start_time > last_job:
                        last_job = job.status.state_start_time

            if last_job:
                stats["last_job_time"] = last_job.isoformat()
                # Calculate idle days
                if isinstance(last_job, datetime):
                    idle_delta = datetime.utcnow() - last_job.replace(tzinfo=None)
                    stats["idle_days"] = idle_delta.days
                else:
                    # Handle protobuf timestamp
                    from google.protobuf.timestamp_pb2 import Timestamp

                    if isinstance(last_job, Timestamp):
                        dt = datetime.fromtimestamp(last_job.seconds)
                        idle_delta = datetime.utcnow() - dt
                        stats["idle_days"] = idle_delta.days

        except Exception as e:
            print(f"Could not get job stats for cluster {cluster_name}: {e}")

        return stats

    def _infer_ownership(self, labels: dict[str, str], cluster_name: str) -> dict[str, str]:
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

        # Try to infer from cluster name
        if not owner:
            parts = cluster_name.split("-")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def _estimate_cost(self, cluster) -> float:
        """Estimate monthly cost for Dataproc cluster."""
        # Dataproc charges for underlying Compute Engine instances
        # This is a simplified estimation
        cost = 0.0

        try:
            # Get instance counts
            master_count = 1  # Default master
            worker_count = 0

            if cluster.config.master_config:
                master_count = cluster.config.master_config.num_instances or 1

            if cluster.config.worker_config:
                worker_count = cluster.config.worker_config.num_instances or 0

            # Rough estimate: $0.10 per hour per instance (varies by machine type)
            # Monthly: 730 hours
            hourly_cost_per_instance = 0.10
            monthly_hours = 730

            total_instances = master_count + worker_count
            cost = total_instances * hourly_cost_per_instance * monthly_hours

        except Exception:
            # If we can't determine instance count, return 0
            pass

        return cost

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for Dataproc cluster."""
        return asset.usage_metrics or {}
