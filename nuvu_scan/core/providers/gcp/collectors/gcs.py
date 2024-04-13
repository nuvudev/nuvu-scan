"""
GCS (Cloud Storage) bucket collector.

Collects GCS buckets, their metadata, usage, and cost estimates.
"""

from typing import Any

from google.cloud import storage

from nuvu_scan.core.base import Asset, NormalizedCategory


class GCSCollector:
    """Collects GCS buckets and their metadata."""

    def __init__(self, credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.client = storage.Client(credentials=credentials, project=project_id)

    def collect(self) -> list[Asset]:
        """Collect all GCS buckets."""
        import sys

        assets = []

        try:
            # List all buckets
            buckets = list(self.client.list_buckets())

            for bucket in buckets:
                try:
                    # Get bucket metadata
                    bucket_name = bucket.name
                    created_at = bucket.time_created.isoformat() if bucket.time_created else None
                    location = bucket.location or "us-central1"
                    storage_class = bucket.storage_class or "STANDARD"

                    # Get bucket IAM policy to check public access
                    public_access = self._check_public_access(bucket)

                    # Get bucket labels (tags)
                    labels = bucket.labels or {}

                    # Get storage info
                    storage_info = self._get_storage_info(bucket)

                    # Build risk flags
                    risk_flags = []
                    if public_access:
                        risk_flags.append("public_access")
                    if self._has_pii_naming(bucket_name):
                        risk_flags.append("potential_pii")
                    if storage_info.get("object_count", 0) == 0:
                        risk_flags.append("empty_bucket")

                    # Infer ownership
                    ownership = self._infer_ownership(labels, bucket_name)

                    # Estimate cost (GCS pricing varies by storage class and location)
                    cost_estimate = self._estimate_cost(
                        storage_info.get("total_size", 0), storage_class
                    )

                    asset = Asset(
                        provider="gcp",
                        asset_type="gcs_bucket",
                        normalized_category=NormalizedCategory.OBJECT_STORAGE,
                        service="GCS",
                        region=location,
                        arn=f"gs://{bucket_name}",
                        name=bucket_name,
                        created_at=created_at,
                        last_activity_at=self._get_last_activity(bucket),
                        size_bytes=storage_info.get("total_size", 0),
                        tags=labels,
                        cost_estimate_usd=cost_estimate,
                        risk_flags=risk_flags,
                        ownership_confidence=ownership["confidence"],
                        suggested_owner=ownership["owner"],
                        usage_metrics={
                            "storage_class": storage_class,
                            "object_count": storage_info.get("object_count", 0),
                            "public_access": public_access,
                            "location": location,
                            "last_used": self._get_last_activity(bucket),
                            "days_since_last_use": self._calculate_days_since_last_use(
                                self._get_last_activity(bucket)
                            ),
                        },
                    )

                    assets.append(asset)

                except Exception as e:
                    # Skip buckets we can't access
                    print(f"Error accessing bucket {bucket.name}: {e}")
                    continue

        except Exception as e:
            import sys
            import traceback

            print(f"ERROR: Error listing GCS buckets: {type(e).__name__}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

        return assets

    def _check_public_access(self, bucket) -> bool:
        """Check if bucket has public access."""
        try:
            # Check IAM policy for allUsers or allAuthenticatedUsers
            policy = bucket.get_iam_policy()
            for binding in policy.bindings:
                if binding["role"] in [
                    "roles/storage.objectViewer",
                    "roles/storage.legacyBucketReader",
                ]:
                    if "allUsers" in binding.get(
                        "members", []
                    ) or "allAuthenticatedUsers" in binding.get("members", []):
                        return True
        except Exception:
            # If we can't check IAM, assume not public
            pass
        return False

    def _get_last_activity(self, bucket) -> str | None:
        """Get last activity timestamp for a GCS bucket."""

        try:
            # Try to get last object update time
            # This is approximate - GCS doesn't provide direct last access time
            # We can check the most recent object modification time
            try:
                # Get the most recent object
                blobs = list(bucket.list_blobs(max_results=1, order_by="timeCreated", reverse=True))
                if blobs:
                    # Use the most recent object's update time as proxy for last activity
                    most_recent = blobs[0]
                    if most_recent.updated:
                        return most_recent.updated.isoformat()
            except Exception:
                pass

            # Alternative: Check Cloud Logging for bucket access (requires logging API)
            # For now, return None if we can't determine
            return None

        except Exception:
            return None

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

    def _get_storage_info(self, bucket) -> dict[str, Any]:
        """Get storage information for a bucket."""
        total_size = 0
        object_count = 0

        try:
            # List objects in bucket (this can be slow for large buckets)
            # For now, we'll do a quick sample
            blobs = bucket.list_blobs(max_results=1000)
            for blob in blobs:
                total_size += blob.size or 0
                object_count += 1
        except Exception:
            # If we can't list objects, return empty
            pass

        return {"total_size": total_size, "object_count": object_count}

    def _has_pii_naming(self, bucket_name: str) -> bool:
        """Check if bucket name suggests PII data."""
        bucket_lower = bucket_name.lower()
        pii_keywords = ["pii", "personal", "private", "sensitive", "ssn", "credit", "card"]
        return any(keyword in bucket_lower for keyword in pii_keywords)

    def _infer_ownership(self, labels: dict[str, str], bucket_name: str) -> dict[str, str]:
        """Infer ownership from labels or naming."""
        owner = None
        confidence = "unknown"

        # Check labels for owner
        if "owner" in labels:
            owner = labels["owner"]
            confidence = "high"
        elif "team" in labels:
            owner = labels["team"]
            confidence = "medium"
        elif "project" in labels:
            owner = labels["project"]
            confidence = "medium"

        # Try to infer from bucket name
        if not owner:
            # Common patterns: team-name-bucket, project-name-data
            parts = bucket_name.split("-")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def _estimate_cost(self, size_bytes: int, storage_class: str) -> float:
        """Estimate monthly cost for GCS bucket."""
        if size_bytes == 0:
            return 0.0

        size_gb = size_bytes / (1024**3)

        # GCS pricing (approximate, as of 2024)
        # Standard: $0.020 per GB/month
        # Nearline: $0.010 per GB/month
        # Coldline: $0.004 per GB/month
        # Archive: $0.0012 per GB/month

        pricing = {
            "STANDARD": 0.020,
            "NEARLINE": 0.010,
            "COLDLINE": 0.004,
            "ARCHIVE": 0.0012,
            "MULTI_REGIONAL": 0.026,  # Multi-regional standard
            "REGIONAL": 0.020,  # Regional standard
        }

        price_per_gb = pricing.get(storage_class.upper(), 0.020)
        return size_gb * price_per_gb

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get detailed usage metrics for a GCS bucket."""
        metrics = asset.usage_metrics.copy() if asset.usage_metrics else {}

        # Additional metrics could be added here using Cloud Monitoring API
        # For now, return existing metrics

        return metrics
