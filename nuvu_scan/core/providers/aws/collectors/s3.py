"""
S3 bucket collector.

Collects S3 buckets, their metadata, usage, and cost estimates.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class S3Collector:
    """Collects S3 buckets and their metadata."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []
        self.s3_client = session.client("s3")
        self.s3_resource = session.resource("s3")

    def collect(self) -> list[Asset]:
        """Collect all S3 buckets."""
        import sys

        assets = []

        try:
            # List all buckets
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            if not buckets:
                print("No S3 buckets found", file=sys.stderr)
                return assets

            print(f"Found {len(buckets)} S3 buckets, processing...", file=sys.stderr)

            for i, bucket_info in enumerate(buckets, 1):
                bucket_name = bucket_info["Name"]
                created_at = bucket_info["CreationDate"].isoformat()
                print(
                    f"  [{i}/{len(buckets)}] Processing bucket: {bucket_name}...",
                    file=sys.stderr,
                    end="\r",
                )

                try:
                    # Get bucket location
                    location_response = self.s3_client.get_bucket_location(Bucket=bucket_name)
                    region = location_response.get("LocationConstraint") or "us-east-1"

                    # Skip if region filtering is enabled and bucket not in regions
                    if self.regions and region not in self.regions:
                        continue

                    # Get bucket details
                    bucket = self.s3_resource.Bucket(bucket_name)

                    # Get bucket tagging
                    tags = self._get_bucket_tags(bucket_name)

                    # Get public access status
                    public_access = self._check_public_access(bucket_name)

                    # Get storage class distribution
                    storage_info = self._get_storage_info(bucket)

                    # Calculate size
                    size_bytes = storage_info.get("total_size", 0)

                    # Build risk flags
                    risk_flags = []
                    if public_access:
                        risk_flags.append("public_access")
                    if self._has_pii_naming(bucket_name):
                        risk_flags.append("potential_pii")
                    if size_bytes == 0:
                        risk_flags.append("empty_bucket")

                    # Infer ownership
                    ownership = self._infer_ownership(tags, bucket_name)

                    asset = Asset(
                        provider="aws",
                        asset_type="s3_bucket",
                        normalized_category=NormalizedCategory.OBJECT_STORAGE,
                        service="S3",
                        region=region,
                        arn=f"arn:aws:s3:::{bucket_name}",
                        name=bucket_name,
                        created_at=created_at,
                        last_activity_at=self._get_last_activity(bucket_name),
                        size_bytes=size_bytes,
                        tags=tags,
                        risk_flags=risk_flags,
                        ownership_confidence=ownership["confidence"],
                        suggested_owner=ownership["owner"],
                        usage_metrics={
                            "storage_class_distribution": storage_info.get("storage_classes", {}),
                            "object_count": storage_info.get("object_count", 0),
                            "public_access": public_access,
                        },
                    )

                    assets.append(asset)
                    print(
                        f"  [{i}/{len(buckets)}] Processed: {bucket_name} ({len(assets)} assets)",
                        file=sys.stderr,
                    )

                except ClientError as e:
                    # Skip buckets we can't access
                    print(
                        f"  [{i}/{len(buckets)}] Error accessing bucket {bucket_name}: {e}",
                        file=sys.stderr,
                    )
                    continue

        except ClientError as e:
            print(f"Error listing S3 buckets: {e}", file=sys.stderr)

        print(f"\nCompleted S3 collection: {len(assets)} buckets", file=sys.stderr)
        return assets

    def _get_bucket_tags(self, bucket_name: str) -> dict[str, str]:
        """Get tags for a bucket."""
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            return {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}
        except ClientError:
            return {}

    def _check_public_access(self, bucket_name: str) -> bool:
        """Check if bucket has public access."""
        try:
            response = self.s3_client.get_bucket_policy_status(Bucket=bucket_name)
            return response.get("PolicyStatus", {}).get("IsPublic", False)
        except ClientError:
            # Check public access block
            try:
                response = self.s3_client.get_public_access_block(Bucket=bucket_name)
                pab = response.get("PublicAccessBlockConfiguration", {})
                # If any block is False, bucket might be public
                return not (
                    pab.get("BlockPublicAcls", False)
                    and pab.get("IgnorePublicAcls", False)
                    and pab.get("BlockPublicPolicy", False)
                    and pab.get("RestrictPublicBuckets", False)
                )
            except ClientError:
                return False

    def _get_storage_info(self, bucket) -> dict[str, Any]:
        """Get storage information for a bucket."""
        total_size = 0
        object_count = 0
        storage_classes = {}
        max_objects_to_check = 10000  # Limit to prevent hanging on huge buckets

        try:
            # Use paginator for large buckets
            paginator = self.s3_client.get_paginator("list_objects_v2")

            for page in paginator.paginate(Bucket=bucket.name, MaxKeys=1000):
                for obj in page.get("Contents", []):
                    size = obj.get("Size", 0)
                    storage_class = obj.get("StorageClass", "STANDARD")

                    total_size += size
                    object_count += 1
                    storage_classes[storage_class] = storage_classes.get(storage_class, 0) + size

                    # Limit object counting to prevent hanging on huge buckets
                    if object_count >= max_objects_to_check:
                        # Estimate total size based on sampled objects
                        # This is approximate but prevents hanging
                        break

                if object_count >= max_objects_to_check:
                    break
        except ClientError:
            pass

        return {
            "total_size": total_size,
            "object_count": object_count,
            "storage_classes": storage_classes,
        }

    def _get_last_activity(self, bucket_name: str) -> str | None:
        """Get last activity timestamp for a bucket from CloudTrail or CloudWatch."""
        from datetime import datetime, timedelta

        try:
            # Try CloudTrail to find last API call to this bucket
            # Use shorter time window and timeout to prevent hanging
            cloudtrail_client = self.session.client("cloudtrail", region_name="us-east-1")

            # Look for S3 API calls in the last 30 days (reduced from 90 to speed up)
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=30)

            try:
                # Use a timeout or limit the lookup to prevent hanging
                response = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": "ResourceName", "AttributeValue": bucket_name},
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=1,  # Just need the most recent
                )

                events = response.get("Events", [])
                if events:
                    # Get the most recent event
                    latest_event = max(events, key=lambda x: x.get("EventTime", datetime.min))
                    event_time = latest_event.get("EventTime")
                    if event_time:
                        return event_time.isoformat()

            except Exception:
                # CloudTrail might not be available or no events found
                # Skip CloudWatch fallback to speed things up
                pass

        except Exception:
            pass

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

    def _has_pii_naming(self, bucket_name: str) -> bool:
        """Check if bucket name suggests PII data."""
        pii_keywords = [
            "pii",
            "personal",
            "customer",
            "user",
            "ssn",
            "credit",
            "card",
            "password",
            "secret",
            "private",
            "confidential",
        ]
        bucket_lower = bucket_name.lower()
        return any(keyword in bucket_lower for keyword in pii_keywords)

    def _infer_ownership(self, tags: dict[str, str], bucket_name: str) -> dict[str, str]:
        """Infer ownership from tags or naming."""
        owner = None
        confidence = "unknown"

        # Check tags
        if "owner" in tags:
            owner = tags["owner"]
            confidence = "high"
        elif "team" in tags:
            owner = tags["team"]
            confidence = "medium"
        elif "created-by" in tags:
            owner = tags["created-by"]
            confidence = "medium"

        return {"owner": owner, "confidence": confidence}

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get detailed usage metrics for an S3 bucket."""
        metrics = asset.usage_metrics.copy() if asset.usage_metrics else {}

        # Try to get CloudWatch metrics for last access
        try:
            self.session.client("cloudwatch")
            # S3 doesn't have direct last access metrics, but we can check request metrics
            # This is a simplified version
            pass
        except Exception:
            pass

        return metrics

    def get_cost_estimate(self, asset: Asset) -> float:
        """Estimate monthly cost for S3 bucket."""
        # S3 pricing (approximate, as of 2024)
        # Standard: $0.023 per GB/month
        # Standard-IA: $0.0125 per GB/month
        # Glacier: $0.004 per GB/month
        # Glacier Deep Archive: $0.00099 per GB/month
        # Plus: PUT/GET requests, data transfer, etc.

        # Get storage class distribution
        storage_classes = asset.usage_metrics.get("storage_class_distribution", {})

        if not storage_classes and asset.size_bytes:
            # Default to Standard if unknown but has data
            storage_classes = {"STANDARD": asset.size_bytes}

        total_cost = 0.0
        pricing = {
            "STANDARD": 0.023,
            "STANDARD_IA": 0.0125,
            "GLACIER": 0.004,
            "DEEP_ARCHIVE": 0.00099,
            "INTELLIGENT_TIERING": 0.023,  # Base tier
        }

        # Calculate storage cost
        for storage_class, size_bytes in storage_classes.items():
            if size_bytes > 0:
                size_gb = size_bytes / (1024**3)
                price_per_gb = pricing.get(storage_class, 0.023)
                total_cost += size_gb * price_per_gb

        # Add request costs (PUT/GET requests)
        # S3 charges $0.005 per 1,000 PUT requests and $0.0004 per 1,000 GET requests
        # We don't have request counts, so we estimate based on object count
        object_count = asset.usage_metrics.get("object_count", 0)
        if object_count > 0:
            # Rough estimate: assume some GET requests per object per month
            # This is a conservative estimate
            estimated_get_requests = object_count * 10  # Assume 10 GETs per object per month
            get_cost = (estimated_get_requests / 1000) * 0.0004
            total_cost += get_cost

        return total_cost
