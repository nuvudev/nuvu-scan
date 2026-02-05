"""
Secrets Manager collector for AWS.

Collects secrets and their configurations for secrets governance.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class SecretsManagerCollector:
    """Collects AWS Secrets Manager secrets."""

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
        """Collect all Secrets Manager secrets."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(
            f"  → Scanning {len(regions)} regions for Secrets Manager secrets...", file=sys.stderr
        )

        for region in regions:
            try:
                secrets = self.session.client("secretsmanager", region_name=region)
                paginator = secrets.get_paginator("list_secrets")

                for page in paginator.paginate():
                    for secret in page.get("SecretList", []):
                        secret_name = secret["Name"]
                        secret_arn = secret.get("ARN", "")

                        # Get detailed info
                        rotation_enabled = secret.get("RotationEnabled", False)
                        rotation_days = secret.get("RotationRules", {}).get(
                            "AutomaticallyAfterDays"
                        )
                        last_rotated = secret.get("LastRotatedDate")
                        last_accessed = secret.get("LastAccessedDate")
                        last_changed = secret.get("LastChangedDate")
                        created_date = secret.get("CreatedDate")

                        # Get tags
                        tags = {t["Key"]: t["Value"] for t in secret.get("Tags", [])}
                        ownership = self._infer_ownership(tags, secret_name)

                        # Calculate ages
                        now = datetime.now(timezone.utc)
                        days_since_rotation = None
                        days_since_access = None

                        if last_rotated:
                            days_since_rotation = (
                                now - last_rotated.replace(tzinfo=timezone.utc)
                            ).days
                        elif created_date:
                            days_since_rotation = (
                                now - created_date.replace(tzinfo=timezone.utc)
                            ).days

                        if last_accessed:
                            days_since_access = (
                                now - last_accessed.replace(tzinfo=timezone.utc)
                            ).days

                        # Build risk flags
                        risk_flags = []
                        if not rotation_enabled:
                            risk_flags.append("rotation_disabled")
                        if days_since_rotation and days_since_rotation > 90:
                            risk_flags.append("not_rotated_90_days")
                        if days_since_rotation and days_since_rotation > 365:
                            risk_flags.append("not_rotated_year")
                        if days_since_access and days_since_access > 90:
                            risk_flags.append("unused_90_days")
                        if secret.get("DeletedDate"):
                            risk_flags.append("pending_deletion")

                        # Check for primary region (if replicated)
                        primary_region = secret.get("PrimaryRegion")
                        is_replica = primary_region and primary_region != region

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="secret",
                                normalized_category=NormalizedCategory.SECURITY,
                                service="Secrets Manager",
                                region=region,
                                arn=secret_arn,
                                name=secret_name,
                                created_at=created_date.isoformat() if created_date else None,
                                last_activity_at=last_accessed.isoformat()
                                if last_accessed
                                else None,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "secret_name": secret_name,
                                    "description": secret.get("Description", ""),
                                    "rotation_enabled": rotation_enabled,
                                    "rotation_interval_days": rotation_days,
                                    "days_since_rotation": days_since_rotation,
                                    "days_since_access": days_since_access,
                                    "last_rotated": last_rotated.isoformat()
                                    if last_rotated
                                    else None,
                                    "last_accessed": last_accessed.isoformat()
                                    if last_accessed
                                    else None,
                                    "last_changed": last_changed.isoformat()
                                    if last_changed
                                    else None,
                                    "kms_key_id": secret.get("KmsKeyId", ""),
                                    "is_replica": is_replica,
                                    "primary_region": primary_region,
                                    "owning_service": secret.get("OwningService", ""),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting secrets in {region}: {e}")

        print(f"  → Found {len(assets)} secrets", file=sys.stderr)
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

        return {"owner": owner, "confidence": confidence}

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for secret."""
        return asset.usage_metrics or {}
