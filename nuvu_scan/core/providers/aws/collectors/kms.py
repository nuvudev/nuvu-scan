"""
KMS collector for AWS.

Collects KMS keys, their configurations, and encryption governance status.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class KMSCollector:
    """Collects AWS KMS keys and their configurations."""

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
        """Collect all KMS keys."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for KMS keys...", file=sys.stderr)

        for region in regions:
            try:
                kms = self.session.client("kms", region_name=region)
                paginator = kms.get_paginator("list_keys")

                for page in paginator.paginate():
                    for key_entry in page.get("Keys", []):
                        key_id = key_entry["KeyId"]

                        try:
                            # Get key details
                            key_info = kms.describe_key(KeyId=key_id)
                            metadata = key_info.get("KeyMetadata", {})

                            # Skip AWS managed keys for governance (they're managed by AWS)
                            key_manager = metadata.get("KeyManager", "")
                            if key_manager == "AWS":
                                continue

                            key_arn = metadata.get("Arn", "")
                            key_state = metadata.get("KeyState", "unknown")
                            description = metadata.get("Description", "")
                            creation_date = metadata.get("CreationDate")
                            key_usage = metadata.get("KeyUsage", "")
                            key_spec = metadata.get("KeySpec", "")

                            # Get rotation status
                            rotation_enabled = False
                            try:
                                rotation_info = kms.get_key_rotation_status(KeyId=key_id)
                                rotation_enabled = rotation_info.get("KeyRotationEnabled", False)
                            except ClientError:
                                pass

                            # Get aliases
                            aliases = []
                            try:
                                alias_response = kms.list_aliases(KeyId=key_id)
                                aliases = [
                                    a["AliasName"] for a in alias_response.get("Aliases", [])
                                ]
                            except ClientError:
                                pass

                            # Get tags
                            tags = {}
                            try:
                                tags_response = kms.list_resource_tags(KeyId=key_id)
                                tags = {
                                    t["TagKey"]: t["TagValue"]
                                    for t in tags_response.get("Tags", [])
                                }
                            except ClientError:
                                pass

                            ownership = self._infer_ownership(
                                tags, aliases[0] if aliases else key_id
                            )

                            # Build risk flags
                            risk_flags = []
                            if not rotation_enabled and key_usage == "ENCRYPT_DECRYPT":
                                risk_flags.append("rotation_disabled")
                            if key_state == "PendingDeletion":
                                risk_flags.append("pending_deletion")
                            if key_state == "Disabled":
                                risk_flags.append("key_disabled")
                            if not description and not aliases:
                                risk_flags.append("undocumented_key")

                            # Calculate age
                            age_days = None
                            if creation_date:
                                age_days = (
                                    datetime.now(timezone.utc)
                                    - creation_date.replace(tzinfo=timezone.utc)
                                ).days

                            assets.append(
                                Asset(
                                    provider="aws",
                                    asset_type="kms_key",
                                    normalized_category=NormalizedCategory.SECURITY,
                                    service="KMS",
                                    region=region,
                                    arn=key_arn,
                                    name=aliases[0] if aliases else key_id,
                                    created_at=creation_date.isoformat() if creation_date else None,
                                    tags=tags,
                                    risk_flags=risk_flags,
                                    ownership_confidence=ownership["confidence"],
                                    suggested_owner=ownership["owner"],
                                    usage_metrics={
                                        "key_id": key_id,
                                        "key_state": key_state,
                                        "key_usage": key_usage,
                                        "key_spec": key_spec,
                                        "key_manager": key_manager,
                                        "description": description,
                                        "rotation_enabled": rotation_enabled,
                                        "aliases": aliases,
                                        "age_days": age_days,
                                        "multi_region": metadata.get("MultiRegion", False),
                                    },
                                )
                            )

                        except ClientError as e:
                            if "AccessDenied" not in str(e):
                                continue

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting KMS keys in {region}: {e}")

        print(f"  → Found {len(assets)} customer-managed KMS keys", file=sys.stderr)
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
        """Get usage metrics for KMS key."""
        return asset.usage_metrics or {}
