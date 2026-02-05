"""
AWS Backup collector.

Collects backup vaults, plans, and protected resources for resilience governance.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class BackupCollector:
    """Collects AWS Backup resources."""

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
        """Collect all AWS Backup resources."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for AWS Backup resources...", file=sys.stderr)

        # Collect backup vaults
        print("  → Collecting backup vaults...", file=sys.stderr)
        vault_assets = self._collect_vaults(regions)
        assets.extend(vault_assets)
        print(f"  → Found {len(vault_assets)} backup vaults", file=sys.stderr)

        # Collect backup plans
        print("  → Collecting backup plans...", file=sys.stderr)
        plan_assets = self._collect_plans(regions)
        assets.extend(plan_assets)
        print(f"  → Found {len(plan_assets)} backup plans", file=sys.stderr)

        return assets

    def _collect_vaults(self, regions: list[str]) -> list[Asset]:
        """Collect backup vaults."""
        assets = []

        for region in regions:
            try:
                backup = self.session.client("backup", region_name=region)
                paginator = backup.get_paginator("list_backup_vaults")

                for page in paginator.paginate():
                    for vault in page.get("BackupVaultList", []):
                        vault_name = vault["BackupVaultName"]
                        vault_arn = vault.get("BackupVaultArn", "")

                        # Get vault details
                        creation_date = vault.get("CreationDate")
                        recovery_points = vault.get("NumberOfRecoveryPoints", 0)
                        encrypted = vault.get("EncryptionKeyArn") is not None

                        # Get tags
                        tags = {}
                        try:
                            tags_response = backup.list_tags(ResourceArn=vault_arn)
                            tags = tags_response.get("Tags", {})
                        except ClientError:
                            pass

                        ownership = self._infer_ownership(tags, vault_name)

                        # Check lock configuration
                        locked = vault.get("Locked", False)

                        # Build risk flags
                        risk_flags = []
                        if not encrypted:
                            risk_flags.append("unencrypted")
                        if recovery_points == 0:
                            risk_flags.append("empty_vault")
                        if not locked and "prod" in vault_name.lower():
                            risk_flags.append("production_vault_unlocked")

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="backup_vault",
                                normalized_category=NormalizedCategory.OBJECT_STORAGE,
                                service="AWS Backup",
                                region=region,
                                arn=vault_arn,
                                name=vault_name,
                                created_at=creation_date.isoformat() if creation_date else None,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "vault_name": vault_name,
                                    "recovery_points": recovery_points,
                                    "encrypted": encrypted,
                                    "encryption_key_arn": vault.get("EncryptionKeyArn", ""),
                                    "locked": locked,
                                    "min_retention_days": vault.get("MinRetentionDays"),
                                    "max_retention_days": vault.get("MaxRetentionDays"),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting backup vaults in {region}: {e}")

        return assets

    def _collect_plans(self, regions: list[str]) -> list[Asset]:
        """Collect backup plans."""
        assets = []

        for region in regions:
            try:
                backup = self.session.client("backup", region_name=region)
                paginator = backup.get_paginator("list_backup_plans")

                for page in paginator.paginate():
                    for plan_entry in page.get("BackupPlansList", []):
                        plan_id = plan_entry["BackupPlanId"]
                        plan_name = plan_entry.get("BackupPlanName", plan_id)
                        plan_arn = plan_entry.get("BackupPlanArn", "")
                        creation_date = plan_entry.get("CreationDate")
                        last_execution = plan_entry.get("LastExecutionDate")

                        # Get full plan details
                        try:
                            plan_detail = backup.get_backup_plan(BackupPlanId=plan_id)
                            plan = plan_detail.get("BackupPlan", {})
                            rules = plan.get("Rules", [])
                        except ClientError:
                            rules = []

                        # Get selections (what resources are backed up)
                        selections = []
                        try:
                            selections_response = backup.list_backup_selections(
                                BackupPlanId=plan_id
                            )
                            selections = selections_response.get("BackupSelectionsList", [])
                        except ClientError:
                            pass

                        # Get tags
                        tags = {}
                        try:
                            tags_response = backup.list_tags(ResourceArn=plan_arn)
                            tags = tags_response.get("Tags", {})
                        except ClientError:
                            pass

                        ownership = self._infer_ownership(tags, plan_name)

                        # Analyze backup rules
                        has_lifecycle = False
                        has_cross_region = False
                        for rule in rules:
                            if rule.get("Lifecycle"):
                                has_lifecycle = True
                            if rule.get("CopyActions"):
                                has_cross_region = True

                        # Build risk flags
                        risk_flags = []
                        if len(selections) == 0:
                            risk_flags.append("no_resources_selected")
                        if not has_lifecycle:
                            risk_flags.append("no_lifecycle_policy")
                        if not has_cross_region and "prod" in plan_name.lower():
                            risk_flags.append("no_cross_region_copy")

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="backup_plan",
                                normalized_category=NormalizedCategory.OBJECT_STORAGE,
                                service="AWS Backup",
                                region=region,
                                arn=plan_arn,
                                name=plan_name,
                                created_at=creation_date.isoformat() if creation_date else None,
                                last_activity_at=last_execution.isoformat()
                                if last_execution
                                else None,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "plan_id": plan_id,
                                    "plan_name": plan_name,
                                    "rule_count": len(rules),
                                    "selection_count": len(selections),
                                    "has_lifecycle": has_lifecycle,
                                    "has_cross_region_copy": has_cross_region,
                                    "version_id": plan_entry.get("VersionId", ""),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting backup plans in {region}: {e}")

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
        """Get usage metrics for backup resource."""
        return asset.usage_metrics or {}
