"""
RDS collector for AWS.

Collects RDS instances, Aurora clusters, snapshots, and their configurations
for database governance.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class RDSCollector:
    """Collects AWS RDS instances and Aurora clusters."""

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
        """Collect all RDS resources."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for RDS resources...", file=sys.stderr)

        # Collect RDS instances
        print("  → Collecting RDS instances...", file=sys.stderr)
        instance_assets = self._collect_instances(regions)
        assets.extend(instance_assets)
        print(f"  → Found {len(instance_assets)} RDS instances", file=sys.stderr)

        # Collect Aurora clusters
        print("  → Collecting Aurora clusters...", file=sys.stderr)
        cluster_assets = self._collect_clusters(regions)
        assets.extend(cluster_assets)
        print(f"  → Found {len(cluster_assets)} Aurora clusters", file=sys.stderr)

        # Collect snapshots
        print("  → Collecting RDS snapshots...", file=sys.stderr)
        snapshot_assets = self._collect_snapshots(regions)
        assets.extend(snapshot_assets)
        print(f"  → Found {len(snapshot_assets)} RDS snapshots", file=sys.stderr)

        return assets

    def _collect_instances(self, regions: list[str]) -> list[Asset]:
        """Collect RDS instances."""
        assets = []

        for region in regions:
            try:
                rds = self.session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")

                for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        db_id = db["DBInstanceIdentifier"]
                        db_arn = db.get("DBInstanceArn", "")
                        engine = db.get("Engine", "")
                        engine_version = db.get("EngineVersion", "")
                        instance_class = db.get("DBInstanceClass", "")
                        status = db.get("DBInstanceStatus", "")

                        # Skip Aurora instances (covered by cluster)
                        if db.get("DBClusterIdentifier"):
                            continue

                        # Get tags
                        tags = {}
                        try:
                            tags_response = rds.list_tags_for_resource(ResourceName=db_arn)
                            tags = {t["Key"]: t["Value"] for t in tags_response.get("TagList", [])}
                        except ClientError:
                            pass

                        ownership = self._infer_ownership(tags, db_id)

                        # Security checks
                        encrypted = db.get("StorageEncrypted", False)
                        publicly_accessible = db.get("PubliclyAccessible", False)
                        multi_az = db.get("MultiAZ", False)
                        auto_minor_upgrade = db.get("AutoMinorVersionUpgrade", False)

                        # Get backup retention
                        backup_retention = db.get("BackupRetentionPeriod", 0)

                        # Build risk flags
                        risk_flags = []
                        if not encrypted:
                            risk_flags.append("unencrypted")
                        if publicly_accessible:
                            risk_flags.append("publicly_accessible")
                        if not multi_az:
                            risk_flags.append("single_az")
                        if backup_retention == 0:
                            risk_flags.append("no_backups")
                        if not auto_minor_upgrade:
                            risk_flags.append("auto_upgrade_disabled")

                        # Estimate cost
                        monthly_cost = self._estimate_instance_cost(instance_class, engine)

                        # Determine last activity
                        # LatestRestorableTime indicates when the last automated backup was taken
                        # For available instances, use this or consider them currently active
                        last_activity_at = None
                        latest_restorable = db.get("LatestRestorableTime")
                        if status == "available":
                            if latest_restorable:
                                last_activity_at = latest_restorable.isoformat()
                            else:
                                # Instance is running, consider it active now
                                last_activity_at = datetime.now(timezone.utc).isoformat()
                        elif status == "stopped":
                            # Use the latest restorable time as the last known activity
                            if latest_restorable:
                                last_activity_at = latest_restorable.isoformat()

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="rds_instance",
                                normalized_category=NormalizedCategory.DATABASE,
                                service="RDS",
                                region=region,
                                arn=db_arn,
                                name=db_id,
                                created_at=db.get("InstanceCreateTime").isoformat()
                                if db.get("InstanceCreateTime")
                                else None,
                                last_activity_at=last_activity_at,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                cost_estimate_usd=monthly_cost,
                                usage_metrics={
                                    "db_instance_id": db_id,
                                    "engine": engine,
                                    "engine_version": engine_version,
                                    "instance_class": instance_class,
                                    "status": status,
                                    "storage_type": db.get("StorageType", ""),
                                    "allocated_storage_gb": db.get("AllocatedStorage", 0),
                                    "encrypted": encrypted,
                                    "publicly_accessible": publicly_accessible,
                                    "multi_az": multi_az,
                                    "backup_retention_days": backup_retention,
                                    "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId", ""),
                                    "endpoint": db.get("Endpoint", {}).get("Address", ""),
                                    "port": db.get("Endpoint", {}).get("Port"),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting RDS instances in {region}: {e}")

        return assets

    def _collect_clusters(self, regions: list[str]) -> list[Asset]:
        """Collect Aurora clusters."""
        assets = []

        for region in regions:
            try:
                rds = self.session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_clusters")

                for page in paginator.paginate():
                    for cluster in page.get("DBClusters", []):
                        cluster_id = cluster["DBClusterIdentifier"]
                        cluster_arn = cluster.get("DBClusterArn", "")
                        engine = cluster.get("Engine", "")
                        engine_version = cluster.get("EngineVersion", "")
                        status = cluster.get("Status", "")

                        # Get tags
                        tags = {}
                        try:
                            tags_response = rds.list_tags_for_resource(ResourceName=cluster_arn)
                            tags = {t["Key"]: t["Value"] for t in tags_response.get("TagList", [])}
                        except ClientError:
                            pass

                        ownership = self._infer_ownership(tags, cluster_id)

                        # Security checks
                        encrypted = cluster.get("StorageEncrypted", False)
                        deletion_protection = cluster.get("DeletionProtection", False)
                        multi_az = len(cluster.get("AvailabilityZones", [])) > 1

                        # Get backup retention
                        backup_retention = cluster.get("BackupRetentionPeriod", 0)

                        # Build risk flags
                        risk_flags = []
                        if not encrypted:
                            risk_flags.append("unencrypted")
                        if not deletion_protection:
                            risk_flags.append("deletion_protection_disabled")
                        if backup_retention == 0:
                            risk_flags.append("no_backups")

                        # Count members
                        member_count = len(cluster.get("DBClusterMembers", []))

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="aurora_cluster",
                                normalized_category=NormalizedCategory.DATABASE,
                                service="Aurora",
                                region=region,
                                arn=cluster_arn,
                                name=cluster_id,
                                created_at=cluster.get("ClusterCreateTime").isoformat()
                                if cluster.get("ClusterCreateTime")
                                else None,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "cluster_id": cluster_id,
                                    "engine": engine,
                                    "engine_version": engine_version,
                                    "engine_mode": cluster.get("EngineMode", ""),
                                    "status": status,
                                    "member_count": member_count,
                                    "encrypted": encrypted,
                                    "deletion_protection": deletion_protection,
                                    "multi_az": multi_az,
                                    "backup_retention_days": backup_retention,
                                    "endpoint": cluster.get("Endpoint", ""),
                                    "reader_endpoint": cluster.get("ReaderEndpoint", ""),
                                    "port": cluster.get("Port"),
                                    "capacity": cluster.get("Capacity"),
                                    "serverless_v2_scaling": cluster.get(
                                        "ServerlessV2ScalingConfiguration"
                                    ),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting Aurora clusters in {region}: {e}")

        return assets

    def _collect_snapshots(self, regions: list[str]) -> list[Asset]:
        """Collect RDS snapshots."""
        assets = []

        for region in regions:
            try:
                rds = self.session.client("rds", region_name=region)

                # Only manual snapshots (automated are managed by RDS)
                paginator = rds.get_paginator("describe_db_snapshots")

                for page in paginator.paginate(SnapshotType="manual"):
                    for snapshot in page.get("DBSnapshots", []):
                        snapshot_id = snapshot["DBSnapshotIdentifier"]
                        snapshot_arn = snapshot.get("DBSnapshotArn", "")
                        db_id = snapshot.get("DBInstanceIdentifier", "")
                        status = snapshot.get("Status", "")
                        create_time = snapshot.get("SnapshotCreateTime")

                        # Calculate age
                        age_days = None
                        if create_time:
                            age_days = (
                                datetime.now(timezone.utc)
                                - create_time.replace(tzinfo=timezone.utc)
                            ).days

                        # Get size
                        size_gb = snapshot.get("AllocatedStorage", 0)

                        # Build risk flags
                        risk_flags = []
                        if age_days and age_days > 90:
                            risk_flags.append("old_snapshot")
                        if age_days and age_days > 365:
                            risk_flags.append("very_old_snapshot")
                        if not snapshot.get("Encrypted", False):
                            risk_flags.append("unencrypted")

                        # Estimate cost (~$0.02/GB-month for snapshots)
                        monthly_cost = size_gb * 0.02

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="rds_snapshot",
                                normalized_category=NormalizedCategory.DATABASE,
                                service="RDS",
                                region=region,
                                arn=snapshot_arn,
                                name=snapshot_id,
                                created_at=create_time.isoformat() if create_time else None,
                                risk_flags=risk_flags,
                                size_bytes=size_gb * 1024 * 1024 * 1024,
                                cost_estimate_usd=monthly_cost,
                                usage_metrics={
                                    "snapshot_id": snapshot_id,
                                    "db_instance_id": db_id,
                                    "engine": snapshot.get("Engine", ""),
                                    "engine_version": snapshot.get("EngineVersion", ""),
                                    "status": status,
                                    "size_gb": size_gb,
                                    "age_days": age_days,
                                    "encrypted": snapshot.get("Encrypted", False),
                                    "snapshot_type": "manual",
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting RDS snapshots in {region}: {e}")

        return assets

    def _estimate_instance_cost(self, instance_class: str, engine: str) -> float:
        """Estimate monthly cost for RDS instance."""
        # Simplified pricing (varies by region and engine)
        base_pricing = {
            "db.t3.micro": 12.0,
            "db.t3.small": 25.0,
            "db.t3.medium": 50.0,
            "db.t3.large": 100.0,
            "db.r5.large": 150.0,
            "db.r5.xlarge": 300.0,
            "db.r5.2xlarge": 600.0,
            "db.m5.large": 120.0,
            "db.m5.xlarge": 240.0,
        }

        base_cost = base_pricing.get(instance_class, 100.0)

        # Engine multipliers
        engine_multiplier = {
            "mysql": 1.0,
            "postgres": 1.0,
            "mariadb": 1.0,
            "oracle-se2": 2.0,
            "sqlserver-se": 1.8,
        }

        multiplier = 1.0
        for eng, mult in engine_multiplier.items():
            if eng in engine.lower():
                multiplier = mult
                break

        return base_cost * multiplier

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
        """Get usage metrics for RDS asset."""
        return asset.usage_metrics or {}
