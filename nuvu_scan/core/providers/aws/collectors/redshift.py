"""
Amazon Redshift collector.

Collects Redshift clusters, serverless namespaces, datashares, and external schemas.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class RedshiftCollector:
    """Collects Amazon Redshift resources."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []
        self._account_id: str | None = None

    def collect(self) -> list[Asset]:
        """Collect all Redshift resources."""
        import sys

        assets = []

        # Collect reserved nodes first to compare with clusters
        print("  → Checking reserved nodes...", file=sys.stderr)
        self._reserved_nodes = self._get_reserved_nodes()

        # Collect provisioned clusters
        print("  → Collecting Redshift clusters...", file=sys.stderr)
        cluster_assets = self._collect_clusters()
        assets.extend(cluster_assets)
        print(f"  → Found {len(cluster_assets)} clusters", file=sys.stderr)

        # Collect serverless namespaces and workgroups
        print("  → Collecting Redshift Serverless...", file=sys.stderr)
        serverless_assets = self._collect_serverless()
        assets.extend(serverless_assets)
        print(f"  → Found {len(serverless_assets)} serverless resources", file=sys.stderr)

        # Collect datashares (cross-account data sharing)
        print("  → Collecting Redshift datashares...", file=sys.stderr)
        datashare_assets = self._collect_datashares()
        assets.extend(datashare_assets)
        print(f"  → Found {len(datashare_assets)} datashares", file=sys.stderr)

        # Collect snapshots (cost saving opportunity)
        print("  → Collecting Redshift snapshots (may take a moment)...", file=sys.stderr)
        snapshot_assets = self._collect_snapshots()
        assets.extend(snapshot_assets)
        print(f"  → Found {len(snapshot_assets)} snapshots", file=sys.stderr)

        # Collect reserved node info as assets (for visibility)
        reserved_assets = self._collect_reserved_nodes_as_assets()
        assets.extend(reserved_assets)
        print(f"  → Found {len(reserved_assets)} reserved nodes", file=sys.stderr)

        return assets

    def _get_reserved_nodes(self) -> dict[str, list[dict]]:
        """Get reserved nodes per region for comparison with on-demand clusters."""
        reserved_by_region = {}

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift", region_name=region)
                response = redshift_client.describe_reserved_nodes()

                active_reservations = []
                for node in response.get("ReservedNodes", []):
                    if node.get("State") == "active":
                        active_reservations.append(
                            {
                                "node_type": node.get("NodeType"),
                                "node_count": node.get("NodeCount", 0),
                                "duration": node.get("Duration", 0),
                                "start_time": node.get("StartTime"),
                                "offering_type": node.get("OfferingType"),
                                "reserved_node_id": node.get("ReservedNodeId"),
                            }
                        )

                reserved_by_region[region] = active_reservations

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error getting reserved nodes in {region}: {e}")
                reserved_by_region[region] = []

        return reserved_by_region

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

    def _collect_clusters(self) -> list[Asset]:
        """Collect provisioned Redshift clusters with enhanced metrics."""
        assets = []

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift", region_name=region)

                # List clusters
                response = redshift_client.describe_clusters()

                for cluster in response.get("Clusters", []):
                    cluster_id = cluster["ClusterIdentifier"]

                    # Get cluster status and configuration
                    status = cluster.get("ClusterStatus", "unknown")
                    node_count = cluster.get("NumberOfNodes", 0)
                    node_type = cluster.get("NodeType", "")
                    db_name = cluster.get("DBName", "")

                    # Get encryption status
                    encrypted = cluster.get("Encrypted", False)

                    # Get VPC security info
                    publicly_accessible = cluster.get("PubliclyAccessible", False)
                    vpc_id = cluster.get("VpcId", "")

                    # Get tags
                    tags = {tag["Key"]: tag["Value"] for tag in cluster.get("Tags", [])}
                    ownership = self._infer_ownership(tags, cluster_id)

                    # Get last activity from CloudWatch metrics
                    last_activity = self._get_last_activity_cloudwatch(cluster_id, region)
                    days_since_last_use = self._calculate_days_since_last_use(last_activity)

                    # Check if cluster is covered by reserved nodes
                    reservation_status = self._check_reservation_coverage(
                        region, node_type, node_count
                    )

                    # Get WLM configuration
                    wlm_config = self._get_wlm_configuration(redshift_client, cluster_id)

                    # Calculate cluster age for reservation recommendation
                    create_time = cluster.get("ClusterCreateTime")
                    cluster_age_days = None
                    if create_time:
                        cluster_age_days = (
                            datetime.now(timezone.utc) - create_time.replace(tzinfo=timezone.utc)
                        ).days

                    # Build risk flags
                    risk_flags = []
                    if publicly_accessible:
                        risk_flags.append("publicly_accessible")
                    if not encrypted:
                        risk_flags.append("unencrypted")
                    if days_since_last_use is not None and days_since_last_use > 30:
                        risk_flags.append("low_activity")
                    if days_since_last_use is not None and days_since_last_use > 90:
                        risk_flags.append("potentially_unused")

                    # Reservation-related risks (cost optimization)
                    if (
                        not reservation_status["covered"]
                        and cluster_age_days
                        and cluster_age_days > 90
                    ):
                        risk_flags.append("no_reservation_long_running")

                    # WLM risks
                    if wlm_config.get("is_default_only"):
                        risk_flags.append("default_wlm_only")
                    if wlm_config.get("has_unlimited_queue"):
                        risk_flags.append("unlimited_wlm_queue")

                    # Get maintenance window info
                    maintenance_window = cluster.get("PreferredMaintenanceWindow", "")

                    # Estimate cost based on node type and count
                    monthly_cost = self._estimate_cluster_cost(node_type, node_count)

                    # Calculate potential savings from reservation
                    potential_reservation_savings = 0.0
                    if (
                        not reservation_status["covered"]
                        and cluster_age_days
                        and cluster_age_days > 30
                    ):
                        # Reserved nodes typically save 30-75% depending on term
                        potential_reservation_savings = (
                            monthly_cost * 0.40
                        )  # Conservative 40% estimate

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="redshift_cluster",
                            normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                            service="Redshift",
                            region=region,
                            arn=cluster.get(
                                "ClusterNamespaceArn",
                                f"arn:aws:redshift:{region}:{self._get_account_id()}:cluster:{cluster_id}",
                            ),
                            name=cluster_id,
                            created_at=(
                                cluster.get("ClusterCreateTime", "").isoformat()
                                if cluster.get("ClusterCreateTime")
                                else None
                            ),
                            tags=tags,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            last_activity_at=last_activity,
                            usage_metrics={
                                "status": status,
                                "node_count": node_count,
                                "node_type": node_type,
                                "database_name": db_name,
                                "encrypted": encrypted,
                                "publicly_accessible": publicly_accessible,
                                "vpc_id": vpc_id,
                                "maintenance_window": maintenance_window,
                                "cluster_version": cluster.get("ClusterVersion", ""),
                                "cluster_age_days": cluster_age_days,
                                "last_used": last_activity,
                                "days_since_last_use": days_since_last_use,
                                # Reservation info
                                "has_reservation": reservation_status["covered"],
                                "reserved_nodes_count": reservation_status.get("reserved_count", 0),
                                "on_demand_nodes_count": reservation_status.get(
                                    "on_demand_count", node_count
                                ),
                                "potential_reservation_savings_usd": potential_reservation_savings,
                                # WLM configuration
                                "wlm_queue_count": wlm_config.get("queue_count", 0),
                                "wlm_is_default_only": wlm_config.get("is_default_only", True),
                                "wlm_has_unlimited_queue": wlm_config.get(
                                    "has_unlimited_queue", False
                                ),
                                "wlm_auto_wlm": wlm_config.get("auto_wlm", False),
                            },
                            cost_estimate_usd=monthly_cost,
                        )
                    )

            except ClientError as e:
                print(f"Error collecting Redshift clusters in {region}: {e}")

        return assets

    def _collect_serverless(self) -> list[Asset]:
        """Collect Redshift Serverless namespaces and workgroups."""
        assets = []

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift-serverless", region_name=region)

                # List namespaces
                response = redshift_client.list_namespaces()

                for namespace in response.get("namespaces", []):
                    namespace_name = namespace.get("namespaceName", "")
                    namespace_id = namespace.get("namespaceId", "")

                    # Get workgroups for namespace
                    workgroups_response = redshift_client.list_workgroups()
                    associated_workgroups = [
                        wg
                        for wg in workgroups_response.get("workgroups", [])
                        if wg.get("namespaceName") == namespace_name
                    ]
                    workgroup_count = len(associated_workgroups)

                    # Check for encryption
                    kms_key = namespace.get("kmsKeyId")
                    encrypted = bool(kms_key)

                    risk_flags = []
                    if not encrypted:
                        risk_flags.append("unencrypted")

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="redshift_serverless_namespace",
                            normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                            service="Redshift Serverless",
                            region=region,
                            arn=namespace.get(
                                "namespaceArn",
                                f"arn:aws:redshift-serverless:{region}:{self._get_account_id()}:namespace/{namespace_id}",
                            ),
                            name=namespace_name,
                            created_at=(
                                namespace.get("creationDate", "").isoformat()
                                if namespace.get("creationDate")
                                else None
                            ),
                            risk_flags=risk_flags,
                            last_activity_at=None,
                            usage_metrics={
                                "namespace_id": namespace_id,
                                "workgroup_count": workgroup_count,
                                "status": namespace.get("status", "unknown"),
                                "db_name": namespace.get("dbName", ""),
                                "admin_username": namespace.get("adminUsername", ""),
                                "encrypted": encrypted,
                                "last_used": None,
                                "days_since_last_use": None,
                            },
                        )
                    )

                    # Collect individual workgroups
                    for wg in associated_workgroups:
                        wg_name = wg.get("workgroupName", "")
                        base_capacity = wg.get("baseCapacity", 0)

                        # Estimate cost: Serverless charges $0.36/RPU-hour
                        # Assume 10% utilization for base estimate
                        estimated_monthly_cost = base_capacity * 0.36 * 24 * 30 * 0.1

                        # Check public accessibility
                        publicly_accessible = wg.get("publiclyAccessible", False)

                        wg_risk_flags = []
                        if publicly_accessible:
                            wg_risk_flags.append("publicly_accessible")

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="redshift_serverless_workgroup",
                                normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                                service="Redshift Serverless",
                                region=region,
                                arn=wg.get(
                                    "workgroupArn",
                                    f"arn:aws:redshift-serverless:{region}:{self._get_account_id()}:workgroup/{wg_name}",
                                ),
                                name=wg_name,
                                created_at=(
                                    wg.get("creationDate", "").isoformat()
                                    if wg.get("creationDate")
                                    else None
                                ),
                                risk_flags=wg_risk_flags,
                                cost_estimate_usd=estimated_monthly_cost,
                                usage_metrics={
                                    "namespace_name": namespace_name,
                                    "base_capacity": base_capacity,
                                    "status": wg.get("status", "unknown"),
                                    "publicly_accessible": publicly_accessible,
                                    "enhanced_vpc_routing": wg.get("enhancedVpcRouting", False),
                                },
                            )
                        )

            except ClientError as e:
                print(f"Error collecting Redshift Serverless in {region}: {e}")

        return assets

    def _collect_datashares(self) -> list[Asset]:
        """Collect Redshift Datashares (cross-account data sharing)."""
        assets = []

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift", region_name=region)

                # Get all datashares
                try:
                    response = redshift_client.describe_data_shares()

                    for datashare in response.get("DataShares", []):
                        share_arn = datashare.get("DataShareArn", "")
                        share_name = share_arn.split("/")[-1] if "/" in share_arn else share_arn
                        producer_arn = datashare.get("ProducerArn", "")

                        # Get associations (consumers)
                        associations = datashare.get("DataShareAssociations", [])
                        consumer_accounts = []
                        cross_account = False
                        cross_region = False

                        for assoc in associations:
                            consumer_id = assoc.get("ConsumerIdentifier", "")
                            consumer_region = assoc.get("ConsumerRegion", "")
                            status = assoc.get("Status", "")

                            if consumer_id and consumer_id != self._get_account_id():
                                cross_account = True
                            if consumer_region and consumer_region != region:
                                cross_region = True

                            consumer_accounts.append(
                                {
                                    "account_id": consumer_id,
                                    "region": consumer_region,
                                    "status": status,
                                }
                            )

                        # Build risk flags
                        risk_flags = []
                        if cross_account:
                            risk_flags.append("cross_account_sharing")
                        if cross_region:
                            risk_flags.append("cross_region_sharing")
                        if datashare.get("AllowPubliclyAccessibleConsumers", False):
                            risk_flags.append("allows_public_consumers")

                        # Determine share type
                        share_type = (
                            "OUTBOUND"
                            if producer_arn.split(":")[4] == self._get_account_id()
                            else "INBOUND"
                        )

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="redshift_datashare",
                                normalized_category=NormalizedCategory.DATA_SHARING,
                                service="Redshift",
                                region=region,
                                arn=share_arn,
                                name=share_name,
                                risk_flags=risk_flags,
                                usage_metrics={
                                    "share_type": share_type,
                                    "producer_arn": producer_arn,
                                    "consumer_count": len(consumer_accounts),
                                    "consumers": consumer_accounts[:5],  # Limit to first 5 for size
                                    "cross_account": cross_account,
                                    "cross_region": cross_region,
                                    "allows_public_consumers": datashare.get(
                                        "AllowPubliclyAccessibleConsumers", False
                                    ),
                                },
                            )
                        )

                except ClientError as e:
                    if "AccessDenied" not in str(e):
                        print(f"Error collecting datashares in {region}: {e}")

            except ClientError as e:
                print(f"Error collecting Redshift datashares in {region}: {e}")

        return assets

    def _estimate_cluster_cost(self, node_type: str, node_count: int) -> float:
        """Estimate monthly cost for Redshift cluster."""
        # Redshift pricing (approximate, as of 2024-2025)
        pricing = {
            "dc2.large": 180.0,
            "dc2.8xlarge": 1440.0,
            "ra3.xlplus": 2347.0,
            "ra3.4xlarge": 4694.0,
            "ra3.16xlarge": 18776.0,
            "ds2.xlarge": 850.0,
            "ds2.8xlarge": 6800.0,
        }

        base_cost = pricing.get(node_type, 500.0)  # Default estimate
        return base_cost * node_count

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
        """Get usage metrics for Redshift asset."""
        return asset.usage_metrics or {}

    def _get_last_activity_cloudwatch(self, cluster_id: str, region: str) -> str | None:
        """Get last activity timestamp using CloudWatch metrics (more reliable than CloudTrail)."""
        try:
            cloudwatch = self.session.client("cloudwatch", region_name=region)

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=14)  # Look back 14 days

            # Check DatabaseConnections metric - indicates actual usage
            response = cloudwatch.get_metric_statistics(
                Namespace="AWS/Redshift",
                MetricName="DatabaseConnections",
                Dimensions=[
                    {"Name": "ClusterIdentifier", "Value": cluster_id},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # 1 hour granularity
                Statistics=["Maximum"],
            )

            datapoints = response.get("Datapoints", [])
            if datapoints:
                # Find the most recent datapoint with connections > 0
                active_points = [dp for dp in datapoints if dp.get("Maximum", 0) > 0]
                if active_points:
                    latest = max(active_points, key=lambda x: x["Timestamp"])
                    return latest["Timestamp"].isoformat()
                else:
                    # No connections in the last 14 days
                    return None

            # Fallback to CPUUtilization as activity indicator
            response = cloudwatch.get_metric_statistics(
                Namespace="AWS/Redshift",
                MetricName="CPUUtilization",
                Dimensions=[
                    {"Name": "ClusterIdentifier", "Value": cluster_id},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=["Average"],
            )

            datapoints = response.get("Datapoints", [])
            if datapoints:
                # Find most recent with CPU > 5% (indicates active queries)
                active_points = [dp for dp in datapoints if dp.get("Average", 0) > 5]
                if active_points:
                    latest = max(active_points, key=lambda x: x["Timestamp"])
                    return latest["Timestamp"].isoformat()

        except ClientError as e:
            if "AccessDenied" not in str(e):
                print(f"Error getting CloudWatch metrics for {cluster_id}: {e}")
        except Exception:
            pass

        return None

    def _get_last_activity(self, cluster_id: str, region: str) -> str | None:
        """Get last activity timestamp using CloudTrail (fallback method)."""
        try:
            cloudtrail_client = self.session.client("cloudtrail", region_name="us-east-1")

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=90)

            try:
                response = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": "ResourceName", "AttributeValue": cluster_id},
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=1,
                )

                events = response.get("Events", [])
                if events:
                    latest_event = max(events, key=lambda x: x.get("EventTime", datetime.min))
                    event_time = latest_event.get("EventTime")
                    if event_time:
                        return event_time.isoformat()
            except Exception:
                pass

        except Exception:
            pass

        return None

    def _calculate_days_since_last_use(self, last_activity: str | None) -> int | None:
        """Calculate days since last use."""
        if not last_activity:
            return None

        try:
            last_used = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days = (now - last_used).days
            return days
        except Exception:
            return None

    def get_cost_estimate(self, asset: Asset) -> float:
        """Get cost estimate for Redshift asset."""
        return asset.cost_estimate_usd or 0.0

    def _check_reservation_coverage(self, region: str, node_type: str, node_count: int) -> dict:
        """Check if cluster nodes are covered by reserved nodes."""
        reserved_nodes = self._reserved_nodes.get(region, [])

        # Find matching reservations by node type
        matching = [r for r in reserved_nodes if r.get("node_type") == node_type]
        total_reserved = sum(r.get("node_count", 0) for r in matching)

        if total_reserved >= node_count:
            return {
                "covered": True,
                "reserved_count": node_count,
                "on_demand_count": 0,
            }
        else:
            return {
                "covered": total_reserved > 0,
                "reserved_count": total_reserved,
                "on_demand_count": node_count - total_reserved,
            }

    def _get_wlm_configuration(self, redshift_client, cluster_id: str) -> dict:
        """Get WLM (Workload Management) configuration for a cluster."""
        try:
            # Get cluster parameter group
            clusters_resp = redshift_client.describe_clusters(ClusterIdentifier=cluster_id)
            clusters = clusters_resp.get("Clusters", [])

            if not clusters:
                return {
                    "queue_count": 0,
                    "is_default_only": True,
                    "has_unlimited_queue": False,
                    "auto_wlm": False,
                }

            cluster = clusters[0]
            param_groups = cluster.get("ClusterParameterGroups", [])

            if not param_groups:
                return {
                    "queue_count": 0,
                    "is_default_only": True,
                    "has_unlimited_queue": False,
                    "auto_wlm": False,
                }

            param_group_name = param_groups[0].get("ParameterGroupName", "")

            # Get WLM configuration from parameter group
            params_resp = redshift_client.describe_cluster_parameters(
                ParameterGroupName=param_group_name
            )

            wlm_config = {
                "queue_count": 0,
                "is_default_only": True,
                "has_unlimited_queue": False,
                "auto_wlm": False,
            }

            for param in params_resp.get("Parameters", []):
                param_name = param.get("ParameterName", "")
                param_value = param.get("ParameterValue", "")

                if param_name == "wlm_json_configuration" and param_value:
                    try:
                        import json

                        wlm_json = json.loads(param_value)

                        if isinstance(wlm_json, list):
                            wlm_config["queue_count"] = len(wlm_json)
                            wlm_config["is_default_only"] = len(wlm_json) <= 1

                            for queue in wlm_json:
                                if (
                                    queue.get("query_concurrency", 0) == 0
                                    or queue.get("memory_percent_to_use", 0) == 100
                                ):
                                    wlm_config["has_unlimited_queue"] = True
                                if queue.get("auto_wlm"):
                                    wlm_config["auto_wlm"] = True
                    except (json.JSONDecodeError, TypeError):
                        pass

            return wlm_config

        except ClientError as e:
            if "AccessDenied" not in str(e) and "ClusterNotFound" not in str(e):
                print(f"Error getting WLM config for {cluster_id}: {e}")
            return {
                "queue_count": 0,
                "is_default_only": True,
                "has_unlimited_queue": False,
                "auto_wlm": False,
            }

    def _collect_snapshots(self) -> list[Asset]:
        """Collect Redshift snapshots with cost and retention analysis."""
        assets = []

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift", region_name=region)

                # Get all snapshots (both manual and automated)
                for snapshot_type in ["manual", "automated"]:
                    try:
                        paginator = redshift_client.get_paginator("describe_cluster_snapshots")

                        for page in paginator.paginate(SnapshotType=snapshot_type):
                            for snapshot in page.get("Snapshots", []):
                                snapshot_id = snapshot.get("SnapshotIdentifier", "")
                                cluster_id = snapshot.get("ClusterIdentifier", "")

                                # Get snapshot details
                                create_time = snapshot.get("SnapshotCreateTime")
                                snapshot_size_gb = (
                                    snapshot.get("TotalBackupSizeInMegaBytes", 0) / 1024
                                )
                                status = snapshot.get("Status", "unknown")

                                # Calculate age
                                snapshot_age_days = None
                                if create_time:
                                    snapshot_age_days = (
                                        datetime.now(timezone.utc)
                                        - create_time.replace(tzinfo=timezone.utc)
                                    ).days

                                # Estimate storage cost (~$0.024/GB-month for Redshift snapshots)
                                # Note: Automated snapshots are FREE up to cluster storage size
                                # Only manual snapshots and storage beyond cluster size are billed
                                if snapshot_type == "automated":
                                    # Automated snapshots are mostly free - only count for awareness
                                    monthly_storage_cost = 0.0  # Free tier
                                else:
                                    monthly_storage_cost = snapshot_size_gb * 0.024

                                # Build risk flags
                                risk_flags = []

                                # Flag old manual snapshots (potential cost waste)
                                if snapshot_type == "manual":
                                    if snapshot_age_days and snapshot_age_days > 90:
                                        risk_flags.append("old_snapshot")
                                    if snapshot_age_days and snapshot_age_days > 365:
                                        risk_flags.append("very_old_snapshot")

                                # Large snapshots
                                if snapshot_size_gb > 1000:  # > 1TB
                                    risk_flags.append("large_snapshot")

                                # Check if source cluster still exists
                                is_orphan = (
                                    snapshot.get("ClusterCreateTime") is None
                                    and snapshot_type == "manual"
                                )
                                if is_orphan:
                                    risk_flags.append("orphan_snapshot")

                                # Get tags
                                tags = {
                                    tag["Key"]: tag["Value"] for tag in snapshot.get("Tags", [])
                                }

                                assets.append(
                                    Asset(
                                        provider="aws",
                                        asset_type="redshift_snapshot",
                                        normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                                        service="Redshift",
                                        region=region,
                                        arn=snapshot.get(
                                            "SnapshotArn",
                                            f"arn:aws:redshift:{region}:{self._get_account_id()}:snapshot:{cluster_id}/{snapshot_id}",
                                        ),
                                        name=snapshot_id,
                                        created_at=create_time.isoformat() if create_time else None,
                                        tags=tags,
                                        risk_flags=risk_flags,
                                        size_bytes=int(snapshot_size_gb * 1024 * 1024 * 1024),
                                        cost_estimate_usd=monthly_storage_cost,
                                        usage_metrics={
                                            "snapshot_type": snapshot_type,
                                            "cluster_identifier": cluster_id,
                                            "status": status,
                                            "size_gb": round(snapshot_size_gb, 2),
                                            "age_days": snapshot_age_days,
                                            "encrypted": snapshot.get("Encrypted", False),
                                            "is_orphan": is_orphan,
                                            "retention_period": snapshot.get(
                                                "ManualSnapshotRetentionPeriod", -1
                                            ),
                                        },
                                    )
                                )

                    except ClientError as e:
                        if "AccessDenied" not in str(e):
                            print(f"Error collecting {snapshot_type} snapshots in {region}: {e}")

            except ClientError as e:
                print(f"Error collecting Redshift snapshots in {region}: {e}")

        return assets

    def _collect_reserved_nodes_as_assets(self) -> list[Asset]:
        """Create assets for reserved nodes for visibility and tracking."""
        assets = []

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift", region_name=region)
                response = redshift_client.describe_reserved_nodes()

                for node in response.get("ReservedNodes", []):
                    node_id = node.get("ReservedNodeId", "")
                    node_type = node.get("NodeType", "")
                    node_count = node.get("NodeCount", 0)
                    state = node.get("State", "unknown")
                    offering_type = node.get("OfferingType", "")
                    duration = node.get("Duration", 0)  # seconds
                    start_time = node.get("StartTime")

                    # Calculate remaining time
                    remaining_days = None
                    is_expired = False
                    is_expiring_soon = False

                    if start_time and duration:
                        end_time = start_time + timedelta(seconds=duration)
                        remaining_days = (end_time - datetime.now(timezone.utc)).days

                        if remaining_days < 0:
                            is_expired = True
                            remaining_days = 0
                        elif remaining_days < 30:
                            is_expiring_soon = True

                    # Calculate annual cost
                    fixed_price = node.get("FixedPrice", 0)
                    recurring_charges = node.get("RecurringCharges", [])
                    monthly_recurring = sum(
                        c.get("RecurringChargeAmount", 0) for c in recurring_charges
                    )
                    annual_cost = fixed_price + (monthly_recurring * 12)

                    # Build risk flags
                    risk_flags = []
                    if is_expired:
                        risk_flags.append("reservation_expired")
                    if is_expiring_soon:
                        risk_flags.append("reservation_expiring_soon")
                    if state != "active":
                        risk_flags.append(f"reservation_{state}")

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="redshift_reserved_node",
                            normalized_category=NormalizedCategory.BILLING,
                            service="Redshift",
                            region=region,
                            arn=f"arn:aws:redshift:{region}:{self._get_account_id()}:reserved-node:{node_id}",
                            name=f"{node_type} x{node_count} ({offering_type})",
                            created_at=start_time.isoformat() if start_time else None,
                            risk_flags=risk_flags,
                            cost_estimate_usd=annual_cost / 12,  # Monthly equivalent
                            usage_metrics={
                                "reserved_node_id": node_id,
                                "node_type": node_type,
                                "node_count": node_count,
                                "state": state,
                                "offering_type": offering_type,
                                "duration_years": duration / (365 * 24 * 3600) if duration else 0,
                                "remaining_days": remaining_days,
                                "is_expiring_soon": is_expiring_soon,
                                "fixed_price": fixed_price,
                                "monthly_recurring": monthly_recurring,
                                "annual_cost": annual_cost,
                            },
                        )
                    )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting reserved nodes in {region}: {e}")

        return assets
