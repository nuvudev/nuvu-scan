"""
AWS ElastiCache Collector - Redis and Memcached clusters.

Collects ElastiCache clusters, replication groups, and reserved cache nodes.
"""

import logging
from datetime import datetime, timezone

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class ElastiCacheCollector:
    """Collector for ElastiCache clusters (Redis and Memcached)."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect ElastiCache clusters and replication groups."""
        assets = []

        for region in self.regions:
            try:
                elasticache = self.session.client("elasticache", region_name=region)

                # Collect Redis replication groups
                assets.extend(self._collect_replication_groups(elasticache, region))

                # Collect standalone cache clusters (Memcached or standalone Redis)
                assets.extend(self._collect_cache_clusters(elasticache, region))

                # Collect reserved cache nodes
                assets.extend(self._collect_reserved_nodes(elasticache, region))

            except Exception as e:
                logger.warning(f"Error collecting ElastiCache in {region}: {e}")

        return assets

    def _collect_replication_groups(self, elasticache, region: str) -> list[Asset]:
        """Collect Redis replication groups."""
        assets = []

        try:
            paginator = elasticache.get_paginator("describe_replication_groups")
            for page in paginator.paginate():
                for rg in page.get("ReplicationGroups", []):
                    rg_id = rg["ReplicationGroupId"]
                    status = rg.get("Status", "unknown")

                    # Get member clusters
                    member_clusters = rg.get("MemberClusters", [])
                    node_groups = rg.get("NodeGroups", [])

                    # Count nodes
                    total_nodes = sum(len(ng.get("NodeGroupMembers", [])) for ng in node_groups)

                    # Get node type from first node group
                    node_type = None
                    for ng in node_groups:
                        for member in ng.get("NodeGroupMembers", []):
                            node_type = member.get("CacheNodeType")
                            break
                        if node_type:
                            break

                    # Estimate cost based on node type (rough estimates)
                    cost_per_node = self._estimate_node_cost(node_type or "cache.t3.micro")
                    estimated_cost = cost_per_node * max(total_nodes, 1)

                    risk_flags = []
                    if status != "available":
                        risk_flags.append("not_available")
                    if not rg.get("AutomaticFailover") or rg.get("AutomaticFailover") == "disabled":
                        risk_flags.append("no_automatic_failover")
                    if not rg.get("AtRestEncryptionEnabled"):
                        risk_flags.append("no_encryption_at_rest")
                    if not rg.get("TransitEncryptionEnabled"):
                        risk_flags.append("no_encryption_in_transit")
                    if total_nodes == 1:
                        risk_flags.append("single_node")

                    # Get ARN and tags
                    arn = rg.get(
                        "ARN",
                        f"arn:aws:elasticache:{region}:{self.account_id}:replicationgroup:{rg_id}",
                    )

                    tags = {}
                    try:
                        tag_response = elasticache.list_tags_for_resource(ResourceName=arn)
                        for tag in tag_response.get("TagList", []):
                            tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="elasticache_replication_group",
                            normalized_category=NormalizedCategory.CACHING,
                            service="ElastiCache",
                            region=region,
                            arn=arn,
                            name=rg_id,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "replication_group_id": rg_id,
                                "status": status,
                                "engine": "redis",
                                "engine_version": rg.get("CacheNodeType"),
                                "node_type": node_type,
                                "total_nodes": total_nodes,
                                "num_node_groups": len(node_groups),
                                "member_clusters": member_clusters,
                                "automatic_failover": rg.get("AutomaticFailover"),
                                "multi_az": rg.get("MultiAZ"),
                                "cluster_mode_enabled": rg.get("ClusterEnabled", False),
                                "at_rest_encryption": rg.get("AtRestEncryptionEnabled", False),
                                "transit_encryption": rg.get("TransitEncryptionEnabled", False),
                                "snapshot_retention_days": rg.get("SnapshotRetentionLimit", 0),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting replication groups: {e}")

        return assets

    def _collect_cache_clusters(self, elasticache, region: str) -> list[Asset]:
        """Collect standalone cache clusters (Memcached or standalone Redis not in replication groups)."""
        assets = []

        try:
            # Get list of clusters that are part of replication groups
            rg_clusters = set()
            try:
                rg_paginator = elasticache.get_paginator("describe_replication_groups")
                for rg_page in rg_paginator.paginate():
                    for rg in rg_page.get("ReplicationGroups", []):
                        rg_clusters.update(rg.get("MemberClusters", []))
            except Exception:
                pass

            paginator = elasticache.get_paginator("describe_cache_clusters")
            for page in paginator.paginate(ShowCacheNodeInfo=True):
                for cluster in page.get("CacheClusters", []):
                    cluster_id = cluster["CacheClusterId"]

                    # Skip clusters that are part of replication groups (already collected)
                    if cluster_id in rg_clusters:
                        continue

                    status = cluster.get("CacheClusterStatus", "unknown")
                    engine = cluster.get("Engine", "unknown")
                    node_type = cluster.get("CacheNodeType", "cache.t3.micro")
                    num_nodes = cluster.get("NumCacheNodes", 1)

                    # Estimate cost
                    cost_per_node = self._estimate_node_cost(node_type)
                    estimated_cost = cost_per_node * num_nodes

                    risk_flags = []
                    if status != "available":
                        risk_flags.append("not_available")
                    if num_nodes == 1:
                        risk_flags.append("single_node")
                    if engine == "memcached":
                        risk_flags.append("memcached")  # Consider migrating to Redis

                    arn = cluster.get(
                        "ARN",
                        f"arn:aws:elasticache:{region}:{self.account_id}:cluster:{cluster_id}",
                    )

                    tags = {}
                    try:
                        tag_response = elasticache.list_tags_for_resource(ResourceName=arn)
                        for tag in tag_response.get("TagList", []):
                            tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="elasticache_cluster",
                            normalized_category=NormalizedCategory.CACHING,
                            service="ElastiCache",
                            region=region,
                            arn=arn,
                            name=cluster_id,
                            created_at=cluster.get("CacheClusterCreateTime", "").isoformat()
                            if cluster.get("CacheClusterCreateTime")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "cluster_id": cluster_id,
                                "status": status,
                                "engine": engine,
                                "engine_version": cluster.get("EngineVersion"),
                                "node_type": node_type,
                                "num_nodes": num_nodes,
                                "preferred_az": cluster.get("PreferredAvailabilityZone"),
                                "snapshot_retention_days": cluster.get("SnapshotRetentionLimit", 0),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting cache clusters: {e}")

        return assets

    def _collect_reserved_nodes(self, elasticache, region: str) -> list[Asset]:
        """Collect reserved cache nodes."""
        assets = []

        try:
            paginator = elasticache.get_paginator("describe_reserved_cache_nodes")
            for page in paginator.paginate():
                for reserved in page.get("ReservedCacheNodes", []):
                    reserved_id = reserved["ReservedCacheNodeId"]
                    state = reserved.get("State", "unknown")
                    node_type = reserved.get("CacheNodeType", "unknown")
                    node_count = reserved.get("CacheNodeCount", 1)

                    risk_flags = []
                    if state == "retired":
                        risk_flags.append("reservation_retired")

                    # Check if expiring soon
                    start_time = reserved.get("StartTime")
                    duration = reserved.get("Duration", 0)  # in seconds
                    if start_time and duration:
                        end_time = start_time.timestamp() + duration
                        days_remaining = (end_time - datetime.now(timezone.utc).timestamp()) / 86400
                        if days_remaining < 30:
                            risk_flags.append("expiring_soon")

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="elasticache_reserved_node",
                            normalized_category=NormalizedCategory.CACHING,
                            service="ElastiCache",
                            region=region,
                            arn=f"arn:aws:elasticache:{region}:{self.account_id}:reserved-instance:{reserved_id}",
                            name=reserved_id,
                            created_at=reserved.get("StartTime", "").isoformat()
                            if reserved.get("StartTime")
                            else None,
                            tags={},
                            cost_estimate_usd=0,  # Already paid for
                            usage_metrics={
                                "reserved_id": reserved_id,
                                "state": state,
                                "node_type": node_type,
                                "node_count": node_count,
                                "product_description": reserved.get("ProductDescription"),
                                "offering_type": reserved.get("OfferingType"),
                                "duration_seconds": duration,
                                "fixed_price": reserved.get("FixedPrice"),
                                "usage_price": reserved.get("UsagePrice"),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="unknown",
                            suggested_owner=None,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting reserved cache nodes: {e}")

        return assets

    def _estimate_node_cost(self, node_type: str) -> float:
        """Estimate monthly cost for a cache node type."""
        # Rough estimates for us-west-2 (Redis)
        node_costs = {
            "cache.t3.micro": 12.0,
            "cache.t3.small": 24.0,
            "cache.t3.medium": 48.0,
            "cache.t4g.micro": 11.0,
            "cache.t4g.small": 22.0,
            "cache.t4g.medium": 44.0,
            "cache.m5.large": 120.0,
            "cache.m5.xlarge": 240.0,
            "cache.m5.2xlarge": 480.0,
            "cache.m6g.large": 110.0,
            "cache.m6g.xlarge": 220.0,
            "cache.r5.large": 150.0,
            "cache.r5.xlarge": 300.0,
            "cache.r6g.large": 140.0,
            "cache.r6g.xlarge": 280.0,
        }
        return node_costs.get(node_type, 50.0)  # Default to $50/month
