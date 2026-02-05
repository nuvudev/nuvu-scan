"""
AWS ECS Collector - ECS Clusters, Services, and Tasks.

Collects Elastic Container Service resources.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class ECSCollector:
    """Collector for ECS clusters and services."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect ECS clusters and services."""
        assets = []

        for region in self.regions:
            try:
                ecs = self.session.client("ecs", region_name=region)
                assets.extend(self._collect_clusters(ecs, region))
            except Exception as e:
                logger.warning(f"Error collecting ECS in {region}: {e}")

        return assets

    def _collect_clusters(self, ecs, region: str) -> list[Asset]:
        """Collect ECS clusters and their services."""
        assets = []

        try:
            # List all clusters
            cluster_arns = []
            paginator = ecs.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_arns.extend(page.get("clusterArns", []))

            if not cluster_arns:
                return assets

            # Describe clusters
            # describe_clusters can only handle 100 at a time
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i : i + 100]
                response = ecs.describe_clusters(
                    clusters=batch, include=["ATTACHMENTS", "SETTINGS", "STATISTICS", "TAGS"]
                )

                for cluster in response.get("clusters", []):
                    cluster_arn = cluster["clusterArn"]
                    cluster_name = cluster["clusterName"]
                    status = cluster.get("status", "unknown")

                    # Get tags
                    tags = {t["key"]: t["value"] for t in cluster.get("tags", [])}

                    # Get statistics
                    running_tasks = cluster.get("runningTasksCount", 0)
                    pending_tasks = cluster.get("pendingTasksCount", 0)
                    active_services = cluster.get("activeServicesCount", 0)
                    registered_instances = cluster.get("registeredContainerInstancesCount", 0)

                    # Check capacity providers
                    capacity_providers = cluster.get("capacityProviders", [])
                    has_fargate = (
                        "FARGATE" in capacity_providers or "FARGATE_SPOT" in capacity_providers
                    )

                    # ECS itself is free, cost comes from underlying compute (EC2 or Fargate)
                    estimated_cost = 0  # Compute costs tracked separately

                    risk_flags = []
                    if status != "ACTIVE":
                        risk_flags.append("not_active")
                    if running_tasks == 0 and active_services > 0:
                        risk_flags.append("no_running_tasks")
                    if registered_instances == 0 and not has_fargate:
                        risk_flags.append("no_capacity")

                    # Check container insights
                    settings = cluster.get("settings", [])
                    has_insights = any(
                        s.get("name") == "containerInsights" and s.get("value") == "enabled"
                        for s in settings
                    )
                    if not has_insights:
                        risk_flags.append("no_container_insights")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="ecs_cluster",
                            normalized_category=NormalizedCategory.CONTAINER,
                            service="ECS",
                            region=region,
                            arn=cluster_arn,
                            name=cluster_name,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "cluster_name": cluster_name,
                                "status": status,
                                "running_tasks": running_tasks,
                                "pending_tasks": pending_tasks,
                                "active_services": active_services,
                                "registered_instances": registered_instances,
                                "capacity_providers": capacity_providers,
                                "has_fargate": has_fargate,
                                "container_insights": has_insights,
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

                    # Collect services for this cluster
                    assets.extend(self._collect_services(ecs, region, cluster_arn, cluster_name))

        except Exception as e:
            logger.warning(f"Error collecting clusters: {e}")

        return assets

    def _collect_services(
        self, ecs, region: str, cluster_arn: str, cluster_name: str
    ) -> list[Asset]:
        """Collect ECS services for a cluster."""
        assets = []

        try:
            # List services
            service_arns = []
            paginator = ecs.get_paginator("list_services")
            for page in paginator.paginate(cluster=cluster_arn):
                service_arns.extend(page.get("serviceArns", []))

            if not service_arns:
                return assets

            # Describe services (max 10 at a time)
            for i in range(0, len(service_arns), 10):
                batch = service_arns[i : i + 10]
                response = ecs.describe_services(
                    cluster=cluster_arn, services=batch, include=["TAGS"]
                )

                for service in response.get("services", []):
                    service_arn = service["serviceArn"]
                    service_name = service["serviceName"]
                    status = service.get("status", "unknown")

                    tags = {t["key"]: t["value"] for t in service.get("tags", [])}

                    # Task counts
                    desired = service.get("desiredCount", 0)
                    running = service.get("runningCount", 0)
                    pending = service.get("pendingCount", 0)

                    # Launch type
                    launch_type = service.get("launchType", "EC2")
                    capacity_providers = service.get("capacityProviderStrategy", [])

                    # Estimate Fargate cost if applicable
                    estimated_cost = 0
                    if launch_type == "FARGATE" or any(
                        cp.get("capacityProvider", "").startswith("FARGATE")
                        for cp in capacity_providers
                    ):
                        # Rough estimate: ~$30/month per 0.5vCPU/1GB task
                        estimated_cost = running * 30.0

                    risk_flags = []
                    if status != "ACTIVE":
                        risk_flags.append("not_active")
                    if running < desired:
                        risk_flags.append("under_capacity")
                    if desired == 0:
                        risk_flags.append("scaled_to_zero")

                    # Check deployment status
                    deployments = service.get("deployments", [])
                    if len(deployments) > 1:
                        risk_flags.append("deployment_in_progress")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="ecs_service",
                            normalized_category=NormalizedCategory.CONTAINER,
                            service="ECS",
                            region=region,
                            arn=service_arn,
                            name=f"{cluster_name}/{service_name}",
                            created_at=service.get("createdAt", "").isoformat()
                            if service.get("createdAt")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "service_name": service_name,
                                "cluster_name": cluster_name,
                                "status": status,
                                "desired_count": desired,
                                "running_count": running,
                                "pending_count": pending,
                                "launch_type": launch_type,
                                "scheduling_strategy": service.get("schedulingStrategy"),
                                "deployment_count": len(deployments),
                                "load_balancers": len(service.get("loadBalancers", [])),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting services for cluster {cluster_name}: {e}")

        return assets
