"""
AWS Route 53 Collector - Hosted Zones, Health Checks, Query Logging.

Collects DNS resources and their configurations.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class Route53Collector:
    """Collector for Route 53 DNS resources."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id
        # Route 53 is global service
        self.route53 = session.client("route53", region_name="us-east-1")

    def collect(self) -> list[Asset]:
        """Collect Route 53 hosted zones and health checks."""
        assets = []

        try:
            # Collect hosted zones
            assets.extend(self._collect_hosted_zones())

            # Collect health checks
            assets.extend(self._collect_health_checks())

        except Exception as e:
            logger.warning(f"Error collecting Route 53: {e}")

        return assets

    def _collect_hosted_zones(self) -> list[Asset]:
        """Collect hosted zones."""
        assets = []

        try:
            paginator = self.route53.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page.get("HostedZones", []):
                    zone_id = zone["Id"].split("/")[-1]  # Extract ID from /hostedzone/XXXXX
                    zone_name = zone["Name"]
                    is_private = zone.get("Config", {}).get("PrivateZone", False)
                    record_count = zone.get("ResourceRecordSetCount", 0)

                    # Get tags
                    tags = {}
                    try:
                        tag_response = self.route53.list_tags_for_resource(
                            ResourceType="hostedzone", ResourceId=zone_id
                        )
                        for tag in tag_response.get("ResourceTagSet", {}).get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    # Estimate cost
                    # Hosted zone: $0.50/month
                    # Queries: $0.40/million for first billion
                    estimated_cost = 0.50

                    risk_flags = []
                    if record_count == 0:
                        risk_flags.append("empty_zone")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="route53_hosted_zone",
                            normalized_category=NormalizedCategory.NETWORKING,
                            service="Route 53",
                            region="global",
                            arn=f"arn:aws:route53:::hostedzone/{zone_id}",
                            name=zone_name.rstrip("."),
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "zone_id": zone_id,
                                "zone_name": zone_name,
                                "is_private": is_private,
                                "record_count": record_count,
                                "comment": zone.get("Config", {}).get("Comment", ""),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting hosted zones: {e}")

        return assets

    def _collect_health_checks(self) -> list[Asset]:
        """Collect health checks."""
        assets = []

        try:
            paginator = self.route53.get_paginator("list_health_checks")
            for page in paginator.paginate():
                for check in page.get("HealthChecks", []):
                    check_id = check["Id"]
                    config = check.get("HealthCheckConfig", {})
                    check_type = config.get("Type", "unknown")

                    # Get tags
                    tags = {}
                    try:
                        tag_response = self.route53.list_tags_for_resource(
                            ResourceType="healthcheck", ResourceId=check_id
                        )
                        for tag in tag_response.get("ResourceTagSet", {}).get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    name = tags.get("Name", check_id)

                    # Health check: $0.50/month for basic, up to $2/month for advanced
                    estimated_cost = 0.50
                    if config.get("MeasureLatency"):
                        estimated_cost += 1.0
                    if config.get("EnableSNI"):
                        estimated_cost += 0.50

                    risk_flags = []
                    # Note: HealthCheckStatus requires separate API call

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="route53_health_check",
                            normalized_category=NormalizedCategory.NETWORKING,
                            service="Route 53",
                            region="global",
                            arn=f"arn:aws:route53:::healthcheck/{check_id}",
                            name=name,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "health_check_id": check_id,
                                "type": check_type,
                                "fqdn": config.get("FullyQualifiedDomainName"),
                                "ip_address": config.get("IPAddress"),
                                "port": config.get("Port"),
                                "resource_path": config.get("ResourcePath"),
                                "request_interval": config.get("RequestInterval"),
                                "failure_threshold": config.get("FailureThreshold"),
                                "measure_latency": config.get("MeasureLatency", False),
                                "regions": config.get("Regions", []),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting health checks: {e}")

        return assets
