"""
AWS CloudFront Collector - CDN distributions.

Collects CloudFront distributions and their configurations.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class CloudFrontCollector:
    """Collector for CloudFront distributions."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id
        # CloudFront is global service
        self.cloudfront = session.client("cloudfront", region_name="us-east-1")

    def collect(self) -> list[Asset]:
        """Collect CloudFront distributions."""
        assets = []

        try:
            assets.extend(self._collect_distributions())
        except Exception as e:
            logger.warning(f"Error collecting CloudFront: {e}")

        return assets

    def _collect_distributions(self) -> list[Asset]:
        """Collect CloudFront distributions."""
        assets = []

        try:
            paginator = self.cloudfront.get_paginator("list_distributions")
            for page in paginator.paginate():
                distribution_list = page.get("DistributionList", {})
                for dist in distribution_list.get("Items", []):
                    dist_id = dist["Id"]
                    dist_arn = dist["ARN"]
                    domain_name = dist.get("DomainName", "")
                    status = dist.get("Status", "unknown")
                    enabled = dist.get("Enabled", True)

                    # Get aliases (CNAMEs)
                    aliases = dist.get("Aliases", {}).get("Items", [])

                    # Get origins
                    origins = dist.get("Origins", {}).get("Items", [])
                    origin_domains = [o.get("DomainName") for o in origins]

                    # Get cache behaviors
                    default_cache = dist.get("DefaultCacheBehavior", {})
                    viewer_protocol = default_cache.get("ViewerProtocolPolicy", "allow-all")

                    # Get tags
                    tags = {}
                    try:
                        tag_response = self.cloudfront.list_tags_for_resource(Resource=dist_arn)
                        for tag in tag_response.get("Tags", {}).get("Items", []):
                            tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    name = tags.get("Name") or (aliases[0] if aliases else dist_id)

                    # Estimate cost - CloudFront charges per GB transferred + requests
                    # Varies significantly by usage, estimate based on typical usage
                    estimated_cost = 20.0  # Rough estimate

                    risk_flags = []
                    if not enabled:
                        risk_flags.append("disabled")
                    if viewer_protocol == "allow-all":
                        risk_flags.append("allows_http")  # Should enforce HTTPS
                    if not dist.get("HttpVersion") or dist.get("HttpVersion") == "http1.1":
                        risk_flags.append("http1_only")  # Should use HTTP/2

                    # Check WAF
                    if not dist.get("WebACLId"):
                        risk_flags.append("no_waf")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="cloudfront_distribution",
                            normalized_category=NormalizedCategory.NETWORKING,
                            service="CloudFront",
                            region="global",
                            arn=dist_arn,
                            name=name,
                            created_at=dist.get("LastModifiedTime", "").isoformat()
                            if dist.get("LastModifiedTime")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "distribution_id": dist_id,
                                "domain_name": domain_name,
                                "status": status,
                                "enabled": enabled,
                                "aliases": aliases,
                                "origin_domains": origin_domains,
                                "origin_count": len(origins),
                                "http_version": dist.get("HttpVersion"),
                                "price_class": dist.get("PriceClass"),
                                "viewer_protocol_policy": viewer_protocol,
                                "is_ipv6_enabled": dist.get("IsIPV6Enabled", False),
                                "has_waf": bool(dist.get("WebACLId")),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting distributions: {e}")

        return assets
