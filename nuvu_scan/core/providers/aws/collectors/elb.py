"""
AWS Elastic Load Balancing Collector - ALB, NLB, CLB.

Collects Application Load Balancers, Network Load Balancers, and Classic Load Balancers.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class ELBCollector:
    """Collector for Elastic Load Balancers (ALB, NLB, CLB)."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect all load balancers across regions."""
        assets = []

        for region in self.regions:
            try:
                # ALB and NLB (ELBv2)
                elbv2 = self.session.client("elbv2", region_name=region)
                assets.extend(self._collect_v2_load_balancers(elbv2, region))

                # Classic Load Balancers (ELB)
                elb = self.session.client("elb", region_name=region)
                assets.extend(self._collect_classic_load_balancers(elb, region))

            except Exception as e:
                logger.warning(f"Error collecting ELB in {region}: {e}")

        return assets

    def _collect_v2_load_balancers(self, elbv2, region: str) -> list[Asset]:
        """Collect ALB and NLB (ELBv2)."""
        assets = []

        try:
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb["LoadBalancerName"]
                    lb_type = lb.get("Type", "application")  # application, network, gateway
                    state = lb.get("State", {}).get("Code", "unknown")

                    # Get tags
                    tags = {}
                    try:
                        tag_response = elbv2.describe_tags(ResourceArns=[lb_arn])
                        for tag_desc in tag_response.get("TagDescriptions", []):
                            for tag in tag_desc.get("Tags", []):
                                tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    # Estimate costs
                    # ALB: ~$16/month base + LCU charges
                    # NLB: ~$16/month base + NLCU charges
                    if lb_type == "application":
                        estimated_cost = 16.20
                        asset_type = "alb"
                    elif lb_type == "network":
                        estimated_cost = 16.20
                        asset_type = "nlb"
                    else:
                        estimated_cost = 16.20
                        asset_type = "gateway_lb"

                    risk_flags = []
                    if state != "active":
                        risk_flags.append("not_active")

                    # Check for internet-facing
                    scheme = lb.get("Scheme", "internal")
                    if scheme == "internet-facing":
                        risk_flags.append("internet_facing")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type=asset_type,
                            normalized_category=NormalizedCategory.NETWORKING,
                            service="Elastic Load Balancing",
                            region=region,
                            arn=lb_arn,
                            name=lb_name,
                            created_at=lb.get("CreatedTime", "").isoformat()
                            if lb.get("CreatedTime")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "type": lb_type,
                                "state": state,
                                "scheme": scheme,
                                "vpc_id": lb.get("VpcId"),
                                "dns_name": lb.get("DNSName"),
                                "availability_zones": [
                                    az.get("ZoneName") for az in lb.get("AvailabilityZones", [])
                                ],
                                "security_groups": lb.get("SecurityGroups", []),
                                "ip_address_type": lb.get("IpAddressType"),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting ALB/NLB: {e}")

        return assets

    def _collect_classic_load_balancers(self, elb, region: str) -> list[Asset]:
        """Collect Classic Load Balancers."""
        assets = []

        try:
            paginator = elb.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancerDescriptions", []):
                    lb_name = lb["LoadBalancerName"]

                    # Get tags
                    tags = {}
                    try:
                        tag_response = elb.describe_tags(LoadBalancerNames=[lb_name])
                        for tag_desc in tag_response.get("TagDescriptions", []):
                            for tag in tag_desc.get("Tags", []):
                                tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    # CLB: ~$18/month base
                    estimated_cost = 18.0

                    risk_flags = ["classic_lb"]  # CLB is deprecated, should migrate to ALB/NLB

                    scheme = lb.get("Scheme", "internal")
                    if scheme == "internet-facing":
                        risk_flags.append("internet_facing")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="clb",
                            normalized_category=NormalizedCategory.NETWORKING,
                            service="Elastic Load Balancing",
                            region=region,
                            arn=f"arn:aws:elasticloadbalancing:{region}:{self.account_id}:loadbalancer/{lb_name}",
                            name=lb_name,
                            created_at=lb.get("CreatedTime", "").isoformat()
                            if lb.get("CreatedTime")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "type": "classic",
                                "scheme": scheme,
                                "vpc_id": lb.get("VPCId"),
                                "dns_name": lb.get("DNSName"),
                                "availability_zones": lb.get("AvailabilityZones", []),
                                "security_groups": lb.get("SecurityGroups", []),
                                "instances": len(lb.get("Instances", [])),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting Classic Load Balancers: {e}")

        return assets
