"""
AWS VPC Costs Collector - NAT Gateways, VPN Connections, VPC Endpoints.

These are the expensive VPC components that drive the "Amazon Virtual Private Cloud"
Cost Explorer charges (separate from EC2 VPC resources).
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class VPCCostsCollector:
    """Collector for costly VPC resources: NAT Gateways, VPN, Endpoints."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect NAT Gateways, VPN connections, and VPC Endpoints."""
        assets = []

        for region in self.regions:
            try:
                ec2 = self.session.client("ec2", region_name=region)

                # Collect NAT Gateways (major cost driver ~$32/month each + data processing)
                assets.extend(self._collect_nat_gateways(ec2, region))

                # Collect VPN Connections (~$36/month each)
                assets.extend(self._collect_vpn_connections(ec2, region))

                # Collect VPC Endpoints (Interface endpoints cost ~$7/month each)
                assets.extend(self._collect_vpc_endpoints(ec2, region))

                # Collect Transit Gateways (if any)
                assets.extend(self._collect_transit_gateways(ec2, region))

            except Exception as e:
                logger.warning(f"Error collecting VPC costs in {region}: {e}")

        return assets

    def _collect_nat_gateways(self, ec2, region: str) -> list[Asset]:
        """Collect NAT Gateways - major cost driver."""
        assets = []

        try:
            paginator = ec2.get_paginator("describe_nat_gateways")
            for page in paginator.paginate():
                for nat in page.get("NatGateways", []):
                    nat_id = nat["NatGatewayId"]
                    state = nat.get("State", "unknown")

                    # Extract tags
                    tags = {t["Key"]: t["Value"] for t in nat.get("Tags", [])}
                    name = tags.get("Name", nat_id)

                    # Risk flags
                    risk_flags = []
                    if state != "available":
                        risk_flags.append("not_available")

                    # NAT Gateway costs ~$32.40/month + $0.045/GB processed
                    estimated_cost = 32.40 if state == "available" else 0

                    # Infer owner from tags
                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="nat_gateway",
                            normalized_category=NormalizedCategory.NETWORKING,
                            service="VPC",
                            region=region,
                            arn=f"arn:aws:ec2:{region}:{self.account_id}:natgateway/{nat_id}",
                            name=name,
                            created_at=nat.get("CreateTime", "").isoformat()
                            if nat.get("CreateTime")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "nat_gateway_id": nat_id,
                                "state": state,
                                "vpc_id": nat.get("VpcId"),
                                "subnet_id": nat.get("SubnetId"),
                                "connectivity_type": nat.get("ConnectivityType", "public"),
                                "public_ip": next(
                                    (
                                        addr.get("PublicIp")
                                        for addr in nat.get("NatGatewayAddresses", [])
                                    ),
                                    None,
                                ),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting NAT Gateways: {e}")

        return assets

    def _collect_vpn_connections(self, ec2, region: str) -> list[Asset]:
        """Collect VPN Connections."""
        assets = []

        try:
            response = ec2.describe_vpn_connections()
            for vpn in response.get("VpnConnections", []):
                vpn_id = vpn["VpnConnectionId"]
                state = vpn.get("State", "unknown")

                tags = {t["Key"]: t["Value"] for t in vpn.get("Tags", [])}
                name = tags.get("Name", vpn_id)

                risk_flags = []
                if state not in ["available", "pending"]:
                    risk_flags.append("connection_down")

                # VPN connection costs ~$36/month
                estimated_cost = 36.0 if state == "available" else 0

                owner = (
                    tags.get("team") or tags.get("owner") or tags.get("Team") or tags.get("Owner")
                )

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="vpn_connection",
                        normalized_category=NormalizedCategory.NETWORKING,
                        service="VPC",
                        region=region,
                        arn=f"arn:aws:ec2:{region}:{self.account_id}:vpn-connection/{vpn_id}",
                        name=name,
                        tags=tags,
                        cost_estimate_usd=estimated_cost,
                        usage_metrics={
                            "vpn_connection_id": vpn_id,
                            "state": state,
                            "type": vpn.get("Type"),
                            "customer_gateway_id": vpn.get("CustomerGatewayId"),
                            "vpn_gateway_id": vpn.get("VpnGatewayId"),
                            "transit_gateway_id": vpn.get("TransitGatewayId"),
                        },
                        risk_flags=risk_flags if risk_flags else None,
                        ownership_confidence="high" if owner else "unknown",
                        suggested_owner=owner,
                    )
                )

        except Exception as e:
            logger.warning(f"Error collecting VPN connections: {e}")

        return assets

    def _collect_vpc_endpoints(self, ec2, region: str) -> list[Asset]:
        """Collect VPC Endpoints (Interface endpoints cost money, Gateway endpoints are free)."""
        assets = []

        try:
            paginator = ec2.get_paginator("describe_vpc_endpoints")
            for page in paginator.paginate():
                for endpoint in page.get("VpcEndpoints", []):
                    endpoint_id = endpoint["VpcEndpointId"]
                    endpoint_type = endpoint.get("VpcEndpointType", "unknown")
                    state = endpoint.get("State", "unknown")

                    tags = {t["Key"]: t["Value"] for t in endpoint.get("Tags", [])}
                    name = tags.get("Name", endpoint_id)

                    # Interface endpoints cost ~$7.30/month per AZ
                    # Gateway endpoints (S3, DynamoDB) are free
                    if endpoint_type == "Interface":
                        # Count number of subnets (AZs)
                        num_azs = len(endpoint.get("SubnetIds", [1]))
                        estimated_cost = 7.30 * num_azs
                    else:
                        estimated_cost = 0

                    risk_flags = []
                    if state != "available":
                        risk_flags.append("not_available")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="vpc_endpoint",
                            normalized_category=NormalizedCategory.NETWORKING,
                            service="VPC",
                            region=region,
                            arn=f"arn:aws:ec2:{region}:{self.account_id}:vpc-endpoint/{endpoint_id}",
                            name=name,
                            created_at=endpoint.get("CreationTimestamp", "").isoformat()
                            if endpoint.get("CreationTimestamp")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "endpoint_id": endpoint_id,
                                "endpoint_type": endpoint_type,
                                "state": state,
                                "vpc_id": endpoint.get("VpcId"),
                                "service_name": endpoint.get("ServiceName"),
                                "subnet_count": len(endpoint.get("SubnetIds", [])),
                                "private_dns_enabled": endpoint.get("PrivateDnsEnabled", False),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting VPC endpoints: {e}")

        return assets

    def _collect_transit_gateways(self, ec2, region: str) -> list[Asset]:
        """Collect Transit Gateways."""
        assets = []

        try:
            response = ec2.describe_transit_gateways()
            for tgw in response.get("TransitGateways", []):
                tgw_id = tgw["TransitGatewayId"]
                state = tgw.get("State", "unknown")

                tags = {t["Key"]: t["Value"] for t in tgw.get("Tags", [])}
                name = tags.get("Name", tgw_id)

                # Transit Gateway attachment costs ~$36/month + data processing
                estimated_cost = 36.0 if state == "available" else 0

                risk_flags = []
                if state != "available":
                    risk_flags.append("not_available")

                owner = (
                    tags.get("team") or tags.get("owner") or tags.get("Team") or tags.get("Owner")
                )

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="transit_gateway",
                        normalized_category=NormalizedCategory.NETWORKING,
                        service="VPC",
                        region=region,
                        arn=tgw.get(
                            "TransitGatewayArn",
                            f"arn:aws:ec2:{region}:{self.account_id}:transit-gateway/{tgw_id}",
                        ),
                        name=name,
                        created_at=tgw.get("CreationTime", "").isoformat()
                        if tgw.get("CreationTime")
                        else None,
                        tags=tags,
                        cost_estimate_usd=estimated_cost,
                        usage_metrics={
                            "transit_gateway_id": tgw_id,
                            "state": state,
                            "owner_id": tgw.get("OwnerId"),
                        },
                        risk_flags=risk_flags if risk_flags else None,
                        ownership_confidence="high" if owner else "unknown",
                        suggested_owner=owner,
                    )
                )

        except Exception as e:
            logger.warning(f"Error collecting Transit Gateways: {e}")

        return assets
