"""
EC2 and VPC collector for AWS.

Collects EC2 instances, security groups, VPCs, and network configuration
for security and governance analysis.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class EC2Collector:
    """Collects EC2 instances, security groups, VPCs, and network resources."""

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
        """Collect all EC2 and VPC resources."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for EC2/VPC resources...", file=sys.stderr)

        # Collect security groups (critical for network governance)
        print("  → Collecting security groups...", file=sys.stderr)
        sg_assets = self._collect_security_groups(regions)
        assets.extend(sg_assets)
        print(f"  → Found {len(sg_assets)} security groups", file=sys.stderr)

        # Collect VPCs
        print("  → Collecting VPCs...", file=sys.stderr)
        vpc_assets = self._collect_vpcs(regions)
        assets.extend(vpc_assets)
        print(f"  → Found {len(vpc_assets)} VPCs", file=sys.stderr)

        # Collect EC2 instances
        print("  → Collecting EC2 instances...", file=sys.stderr)
        ec2_assets = self._collect_instances(regions)
        assets.extend(ec2_assets)
        print(f"  → Found {len(ec2_assets)} EC2 instances", file=sys.stderr)

        # Collect EBS volumes
        print("  → Collecting EBS volumes...", file=sys.stderr)
        ebs_assets = self._collect_volumes(regions)
        assets.extend(ebs_assets)
        print(f"  → Found {len(ebs_assets)} EBS volumes", file=sys.stderr)

        # Collect Elastic IPs
        print("  → Collecting Elastic IPs...", file=sys.stderr)
        eip_assets = self._collect_elastic_ips(regions)
        assets.extend(eip_assets)
        print(f"  → Found {len(eip_assets)} Elastic IPs", file=sys.stderr)

        return assets

    def _collect_security_groups(self, regions: list[str]) -> list[Asset]:
        """Collect security groups with risk analysis."""
        assets = []

        for region in regions:
            try:
                ec2 = self.session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_security_groups")

                for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        sg_id = sg["GroupId"]
                        sg_name = sg.get("GroupName", sg_id)
                        vpc_id = sg.get("VpcId", "")

                        # Analyze inbound rules for risks
                        inbound_risks = self._analyze_security_group_rules(
                            sg.get("IpPermissions", []), "inbound"
                        )
                        outbound_risks = self._analyze_security_group_rules(
                            sg.get("IpPermissionsEgress", []), "outbound"
                        )

                        # Get tags
                        tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
                        ownership = self._infer_ownership(tags, sg_name)

                        # Build risk flags
                        risk_flags = []
                        if inbound_risks.get("allows_all_traffic"):
                            risk_flags.append("allows_all_inbound")
                        if inbound_risks.get("open_to_world"):
                            risk_flags.append("open_to_internet")
                        if inbound_risks.get("ssh_open"):
                            risk_flags.append("ssh_open_to_world")
                        if inbound_risks.get("rdp_open"):
                            risk_flags.append("rdp_open_to_world")
                        if inbound_risks.get("database_ports_open"):
                            risk_flags.append("database_ports_exposed")
                        if not tags.get("Name") and not tags.get("owner"):
                            risk_flags.append("no_owner")

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="security_group",
                                normalized_category=NormalizedCategory.SECURITY,
                                service="EC2",
                                region=region,
                                arn=f"arn:aws:ec2:{region}:{self._get_account_id()}:security-group/{sg_id}",
                                name=sg_name,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "security_group_id": sg_id,
                                    "vpc_id": vpc_id,
                                    "description": sg.get("Description", ""),
                                    "inbound_rules_count": len(sg.get("IpPermissions", [])),
                                    "outbound_rules_count": len(sg.get("IpPermissionsEgress", [])),
                                    "inbound_analysis": inbound_risks,
                                    "outbound_analysis": outbound_risks,
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting security groups in {region}: {e}")

        return assets

    def _analyze_security_group_rules(self, rules: list, direction: str) -> dict:
        """Analyze security group rules for governance risks."""
        analysis = {
            "allows_all_traffic": False,
            "open_to_world": False,
            "ssh_open": False,
            "rdp_open": False,
            "database_ports_open": False,
            "risky_ports": [],
        }

        database_ports = [
            3306,
            5432,
            1433,
            1521,
            27017,
            6379,
            9200,
            5439,
        ]  # MySQL, Postgres, MSSQL, Oracle, Mongo, Redis, ES, Redshift

        for rule in rules:
            ip_protocol = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            # Check for 0.0.0.0/0 or ::/0
            open_to_world = False
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_to_world = True
                    break
            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    open_to_world = True
                    break

            if open_to_world:
                analysis["open_to_world"] = True

                # All traffic (-1 protocol)
                if ip_protocol == "-1":
                    analysis["allows_all_traffic"] = True

                # SSH (22)
                if from_port <= 22 <= to_port:
                    analysis["ssh_open"] = True
                    analysis["risky_ports"].append(22)

                # RDP (3389)
                if from_port <= 3389 <= to_port:
                    analysis["rdp_open"] = True
                    analysis["risky_ports"].append(3389)

                # Database ports
                for port in database_ports:
                    if from_port <= port <= to_port:
                        analysis["database_ports_open"] = True
                        if port not in analysis["risky_ports"]:
                            analysis["risky_ports"].append(port)

        return analysis

    def _collect_vpcs(self, regions: list[str]) -> list[Asset]:
        """Collect VPCs with network configuration analysis."""
        assets = []

        for region in regions:
            try:
                ec2 = self.session.client("ec2", region_name=region)
                response = ec2.describe_vpcs()

                for vpc in response.get("Vpcs", []):
                    vpc_id = vpc["VpcId"]
                    cidr_block = vpc.get("CidrBlock", "")

                    tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
                    vpc_name = tags.get("Name", vpc_id)
                    ownership = self._infer_ownership(tags, vpc_name)

                    # Check if default VPC
                    is_default = vpc.get("IsDefault", False)

                    # Get flow log status
                    has_flow_logs = self._check_flow_logs(ec2, vpc_id)

                    # Build risk flags
                    risk_flags = []
                    if is_default:
                        risk_flags.append("default_vpc_in_use")
                    if not has_flow_logs:
                        risk_flags.append("no_flow_logs")

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="vpc",
                            normalized_category=NormalizedCategory.SECURITY,
                            service="VPC",
                            region=region,
                            arn=f"arn:aws:ec2:{region}:{self._get_account_id()}:vpc/{vpc_id}",
                            name=vpc_name,
                            tags=tags,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            usage_metrics={
                                "vpc_id": vpc_id,
                                "cidr_block": cidr_block,
                                "is_default": is_default,
                                "state": vpc.get("State", "unknown"),
                                "has_flow_logs": has_flow_logs,
                                "dhcp_options_id": vpc.get("DhcpOptionsId", ""),
                            },
                        )
                    )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting VPCs in {region}: {e}")

        return assets

    def _check_flow_logs(self, ec2_client, vpc_id: str) -> bool:
        """Check if VPC has flow logs enabled."""
        try:
            response = ec2_client.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )
            return len(response.get("FlowLogs", [])) > 0
        except ClientError:
            return False

    def _collect_instances(self, regions: list[str]) -> list[Asset]:
        """Collect EC2 instances."""
        assets = []

        for region in regions:
            try:
                ec2 = self.session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_instances")

                for page in paginator.paginate():
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            instance_id = instance["InstanceId"]
                            instance_type = instance.get("InstanceType", "unknown")
                            state = instance.get("State", {}).get("Name", "unknown")

                            tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                            instance_name = tags.get("Name", instance_id)
                            ownership = self._infer_ownership(tags, instance_name)

                            # Check for public IP
                            public_ip = instance.get("PublicIpAddress")
                            has_public_ip = bool(public_ip)

                            # Get launch time
                            launch_time = instance.get("LaunchTime")
                            age_days = None
                            if launch_time:
                                age_days = (
                                    datetime.now(timezone.utc)
                                    - launch_time.replace(tzinfo=timezone.utc)
                                ).days

                            # Build risk flags
                            risk_flags = []
                            if has_public_ip:
                                risk_flags.append("has_public_ip")
                            if not instance.get("IamInstanceProfile"):
                                risk_flags.append("no_instance_profile")
                            if state == "stopped" and age_days and age_days > 30:
                                risk_flags.append("stopped_long_time")

                            # Estimate cost (simplified)
                            monthly_cost = self._estimate_instance_cost(instance_type, state)

                            # Determine last activity based on state
                            # Running instances are currently active
                            # For stopped instances, use state transition time if available
                            last_activity_at = None
                            if state == "running":
                                # Running = active now
                                last_activity_at = datetime.now(timezone.utc).isoformat()
                            elif state in ["stopped", "stopping"]:
                                # For stopped instances, use StateTransitionReason time if parseable
                                # Otherwise leave as None (unknown)
                                state_transition = instance.get("StateTransitionReason", "")
                                # Format is like "User initiated (2024-01-01 12:00:00 GMT)"
                                if "(" in state_transition and ")" in state_transition:
                                    try:
                                        time_str = state_transition.split("(")[1].split(")")[0]
                                        # Parse the date part
                                        from datetime import datetime as dt

                                        parsed_time = dt.strptime(
                                            time_str.rsplit(" ", 1)[0], "%Y-%m-%d %H:%M:%S"
                                        )
                                        last_activity_at = parsed_time.replace(
                                            tzinfo=timezone.utc
                                        ).isoformat()
                                    except (ValueError, IndexError):
                                        pass

                            assets.append(
                                Asset(
                                    provider="aws",
                                    asset_type="ec2_instance",
                                    normalized_category=NormalizedCategory.COMPUTE,
                                    service="EC2",
                                    region=region,
                                    arn=f"arn:aws:ec2:{region}:{self._get_account_id()}:instance/{instance_id}",
                                    name=instance_name,
                                    created_at=launch_time.isoformat() if launch_time else None,
                                    last_activity_at=last_activity_at,
                                    tags=tags,
                                    risk_flags=risk_flags,
                                    ownership_confidence=ownership["confidence"],
                                    suggested_owner=ownership["owner"],
                                    cost_estimate_usd=monthly_cost,
                                    usage_metrics={
                                        "instance_id": instance_id,
                                        "instance_type": instance_type,
                                        "state": state,
                                        "public_ip": public_ip,
                                        "private_ip": instance.get("PrivateIpAddress"),
                                        "vpc_id": instance.get("VpcId"),
                                        "subnet_id": instance.get("SubnetId"),
                                        "availability_zone": instance.get("Placement", {}).get(
                                            "AvailabilityZone"
                                        ),
                                        "age_days": age_days,
                                        "has_iam_profile": bool(instance.get("IamInstanceProfile")),
                                        "ebs_optimized": instance.get("EbsOptimized", False),
                                    },
                                )
                            )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting EC2 instances in {region}: {e}")

        return assets

    def _collect_volumes(self, regions: list[str]) -> list[Asset]:
        """Collect EBS volumes."""
        assets = []

        for region in regions:
            try:
                ec2 = self.session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_volumes")

                for page in paginator.paginate():
                    for volume in page.get("Volumes", []):
                        volume_id = volume["VolumeId"]
                        state = volume.get("State", "unknown")
                        size_gb = volume.get("Size", 0)
                        encrypted = volume.get("Encrypted", False)

                        tags = {t["Key"]: t["Value"] for t in volume.get("Tags", [])}
                        volume_name = tags.get("Name", volume_id)
                        ownership = self._infer_ownership(tags, volume_name)

                        # Check attachments
                        attachments = volume.get("Attachments", [])
                        is_attached = len(attachments) > 0

                        # Build risk flags
                        risk_flags = []
                        if not encrypted:
                            risk_flags.append("unencrypted")
                        if not is_attached and state == "available":
                            risk_flags.append("unattached_volume")

                        # Estimate cost (~$0.10/GB-month for gp3)
                        monthly_cost = size_gb * 0.08

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="ebs_volume",
                                normalized_category=NormalizedCategory.OBJECT_STORAGE,
                                service="EC2",
                                region=region,
                                arn=f"arn:aws:ec2:{region}:{self._get_account_id()}:volume/{volume_id}",
                                name=volume_name,
                                created_at=volume.get("CreateTime").isoformat()
                                if volume.get("CreateTime")
                                else None,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                size_bytes=size_gb * 1024 * 1024 * 1024,
                                cost_estimate_usd=monthly_cost,
                                usage_metrics={
                                    "volume_id": volume_id,
                                    "volume_type": volume.get("VolumeType", "unknown"),
                                    "size_gb": size_gb,
                                    "iops": volume.get("Iops"),
                                    "throughput": volume.get("Throughput"),
                                    "state": state,
                                    "encrypted": encrypted,
                                    "is_attached": is_attached,
                                    "availability_zone": volume.get("AvailabilityZone"),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting EBS volumes in {region}: {e}")

        return assets

    def _collect_elastic_ips(self, regions: list[str]) -> list[Asset]:
        """Collect Elastic IPs."""
        assets = []

        for region in regions:
            try:
                ec2 = self.session.client("ec2", region_name=region)
                response = ec2.describe_addresses()

                for eip in response.get("Addresses", []):
                    allocation_id = eip.get("AllocationId", "")
                    public_ip = eip.get("PublicIp", "")

                    tags = {t["Key"]: t["Value"] for t in eip.get("Tags", [])}
                    eip_name = tags.get("Name", public_ip)
                    ownership = self._infer_ownership(tags, eip_name)

                    # Check if associated
                    is_associated = bool(eip.get("AssociationId") or eip.get("InstanceId"))

                    # Build risk flags
                    risk_flags = []
                    if not is_associated:
                        risk_flags.append("unassociated_eip")

                    # Unassociated EIPs cost ~$3.60/month
                    monthly_cost = 0.0 if is_associated else 3.60

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="elastic_ip",
                            normalized_category=NormalizedCategory.SECURITY,
                            service="EC2",
                            region=region,
                            arn=f"arn:aws:ec2:{region}:{self._get_account_id()}:elastic-ip/{allocation_id}",
                            name=eip_name,
                            tags=tags,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            cost_estimate_usd=monthly_cost,
                            usage_metrics={
                                "allocation_id": allocation_id,
                                "public_ip": public_ip,
                                "is_associated": is_associated,
                                "instance_id": eip.get("InstanceId"),
                                "network_interface_id": eip.get("NetworkInterfaceId"),
                            },
                        )
                    )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting Elastic IPs in {region}: {e}")

        return assets

    def _estimate_instance_cost(self, instance_type: str, state: str) -> float:
        """Estimate monthly cost for EC2 instance."""
        if state != "running":
            return 0.0

        # Simplified pricing (actual varies by region)
        pricing = {
            "t3.micro": 7.5,
            "t3.small": 15.0,
            "t3.medium": 30.0,
            "t3.large": 60.0,
            "m5.large": 70.0,
            "m5.xlarge": 140.0,
            "m5.2xlarge": 280.0,
            "r5.large": 90.0,
            "r5.xlarge": 180.0,
            "c5.large": 62.0,
            "c5.xlarge": 124.0,
        }

        return pricing.get(instance_type, 50.0)

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
        """Get usage metrics for EC2 asset."""
        return asset.usage_metrics or {}
