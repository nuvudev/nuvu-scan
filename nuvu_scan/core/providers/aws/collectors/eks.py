"""
EKS collector for AWS.

Collects EKS clusters and node groups for Kubernetes governance.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class EKSCollector:
    """Collects AWS EKS clusters and node groups."""

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
        """Collect all EKS resources."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for EKS clusters...", file=sys.stderr)

        for region in regions:
            try:
                eks = self.session.client("eks", region_name=region)

                # List clusters
                clusters_response = eks.list_clusters()

                for cluster_name in clusters_response.get("clusters", []):
                    try:
                        # Get cluster details
                        cluster_detail = eks.describe_cluster(name=cluster_name)
                        cluster = cluster_detail.get("cluster", {})

                        cluster_arn = cluster.get("arn", "")
                        status = cluster.get("status", "")
                        version = cluster.get("version", "")
                        created_at = cluster.get("createdAt")

                        # Get tags
                        tags = cluster.get("tags", {})
                        ownership = self._infer_ownership(tags, cluster_name)

                        # Security analysis
                        endpoint_public = cluster.get("resourcesVpcConfig", {}).get(
                            "endpointPublicAccess", True
                        )
                        endpoint_private = cluster.get("resourcesVpcConfig", {}).get(
                            "endpointPrivateAccess", False
                        )
                        public_access_cidrs = cluster.get("resourcesVpcConfig", {}).get(
                            "publicAccessCidrs", []
                        )

                        # Encryption
                        encryption_config = cluster.get("encryptionConfig", [])
                        secrets_encrypted = any(
                            "secrets" in ec.get("resources", []) for ec in encryption_config
                        )

                        # Logging
                        logging_config = cluster.get("logging", {}).get("clusterLogging", [])
                        logging_enabled = any(lc.get("enabled", False) for lc in logging_config)

                        # Build risk flags
                        risk_flags = []
                        if endpoint_public and not endpoint_private:
                            risk_flags.append("public_endpoint_only")
                        if endpoint_public and "0.0.0.0/0" in public_access_cidrs:
                            risk_flags.append("public_endpoint_open_to_world")
                        if not secrets_encrypted:
                            risk_flags.append("secrets_not_encrypted")
                        if not logging_enabled:
                            risk_flags.append("logging_disabled")

                        # Check Kubernetes version
                        if version:
                            try:
                                major, minor = map(int, version.split(".")[:2])
                                # Flag old versions (EKS supports ~last 4 versions)
                                if minor < 27:  # As of 2024
                                    risk_flags.append("old_kubernetes_version")
                            except ValueError:
                                pass

                        # Count node groups
                        nodegroups = []
                        try:
                            ng_response = eks.list_nodegroups(clusterName=cluster_name)
                            nodegroups = ng_response.get("nodegroups", [])
                        except ClientError:
                            pass

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="eks_cluster",
                                normalized_category=NormalizedCategory.COMPUTE,
                                service="EKS",
                                region=region,
                                arn=cluster_arn,
                                name=cluster_name,
                                created_at=created_at.isoformat() if created_at else None,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "cluster_name": cluster_name,
                                    "status": status,
                                    "kubernetes_version": version,
                                    "platform_version": cluster.get("platformVersion", ""),
                                    "endpoint_public": endpoint_public,
                                    "endpoint_private": endpoint_private,
                                    "public_access_cidrs": public_access_cidrs,
                                    "secrets_encrypted": secrets_encrypted,
                                    "logging_enabled": logging_enabled,
                                    "nodegroup_count": len(nodegroups),
                                    "vpc_id": cluster.get("resourcesVpcConfig", {}).get(
                                        "vpcId", ""
                                    ),
                                    "role_arn": cluster.get("roleArn", ""),
                                },
                            )
                        )

                        # Collect node groups
                        for ng_name in nodegroups:
                            try:
                                ng_detail = eks.describe_nodegroup(
                                    clusterName=cluster_name, nodegroupName=ng_name
                                )
                                ng = ng_detail.get("nodegroup", {})

                                ng_arn = ng.get("nodegroupArn", "")
                                ng_status = ng.get("status", "")
                                ng_tags = ng.get("tags", {})

                                # Instance types
                                instance_types = ng.get("instanceTypes", [])

                                # Scaling config
                                scaling = ng.get("scalingConfig", {})
                                min_size = scaling.get("minSize", 0)
                                max_size = scaling.get("maxSize", 0)
                                desired_size = scaling.get("desiredSize", 0)

                                # Disk size
                                disk_size = ng.get("diskSize", 0)

                                ng_risk_flags = []
                                if min_size == max_size == 1:
                                    ng_risk_flags.append("single_node")
                                if ng.get("amiType", "").startswith("AL2"):
                                    # AL2 is reaching EOL
                                    pass  # AL2023 is current

                                assets.append(
                                    Asset(
                                        provider="aws",
                                        asset_type="eks_nodegroup",
                                        normalized_category=NormalizedCategory.COMPUTE,
                                        service="EKS",
                                        region=region,
                                        arn=ng_arn,
                                        name=f"{cluster_name}/{ng_name}",
                                        created_at=ng.get("createdAt").isoformat()
                                        if ng.get("createdAt")
                                        else None,
                                        tags=ng_tags,
                                        risk_flags=ng_risk_flags,
                                        usage_metrics={
                                            "cluster_name": cluster_name,
                                            "nodegroup_name": ng_name,
                                            "status": ng_status,
                                            "instance_types": instance_types,
                                            "ami_type": ng.get("amiType", ""),
                                            "min_size": min_size,
                                            "max_size": max_size,
                                            "desired_size": desired_size,
                                            "disk_size_gb": disk_size,
                                            "capacity_type": ng.get("capacityType", "ON_DEMAND"),
                                        },
                                    )
                                )

                            except ClientError:
                                continue

                    except ClientError as e:
                        if "AccessDenied" not in str(e):
                            print(f"Error describing EKS cluster {cluster_name}: {e}")

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting EKS clusters in {region}: {e}")

        print(f"  → Found {len(assets)} EKS resources", file=sys.stderr)
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
        """Get usage metrics for EKS resource."""
        return asset.usage_metrics or {}
