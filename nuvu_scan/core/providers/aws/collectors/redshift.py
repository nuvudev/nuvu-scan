"""
Amazon Redshift collector.

Collects Redshift clusters and serverless namespaces.
"""

import boto3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from nuvu_scan.core.base import Asset, NormalizedCategory


class RedshiftCollector:
    """Collects Amazon Redshift resources."""

    def __init__(self, session: boto3.Session, regions: Optional[List[str]] = None):
        self.session = session
        self.regions = regions or []

    def collect(self) -> List[Asset]:
        """Collect Redshift clusters and serverless namespaces."""
        assets = []

        # Collect provisioned clusters
        assets.extend(self._collect_clusters())

        # Collect serverless namespaces
        assets.extend(self._collect_serverless())

        return assets

    def _collect_clusters(self) -> List[Asset]:
        """Collect provisioned Redshift clusters."""
        assets = []

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift", region_name=region)

                # List clusters
                response = redshift_client.describe_clusters()

                for cluster in response.get("Clusters", []):
                    cluster_id = cluster["ClusterIdentifier"]

                    # Get cluster status and usage
                    status = cluster.get("ClusterStatus", "unknown")
                    node_count = cluster.get("NumberOfNodes", 0)
                    node_type = cluster.get("NodeType", "")

                    risk_flags = []
                    if status == "available" and node_count > 0:
                        # Check if cluster is idle (no recent queries)
                        # This would require querying system tables, simplified here
                        pass

                    # Estimate cost based on node type and count
                    monthly_cost = self._estimate_cluster_cost(node_type, node_count)

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="redshift_cluster",
                            normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                            service="Redshift",
                            region=region,
                            arn=cluster.get(
                                "ClusterNamespaceArn",
                                f"arn:aws:redshift:{region}::cluster:{cluster_id}",
                            ),
                            name=cluster_id,
                            created_at=(
                                cluster.get("ClusterCreateTime", "").isoformat()
                                if cluster.get("ClusterCreateTime")
                                else None
                            ),
                            risk_flags=risk_flags,
                            usage_metrics={
                                "status": status,
                                "node_count": node_count,
                                "node_type": node_type,
                            },
                            cost_estimate_usd=monthly_cost,
                        )
                    )

            except ClientError as e:
                print(f"Error collecting Redshift clusters in {region}: {e}")

        return assets

    def _collect_serverless(self) -> List[Asset]:
        """Collect Redshift Serverless namespaces."""
        assets = []

        regions_to_check = self.regions if self.regions else ["us-east-1"]

        for region in regions_to_check:
            try:
                redshift_client = self.session.client("redshift-serverless", region_name=region)

                # List namespaces
                response = redshift_client.list_namespaces()

                for namespace in response.get("namespaces", []):
                    namespace_name = namespace.get("namespaceName", "")

                    # Get workgroups for namespace
                    workgroups_response = redshift_client.list_workgroups()
                    workgroup_count = len(
                        [
                            wg
                            for wg in workgroups_response.get("workgroups", [])
                            if wg.get("namespaceName") == namespace_name
                        ]
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="redshift_serverless_namespace",
                            normalized_category=NormalizedCategory.DATA_WAREHOUSE,
                            service="Redshift Serverless",
                            region=region,
                            arn=namespace.get(
                                "namespaceArn",
                                f"arn:aws:redshift-serverless:{region}::namespace/{namespace_name}",
                            ),
                            name=namespace_name,
                            created_at=(
                                namespace.get("creationDate", "").isoformat()
                                if namespace.get("creationDate")
                                else None
                            ),
                            usage_metrics={
                                "workgroup_count": workgroup_count,
                                "status": namespace.get("status", "unknown"),
                            },
                        )
                    )

            except ClientError as e:
                print(f"Error collecting Redshift Serverless in {region}: {e}")

        return assets

    def _estimate_cluster_cost(self, node_type: str, node_count: int) -> float:
        """Estimate monthly cost for Redshift cluster."""
        # Redshift pricing (approximate, as of 2024)
        # dc2.large: ~$0.25/hour = ~$180/month
        # ra3.xlplus: ~$3.26/hour = ~$2,347/month
        # etc.

        pricing = {
            "dc2.large": 180.0,
            "dc2.8xlarge": 1440.0,
            "ra3.xlplus": 2347.0,
            "ra3.4xlarge": 4694.0,
            "ra3.16xlarge": 18776.0,
        }

        base_cost = pricing.get(node_type, 500.0)  # Default estimate
        return base_cost * node_count

    def get_usage_metrics(self, asset: Asset) -> Dict[str, Any]:
        """Get usage metrics for Redshift asset."""
        return asset.usage_metrics or {}

    def get_cost_estimate(self, asset: Asset) -> float:
        """Get cost estimate for Redshift asset."""
        return asset.cost_estimate_usd or 0.0
