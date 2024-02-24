"""
AWS Glue Data Catalog collector.

Collects Glue databases, tables, and jobs.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class GlueCollector:
    """Collects AWS Glue Data Catalog resources."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or ["us-east-1"]  # Glue is regional but catalog is global
        self.glue_client = session.client("glue", region_name="us-east-1")

    def collect(self) -> list[Asset]:
        """Collect Glue databases and tables."""
        assets = []

        try:
            # List databases
            paginator = self.glue_client.get_paginator("get_databases")

            for page in paginator.paginate():
                for db_info in page.get("DatabaseList", []):
                    db_name = db_info["Name"]

                    # Create database asset
                    tags = self._get_tags(f"database/{db_name}")
                    ownership = self._infer_ownership(tags, db_name)

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="glue_database",
                            normalized_category=NormalizedCategory.DATA_CATALOG,
                            service="Glue",
                            region="us-east-1",  # Glue catalog is in us-east-1
                            arn=db_info.get("CatalogId", "") + "::" + db_name,
                            name=db_name,
                            created_at=(
                                db_info.get("CreateTime", "").isoformat()
                                if db_info.get("CreateTime")
                                else None
                            ),
                            tags=tags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            usage_metrics={"table_count": 0},
                        )
                    )

                    # List tables in database
                    try:
                        table_paginator = self.glue_client.get_paginator("get_tables")
                        for table_page in table_paginator.paginate(DatabaseName=db_name):
                            for table_info in table_page.get("TableList", []):
                                table_name = table_info["Name"]
                                table_tags = self._get_tags(f"table/{db_name}/{table_name}")
                                table_ownership = self._infer_ownership(table_tags, table_name)

                                # Check if table is empty/unused
                                partition_count = len(table_info.get("PartitionKeys", []))
                                risk_flags = []
                                if partition_count == 0 and not table_info.get("StorageDescriptor"):
                                    risk_flags.append("empty_table")

                                assets.append(
                                    Asset(
                                        provider="aws",
                                        asset_type="glue_table",
                                        normalized_category=NormalizedCategory.DATA_CATALOG,
                                        service="Glue",
                                        region="us-east-1",
                                        arn=f"{db_info.get('CatalogId', '')}::{db_name}::{table_name}",
                                        name=f"{db_name}.{table_name}",
                                        created_at=(
                                            table_info.get("CreateTime", "").isoformat()
                                            if table_info.get("CreateTime")
                                            else None
                                        ),
                                        tags=table_tags,
                                        risk_flags=risk_flags,
                                        ownership_confidence=table_ownership["confidence"],
                                        suggested_owner=table_ownership["owner"],
                                        usage_metrics={"partition_count": partition_count},
                                    )
                                )
                    except ClientError:
                        pass

        except ClientError as e:
            print(f"Error collecting Glue resources: {e}")

        return assets

    def _get_tags(self, resource_arn: str) -> dict[str, str]:
        """Get tags for a Glue resource."""
        try:
            # Glue uses get_tags API
            response = self.glue_client.get_tags(ResourceArn=resource_arn)
            return response.get("Tags", {})
        except ClientError:
            return {}

    def _infer_ownership(self, tags: dict[str, str], name: str) -> dict[str, str]:
        """Infer ownership from tags."""
        owner = None
        confidence = "unknown"

        if "owner" in tags:
            owner = tags["owner"]
            confidence = "high"
        elif "team" in tags:
            owner = tags["team"]
            confidence = "medium"

        return {"owner": owner, "confidence": confidence}

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for Glue asset."""
        return asset.usage_metrics or {}

    def get_cost_estimate(self, asset: Asset) -> float:
        """Estimate cost for Glue asset."""
        # Glue Data Catalog: $1 per 100,000 objects per month
        # Tables and partitions count as objects
        if asset.asset_type == "glue_table":
            # Approximate: $0.01 per table per month
            return 0.01
        return 0.0
