"""
DynamoDB collector for AWS.

Collects DynamoDB tables and their configurations for NoSQL governance.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class DynamoDBCollector:
    """Collects AWS DynamoDB tables."""

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
        """Collect all DynamoDB tables."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for DynamoDB tables...", file=sys.stderr)

        for region in regions:
            try:
                dynamodb = self.session.client("dynamodb", region_name=region)
                paginator = dynamodb.get_paginator("list_tables")

                for page in paginator.paginate():
                    for table_name in page.get("TableNames", []):
                        try:
                            # Get table details
                            table_info = dynamodb.describe_table(TableName=table_name)
                            table = table_info.get("Table", {})

                            table_arn = table.get("TableArn", "")
                            table_status = table.get("TableStatus", "")
                            creation_time = table.get("CreationDateTime")

                            # Get billing mode
                            billing_mode = table.get("BillingModeSummary", {}).get(
                                "BillingMode", "PROVISIONED"
                            )

                            # Get capacity
                            provisioned = table.get("ProvisionedThroughput", {})
                            read_capacity = provisioned.get("ReadCapacityUnits", 0)
                            write_capacity = provisioned.get("WriteCapacityUnits", 0)

                            # Get size
                            size_bytes = table.get("TableSizeBytes", 0)
                            item_count = table.get("ItemCount", 0)

                            # Check encryption
                            sse_description = table.get("SSEDescription", {})
                            encrypted = sse_description.get("Status") == "ENABLED"
                            sse_type = sse_description.get("SSEType", "")

                            # Check Point-in-time recovery
                            pitr_enabled = False
                            try:
                                pitr_response = dynamodb.describe_continuous_backups(
                                    TableName=table_name
                                )
                                pitr_status = pitr_response.get(
                                    "ContinuousBackupsDescription", {}
                                ).get("PointInTimeRecoveryDescription", {})
                                pitr_enabled = (
                                    pitr_status.get("PointInTimeRecoveryStatus") == "ENABLED"
                                )
                            except ClientError:
                                pass

                            # Get TTL status
                            ttl_enabled = False
                            try:
                                ttl_response = dynamodb.describe_time_to_live(TableName=table_name)
                                ttl_enabled = (
                                    ttl_response.get("TimeToLiveDescription", {}).get(
                                        "TimeToLiveStatus"
                                    )
                                    == "ENABLED"
                                )
                            except ClientError:
                                pass

                            # Get tags
                            tags = {}
                            try:
                                tags_response = dynamodb.list_tags_of_resource(
                                    ResourceArn=table_arn
                                )
                                tags = {t["Key"]: t["Value"] for t in tags_response.get("Tags", [])}
                            except ClientError:
                                pass

                            ownership = self._infer_ownership(tags, table_name)

                            # Build risk flags
                            risk_flags = []
                            if not encrypted:
                                risk_flags.append("unencrypted")
                            if encrypted and sse_type == "AES256":
                                risk_flags.append("using_aws_managed_key")
                            if not pitr_enabled:
                                risk_flags.append("pitr_disabled")
                            if (
                                billing_mode == "PROVISIONED"
                                and read_capacity == 0
                                and write_capacity == 0
                            ):
                                risk_flags.append("zero_capacity")

                            # Estimate cost
                            monthly_cost = self._estimate_cost(
                                billing_mode, read_capacity, write_capacity, size_bytes
                            )

                            assets.append(
                                Asset(
                                    provider="aws",
                                    asset_type="dynamodb_table",
                                    normalized_category=NormalizedCategory.DATABASE,
                                    service="DynamoDB",
                                    region=region,
                                    arn=table_arn,
                                    name=table_name,
                                    created_at=creation_time.isoformat() if creation_time else None,
                                    tags=tags,
                                    risk_flags=risk_flags,
                                    ownership_confidence=ownership["confidence"],
                                    suggested_owner=ownership["owner"],
                                    size_bytes=size_bytes,
                                    cost_estimate_usd=monthly_cost,
                                    usage_metrics={
                                        "table_name": table_name,
                                        "table_status": table_status,
                                        "billing_mode": billing_mode,
                                        "read_capacity_units": read_capacity,
                                        "write_capacity_units": write_capacity,
                                        "size_bytes": size_bytes,
                                        "size_gb": round(size_bytes / (1024**3), 2),
                                        "item_count": item_count,
                                        "encrypted": encrypted,
                                        "sse_type": sse_type,
                                        "pitr_enabled": pitr_enabled,
                                        "ttl_enabled": ttl_enabled,
                                        "global_secondary_indexes": len(
                                            table.get("GlobalSecondaryIndexes", [])
                                        ),
                                        "local_secondary_indexes": len(
                                            table.get("LocalSecondaryIndexes", [])
                                        ),
                                        "stream_enabled": bool(
                                            table.get("StreamSpecification", {}).get(
                                                "StreamEnabled"
                                            )
                                        ),
                                    },
                                )
                            )

                        except ClientError as e:
                            if "AccessDenied" not in str(e):
                                continue

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting DynamoDB tables in {region}: {e}")

        print(f"  → Found {len(assets)} DynamoDB tables", file=sys.stderr)
        return assets

    def _estimate_cost(
        self, billing_mode: str, read_capacity: int, write_capacity: int, size_bytes: int
    ) -> float:
        """Estimate monthly cost for DynamoDB table."""
        # Storage cost: $0.25/GB-month
        storage_gb = size_bytes / (1024**3)
        storage_cost = storage_gb * 0.25

        if billing_mode == "PAY_PER_REQUEST":
            # On-demand: estimate based on storage only (requests are pay-per-use)
            return storage_cost + 5.0  # Minimum estimate

        # Provisioned: $0.00065/RCU-hour, $0.00065/WCU-hour
        hours_per_month = 730
        rcu_cost = read_capacity * 0.00013 * hours_per_month
        wcu_cost = write_capacity * 0.00065 * hours_per_month

        return storage_cost + rcu_cost + wcu_cost

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
        """Get usage metrics for DynamoDB table."""
        return asset.usage_metrics or {}
