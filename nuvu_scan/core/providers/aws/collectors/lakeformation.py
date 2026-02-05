"""
Lake Formation collector for AWS.

Collects Lake Formation permissions and data lake settings for data governance.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class LakeFormationCollector:
    """Collects AWS Lake Formation resources."""

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
        """Collect all Lake Formation resources."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(
            f"  → Scanning {len(regions)} regions for Lake Formation resources...", file=sys.stderr
        )

        # Collect data lake settings
        print("  → Collecting data lake settings...", file=sys.stderr)
        settings_assets = self._collect_data_lake_settings(regions)
        assets.extend(settings_assets)
        print(f"  → Found {len(settings_assets)} data lake configurations", file=sys.stderr)

        # Collect permissions
        print("  → Collecting Lake Formation permissions...", file=sys.stderr)
        permission_assets = self._collect_permissions(regions)
        assets.extend(permission_assets)
        print(f"  → Found {len(permission_assets)} permission entries", file=sys.stderr)

        # Collect LF-Tags
        print("  → Collecting LF-Tags...", file=sys.stderr)
        tag_assets = self._collect_lf_tags(regions)
        assets.extend(tag_assets)
        print(f"  → Found {len(tag_assets)} LF-Tags", file=sys.stderr)

        return assets

    def _collect_data_lake_settings(self, regions: list[str]) -> list[Asset]:
        """Collect data lake settings."""
        assets = []

        for region in regions:
            try:
                lf = self.session.client("lakeformation", region_name=region)

                settings = lf.get_data_lake_settings()
                data_lake_settings = settings.get("DataLakeSettings", {})

                # Check administrators
                admins = data_lake_settings.get("DataLakeAdmins", [])
                create_db_default = data_lake_settings.get("CreateDatabaseDefaultPermissions", [])
                create_table_default = data_lake_settings.get("CreateTableDefaultPermissions", [])

                # Build risk flags
                risk_flags = []
                if len(admins) == 0:
                    risk_flags.append("no_data_lake_admins")
                if len(admins) > 5:
                    risk_flags.append("too_many_admins")

                # Check for overly permissive defaults
                for perm in create_db_default + create_table_default:
                    principal = perm.get("Principal", {}).get("DataLakePrincipalIdentifier", "")
                    if principal == "IAM_ALLOWED_PRINCIPALS":
                        risk_flags.append("legacy_iam_permissions_enabled")
                        break

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="lakeformation_settings",
                        normalized_category=NormalizedCategory.DATA_CATALOG,
                        service="Lake Formation",
                        region=region,
                        arn=f"arn:aws:lakeformation:{region}:{self._get_account_id()}:settings",
                        name=f"Lake Formation Settings ({region})",
                        tags={},
                        risk_flags=risk_flags,
                        usage_metrics={
                            "admin_count": len(admins),
                            "admins": [a.get("DataLakePrincipalIdentifier", "") for a in admins],
                            "uses_lf_permissions": not any(
                                "legacy_iam_permissions_enabled" in rf for rf in risk_flags
                            ),
                            "create_database_default_permissions": len(create_db_default),
                            "create_table_default_permissions": len(create_table_default),
                            "cross_account_version": data_lake_settings.get("Parameters", {}).get(
                                "CROSS_ACCOUNT_VERSION"
                            ),
                        },
                    )
                )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    pass

        return assets

    def _collect_permissions(self, regions: list[str]) -> list[Asset]:
        """Collect Lake Formation permissions."""
        assets = []

        for region in regions:
            try:
                lf = self.session.client("lakeformation", region_name=region)

                # List permissions
                paginator = lf.get_paginator("list_permissions")

                # Group permissions by principal
                permissions_by_principal: dict[str, list] = {}

                for page in paginator.paginate():
                    for perm in page.get("PrincipalResourcePermissions", []):
                        principal = perm.get("Principal", {}).get(
                            "DataLakePrincipalIdentifier", "unknown"
                        )
                        if principal not in permissions_by_principal:
                            permissions_by_principal[principal] = []
                        permissions_by_principal[principal].append(perm)

                # Create asset per principal
                for principal, perms in permissions_by_principal.items():
                    # Skip if IAM_ALLOWED_PRINCIPALS (legacy)
                    if principal == "IAM_ALLOWED_PRINCIPALS":
                        continue

                    # Analyze permissions
                    databases = set()
                    tables = set()
                    permission_types = set()
                    has_all_access = False
                    has_super = False

                    for perm in perms:
                        resource = perm.get("Resource", {})
                        permissions_list = perm.get("Permissions", [])

                        if "Database" in resource:
                            databases.add(resource["Database"].get("Name", ""))
                        if "Table" in resource:
                            tables.add(
                                f"{resource['Table'].get('DatabaseName', '')}.{resource['Table'].get('Name', '')}"
                            )

                        for p in permissions_list:
                            permission_types.add(p)
                            if p == "ALL":
                                has_all_access = True
                            if p == "SUPER":
                                has_super = True

                    # Build risk flags
                    risk_flags = []
                    if has_all_access:
                        risk_flags.append("has_all_permissions")
                    if has_super:
                        risk_flags.append("has_super_permissions")
                    if len(databases) > 10:
                        risk_flags.append("broad_database_access")

                    # Infer principal type
                    principal_type = "unknown"
                    if ":role/" in principal:
                        principal_type = "role"
                    elif ":user/" in principal:
                        principal_type = "user"
                    elif ":group/" in principal:
                        principal_type = "group"

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="lakeformation_permission",
                            normalized_category=NormalizedCategory.DATA_CATALOG,
                            service="Lake Formation",
                            region=region,
                            arn=f"arn:aws:lakeformation:{region}:{self._get_account_id()}:permission/{principal.split('/')[-1] if '/' in principal else principal[:20]}",
                            name=f"Permissions for {principal.split('/')[-1] if '/' in principal else principal[:30]}",
                            tags={},
                            risk_flags=risk_flags,
                            usage_metrics={
                                "principal": principal,
                                "principal_type": principal_type,
                                "databases_count": len(databases),
                                "tables_count": len(tables),
                                "permission_types": list(permission_types),
                                "total_grants": len(perms),
                                "has_all_access": has_all_access,
                                "has_super": has_super,
                            },
                        )
                    )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    pass

        return assets

    def _collect_lf_tags(self, regions: list[str]) -> list[Asset]:
        """Collect Lake Formation tags (LF-Tags)."""
        assets = []

        for region in regions:
            try:
                lf = self.session.client("lakeformation", region_name=region)

                # List LF-Tags
                tags_response = lf.list_lf_tags()
                lf_tags = tags_response.get("LFTags", [])

                for tag in lf_tags:
                    tag_key = tag.get("TagKey", "")
                    tag_values = tag.get("TagValues", [])
                    catalog_id = tag.get("CatalogId", self._get_account_id())

                    # Build risk flags
                    risk_flags = []
                    if len(tag_values) == 0:
                        risk_flags.append("empty_tag")
                    if len(tag_values) > 50:
                        risk_flags.append("too_many_values")

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="lf_tag",
                            normalized_category=NormalizedCategory.DATA_CATALOG,
                            service="Lake Formation",
                            region=region,
                            arn=f"arn:aws:lakeformation:{region}:{catalog_id}:tag/{tag_key}",
                            name=f"LF-Tag: {tag_key}",
                            tags={},
                            risk_flags=risk_flags,
                            usage_metrics={
                                "tag_key": tag_key,
                                "tag_values": tag_values,
                                "value_count": len(tag_values),
                                "catalog_id": catalog_id,
                            },
                        )
                    )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    pass

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
        """Get usage metrics for Lake Formation resource."""
        return asset.usage_metrics or {}
