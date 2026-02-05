"""
IAM collector for AWS.

Collects IAM roles, users, groups, policies, and access keys for comprehensive
identity and access governance.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class IAMCollector:
    """Collects IAM roles, users, groups, policies, and access keys."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []
        # IAM is global, but we use us-east-1 for the client
        self.iam_client = session.client("iam", region_name="us-east-1")
        self._account_id: str | None = None

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
        """Collect all IAM resources."""
        import sys

        assets = []

        # Collect IAM roles
        print("  → Collecting IAM roles...", file=sys.stderr)
        role_assets = self._collect_roles()
        assets.extend(role_assets)
        print(f"  → Found {len(role_assets)} IAM roles with data access", file=sys.stderr)

        # Collect IAM users
        print("  → Collecting IAM users...", file=sys.stderr)
        user_assets = self._collect_users()
        assets.extend(user_assets)
        print(f"  → Found {len(user_assets)} IAM users", file=sys.stderr)

        # Collect IAM groups
        print("  → Collecting IAM groups...", file=sys.stderr)
        group_assets = self._collect_groups()
        assets.extend(group_assets)
        print(f"  → Found {len(group_assets)} IAM groups", file=sys.stderr)

        # Collect access keys
        print("  → Collecting access keys...", file=sys.stderr)
        key_assets = self._collect_access_keys()
        assets.extend(key_assets)
        print(f"  → Found {len(key_assets)} access keys", file=sys.stderr)

        return assets

    def _collect_roles(self) -> list[Asset]:
        """Collect IAM roles with data-access permissions."""
        assets = []

        try:
            paginator = self.iam_client.get_paginator("list_roles")
            roles = []

            for page in paginator.paginate():
                roles.extend(page.get("Roles", []))

            for role in roles:
                try:
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    created_at = role.get("CreateDate")

                    # Get role details
                    role_details = self.iam_client.get_role(RoleName=role_name)
                    role_doc = role_details.get("Role", {})

                    # Get attached policies
                    attached_policies = self.iam_client.list_attached_role_policies(
                        RoleName=role_name
                    )
                    inline_policies = self.iam_client.list_role_policies(RoleName=role_name)

                    # Check if role has data-access permissions
                    has_data_access = self._has_data_access_permissions(
                        role_name, attached_policies, inline_policies
                    )

                    if not has_data_access:
                        continue

                    # Get last usage
                    last_used = role_doc.get("RoleLastUsed", {})
                    last_activity = None
                    if last_used.get("LastUsedDate"):
                        last_activity = last_used["LastUsedDate"].isoformat()

                    # Calculate idle days
                    idle_days = 0
                    if last_activity:
                        last_used_date = datetime.fromisoformat(
                            last_activity.replace("Z", "+00:00")
                        )
                        idle_days = (datetime.now(timezone.utc) - last_used_date).days
                    elif created_at:
                        idle_days = (
                            datetime.now(timezone.utc) - created_at.replace(tzinfo=timezone.utc)
                        ).days

                    # Build risk flags
                    risk_flags = []
                    if idle_days > 90:
                        risk_flags.append("unused_role")
                    if not last_activity:
                        risk_flags.append("never_used")
                    if self._has_overly_permissive_policies(role_name, attached_policies):
                        risk_flags.append("overly_permissive")

                    # Get tags
                    tags = {}
                    try:
                        tags_response = self.iam_client.list_role_tags(RoleName=role_name)
                        tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}
                    except Exception:
                        pass

                    ownership = self._infer_ownership(tags, role_name)

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="iam_role",
                            normalized_category=NormalizedCategory.SECURITY,
                            service="IAM",
                            region="global",
                            arn=role_arn,
                            name=role_name,
                            created_at=created_at.isoformat() if created_at else None,
                            last_activity_at=last_activity,
                            tags=tags,
                            cost_estimate_usd=0.0,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            usage_metrics={
                                "last_used": last_activity,
                                "idle_days": idle_days,
                                "attached_policies_count": len(
                                    attached_policies.get("AttachedPolicies", [])
                                ),
                                "inline_policies_count": len(
                                    inline_policies.get("PolicyNames", [])
                                ),
                                "last_used_region": last_used.get("Region"),
                                "assume_role_policy": role.get("AssumeRolePolicyDocument", {}),
                            },
                        )
                    )

                except ClientError:
                    continue

        except Exception as e:
            import sys

            print(f"ERROR: Error listing IAM roles: {e}", file=sys.stderr)

        return assets

    def _collect_users(self) -> list[Asset]:
        """Collect IAM users."""
        assets = []

        try:
            paginator = self.iam_client.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]
                    created_at = user.get("CreateDate")
                    password_last_used = user.get("PasswordLastUsed")

                    # Calculate idle days
                    idle_days = 0
                    if password_last_used:
                        idle_days = (
                            datetime.now(timezone.utc)
                            - password_last_used.replace(tzinfo=timezone.utc)
                        ).days
                    elif created_at:
                        idle_days = (
                            datetime.now(timezone.utc) - created_at.replace(tzinfo=timezone.utc)
                        ).days

                    # Get MFA devices
                    mfa_devices = []
                    try:
                        mfa_response = self.iam_client.list_mfa_devices(UserName=user_name)
                        mfa_devices = mfa_response.get("MFADevices", [])
                    except ClientError:
                        pass

                    # Get access keys
                    access_keys = []
                    try:
                        keys_response = self.iam_client.list_access_keys(UserName=user_name)
                        access_keys = keys_response.get("AccessKeyMetadata", [])
                    except ClientError:
                        pass

                    # Get groups
                    groups = []
                    try:
                        groups_response = self.iam_client.list_groups_for_user(UserName=user_name)
                        groups = [g["GroupName"] for g in groups_response.get("Groups", [])]
                    except ClientError:
                        pass

                    # Get attached policies
                    attached_policies = []
                    try:
                        policies_response = self.iam_client.list_attached_user_policies(
                            UserName=user_name
                        )
                        attached_policies = [
                            p["PolicyName"] for p in policies_response.get("AttachedPolicies", [])
                        ]
                    except ClientError:
                        pass

                    # Build risk flags
                    risk_flags = []
                    if len(mfa_devices) == 0:
                        risk_flags.append("mfa_disabled")
                    if idle_days > 90:
                        risk_flags.append("inactive_user")
                    if len(access_keys) > 1:
                        risk_flags.append("multiple_access_keys")
                    if "AdministratorAccess" in attached_policies:
                        risk_flags.append("admin_access")

                    # Get tags
                    tags = {}
                    try:
                        tags_response = self.iam_client.list_user_tags(UserName=user_name)
                        tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}
                    except ClientError:
                        pass

                    ownership = self._infer_ownership(tags, user_name)

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="iam_user",
                            normalized_category=NormalizedCategory.SECURITY,
                            service="IAM",
                            region="global",
                            arn=user_arn,
                            name=user_name,
                            created_at=created_at.isoformat() if created_at else None,
                            last_activity_at=password_last_used.isoformat()
                            if password_last_used
                            else None,
                            tags=tags,
                            cost_estimate_usd=0.0,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            usage_metrics={
                                "idle_days": idle_days,
                                "mfa_enabled": len(mfa_devices) > 0,
                                "mfa_device_count": len(mfa_devices),
                                "access_key_count": len(access_keys),
                                "groups": groups,
                                "attached_policies": attached_policies,
                                "password_last_used": password_last_used.isoformat()
                                if password_last_used
                                else None,
                            },
                        )
                    )

        except Exception as e:
            import sys

            print(f"ERROR: Error listing IAM users: {e}", file=sys.stderr)

        return assets

    def _collect_groups(self) -> list[Asset]:
        """Collect IAM groups."""
        assets = []

        try:
            paginator = self.iam_client.get_paginator("list_groups")

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group["GroupName"]
                    group_arn = group["Arn"]
                    created_at = group.get("CreateDate")

                    # Get group members
                    members = []
                    try:
                        members_response = self.iam_client.get_group(GroupName=group_name)
                        members = [u["UserName"] for u in members_response.get("Users", [])]
                    except ClientError:
                        pass

                    # Get attached policies
                    attached_policies = []
                    try:
                        policies_response = self.iam_client.list_attached_group_policies(
                            GroupName=group_name
                        )
                        attached_policies = [
                            p["PolicyName"] for p in policies_response.get("AttachedPolicies", [])
                        ]
                    except ClientError:
                        pass

                    # Build risk flags
                    risk_flags = []
                    if len(members) == 0:
                        risk_flags.append("empty_group")
                    if "AdministratorAccess" in attached_policies:
                        risk_flags.append("admin_access")
                    if "*" in str(attached_policies):
                        risk_flags.append("wildcard_permissions")

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="iam_group",
                            normalized_category=NormalizedCategory.SECURITY,
                            service="IAM",
                            region="global",
                            arn=group_arn,
                            name=group_name,
                            created_at=created_at.isoformat() if created_at else None,
                            tags={},
                            cost_estimate_usd=0.0,
                            risk_flags=risk_flags,
                            usage_metrics={
                                "member_count": len(members),
                                "members": members,
                                "attached_policies": attached_policies,
                            },
                        )
                    )

        except Exception as e:
            import sys

            print(f"ERROR: Error listing IAM groups: {e}", file=sys.stderr)

        return assets

    def _collect_access_keys(self) -> list[Asset]:
        """Collect access keys for all users."""
        assets = []

        try:
            # Get all users first
            paginator = self.iam_client.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

            for user in users:
                user_name = user["UserName"]

                try:
                    keys_response = self.iam_client.list_access_keys(UserName=user_name)

                    for key in keys_response.get("AccessKeyMetadata", []):
                        access_key_id = key["AccessKeyId"]
                        status = key["Status"]
                        created_at = key.get("CreateDate")

                        # Get last used info
                        last_used = None
                        last_used_service = None
                        last_used_region = None
                        try:
                            usage_response = self.iam_client.get_access_key_last_used(
                                AccessKeyId=access_key_id
                            )
                            access_key_last_used = usage_response.get("AccessKeyLastUsed", {})
                            if access_key_last_used.get("LastUsedDate"):
                                last_used = access_key_last_used["LastUsedDate"]
                                last_used_service = access_key_last_used.get("ServiceName")
                                last_used_region = access_key_last_used.get("Region")
                        except ClientError:
                            pass

                        # Calculate age
                        age_days = 0
                        if created_at:
                            age_days = (
                                datetime.now(timezone.utc) - created_at.replace(tzinfo=timezone.utc)
                            ).days

                        # Calculate idle days
                        idle_days = age_days
                        if last_used:
                            idle_days = (
                                datetime.now(timezone.utc) - last_used.replace(tzinfo=timezone.utc)
                            ).days

                        # Build risk flags
                        risk_flags = []
                        if age_days > 90:
                            risk_flags.append("old_key")
                        if age_days > 365:
                            risk_flags.append("very_old_key")
                        if idle_days > 90:
                            risk_flags.append("unused_key")
                        if status == "Active" and idle_days > 365:
                            risk_flags.append("active_but_unused")
                        if status == "Inactive":
                            risk_flags.append("inactive_key")

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="access_key",
                                normalized_category=NormalizedCategory.SECURITY,
                                service="IAM",
                                region="global",
                                arn=f"arn:aws:iam::{self._get_account_id()}:access-key/{access_key_id}",
                                name=f"{user_name}/{access_key_id[:8]}...",
                                created_at=created_at.isoformat() if created_at else None,
                                last_activity_at=last_used.isoformat() if last_used else None,
                                tags={},
                                cost_estimate_usd=0.0,
                                risk_flags=risk_flags,
                                usage_metrics={
                                    "access_key_id": access_key_id,
                                    "user_name": user_name,
                                    "status": status,
                                    "age_days": age_days,
                                    "idle_days": idle_days,
                                    "last_used_service": last_used_service,
                                    "last_used_region": last_used_region,
                                },
                            )
                        )

                except ClientError:
                    continue

        except Exception as e:
            import sys

            print(f"ERROR: Error listing access keys: {e}", file=sys.stderr)

        return assets

    def _has_data_access_permissions(
        self, role_name: str, attached_policies: dict, inline_policies: dict
    ) -> bool:
        """Check if role has permissions to access data services."""
        for policy in attached_policies.get("AttachedPolicies", []):
            try:
                policy_arn = policy["PolicyArn"]
                policy_doc = self.iam_client.get_policy(PolicyArn=policy_arn)
                policy_version = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_doc["Policy"]["DefaultVersionId"],
                )

                if self._policy_has_data_access(policy_version["PolicyVersion"]["Document"]):
                    return True
            except Exception:
                continue

        for policy_name in inline_policies.get("PolicyNames", []):
            try:
                policy_doc = self.iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                if self._policy_has_data_access(policy_doc["PolicyDocument"]):
                    return True
            except Exception:
                continue

        return False

    def _policy_has_data_access(self, policy_document: dict) -> bool:
        """Check if policy document grants data service access."""
        data_services = [
            "s3",
            "glue",
            "athena",
            "redshift",
            "dynamodb",
            "rds",
            "emr",
            "kinesis",
            "kafka",
            "sagemaker",
            "lakeformation",
            "secretsmanager",
            "kms",
        ]

        statements = policy_document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect", "Deny")
            if effect != "Allow":
                continue

            actions = statement.get("Action", [])
            if not isinstance(actions, list):
                actions = [actions]

            for action in actions:
                action_lower = action.lower()
                for service in data_services:
                    if action_lower.startswith(f"{service}:"):
                        return True

        return False

    def _has_overly_permissive_policies(self, role_name: str, attached_policies: dict) -> bool:
        """Check if role has overly permissive policies."""
        overly_permissive_patterns = ["*", "s3:*", "glue:*", "athena:*", "redshift:*"]

        for policy in attached_policies.get("AttachedPolicies", []):
            try:
                policy_arn = policy["PolicyArn"]
                policy_doc = self.iam_client.get_policy(PolicyArn=policy_arn)
                policy_version = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_doc["Policy"]["DefaultVersionId"],
                )

                statements = policy_version["PolicyVersion"]["Document"].get("Statement", [])
                for statement in statements:
                    if statement.get("Effect") == "Allow":
                        actions = statement.get("Action", [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        for action in actions:
                            if action in overly_permissive_patterns:
                                return True
            except Exception:
                continue

        return False

    def _infer_ownership(self, tags: dict[str, str], name: str) -> dict[str, str]:
        """Infer ownership from tags or naming."""
        owner = None
        confidence = "unknown"

        for key in ["owner", "Owner", "team", "Team", "created-by", "CreatedBy"]:
            if key in tags:
                owner = tags[key]
                confidence = "high" if key.lower() == "owner" else "medium"
                break

        if not owner:
            parts = name.split("-")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for IAM resource."""
        return asset.usage_metrics or {}
