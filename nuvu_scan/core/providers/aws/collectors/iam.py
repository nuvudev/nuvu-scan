"""
IAM collector for AWS.

Collects IAM roles, policies, and users with data-access permissions.
"""

from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class IAMCollector:
    """Collects IAM roles, policies, and users with data-access permissions."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []
        # IAM is global, but we use us-east-1 for the client
        self.iam_client = session.client("iam", region_name="us-east-1")
        self.cloudtrail_client = session.client("cloudtrail", region_name="us-east-1")

    def collect(self) -> list[Asset]:
        """Collect IAM roles with data-access permissions."""
        import sys
        
        assets = []

        try:
            # List all IAM roles
            print("  → Listing IAM roles...", file=sys.stderr)
            paginator = self.iam_client.get_paginator("list_roles")
            roles = []

            for page in paginator.paginate():
                roles.extend(page.get("Roles", []))

            print(f"  → Found {len(roles)} roles, checking data-access permissions...", file=sys.stderr)
            data_roles_count = 0
            for role in roles:
                try:
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    created_at = role.get("CreateDate")
                    created_at_str = created_at.isoformat() if created_at else None

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
                        # Skip roles without data-access permissions
                        continue

                    # Get last usage (when role was last assumed)
                    last_used = role_doc.get("RoleLastUsed", {})
                    last_activity = None
                    if last_used.get("LastUsedDate"):
                        last_activity = last_used["LastUsedDate"].isoformat()

                    # Calculate days since last use
                    idle_days = 0
                    if last_activity:
                        last_used_date = datetime.fromisoformat(
                            last_activity.replace("Z", "+00:00")
                        )
                        idle_days = (datetime.utcnow() - last_used_date.replace(tzinfo=None)).days
                    else:
                        # Never used
                        if created_at:
                            idle_days = (datetime.utcnow() - created_at.replace(tzinfo=None)).days

                    # Build risk flags
                    risk_flags = []
                    if idle_days > 90:
                        risk_flags.append("unused_role")
                    if not last_activity:
                        risk_flags.append("never_used")
                    if self._has_overly_permissive_policies(role_name, attached_policies):
                        risk_flags.append("overly_permissive")

                    # Get tags
                    try:
                        tags_response = self.iam_client.list_role_tags(RoleName=role_name)
                        tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}
                    except Exception:
                        tags = {}

                    # Infer ownership
                    ownership = self._infer_ownership(tags, role_name)

                    asset = Asset(
                        provider="aws",
                        asset_type="iam_role",
                        normalized_category=NormalizedCategory.SECURITY,
                        service="IAM",
                        region="global",  # IAM is global
                        arn=role_arn,
                        name=role_name,
                        created_at=created_at_str,
                        last_activity_at=last_activity,
                        tags=tags,
                        cost_estimate_usd=0.0,  # IAM roles are free
                        risk_flags=risk_flags,
                        ownership_confidence=ownership["confidence"],
                        suggested_owner=ownership["owner"],
                        usage_metrics={
                            "last_used": last_activity,
                            "idle_days": idle_days,
                            "days_since_last_use": idle_days,
                            "attached_policies_count": len(
                                attached_policies.get("AttachedPolicies", [])
                            ),
                            "inline_policies_count": len(inline_policies.get("PolicyNames", [])),
                            "last_used_region": last_used.get("Region"),
                        },
                    )

                    assets.append(asset)
                    data_roles_count += 1

                except ClientError as e:
                    # Skip roles we can't access
                    print(f"Error accessing IAM role {role.get('RoleName', 'unknown')}: {e}")
                    continue

        except Exception as e:
            import sys

            print(f"ERROR: Error listing IAM roles: {type(e).__name__}: {e}", file=sys.stderr)

        return assets

    def _has_data_access_permissions(
        self, role_name: str, attached_policies: dict, inline_policies: dict
    ) -> bool:
        """Check if role has permissions to access data services."""
        # Check attached policies
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

        # Check inline policies
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
        """Check if role has overly permissive policies (e.g., *:*)."""
        overly_permissive_patterns = ["*", "s3:*", "glue:*", "athena:*"]

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

    def _infer_ownership(self, tags: dict[str, str], role_name: str) -> dict[str, str]:
        """Infer ownership from tags or naming."""
        owner = None
        confidence = "unknown"

        # Check tags
        if "Owner" in tags:
            owner = tags["Owner"]
            confidence = "high"
        elif "owner" in tags:
            owner = tags["owner"]
            confidence = "high"
        elif "Team" in tags:
            owner = tags["Team"]
            confidence = "medium"
        elif "team" in tags:
            owner = tags["team"]
            confidence = "medium"

        # Try to infer from role name
        if not owner:
            # Common patterns: team-name-role, project-name-role, service-name-role
            parts = role_name.split("-")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for IAM role."""
        return asset.usage_metrics or {}
