"""
Lambda collector for AWS.

Collects Lambda functions and their configurations for serverless governance.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class LambdaCollector:
    """Collects AWS Lambda functions."""

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
        """Collect all Lambda functions."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for Lambda functions...", file=sys.stderr)

        for region in regions:
            try:
                lambda_client = self.session.client("lambda", region_name=region)
                paginator = lambda_client.get_paginator("list_functions")

                for page in paginator.paginate():
                    for func in page.get("Functions", []):
                        func_name = func["FunctionName"]
                        func_arn = func.get("FunctionArn", "")
                        runtime = func.get("Runtime", "")
                        handler = func.get("Handler", "")
                        code_size = func.get("CodeSize", 0)
                        memory_size = func.get("MemorySize", 128)
                        timeout = func.get("Timeout", 3)
                        last_modified = func.get("LastModified", "")

                        # Get tags
                        tags = {}
                        try:
                            tags_response = lambda_client.list_tags(Resource=func_arn)
                            tags = tags_response.get("Tags", {})
                        except ClientError:
                            pass

                        ownership = self._infer_ownership(tags, func_name)

                        # Check for deprecated runtimes
                        deprecated_runtimes = [
                            "python2.7",
                            "python3.6",
                            "python3.7",
                            "nodejs10.x",
                            "nodejs12.x",
                            "nodejs14.x",
                            "dotnetcore2.1",
                            "dotnetcore3.1",
                            "ruby2.5",
                            "ruby2.7",
                        ]
                        is_deprecated = runtime in deprecated_runtimes

                        # Check VPC configuration
                        vpc_config = func.get("VpcConfig", {})
                        in_vpc = bool(vpc_config.get("VpcId"))

                        # Check environment variables for secrets
                        env_vars = func.get("Environment", {}).get("Variables", {})
                        has_potential_secrets = self._check_for_secrets(env_vars)

                        # Calculate age
                        age_days = None
                        if last_modified:
                            try:
                                last_mod_dt = datetime.fromisoformat(
                                    last_modified.replace("Z", "+00:00")
                                )
                                age_days = (datetime.now(timezone.utc) - last_mod_dt).days
                            except Exception:
                                pass

                        # Build risk flags
                        risk_flags = []
                        if is_deprecated:
                            risk_flags.append("deprecated_runtime")
                        if has_potential_secrets:
                            risk_flags.append("secrets_in_env_vars")
                        if timeout >= 900:  # 15 minutes max
                            risk_flags.append("max_timeout")
                        if memory_size >= 10240:  # 10GB max
                            risk_flags.append("max_memory")
                        if age_days and age_days > 365:
                            risk_flags.append("not_updated_year")

                        # Check for resource policy (public access)
                        try:
                            policy_response = lambda_client.get_policy(FunctionName=func_name)
                            policy = policy_response.get("Policy", "")
                            if '"Principal":"*"' in policy or '"Principal": "*"' in policy:
                                risk_flags.append("public_access")
                        except ClientError:
                            pass

                        # Parse last_modified for last_activity_at
                        last_activity_at = None
                        if last_modified:
                            try:
                                last_mod_dt = datetime.fromisoformat(
                                    last_modified.replace("Z", "+00:00")
                                )
                                last_activity_at = last_mod_dt.isoformat()
                            except Exception:
                                pass

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="lambda_function",
                                normalized_category=NormalizedCategory.COMPUTE,
                                service="Lambda",
                                region=region,
                                arn=func_arn,
                                name=func_name,
                                last_activity_at=last_activity_at,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                size_bytes=code_size,
                                usage_metrics={
                                    "function_name": func_name,
                                    "runtime": runtime,
                                    "handler": handler,
                                    "code_size_bytes": code_size,
                                    "memory_size_mb": memory_size,
                                    "timeout_seconds": timeout,
                                    "last_modified": last_modified,
                                    "age_days": age_days,
                                    "in_vpc": in_vpc,
                                    "vpc_id": vpc_config.get("VpcId", ""),
                                    "is_deprecated_runtime": is_deprecated,
                                    "has_env_vars": len(env_vars) > 0,
                                    "architectures": func.get("Architectures", ["x86_64"]),
                                    "package_type": func.get("PackageType", "Zip"),
                                },
                            )
                        )

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting Lambda functions in {region}: {e}")

        print(f"  → Found {len(assets)} Lambda functions", file=sys.stderr)
        return assets

    def _check_for_secrets(self, env_vars: dict) -> bool:
        """Check if environment variables might contain secrets."""
        secret_patterns = [
            "password",
            "secret",
            "api_key",
            "apikey",
            "token",
            "access_key",
            "private_key",
            "credential",
            "auth",
        ]

        for key in env_vars.keys():
            key_lower = key.lower()
            for pattern in secret_patterns:
                if pattern in key_lower:
                    return True

        return False

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
        """Get usage metrics for Lambda function."""
        return asset.usage_metrics or {}
