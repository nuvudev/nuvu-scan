"""
AWS Miscellaneous Services Collector - Systems Manager, Step Functions, EFS.

Collects various AWS services not covered by other collectors.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class SystemsManagerCollector:
    """Collector for AWS Systems Manager resources."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect Systems Manager resources."""
        assets = []

        for region in self.regions:
            try:
                ssm = self.session.client("ssm", region_name=region)

                # Collect Parameter Store parameters
                assets.extend(self._collect_parameters(ssm, region))

            except Exception as e:
                logger.warning(f"Error collecting Systems Manager in {region}: {e}")

        return assets

    def _collect_parameters(self, ssm, region: str) -> list[Asset]:
        """Collect Parameter Store parameters (especially SecureString)."""
        assets = []

        try:
            paginator = ssm.get_paginator("describe_parameters")

            # Count parameters by type
            standard_count = 0
            advanced_count = 0
            secure_count = 0

            for page in paginator.paginate():
                for param in page.get("Parameters", []):
                    param_type = param.get("Type", "String")
                    tier = param.get("Tier", "Standard")

                    if tier == "Advanced":
                        advanced_count += 1
                    else:
                        standard_count += 1

                    if param_type == "SecureString":
                        secure_count += 1

            # Create a summary asset for the region
            # Parameter Store pricing: Free for standard, $0.05/month for advanced
            estimated_cost = advanced_count * 0.05

            risk_flags = []
            if secure_count == 0 and standard_count > 10:
                risk_flags.append("no_secure_strings")  # Consider using SecureString

            assets.append(
                Asset(
                    provider="aws",
                    asset_type="ssm_parameter_store",
                    normalized_category=NormalizedCategory.SECURITY,
                    service="Systems Manager",
                    region=region,
                    arn=f"arn:aws:ssm:{region}:{self.account_id}:parameter-store",
                    name=f"ParameterStore-{region}",
                    tags={},
                    cost_estimate_usd=estimated_cost,
                    usage_metrics={
                        "total_parameters": standard_count + advanced_count,
                        "standard_count": standard_count,
                        "advanced_count": advanced_count,
                        "secure_string_count": secure_count,
                    },
                    risk_flags=risk_flags if risk_flags else None,
                    ownership_confidence="unknown",
                    suggested_owner=None,
                )
            )

        except Exception as e:
            logger.warning(f"Error collecting parameters: {e}")

        return assets


class StepFunctionsCollector:
    """Collector for AWS Step Functions state machines."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect Step Functions state machines."""
        assets = []

        for region in self.regions:
            try:
                sfn = self.session.client("stepfunctions", region_name=region)
                assets.extend(self._collect_state_machines(sfn, region))
            except Exception as e:
                logger.warning(f"Error collecting Step Functions in {region}: {e}")

        return assets

    def _collect_state_machines(self, sfn, region: str) -> list[Asset]:
        """Collect state machines."""
        assets = []

        try:
            paginator = sfn.get_paginator("list_state_machines")
            for page in paginator.paginate():
                for sm in page.get("stateMachines", []):
                    sm_arn = sm["stateMachineArn"]
                    sm_name = sm["name"]
                    sm_type = sm.get("type", "STANDARD")  # STANDARD or EXPRESS

                    # Get details
                    details = {}
                    tags = {}
                    try:
                        details = sfn.describe_state_machine(stateMachineArn=sm_arn)
                        tag_response = sfn.list_tags_for_resource(resourceArn=sm_arn)
                        for tag in tag_response.get("tags", []):
                            tags[tag["key"]] = tag["value"]
                    except Exception:
                        pass

                    # Step Functions pricing:
                    # Standard: $0.025 per 1000 state transitions
                    # Express: $1.00 per million requests + $0.00001667 per GB-second
                    estimated_cost = 5.0  # Rough estimate

                    risk_flags = []
                    if sm_type == "STANDARD":
                        # Standard workflows can be expensive at high volume
                        risk_flags.append("standard_type")

                    # Check logging
                    logging_config = details.get("loggingConfiguration", {})
                    if logging_config.get("level") in [None, "OFF"]:
                        risk_flags.append("no_logging")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="state_machine",
                            normalized_category=NormalizedCategory.SERVERLESS,
                            service="Step Functions",
                            region=region,
                            arn=sm_arn,
                            name=sm_name,
                            created_at=sm.get("creationDate", "").isoformat()
                            if sm.get("creationDate")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "state_machine_name": sm_name,
                                "type": sm_type,
                                "status": details.get("status"),
                                "role_arn": details.get("roleArn"),
                                "logging_level": logging_config.get("level"),
                                "tracing_enabled": details.get("tracingConfiguration", {}).get(
                                    "enabled", False
                                ),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting state machines: {e}")

        return assets


class EFSCollector:
    """Collector for Amazon Elastic File System."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect EFS file systems."""
        assets = []

        for region in self.regions:
            try:
                efs = self.session.client("efs", region_name=region)
                assets.extend(self._collect_file_systems(efs, region))
            except Exception as e:
                logger.warning(f"Error collecting EFS in {region}: {e}")

        return assets

    def _collect_file_systems(self, efs, region: str) -> list[Asset]:
        """Collect EFS file systems."""
        assets = []

        try:
            paginator = efs.get_paginator("describe_file_systems")
            for page in paginator.paginate():
                for fs in page.get("FileSystems", []):
                    fs_id = fs["FileSystemId"]
                    fs_arn = fs.get(
                        "FileSystemArn",
                        f"arn:aws:elasticfilesystem:{region}:{self.account_id}:file-system/{fs_id}",
                    )
                    lifecycle_state = fs.get("LifeCycleState", "unknown")

                    # Get size
                    size_bytes = fs.get("SizeInBytes", {}).get("Value", 0)
                    size_gb = size_bytes / (1024**3)

                    # Get tags
                    tags = {t["Key"]: t["Value"] for t in fs.get("Tags", [])}
                    name = tags.get("Name", fs_id)

                    # Get performance and throughput mode
                    performance_mode = fs.get("PerformanceMode", "generalPurpose")
                    throughput_mode = fs.get("ThroughputMode", "bursting")

                    # EFS pricing: ~$0.30/GB-month for Standard, ~$0.025/GB-month for IA
                    # Simplified estimate based on Standard storage
                    estimated_cost = size_gb * 0.30

                    risk_flags = []
                    if lifecycle_state != "available":
                        risk_flags.append("not_available")
                    if size_bytes == 0:
                        risk_flags.append("empty_file_system")
                    if not fs.get("Encrypted"):
                        risk_flags.append("not_encrypted")

                    # Check if lifecycle management is enabled
                    lifecycle_policies = []
                    try:
                        lc_response = efs.describe_lifecycle_configuration(FileSystemId=fs_id)
                        lifecycle_policies = lc_response.get("LifecyclePolicies", [])
                    except Exception:
                        pass

                    if not lifecycle_policies:
                        risk_flags.append("no_lifecycle_policy")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="efs_file_system",
                            normalized_category=NormalizedCategory.STORAGE,
                            service="EFS",
                            region=region,
                            arn=fs_arn,
                            name=name,
                            created_at=fs.get("CreationTime", "").isoformat()
                            if fs.get("CreationTime")
                            else None,
                            size_bytes=size_bytes,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "file_system_id": fs_id,
                                "lifecycle_state": lifecycle_state,
                                "size_gb": round(size_gb, 2),
                                "performance_mode": performance_mode,
                                "throughput_mode": throughput_mode,
                                "provisioned_throughput_mibps": fs.get(
                                    "ProvisionedThroughputInMibps"
                                ),
                                "encrypted": fs.get("Encrypted", False),
                                "kms_key_id": fs.get("KmsKeyId"),
                                "number_of_mount_targets": fs.get("NumberOfMountTargets", 0),
                                "lifecycle_policies": [
                                    p.get("TransitionToIA") for p in lifecycle_policies
                                ],
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting file systems: {e}")

        return assets
