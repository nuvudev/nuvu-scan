"""
AWS Security Services Collector - GuardDuty, Inspector, Security Hub, Config.

Collects security monitoring and compliance resources.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class SecurityServicesCollector:
    """Collector for AWS security monitoring services."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect security service configurations."""
        assets = []

        for region in self.regions:
            try:
                # GuardDuty
                assets.extend(self._collect_guardduty(region))

                # Inspector
                assets.extend(self._collect_inspector(region))

                # Security Hub
                assets.extend(self._collect_security_hub(region))

                # AWS Config
                assets.extend(self._collect_config(region))

            except Exception as e:
                logger.warning(f"Error collecting security services in {region}: {e}")

        return assets

    def _collect_guardduty(self, region: str) -> list[Asset]:
        """Collect GuardDuty detectors."""
        assets = []

        try:
            guardduty = self.session.client("guardduty", region_name=region)

            # List detectors
            response = guardduty.list_detectors()
            detector_ids = response.get("DetectorIds", [])

            for detector_id in detector_ids:
                # Get detector details
                details = guardduty.get_detector(DetectorId=detector_id)
                status = details.get("Status", "DISABLED")

                # Get finding statistics
                finding_stats = {}
                try:
                    stats_response = guardduty.get_findings_statistics(
                        DetectorId=detector_id, FindingStatisticTypes=["COUNT_BY_SEVERITY"]
                    )
                    finding_stats = stats_response.get("FindingStatistics", {})
                except Exception:
                    pass

                # Get tags
                tags = details.get("Tags", {})

                # GuardDuty pricing is complex - based on data analyzed
                # Rough estimate: ~$4/million events + $1/GB VPC flow logs
                estimated_cost = 100.0  # Rough estimate

                risk_flags = []
                if status != "ENABLED":
                    risk_flags.append("disabled")

                # Check data sources
                data_sources = details.get("DataSources", {})
                if not data_sources.get("S3Logs", {}).get("Status") == "ENABLED":
                    risk_flags.append("s3_logs_disabled")
                if (
                    not data_sources.get("Kubernetes", {}).get("AuditLogs", {}).get("Status")
                    == "ENABLED"
                ):
                    risk_flags.append("k8s_audit_disabled")

                owner = (
                    tags.get("team") or tags.get("owner") or tags.get("Team") or tags.get("Owner")
                )

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="guardduty_detector",
                        normalized_category=NormalizedCategory.SECURITY,
                        service="GuardDuty",
                        region=region,
                        arn=f"arn:aws:guardduty:{region}:{self.account_id}:detector/{detector_id}",
                        name=f"GuardDuty-{region}",
                        created_at=details.get("CreatedAt"),
                        tags=tags,
                        cost_estimate_usd=estimated_cost,
                        usage_metrics={
                            "detector_id": detector_id,
                            "status": status,
                            "finding_publishing_frequency": details.get(
                                "FindingPublishingFrequency"
                            ),
                            "service_role": details.get("ServiceRole"),
                            "finding_stats": finding_stats,
                        },
                        risk_flags=risk_flags if risk_flags else None,
                        ownership_confidence="high" if owner else "unknown",
                        suggested_owner=owner,
                    )
                )

        except Exception as e:
            if "AccessDenied" not in str(e):
                logger.warning(f"Error collecting GuardDuty: {e}")

        return assets

    def _collect_inspector(self, region: str) -> list[Asset]:
        """Collect Inspector v2 coverage."""
        assets = []

        try:
            inspector = self.session.client("inspector2", region_name=region)

            # Check account status
            response = inspector.batch_get_account_status(accountIds=[self.account_id])

            for account in response.get("accounts", []):
                status = account.get("state", {}).get("status", "DISABLED")
                resource_state = account.get("resourceState", {})

                # Count enabled resource types
                enabled_types = []
                for resource_type, state in resource_state.items():
                    if state.get("status") == "ENABLED":
                        enabled_types.append(resource_type)

                # Inspector v2 pricing: $0.01 per ECR image scan, $0.90 per instance/month
                estimated_cost = 50.0  # Rough estimate

                risk_flags = []
                if status != "ENABLED":
                    risk_flags.append("disabled")
                if "ec2" not in [t.lower() for t in enabled_types]:
                    risk_flags.append("ec2_scanning_disabled")
                if "ecr" not in [t.lower() for t in enabled_types]:
                    risk_flags.append("ecr_scanning_disabled")
                if "lambda" not in [t.lower() for t in enabled_types]:
                    risk_flags.append("lambda_scanning_disabled")

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="inspector_coverage",
                        normalized_category=NormalizedCategory.SECURITY,
                        service="Inspector",
                        region=region,
                        arn=f"arn:aws:inspector2:{region}:{self.account_id}:coverage",
                        name=f"Inspector-{region}",
                        tags={},
                        cost_estimate_usd=estimated_cost,
                        usage_metrics={
                            "status": status,
                            "enabled_resource_types": enabled_types,
                        },
                        risk_flags=risk_flags if risk_flags else None,
                        ownership_confidence="unknown",
                        suggested_owner=None,
                    )
                )

        except Exception as e:
            if "AccessDenied" not in str(e):
                logger.warning(f"Error collecting Inspector: {e}")

        return assets

    def _collect_security_hub(self, region: str) -> list[Asset]:
        """Collect Security Hub status."""
        assets = []

        try:
            securityhub = self.session.client("securityhub", region_name=region)

            # Get hub details
            response = securityhub.describe_hub()
            hub_arn = response.get("HubArn", "")
            auto_enable = response.get("AutoEnableControls", False)

            # Get enabled standards
            standards = []
            try:
                std_response = securityhub.get_enabled_standards()
                standards = [
                    s.get("StandardsArn") for s in std_response.get("StandardsSubscriptions", [])
                ]
            except Exception:
                pass

            # Security Hub: $0.0010 per finding per month
            estimated_cost = 30.0  # Rough estimate

            risk_flags = []
            if not auto_enable:
                risk_flags.append("auto_enable_controls_disabled")
            if not standards:
                risk_flags.append("no_standards_enabled")

            assets.append(
                Asset(
                    provider="aws",
                    asset_type="security_hub",
                    normalized_category=NormalizedCategory.SECURITY,
                    service="Security Hub",
                    region=region,
                    arn=hub_arn or f"arn:aws:securityhub:{region}:{self.account_id}:hub/default",
                    name=f"SecurityHub-{region}",
                    tags={},
                    cost_estimate_usd=estimated_cost,
                    usage_metrics={
                        "hub_arn": hub_arn,
                        "auto_enable_controls": auto_enable,
                        "enabled_standards_count": len(standards),
                        "enabled_standards": standards,
                    },
                    risk_flags=risk_flags if risk_flags else None,
                    ownership_confidence="unknown",
                    suggested_owner=None,
                )
            )

        except securityhub.exceptions.InvalidAccessException:
            # Security Hub not enabled
            pass
        except Exception as e:
            if "AccessDenied" not in str(e) and "not subscribed" not in str(e).lower():
                logger.warning(f"Error collecting Security Hub: {e}")

        return assets

    def _collect_config(self, region: str) -> list[Asset]:
        """Collect AWS Config recorders and rules."""
        assets = []

        try:
            config = self.session.client("config", region_name=region)

            # Get configuration recorders
            recorder_response = config.describe_configuration_recorders()
            recorders = recorder_response.get("ConfigurationRecorders", [])

            # Get recorder status
            status_response = config.describe_configuration_recorder_status()
            statuses = {
                s["name"]: s for s in status_response.get("ConfigurationRecordersStatus", [])
            }

            for recorder in recorders:
                recorder_name = recorder["name"]
                recorder_status = statuses.get(recorder_name, {})
                is_recording = recorder_status.get("recording", False)

                # Get rules count
                rules_count = 0
                try:
                    rules_response = config.describe_config_rules()
                    rules_count = len(rules_response.get("ConfigRules", []))
                except Exception:
                    pass

                # Config pricing: $0.003 per item recorded
                estimated_cost = 20.0  # Rough estimate

                risk_flags = []
                if not is_recording:
                    risk_flags.append("not_recording")
                if rules_count == 0:
                    risk_flags.append("no_rules")

                # Check if recording all resources
                recording_group = recorder.get("recordingGroup", {})
                all_supported = recording_group.get("allSupported", False)
                if not all_supported:
                    risk_flags.append("partial_resource_recording")

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="config_recorder",
                        normalized_category=NormalizedCategory.GOVERNANCE,
                        service="Config",
                        region=region,
                        arn=f"arn:aws:config:{region}:{self.account_id}:config-recorder/{recorder_name}",
                        name=recorder_name,
                        tags={},
                        cost_estimate_usd=estimated_cost,
                        usage_metrics={
                            "recorder_name": recorder_name,
                            "is_recording": is_recording,
                            "last_status": recorder_status.get("lastStatus"),
                            "all_supported": all_supported,
                            "include_global_resources": recording_group.get(
                                "includeGlobalResourceTypes", False
                            ),
                            "rules_count": rules_count,
                            "role_arn": recorder.get("roleARN"),
                        },
                        risk_flags=risk_flags if risk_flags else None,
                        ownership_confidence="unknown",
                        suggested_owner=None,
                    )
                )

        except Exception as e:
            if "AccessDenied" not in str(e):
                logger.warning(f"Error collecting Config: {e}")

        return assets
