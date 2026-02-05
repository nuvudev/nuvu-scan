"""
CloudTrail collector for AWS.

Collects CloudTrail trails and their configurations for audit governance.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class CloudTrailCollector:
    """Collects AWS CloudTrail trails."""

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
        """Collect all CloudTrail trails."""
        import sys

        assets = []

        print("  → Collecting CloudTrail trails...", file=sys.stderr)

        # CloudTrail can be queried from any region, but we need to check all regions
        # for regional trails
        try:
            # Start with us-east-1 to get multi-region and organization trails
            cloudtrail = self.session.client("cloudtrail", region_name="us-east-1")

            # Describe all trails
            trails_response = cloudtrail.describe_trails(includeShadowTrails=False)
            trails = trails_response.get("trailList", [])

            for trail in trails:
                trail_name = trail.get("Name", "")
                trail_arn = trail.get("TrailARN", "")
                home_region = trail.get("HomeRegion", "us-east-1")

                # Get trail status
                try:
                    status_response = cloudtrail.get_trail_status(Name=trail_name)
                    is_logging = status_response.get("IsLogging", False)
                    latest_delivery_time = status_response.get("LatestDeliveryTime")
                    latest_delivery_error = status_response.get("LatestDeliveryError")
                except ClientError:
                    is_logging = False
                    latest_delivery_time = None
                    latest_delivery_error = None

                # Get event selectors
                event_selectors = []
                try:
                    selectors_response = cloudtrail.get_event_selectors(TrailName=trail_name)
                    event_selectors = selectors_response.get("EventSelectors", [])
                except ClientError:
                    pass

                # Get tags
                tags = {}
                try:
                    tags_response = cloudtrail.list_tags(ResourceIdList=[trail_arn])
                    for resource_tag in tags_response.get("ResourceTagList", []):
                        for tag in resource_tag.get("TagsList", []):
                            tags[tag["Key"]] = tag["Value"]
                except ClientError:
                    pass

                # Analyze configuration
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                is_org_trail = trail.get("IsOrganizationTrail", False)
                log_validation = trail.get("LogFileValidationEnabled", False)
                kms_key_id = trail.get("KmsKeyId")
                s3_bucket = trail.get("S3BucketName", "")
                sns_topic = trail.get("SnsTopicARN")
                cloudwatch_logs_arn = trail.get("CloudWatchLogsLogGroupArn")

                # Check if management events are logged
                logs_management_events = False
                logs_data_events = False
                for selector in event_selectors:
                    if selector.get("IncludeManagementEvents", False):
                        logs_management_events = True
                    if selector.get("DataResources"):
                        logs_data_events = True

                # Build risk flags
                risk_flags = []
                if not is_logging:
                    risk_flags.append("logging_disabled")
                if not is_multi_region:
                    risk_flags.append("single_region_trail")
                if not log_validation:
                    risk_flags.append("log_validation_disabled")
                if not kms_key_id:
                    risk_flags.append("not_encrypted")
                if not logs_management_events:
                    risk_flags.append("no_management_events")
                if latest_delivery_error:
                    risk_flags.append("delivery_errors")
                if not cloudwatch_logs_arn:
                    risk_flags.append("no_cloudwatch_integration")

                ownership = self._infer_ownership(tags, trail_name)

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="cloudtrail",
                        normalized_category=NormalizedCategory.SECURITY,
                        service="CloudTrail",
                        region=home_region,
                        arn=trail_arn,
                        name=trail_name,
                        tags=tags,
                        risk_flags=risk_flags,
                        ownership_confidence=ownership["confidence"],
                        suggested_owner=ownership["owner"],
                        usage_metrics={
                            "trail_name": trail_name,
                            "is_logging": is_logging,
                            "is_multi_region": is_multi_region,
                            "is_organization_trail": is_org_trail,
                            "log_validation_enabled": log_validation,
                            "encrypted": bool(kms_key_id),
                            "kms_key_id": kms_key_id,
                            "s3_bucket": s3_bucket,
                            "sns_topic": sns_topic,
                            "cloudwatch_logs_arn": cloudwatch_logs_arn,
                            "logs_management_events": logs_management_events,
                            "logs_data_events": logs_data_events,
                            "event_selector_count": len(event_selectors),
                            "latest_delivery_time": latest_delivery_time.isoformat()
                            if latest_delivery_time
                            else None,
                            "latest_delivery_error": latest_delivery_error,
                        },
                    )
                )

        except ClientError as e:
            if "AccessDenied" not in str(e):
                print(f"Error collecting CloudTrail trails: {e}", file=sys.stderr)

        print(f"  → Found {len(assets)} CloudTrail trails", file=sys.stderr)
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
        """Get usage metrics for CloudTrail trail."""
        return asset.usage_metrics or {}
