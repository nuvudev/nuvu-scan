"""
SNS and SQS collector for AWS.

Collects SNS topics and SQS queues for messaging governance.
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class SNSSQSCollector:
    """Collects AWS SNS topics and SQS queues."""

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
        """Collect all SNS and SQS resources."""
        import sys

        assets = []
        regions = self.regions if self.regions else self._get_all_regions()

        print(f"  → Scanning {len(regions)} regions for SNS/SQS resources...", file=sys.stderr)

        # Collect SNS topics
        print("  → Collecting SNS topics...", file=sys.stderr)
        sns_assets = self._collect_sns_topics(regions)
        assets.extend(sns_assets)
        print(f"  → Found {len(sns_assets)} SNS topics", file=sys.stderr)

        # Collect SQS queues
        print("  → Collecting SQS queues...", file=sys.stderr)
        sqs_assets = self._collect_sqs_queues(regions)
        assets.extend(sqs_assets)
        print(f"  → Found {len(sqs_assets)} SQS queues", file=sys.stderr)

        return assets

    def _collect_sns_topics(self, regions: list[str]) -> list[Asset]:
        """Collect SNS topics."""
        assets = []

        for region in regions:
            try:
                sns = self.session.client("sns", region_name=region)
                paginator = sns.get_paginator("list_topics")

                for page in paginator.paginate():
                    for topic in page.get("Topics", []):
                        topic_arn = topic["TopicArn"]
                        topic_name = topic_arn.split(":")[-1]

                        try:
                            # Get topic attributes
                            attrs = sns.get_topic_attributes(TopicArn=topic_arn)
                            attributes = attrs.get("Attributes", {})

                            # Get tags
                            tags = {}
                            try:
                                tags_response = sns.list_tags_for_resource(ResourceArn=topic_arn)
                                tags = {t["Key"]: t["Value"] for t in tags_response.get("Tags", [])}
                            except ClientError:
                                pass

                            ownership = self._infer_ownership(tags, topic_name)

                            # Check encryption
                            kms_key = attributes.get("KmsMasterKeyId", "")
                            encrypted = bool(kms_key)

                            # Check for public access (policy analysis)
                            policy = attributes.get("Policy", "{}")
                            is_public = '"Principal":"*"' in policy or '"Principal": "*"' in policy

                            # Subscription count
                            subscriptions = int(attributes.get("SubscriptionsConfirmed", 0))
                            pending = int(attributes.get("SubscriptionsPending", 0))

                            # Build risk flags
                            risk_flags = []
                            if not encrypted:
                                risk_flags.append("unencrypted")
                            if is_public:
                                risk_flags.append("public_access")
                            if subscriptions == 0 and pending == 0:
                                risk_flags.append("no_subscribers")

                            assets.append(
                                Asset(
                                    provider="aws",
                                    asset_type="sns_topic",
                                    normalized_category=NormalizedCategory.DATA_INTEGRATION,
                                    service="SNS",
                                    region=region,
                                    arn=topic_arn,
                                    name=topic_name,
                                    tags=tags,
                                    risk_flags=risk_flags,
                                    ownership_confidence=ownership["confidence"],
                                    suggested_owner=ownership["owner"],
                                    usage_metrics={
                                        "topic_name": topic_name,
                                        "subscriptions_confirmed": subscriptions,
                                        "subscriptions_pending": pending,
                                        "encrypted": encrypted,
                                        "kms_key_id": kms_key,
                                        "is_fifo": topic_arn.endswith(".fifo"),
                                        "display_name": attributes.get("DisplayName", ""),
                                    },
                                )
                            )

                        except ClientError:
                            continue

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting SNS topics in {region}: {e}")

        return assets

    def _collect_sqs_queues(self, regions: list[str]) -> list[Asset]:
        """Collect SQS queues."""
        assets = []

        for region in regions:
            try:
                sqs = self.session.client("sqs", region_name=region)

                # List queues
                queues_response = sqs.list_queues()
                queue_urls = queues_response.get("QueueUrls", [])

                for queue_url in queue_urls:
                    queue_name = queue_url.split("/")[-1]

                    try:
                        # Get queue attributes
                        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
                        attributes = attrs.get("Attributes", {})

                        queue_arn = attributes.get("QueueArn", "")

                        # Get tags
                        tags = {}
                        try:
                            tags_response = sqs.list_queue_tags(QueueUrl=queue_url)
                            tags = tags_response.get("Tags", {})
                        except ClientError:
                            pass

                        ownership = self._infer_ownership(tags, queue_name)

                        # Check encryption
                        kms_key = attributes.get("KmsMasterKeyId", "")
                        encrypted = (
                            bool(kms_key) or attributes.get("SqsManagedSseEnabled") == "true"
                        )

                        # Check for public access
                        policy = attributes.get("Policy", "{}")
                        is_public = '"Principal":"*"' in policy or '"Principal": "*"' in policy

                        # Queue metrics
                        messages_visible = int(attributes.get("ApproximateNumberOfMessages", 0))
                        messages_not_visible = int(
                            attributes.get("ApproximateNumberOfMessagesNotVisible", 0)
                        )
                        messages_delayed = int(
                            attributes.get("ApproximateNumberOfMessagesDelayed", 0)
                        )

                        # Retention period
                        retention_seconds = int(attributes.get("MessageRetentionPeriod", 345600))

                        # Dead letter queue
                        dlq_arn = ""
                        redrive_policy = attributes.get("RedrivePolicy", "")
                        if redrive_policy:
                            import json

                            try:
                                redrive = json.loads(redrive_policy)
                                dlq_arn = redrive.get("deadLetterTargetArn", "")
                            except json.JSONDecodeError:
                                pass

                        # Build risk flags
                        risk_flags = []
                        if not encrypted:
                            risk_flags.append("unencrypted")
                        if is_public:
                            risk_flags.append("public_access")
                        if messages_visible > 10000:
                            risk_flags.append("high_message_backlog")
                        if not dlq_arn and not queue_name.endswith("-dlq"):
                            risk_flags.append("no_dead_letter_queue")

                        assets.append(
                            Asset(
                                provider="aws",
                                asset_type="sqs_queue",
                                normalized_category=NormalizedCategory.DATA_INTEGRATION,
                                service="SQS",
                                region=region,
                                arn=queue_arn,
                                name=queue_name,
                                tags=tags,
                                risk_flags=risk_flags,
                                ownership_confidence=ownership["confidence"],
                                suggested_owner=ownership["owner"],
                                usage_metrics={
                                    "queue_name": queue_name,
                                    "queue_url": queue_url,
                                    "messages_visible": messages_visible,
                                    "messages_not_visible": messages_not_visible,
                                    "messages_delayed": messages_delayed,
                                    "encrypted": encrypted,
                                    "kms_key_id": kms_key,
                                    "retention_seconds": retention_seconds,
                                    "retention_days": retention_seconds // 86400,
                                    "visibility_timeout": int(
                                        attributes.get("VisibilityTimeout", 30)
                                    ),
                                    "is_fifo": queue_name.endswith(".fifo"),
                                    "has_dlq": bool(dlq_arn),
                                    "dlq_arn": dlq_arn,
                                },
                            )
                        )

                    except ClientError:
                        continue

            except ClientError as e:
                if "AccessDenied" not in str(e):
                    print(f"Error collecting SQS queues in {region}: {e}")

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
        """Get usage metrics for SNS/SQS resource."""
        return asset.usage_metrics or {}
