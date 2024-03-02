"""
Pub/Sub collector.

Collects Pub/Sub topics and subscriptions.
"""

from typing import Any

from google.cloud import pubsub_v1

from nuvu_scan.core.base import Asset, NormalizedCategory


class PubSubCollector:
    """Collects Pub/Sub topics and subscriptions."""

    def __init__(self, credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.publisher = pubsub_v1.PublisherClient(credentials=credentials)
        self.subscriber = pubsub_v1.SubscriberClient(credentials=credentials)

    def collect(self) -> list[Asset]:
        """Collect Pub/Sub topics and subscriptions."""
        assets = []

        try:
            # List all topics
            project_path = f"projects/{self.project_id}"
            topics = self.publisher.list_topics(request={"project": project_path})

            for topic in topics:
                try:
                    topic_name = topic.name.split("/")[-1]
                    created_at = None  # Pub/Sub doesn't provide creation time directly

                    # Get subscriptions for this topic
                    subscriptions = self.subscriber.list_subscriptions(
                        request={"project": project_path, "topic": topic.name}
                    )
                    subscription_count = len(list(subscriptions))

                    # Build risk flags
                    risk_flags = []
                    if subscription_count == 0:
                        risk_flags.append("no_subscriptions")

                    # Infer ownership from labels
                    labels = {}  # Pub/Sub topics don't have labels in the API
                    ownership = self._infer_ownership(labels, topic_name)

                    # Estimate cost (Pub/Sub charges per message and storage)
                    cost_estimate = self._estimate_cost()

                    asset = Asset(
                        provider="gcp",
                        asset_type="pubsub_topic",
                        normalized_category=NormalizedCategory.STREAMING,
                        service="Pub/Sub",
                        region="global",  # Pub/Sub is global
                        arn=topic.name,
                        name=topic_name,
                        created_at=created_at,
                        tags=labels,
                        cost_estimate_usd=cost_estimate,
                        risk_flags=risk_flags,
                        ownership_confidence=ownership["confidence"],
                        suggested_owner=ownership["owner"],
                        last_activity_at=None,  # Pub/Sub doesn't track last access directly
                        usage_metrics={
                            "subscription_count": subscription_count,
                            "last_used": None,
                            "days_since_last_use": None,
                        },
                    )

                    assets.append(asset)

                except Exception as e:
                    print(f"Error processing topic {topic.name}: {e}")
                    continue

        except Exception as e:
            import sys

            # Check if it's an API not enabled error (common and expected)
            error_str = str(e)
            if "SERVICE_DISABLED" in error_str or "API has not been used" in error_str:
                # This is expected if Pub/Sub API is not enabled - don't print as error
                print(
                    "INFO: Pub/Sub API not enabled in project (this is normal if you don't use Pub/Sub)",
                    file=sys.stderr,
                )
            else:
                # Real error - print it
                import traceback

                print(
                    f"ERROR: Error listing Pub/Sub topics: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                traceback.print_exc(file=sys.stderr)

        return assets

    def _infer_ownership(self, labels: dict[str, str], topic_name: str) -> dict[str, str]:
        """Infer ownership from naming."""
        owner = None
        confidence = "unknown"

        # Try to infer from topic name
        # Common patterns: team-name-topic, project-name-events
        parts = topic_name.split("-")
        if len(parts) > 1:
            owner = parts[0]
            confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def _estimate_cost(self) -> float:
        """Estimate monthly cost for Pub/Sub topic."""
        # Pub/Sub pricing:
        # - $0.40 per million messages
        # - $0.27 per GB of message storage
        # Without usage data, we can't estimate accurately
        # Return a minimal cost for topics with no subscriptions
        return 0.0

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for Pub/Sub topic."""
        return asset.usage_metrics or {}
