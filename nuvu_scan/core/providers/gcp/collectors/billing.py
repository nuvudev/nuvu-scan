"""
Cloud Billing collector for GCP.

Collects actual costs from Cloud Billing API for more accurate cost estimation.
"""

from datetime import datetime
from typing import Any

from googleapiclient import discovery
from googleapiclient.errors import HttpError

from nuvu_scan.core.base import Asset, NormalizedCategory


class BillingCollector:
    """Collects actual GCP costs from Cloud Billing API."""

    def __init__(self, credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.cloudbilling_client = None
        self.cloudbilling_v1beta_client = None

        try:
            self.cloudbilling_client = discovery.build(
                "cloudbilling", "v1", credentials=credentials
            )
            # Try v1beta for more detailed cost data
            try:
                self.cloudbilling_v1beta_client = discovery.build(
                    "cloudbilling", "v1beta", credentials=credentials
                )
            except Exception:
                pass
        except Exception:
            pass

    def collect(self) -> list[Asset]:
        """Collect actual costs from Cloud Billing API."""
        assets = []

        if not self.cloudbilling_client:
            return assets

        try:
            # Get billing account for the project
            project_name = f"projects/{self.project_id}"
            try:
                project_info = (
                    self.cloudbilling_client.projects().getBillingInfo(name=project_name).execute()
                )
                billing_account = project_info.get("billingAccountName")
            except HttpError as e:
                if e.resp.status == 403:
                    import sys

                    print(
                        "INFO: Cloud Billing API access denied (cannot get actual costs)",
                        file=sys.stderr,
                    )
                    return assets
                raise

            if not billing_account:
                # Project doesn't have billing enabled
                return assets

            # Get costs for the last 30 days
            # Note: This requires cloudbilling.billingAccounts.getCosts permission
            try:
                # Use Cloud Billing API to get actual costs
                # This is a simplified version - full implementation would use
                # the Cost Insights API or BigQuery billing export
                costs = self._get_recent_costs(billing_account)

                if costs:
                    asset = Asset(
                        provider="gcp",
                        asset_type="billing_summary",
                        normalized_category=NormalizedCategory.SECURITY,  # Using security as closest category
                        service="Cloud Billing",
                        region="global",
                        arn=billing_account,
                        name=f"{self.project_id} - Billing Summary",
                        created_at=None,
                        last_activity_at=datetime.utcnow().isoformat(),
                        tags={},
                        cost_estimate_usd=costs.get("total_cost", 0.0),
                        risk_flags=[],
                        ownership_confidence="unknown",
                        suggested_owner=None,
                        usage_metrics=costs,
                    )
                    assets.append(asset)
            except HttpError as e:
                if e.resp.status == 403:
                    import sys

                    print(
                        "INFO: Cloud Billing cost data access denied (enable cloudbilling.billingAccounts.getCosts permission)",
                        file=sys.stderr,
                    )
                else:
                    raise

        except Exception as e:
            import sys

            print(
                f"ERROR: Error getting billing data: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

        return assets

    def _get_recent_costs(self, billing_account: str) -> dict[str, Any] | None:
        """Get recent costs from billing account."""
        # Note: Getting detailed cost breakdown requires:
        # 1. Cloud Billing API with proper permissions
        # 2. Or BigQuery billing export
        # 3. Or Cost Management API

        # For now, return None - this would need to be implemented with proper API calls
        # The actual implementation would query the billing API for service-level costs
        return None

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for billing asset."""
        return asset.usage_metrics or {}
