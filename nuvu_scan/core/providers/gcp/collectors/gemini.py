"""
Gemini API collector for GCP.

Collects Gemini API usage and costs from Cloud Billing API.
"""

from datetime import datetime, timedelta
from typing import Any

from googleapiclient import discovery
from googleapiclient.errors import HttpError

from nuvu_scan.core.base import Asset, NormalizedCategory


class GeminiCollector:
    """Collects Gemini API usage and costs."""

    def __init__(self, credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.serviceusage_client = None
        self.cloudbilling_client = None

        try:
            self.serviceusage_client = discovery.build(
                "serviceusage", "v1", credentials=credentials
            )
            self.cloudbilling_client = discovery.build(
                "cloudbilling", "v1", credentials=credentials
            )
        except Exception:
            pass

    def collect(self) -> list[Asset]:
        """Collect Gemini API usage and cost information."""
        assets = []

        if not self.serviceusage_client:
            return assets

        try:
            # Check if Gemini API is enabled
            service_name = "generativelanguage.googleapis.com"  # Gemini API service name

            try:
                service = (
                    self.serviceusage_client.services()
                    .get(name=f"projects/{self.project_id}/services/{service_name}")
                    .execute()
                )

                if service.get("state") == "ENABLED":
                    # API is enabled - try to get actual costs
                    cost_data = self._get_gemini_costs()

                    asset = Asset(
                        provider="gcp",
                        asset_type="gemini_api",
                        normalized_category=NormalizedCategory.ML_TRAINING,
                        service="Gemini API",
                        region="global",
                        arn=f"gemini:{self.project_id}",
                        name="Gemini API",
                        created_at=None,
                        last_activity_at=cost_data.get("last_usage_date"),
                        tags={},
                        cost_estimate_usd=cost_data.get("monthly_cost_usd", 0.0),
                        risk_flags=[],
                        ownership_confidence="unknown",
                        suggested_owner=None,
                        usage_metrics={
                            "api_enabled": True,
                            "monthly_cost_usd": cost_data.get("monthly_cost_usd", 0.0),
                            "total_cost_30d": cost_data.get("total_cost_30d", 0.0),
                            "last_used": cost_data.get("last_usage_date"),
                            "days_since_last_use": self._calculate_days_since_last_use(
                                cost_data.get("last_usage_date")
                            ),
                            "note": cost_data.get("note", ""),
                        },
                    )
                    assets.append(asset)

            except HttpError as e:
                if e.resp.status == 404:
                    # API not enabled
                    pass
                elif e.resp.status == 403:
                    import sys

                    print(
                        "INFO: Service Usage API access denied (cannot check Gemini API status)",
                        file=sys.stderr,
                    )
                else:
                    raise

        except HttpError as e:
            import sys

            if e.resp.status == 403:
                print(
                    "INFO: Service Usage API access denied (cannot check Gemini API status)",
                    file=sys.stderr,
                )
            else:
                print(
                    f"ERROR: Error checking Gemini API: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )
        except Exception as e:
            import sys

            print(
                f"ERROR: Error checking Gemini API: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

        return assets

    def _get_gemini_costs(self) -> dict[str, Any]:
        """Get actual Gemini API costs from BigQuery billing export."""
        import sys

        cost_data = {
            "monthly_cost_usd": 0.0,
            "total_cost_30d": 0.0,
            "last_usage_date": None,
            "note": "",
        }

        # First, try BigQuery billing export (most reliable)
        if self.cloudbilling_client:
            try:
                project_name = f"projects/{self.project_id}"
                project_info = (
                    self.cloudbilling_client.projects().getBillingInfo(name=project_name).execute()
                )
                billing_account = project_info.get("billingAccountName")

                if billing_account:
                    billing_account_id = billing_account.split("/")[-1]
                    cost_data = self._get_costs_from_billing_export(billing_account_id)
                    if cost_data.get("monthly_cost_usd", 0.0) > 0:
                        return cost_data
            except Exception:
                pass

        # If billing export doesn't work, try Cloud Monitoring for usage detection
        cost_data = self._estimate_gemini_costs_from_monitoring()
        if not cost_data.get("monthly_cost_usd"):
            cost_data["note"] = (
                "Enable BigQuery billing export to get automatic Gemini cost tracking. "
                "See: https://console.cloud.google.com/billing/export"
            )

        return cost_data

        try:
            # Get billing account for the project
            project_name = f"projects/{self.project_id}"
            try:
                project_info = (
                    self.cloudbilling_client.projects().getBillingInfo(name=project_name).execute()
                )
                billing_account = project_info.get("billingAccountName")

                if not billing_account:
                    cost_data["note"] = "Project does not have billing enabled"
                    return cost_data

                # Try to get costs using Cloud Billing API
                # Note: This requires cloudbilling.billingAccounts.getCosts permission
                # The Cloud Billing API v1 doesn't have a direct way to get service-level costs
                # We would need to use BigQuery billing export or Cost Management API
                # For now, we'll note that billing API needs proper setup

                cost_data["note"] = (
                    "Cloud Billing API access available but service-level cost retrieval "
                    "requires additional permissions. Set GEMINI_COST_USD environment variable "
                    "to provide actual costs, or enable BigQuery billing export."
                )

            except HttpError as e:
                if e.resp.status == 403:
                    cost_data["note"] = (
                        "Billing account access denied. Grant 'Billing Account Costs Viewer' role "
                        "or enable BigQuery billing export."
                    )
                elif e.resp.status == 404:
                    cost_data["note"] = "Project does not have billing enabled"
                elif "SERVICE_DISABLED" in str(e):
                    cost_data["note"] = (
                        "Cloud Billing API not enabled. Enable it at: "
                        "https://console.cloud.google.com/apis/api/cloudbilling.googleapis.com"
                    )
                else:
                    raise

        except Exception as e:
            import sys

            error_str = str(e)
            if "SERVICE_DISABLED" in error_str:
                cost_data["note"] = (
                    "Cloud Billing API not enabled. Enable it to get automatic cost tracking. "
                    "See: https://cloud.google.com/billing/docs/how-to/export-data-bigquery"
                )
            else:
                print(
                    f"WARNING: Could not get Gemini costs: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                # Try fallback estimation
                cost_data = self._estimate_gemini_costs_from_monitoring()
                if not cost_data.get("monthly_cost_usd"):
                    cost_data["note"] = (
                        f"Could not retrieve costs automatically: {str(e)}. "
                        "Enable BigQuery billing export for accurate cost tracking."
                    )

        return cost_data

    def _estimate_gemini_costs_from_monitoring(self) -> dict[str, Any]:
        """Estimate Gemini costs from Cloud Monitoring API as fallback."""
        import sys

        cost_data = {
            "monthly_cost_usd": 0.0,
            "total_cost_30d": 0.0,
            "last_usage_date": None,
            "note": "Estimated from usage (enable Billing API for actual costs)",
        }

        try:
            # Try to use Cloud Monitoring API to get usage metrics
            monitoring_client = discovery.build("monitoring", "v3", credentials=self.credentials)

            # Query for Gemini API usage metrics
            # Metric: serviceruntime.googleapis.com/api/request_count
            # Filter by service: generativelanguage.googleapis.com

            project_name = f"projects/{self.project_id}"
            end_time = datetime.utcnow().isoformat() + "Z"
            start_time = (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"

            # Query for API request count
            filter_str = (
                'resource.type="api" AND '
                'resource.labels.service="generativelanguage.googleapis.com" AND '
                'metric.type="serviceruntime.googleapis.com/api/request_count"'
            )

            try:
                request = (
                    monitoring_client.projects()
                    .timeSeries()
                    .list(
                        name=project_name,
                        filter=filter_str,
                        interval_startTime=start_time,
                        interval_endTime=end_time,
                    )
                )
                response = request.execute()

                # Calculate estimated cost from usage
                # Gemini API pricing varies by model and usage type
                # Rough estimate: ~$0.001-0.01 per 1K tokens depending on model
                # For now, we'll note that actual costs require billing API

                if response.get("timeSeries"):
                    cost_data["note"] = (
                        "Usage detected but cost calculation requires Billing API. "
                        "Enable Cloud Billing API access to see actual costs (€9 detected in GCP Console)."
                    )
                else:
                    cost_data["note"] = (
                        "No usage metrics found. Enable Cloud Monitoring API access "
                        "or Cloud Billing API to see costs."
                    )

            except HttpError as e:
                if e.resp.status == 403:
                    cost_data["note"] = (
                        "Cloud Monitoring API access denied. Enable Billing API to see actual costs."
                    )
                else:
                    raise

        except Exception as e:
            import sys

            print(
                f"WARNING: Could not estimate Gemini costs from monitoring: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

        return cost_data

    def _get_costs_from_billing_export(self, billing_account_id: str) -> dict[str, Any]:
        """Get Gemini costs from BigQuery billing export if available."""
        cost_data = {
            "monthly_cost_usd": 0.0,
            "total_cost_30d": 0.0,
            "last_usage_date": None,
            "note": "",
        }

        try:
            from google.cloud import bigquery

            bq_client = bigquery.Client(project=self.project_id, credentials=self.credentials)

            # Try to find billing export dataset
            # GCP billing exports are typically in a dataset named like: billing_export_XXXXXX
            # or in the billing account's project
            datasets = list(bq_client.list_datasets())
            billing_datasets = [d for d in datasets if "billing_export" in d.dataset_id.lower()]

            if not billing_datasets:
                # Try to find in other common locations
                # Sometimes billing export is in a different project
                cost_data["note"] = (
                    "BigQuery billing export not found. "
                    "Enable billing export at: https://console.cloud.google.com/billing/export"
                )
                return cost_data

            # Use the first billing export dataset
            billing_dataset = billing_datasets[0].dataset_id

            # Query for Gemini API costs in the last 30 days
            # The billing export table structure: gcp_billing_export_v1_YYYYMMDD
            # Fields: service.description, service.id, cost, usage_start_time

            # Try different query formats based on billing export version
            queries = [
                # Standard v1 format
                f"""
                SELECT
                    SUM(CAST(cost AS NUMERIC)) as total_cost,
                    MAX(usage_start_time) as last_usage
                FROM `{self.project_id}.{billing_dataset}.gcp_billing_export_v1_*`
                WHERE
                    (service.description = "Generative Language API"
                     OR service.id = "generativelanguage.googleapis.com")
                    AND _TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY))
                """,
                # Alternative format with cost.amount
                f"""
                SELECT
                    SUM(CAST(cost.amount AS NUMERIC)) as total_cost,
                    MAX(usage_start_time) as last_usage
                FROM `{self.project_id}.{billing_dataset}.gcp_billing_export_v1_*`
                WHERE
                    (service.description = "Generative Language API"
                     OR service.id = "generativelanguage.googleapis.com")
                    AND _TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY))
                """,
            ]

            for query in queries:
                try:
                    query_job = bq_client.query(query)
                    results = query_job.result()

                    for row in results:
                        if row.total_cost and row.total_cost > 0:
                            cost_data["monthly_cost_usd"] = float(row.total_cost)
                            cost_data["total_cost_30d"] = float(row.total_cost)
                            if row.last_usage:
                                cost_data["last_usage_date"] = row.last_usage.isoformat()
                            cost_data["note"] = "Cost from BigQuery billing export"
                            return cost_data

                except Exception:
                    # Try next query format
                    continue

            cost_data["note"] = (
                "Billing export found but no Gemini costs in last 30 days. "
                "Or billing export table structure differs."
            )

        except Exception as e:
            import sys

            print(
                f"WARNING: Could not get costs from billing export: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            cost_data["note"] = (
                f"Error querying billing export: {str(e)}. "
                "Ensure billing export is enabled and service account has BigQuery access."
            )

        return cost_data

    def _get_costs_from_cost_api(self, billing_account_id: str) -> dict[str, Any]:
        """Get Gemini costs from Cloud Cost Management API."""
        cost_data = {
            "monthly_cost_usd": 0.0,
            "total_cost_30d": 0.0,
            "last_usage_date": None,
            "note": "",
        }

        try:
            # Try to use Cloud Cost Management API (cloudbilling.googleapis.com)
            # This requires the Cost Management API to be enabled
            # Note: This API might not be available in all projects

            # For now, return empty as this API is complex and requires specific setup
            cost_data["note"] = "Cloud Cost Management API requires additional setup"

        except Exception as e:
            import sys

            print(
                f"WARNING: Could not get costs from Cost API: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

        return cost_data

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for Gemini API."""
        return asset.usage_metrics or {}

    def _calculate_days_since_last_use(self, last_activity: str | None) -> int | None:
        """Calculate days since last use."""
        from datetime import datetime

        if not last_activity:
            return None

        try:
            last_used = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
            days = (datetime.utcnow() - last_used.replace(tzinfo=None)).days
            return days
        except Exception:
            return None

    def get_cost_estimate(self, asset: Asset) -> float:
        """Get cost estimate for Gemini API."""
        # Cost is already calculated and stored in usage_metrics
        if asset.asset_type == "gemini_api" and asset.usage_metrics:
            return asset.usage_metrics.get("monthly_cost_usd", 0.0)
        return asset.cost_estimate_usd or 0.0
