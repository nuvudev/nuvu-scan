"""
GCP provider scanner implementation.

Implements CloudProviderScan interface for Google Cloud Platform.
"""

from typing import Any

from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from google.oauth2 import service_account

from nuvu_scan.core.base import Asset, CloudProviderScan, ScanConfig

from .collectors.bigquery import BigQueryCollector
from .collectors.dataproc import DataprocCollector
from .collectors.gcs import GCSCollector
from .collectors.gemini import GeminiCollector
from .collectors.iam import IAMCollector
from .collectors.pubsub import PubSubCollector


class GCPScanner(CloudProviderScan):
    """GCP cloud provider scanner."""

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.credentials = self._create_credentials()
        self.project_id = self._get_project_id()
        # Set account_id to project_id for consistency in ScanResult
        if not self.config.account_id:
            self.config.account_id = self.project_id
        self.collectors = self._initialize_collectors()

    def _create_credentials(self):
        """Create GCP credentials from config."""
        credentials_dict = self.config.credentials

        # Option 1: Service account JSON key file path
        if "service_account_key_file" in credentials_dict:
            return service_account.Credentials.from_service_account_file(
                credentials_dict["service_account_key_file"]
            )

        # Option 2: Service account JSON key content
        if "service_account_key_json" in credentials_dict:
            import json

            key_data = json.loads(credentials_dict["service_account_key_json"])
            return service_account.Credentials.from_service_account_info(key_data)

        # Option 3: Use GOOGLE_APPLICATION_CREDENTIALS environment variable
        try:
            creds, _ = default()
            return creds
        except DefaultCredentialsError as e:
            raise ValueError(
                "GCP credentials not found. Provide service_account_key_file, "
                "service_account_key_json, or set GOOGLE_APPLICATION_CREDENTIALS"
            ) from e

    def _get_project_id(self) -> str:
        """Get GCP project ID from credentials or config."""
        # Try from credentials
        if hasattr(self.credentials, "project_id") and self.credentials.project_id:
            return self.credentials.project_id

        # Try from config
        if "project_id" in self.config.credentials:
            return self.config.credentials["project_id"]

        # Try from account_id (for consistency with AWS)
        if self.config.account_id:
            return self.config.account_id

        raise ValueError("GCP project_id is required. Set it in credentials or use --gcp-project")

    # Map of collector names to their classes for filtering
    COLLECTOR_MAP = {
        "gcs": GCSCollector,
        "bigquery": BigQueryCollector,
        "dataproc": DataprocCollector,
        "pubsub": PubSubCollector,
        "iam": IAMCollector,
        "gemini": GeminiCollector,
    }

    @classmethod
    def get_available_collectors(cls) -> list[str]:
        """Return list of available collector names."""
        return list(cls.COLLECTOR_MAP.keys())

    def _initialize_collectors(self) -> list:
        """Initialize GCP service collectors based on config."""
        collectors = []

        # Get requested collectors from config
        requested = self.config.collectors if self.config.collectors else []

        # Normalize to lowercase
        requested_lower = [c.lower() for c in requested]

        # If no specific collectors requested, use all
        if not requested_lower:
            for collector_cls in self.COLLECTOR_MAP.values():
                collectors.append(collector_cls(self.credentials, self.project_id))
        else:
            # Filter to only requested collectors
            for name, collector_cls in self.COLLECTOR_MAP.items():
                if name in requested_lower:
                    collectors.append(collector_cls(self.credentials, self.project_id))

            # Warn about unknown collectors
            known = set(self.COLLECTOR_MAP.keys())
            unknown = set(requested_lower) - known
            if unknown:
                import sys

                print(f"Warning: Unknown collectors ignored: {', '.join(unknown)}", file=sys.stderr)
                print(f"Available collectors: {', '.join(sorted(known))}", file=sys.stderr)

        return collectors

    def list_assets(self) -> list[Asset]:
        """Discover all GCP assets across all collectors."""
        import sys
        import traceback

        all_assets = []

        for collector in self.collectors:
            try:
                assets = collector.collect()
                if len(assets) > 0:
                    print(
                        f"INFO: {collector.__class__.__name__} found {len(assets)} assets",
                        file=sys.stderr,
                    )
                all_assets.extend(assets)
            except Exception as e:
                # Check if it's a permission error vs API not enabled
                error_str = str(e)
                if "SERVICE_DISABLED" in error_str or "API has not been used" in error_str:
                    # API not enabled - this is expected for some services
                    print(
                        f"INFO: {collector.__class__.__name__} - API not enabled (this is normal if you don't use this service)",
                        file=sys.stderr,
                    )
                elif (
                    "403" in error_str or "Permission" in error_str or "denied" in error_str.lower()
                ):
                    # Permission error - this is a real issue
                    print(
                        f"ERROR: {collector.__class__.__name__} - Permission denied: {type(e).__name__}: {e}",
                        file=sys.stderr,
                    )
                    traceback.print_exc(file=sys.stderr)
                else:
                    # Other error
                    print(
                        f"ERROR: {collector.__class__.__name__} failed: {type(e).__name__}: {e}",
                        file=sys.stderr,
                    )
                    traceback.print_exc(file=sys.stderr)
                continue

        return all_assets

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for a GCP asset."""
        # Delegate to appropriate collector based on service
        for collector in self.collectors:
            if hasattr(collector, "get_usage_metrics"):
                try:
                    return collector.get_usage_metrics(asset)
                except Exception:
                    continue

        # Default: return empty metrics
        return {}

    def get_cost_estimate(self, asset: Asset) -> float:
        """Estimate monthly cost for a GCP asset."""
        # Delegate to appropriate collector based on service
        for collector in self.collectors:
            if hasattr(collector, "get_cost_estimate"):
                try:
                    return collector.get_cost_estimate(asset)
                except Exception:
                    continue

        # Default: return 0 if no cost estimation available
        return 0.0
