"""
IAM collector for GCP.

Collects IAM roles, service accounts, and policies with data-access permissions.
"""

from typing import Any

from googleapiclient import discovery
from googleapiclient.errors import HttpError

from nuvu_scan.core.base import Asset, NormalizedCategory


class IAMCollector:
    """Collects GCP IAM roles, service accounts, and policies."""

    def __init__(self, credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.iam_client = discovery.build("iam", "v1", credentials=credentials)
        self.serviceusage_client = discovery.build("serviceusage", "v1", credentials=credentials)

    def collect(self) -> list[Asset]:
        """Collect IAM service accounts with data-access permissions."""
        assets = []

        try:
            # List all service accounts in the project
            service_accounts = (
                self.iam_client.projects()
                .serviceAccounts()
                .list(name=f"projects/{self.project_id}")
                .execute()
            )

            for sa in service_accounts.get("accounts", []):
                try:
                    sa_email = sa["email"]
                    sa_name = sa["name"]
                    sa_display_name = sa.get("displayName", "")
                    created_at = None
                    if "oauth2ClientId" in sa:
                        # Service account creation time is not directly available
                        # We'll use None for now
                        pass

                    # Get IAM policy for the service account
                    try:
                        policy = (
                            self.iam_client.projects()
                            .serviceAccounts()
                            .getIamPolicy(resource=sa_name)
                            .execute()
                        )
                    except Exception:
                        policy = None

                    # Check if service account has data-access permissions
                    has_data_access = self._has_data_access_permissions(sa_email, policy)

                    if not has_data_access:
                        # Skip service accounts without data-access permissions
                        continue

                    # Get last usage (approximate - GCP doesn't provide direct last use)
                    last_activity = None
                    idle_days = 0

                    # Build risk flags
                    risk_flags = []
                    if not sa.get("oauth2ClientId"):
                        risk_flags.append("no_oauth_client")
                    if self._has_overly_permissive_roles(policy):
                        risk_flags.append("overly_permissive")

                    # Get labels (service accounts don't have labels, but we can check display name)
                    labels = {}

                    # Infer ownership
                    ownership = self._infer_ownership(labels, sa_email, sa_display_name)

                    asset = Asset(
                        provider="gcp",
                        asset_type="service_account",
                        normalized_category=NormalizedCategory.SECURITY,
                        service="IAM",
                        region="global",  # IAM is global
                        arn=sa_name,
                        name=sa_email,
                        created_at=created_at,
                        last_activity_at=last_activity,
                        tags=labels,
                        cost_estimate_usd=0.0,  # Service accounts are free
                        risk_flags=risk_flags,
                        ownership_confidence=ownership["confidence"],
                        suggested_owner=ownership["owner"],
                        usage_metrics={
                            "idle_days": idle_days,
                            "display_name": sa_display_name,
                            "disabled": sa.get("disabled", False),
                        },
                    )

                    assets.append(asset)

                except Exception as e:
                    import sys

                    print(
                        f"Error processing service account {sa.get('email', 'unknown')}: {e}",
                        file=sys.stderr,
                    )
                    continue

        except HttpError as e:
            import sys

            if e.resp.status == 403:
                print(
                    "INFO: IAM API access denied or not enabled (this is normal if you don't use IAM service accounts)",
                    file=sys.stderr,
                )
            else:
                print(
                    f"ERROR: Error listing IAM service accounts: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )
        except Exception as e:
            import sys

            print(
                f"ERROR: Error listing IAM service accounts: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

        return assets

    def _has_data_access_permissions(self, sa_email: str, policy: dict | None) -> bool:
        """Check if service account has permissions to access data services."""
        data_roles = [
            "roles/storage.objectViewer",
            "roles/storage.objectAdmin",
            "roles/storage.admin",
            "roles/bigquery.dataViewer",
            "roles/bigquery.dataEditor",
            "roles/bigquery.admin",
            "roles/dataproc.worker",
            "roles/dataproc.admin",
            "roles/pubsub.subscriber",
            "roles/pubsub.publisher",
            "roles/pubsub.admin",
            "roles/bigtable.user",
            "roles/bigtable.admin",
            "roles/spanner.databaseUser",
            "roles/spanner.admin",
        ]

        if not policy:
            return False

        # Check bindings for data-access roles
        bindings = policy.get("bindings", [])
        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])

            # Check if this service account has the role
            if f"serviceAccount:{sa_email}" in members:
                if any(data_role in role for data_role in data_roles):
                    return True

        return False

    def _has_overly_permissive_roles(self, policy: dict | None) -> bool:
        """Check if service account has overly permissive roles."""
        overly_permissive_roles = [
            "roles/owner",
            "roles/editor",
            "roles/viewer",  # Less permissive but still broad
        ]

        if not policy:
            return False

        bindings = policy.get("bindings", [])
        for binding in bindings:
            role = binding.get("role", "")
            if role in overly_permissive_roles:
                return True

        return False

    def _infer_ownership(
        self, labels: dict[str, str], sa_email: str, display_name: str
    ) -> dict[str, str]:
        """Infer ownership from labels, email, or display name."""
        owner = None
        confidence = "unknown"

        # Check labels
        if "owner" in labels:
            owner = labels["owner"]
            confidence = "high"
        elif "team" in labels:
            owner = labels["team"]
            confidence = "medium"

        # Try to infer from display name
        if not owner and display_name:
            # Common patterns: team-name, project-name
            parts = display_name.split("-")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        # Try to infer from service account email
        if not owner:
            # Service account emails are usually: name@project.iam.gserviceaccount.com
            # Extract name part
            name_part = sa_email.split("@")[0]
            parts = name_part.split("-")
            if len(parts) > 1:
                owner = parts[0]
                confidence = "low"

        return {"owner": owner, "confidence": confidence}

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for IAM service account."""
        return asset.usage_metrics or {}
