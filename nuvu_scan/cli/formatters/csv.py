"""
CSV report formatter.
"""

import csv
import io

from ...core import ScanResult


class CSVFormatter:
    """Formats scan results as CSV."""

    def format(self, result: ScanResult) -> str:
        """Format scan result as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "Name",
                "Provider",
                "Service",
                "Asset Type",
                "Category",
                "Region",
                "ARN",
                "Created At",
                "Last Activity",
                "Size (Bytes)",
                "Cost (USD/mo)",
                "Owner",
                "Ownership Confidence",
                "Risk Flags",
                "Tags",
            ]
        )

        # Write data rows
        for asset in result.assets:
            writer.writerow(
                [
                    asset.name,
                    asset.provider,
                    asset.service,
                    asset.asset_type,
                    asset.normalized_category.value,
                    asset.region,
                    asset.arn,
                    asset.created_at or "",
                    asset.last_activity_at or "",
                    asset.size_bytes or 0,
                    asset.cost_estimate_usd or 0.0,
                    asset.suggested_owner or "",
                    asset.ownership_confidence,
                    ", ".join(asset.risk_flags) if asset.risk_flags else "",
                    ", ".join([f"{k}={v}" for k, v in asset.tags.items()]) if asset.tags else "",
                ]
            )

        return output.getvalue()
