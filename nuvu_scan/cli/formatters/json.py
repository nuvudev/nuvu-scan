"""
JSON report formatter.
"""

import json
from typing import Dict, Any
from ...core import ScanResult


class JSONFormatter:
    """Formats scan results as JSON."""

    def format(self, result: ScanResult) -> str:
        """Format scan result as JSON."""
        # Convert result to dictionary
        data = {
            "provider": result.provider,
            "account_id": result.account_id,
            "scan_timestamp": result.scan_timestamp,
            "summary": result.summary,
            "total_cost_estimate_usd": result.total_cost_estimate_usd,
            "assets": [
                {
                    "provider": asset.provider,
                    "asset_type": asset.asset_type,
                    "normalized_category": asset.normalized_category.value,
                    "service": asset.service,
                    "region": asset.region,
                    "arn": asset.arn,
                    "name": asset.name,
                    "created_at": asset.created_at,
                    "last_activity_at": asset.last_activity_at,
                    "size_bytes": asset.size_bytes,
                    "tags": asset.tags,
                    "cost_estimate_usd": asset.cost_estimate_usd,
                    "usage_metrics": asset.usage_metrics,
                    "risk_flags": asset.risk_flags,
                    "ownership_confidence": asset.ownership_confidence,
                    "suggested_owner": asset.suggested_owner,
                    "underlying_cloud_account_id": asset.underlying_cloud_account_id,
                }
                for asset in result.assets
            ],
        }

        return json.dumps(data, indent=2, default=str)
