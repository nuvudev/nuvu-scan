"""
AWS Cost Explorer collector.

Retrieves actual costs from AWS Cost Explorer API for accurate cost reporting.
"""

from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError


class CostExplorerCollector:
    """Collects actual AWS costs from Cost Explorer API."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or []
        self.cost_explorer_client = session.client("ce", region_name="us-east-1")  # Cost Explorer is global

    def get_service_costs(self, start_date: datetime, end_date: datetime) -> dict[str, float]:
        """Get costs by service for a date range."""
        costs_by_service = {}

        try:
            # Get costs grouped by service
            response = self.cost_explorer_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                ],
            )

            # Process results
            for result in response.get("ResultsByTime", []):
                for group in result.get("Groups", []):
                    service = group.get("Keys", [""])[0]
                    amount = float(group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0"))
                    if service and amount > 0:
                        # Sum costs across months
                        costs_by_service[service] = costs_by_service.get(service, 0.0) + amount

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                import sys
                print(
                    "INFO: Cost Explorer API access denied. Grant 'ce:GetCostAndUsage' permission to see actual costs.",
                    file=sys.stderr,
                )
            else:
                import sys
                print(
                    f"WARNING: Could not get costs from Cost Explorer: {e}",
                    file=sys.stderr,
                )

        return costs_by_service

    def get_resource_costs(
        self, service: str, start_date: datetime, end_date: datetime
    ) -> dict[str, float]:
        """Get costs by resource for a specific service using usage type grouping."""
        costs_by_resource = {}

        try:
            # Cost Explorer doesn't support RESOURCE_ID grouping directly
            # Instead, we'll use USAGE_TYPE to get more granular cost data
            # For S3, we can filter by usage type (e.g., "Storage", "DataTransfer-Out-Bytes")
            response = self.cost_explorer_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                Filter={
                    "Dimensions": {
                        "Key": "SERVICE",
                        "Values": [service],
                    }
                },
                GroupBy=[
                    {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
                ],
            )

            # Process results - sum all usage types for the service
            total_service_cost = 0.0
            for result in response.get("ResultsByTime", []):
                for group in result.get("Groups", []):
                    amount = float(group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0"))
                    if amount > 0:
                        total_service_cost += amount

            # Return service-level cost (we can't get per-resource costs without resource tags)
            if total_service_cost > 0:
                # Store as service-level cost
                costs_by_resource[service] = total_service_cost

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                pass  # Already logged in get_service_costs
            else:
                import sys
                print(
                    f"WARNING: Could not get resource costs for {service}: {e}",
                    file=sys.stderr,
                )

        return costs_by_resource

    def get_monthly_cost_for_service(self, service: str) -> float:
        """Get estimated monthly cost for a service based on last 30 days."""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)

        service_costs = self.get_service_costs(start_date, end_date)
        total_cost = service_costs.get(service, 0.0)

        # Convert to monthly estimate (30-day average * 30)
        days_in_period = (end_date - start_date).days
        if days_in_period > 0:
            daily_avg = total_cost / days_in_period
            monthly_estimate = daily_avg * 30
            return monthly_estimate

        return total_cost

    def get_cost_for_resource(self, service: str, resource_id: str) -> float:
        """Get estimated monthly cost for a specific resource."""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)

        resource_costs = self.get_resource_costs(service, start_date, end_date)
        total_cost = resource_costs.get(resource_id, 0.0)

        # Convert to monthly estimate
        days_in_period = (end_date - start_date).days
        if days_in_period > 0:
            daily_avg = total_cost / days_in_period
            monthly_estimate = daily_avg * 30
            return monthly_estimate

        return total_cost
