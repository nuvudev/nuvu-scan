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
        self.cost_explorer_client = session.client(
            "ce", region_name="us-east-1"
        )  # Cost Explorer is global

    def get_service_costs(self, start_date: datetime, end_date: datetime) -> dict[str, float]:
        """Get costs by service for a date range.

        Returns actual costs (not estimates) for the specified date range.
        When using MONTHLY granularity, returns full month costs.
        When using DAILY granularity, returns sum of daily costs.
        """
        costs_by_service = {}

        try:
            # Calculate the date range
            days_in_period = (end_date - start_date).days

            # Use DAILY granularity for periods < 90 days to get accurate daily costs
            # Use MONTHLY granularity for longer periods for efficiency
            if days_in_period <= 90:
                granularity = "DAILY"
            else:
                granularity = "MONTHLY"

            # Get costs grouped by service
            response = self.cost_explorer_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
                Granularity=granularity,
                Metrics=["UnblendedCost"],
                GroupBy=[
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                ],
            )

            # Process results
            for result in response.get("ResultsByTime", []):
                for group in result.get("Groups", []):
                    service = group.get("Keys", [""])[0]
                    amount = float(
                        group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0")
                    )
                    if service and amount > 0:
                        # Sum costs across time periods (days or months)
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
        """Get costs by resource for a specific service using usage type grouping.

        Note: Cost Explorer doesn't support resource-level costs without tags.
        This returns service-level totals grouped by usage type.
        """
        costs_by_resource = {}

        try:
            # Cost Explorer doesn't support RESOURCE_ID grouping directly
            # Instead, we'll use USAGE_TYPE to get more granular cost data
            # For S3, we can filter by usage type (e.g., "Storage", "DataTransfer-Out-Bytes")
            days_in_period = (end_date - start_date).days
            if days_in_period <= 90:
                granularity = "DAILY"
            else:
                granularity = "MONTHLY"

            response = self.cost_explorer_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
                Granularity=granularity,
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
                    amount = float(
                        group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0")
                    )
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
        """Get estimated monthly cost for a service based on last 30 days.

        Returns the actual cost for the last 30 days, which serves as a monthly estimate.
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)

        service_costs = self.get_service_costs(start_date, end_date)
        total_cost = service_costs.get(service, 0.0)

        # Return the actual 30-day cost as monthly estimate
        # This is more accurate than extrapolating from a shorter period
        return total_cost

    def get_cost_for_resource(self, service: str, resource_id: str) -> float:
        """Get estimated monthly cost for a specific resource.

        Returns the actual 30-day cost as the monthly estimate.
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)

        resource_costs = self.get_resource_costs(service, start_date, end_date)
        total_cost = resource_costs.get(resource_id, 0.0)

        # Return the actual 30-day cost
        return total_cost

    def get_savings_plans_summary(self, start_date: datetime, end_date: datetime) -> dict:
        """Get Savings Plans summary including utilization and coverage.

        Returns savings from active Savings Plans.
        """
        summary = {
            "total_savings": 0.0,
            "utilization_percent": 0.0,
            "coverage_percent": 0.0,
            "plans": [],
        }

        try:
            # Get Savings Plans utilization
            util_response = self.cost_explorer_client.get_savings_plans_utilization(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
            )

            total_util = util_response.get("Total", {})
            utilization = total_util.get("Utilization", {})
            summary["utilization_percent"] = float(utilization.get("UtilizationPercentage", 0))

            # Calculate savings from commitment vs on-demand
            amortized = float(
                total_util.get("AmortizedCommitment", {}).get("TotalAmortizedCommitment", 0)
            )
            on_demand = float(total_util.get("Savings", {}).get("OnDemandCostEquivalent", 0))
            net_savings = float(total_util.get("Savings", {}).get("NetSavings", 0))

            summary["total_savings"] = net_savings
            summary["amortized_commitment"] = amortized
            summary["on_demand_equivalent"] = on_demand

        except ClientError as e:
            if "AccessDenied" not in str(e):
                import sys

                print(f"WARNING: Could not get Savings Plans utilization: {e}", file=sys.stderr)
        except Exception as e:
            import sys

            print(f"INFO: Savings Plans data not available: {e}", file=sys.stderr)

        try:
            # Get Savings Plans coverage
            coverage_response = self.cost_explorer_client.get_savings_plans_coverage(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
            )

            total_coverage = coverage_response.get("Total", {})
            coverage = total_coverage.get("Coverage", {})
            summary["coverage_percent"] = float(coverage.get("CoveragePercentage", 0))

        except ClientError:
            pass  # Coverage might not be available
        except Exception:
            pass

        return summary

    def get_all_costs_with_savings(self, start_date: datetime, end_date: datetime) -> dict:
        """Get comprehensive cost breakdown including all services and Savings Plans.

        Returns:
            dict with:
            - service_costs: Dict of service name to cost
            - savings_plans: Savings Plans summary
            - total_cost: Total cost across all services
        """
        result = {
            "service_costs": {},
            "savings_plans": {},
            "total_cost": 0.0,
        }

        # Get all service costs
        result["service_costs"] = self.get_service_costs(start_date, end_date)
        result["total_cost"] = sum(result["service_costs"].values())

        # Get Savings Plans summary
        result["savings_plans"] = self.get_savings_plans_summary(start_date, end_date)

        return result
