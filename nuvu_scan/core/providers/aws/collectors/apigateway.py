"""
AWS API Gateway Collector - REST APIs, HTTP APIs, WebSocket APIs.

Collects API Gateway resources and their configurations.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class APIGatewayCollector:
    """Collector for API Gateway APIs."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect API Gateway APIs."""
        assets = []

        for region in self.regions:
            try:
                # REST APIs (API Gateway v1)
                apigw = self.session.client("apigateway", region_name=region)
                assets.extend(self._collect_rest_apis(apigw, region))

                # HTTP APIs and WebSocket APIs (API Gateway v2)
                apigwv2 = self.session.client("apigatewayv2", region_name=region)
                assets.extend(self._collect_v2_apis(apigwv2, region))

            except Exception as e:
                logger.warning(f"Error collecting API Gateway in {region}: {e}")

        return assets

    def _collect_rest_apis(self, apigw, region: str) -> list[Asset]:
        """Collect REST APIs (v1)."""
        assets = []

        try:
            paginator = apigw.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    api_id = api["id"]
                    api_name = api.get("name", api_id)

                    # Get tags
                    tags = api.get("tags", {})

                    # Get stages to determine if deployed
                    stages = []
                    try:
                        stage_response = apigw.get_stages(restApiId=api_id)
                        stages = stage_response.get("item", [])
                    except Exception:
                        pass

                    # Estimate cost - REST API costs per million requests
                    # ~$3.50 per million requests (first 333 million)
                    estimated_cost = 10.0  # Rough estimate, depends on usage

                    risk_flags = []
                    if len(stages) == 0:
                        risk_flags.append("not_deployed")

                    # Check endpoint type
                    endpoint_config = api.get("endpointConfiguration", {})
                    endpoint_types = endpoint_config.get("types", [])
                    if "EDGE" in endpoint_types:
                        risk_flags.append("edge_optimized")  # Consider REGIONAL for cost

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="rest_api",
                            normalized_category=NormalizedCategory.SERVERLESS,
                            service="API Gateway",
                            region=region,
                            arn=f"arn:aws:apigateway:{region}::/restapis/{api_id}",
                            name=api_name,
                            created_at=api.get("createdDate", "").isoformat()
                            if api.get("createdDate")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "api_id": api_id,
                                "api_type": "REST",
                                "description": api.get("description", ""),
                                "endpoint_types": endpoint_types,
                                "stages": [s.get("stageName") for s in stages],
                                "stage_count": len(stages),
                                "api_key_source": api.get("apiKeySource"),
                                "minimum_compression_size": api.get("minimumCompressionSize"),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting REST APIs: {e}")

        return assets

    def _collect_v2_apis(self, apigwv2, region: str) -> list[Asset]:
        """Collect HTTP APIs and WebSocket APIs (v2)."""
        assets = []

        try:
            paginator = apigwv2.get_paginator("get_apis")
            for page in paginator.paginate():
                for api in page.get("Items", []):
                    api_id = api["ApiId"]
                    api_name = api.get("Name", api_id)
                    protocol_type = api.get("ProtocolType", "HTTP")  # HTTP or WEBSOCKET

                    # Get tags
                    tags = api.get("Tags", {})

                    # Get stages
                    stages = []
                    try:
                        stage_response = apigwv2.get_stages(ApiId=api_id)
                        stages = stage_response.get("Items", [])
                    except Exception:
                        pass

                    # HTTP API is cheaper than REST API
                    # ~$1.00 per million requests
                    estimated_cost = 5.0  # Rough estimate

                    risk_flags = []
                    if len(stages) == 0:
                        risk_flags.append("not_deployed")

                    # Check if CORS is configured
                    if not api.get("CorsConfiguration"):
                        risk_flags.append("no_cors_config")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    asset_type = "http_api" if protocol_type == "HTTP" else "websocket_api"

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type=asset_type,
                            normalized_category=NormalizedCategory.SERVERLESS,
                            service="API Gateway",
                            region=region,
                            arn=f"arn:aws:apigateway:{region}::/apis/{api_id}",
                            name=api_name,
                            created_at=api.get("CreatedDate", "").isoformat()
                            if api.get("CreatedDate")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "api_id": api_id,
                                "api_type": protocol_type,
                                "description": api.get("Description", ""),
                                "api_endpoint": api.get("ApiEndpoint"),
                                "stages": [s.get("StageName") for s in stages],
                                "stage_count": len(stages),
                                "disable_execute_api_endpoint": api.get(
                                    "DisableExecuteApiEndpoint", False
                                ),
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error collecting HTTP/WebSocket APIs: {e}")

        return assets
