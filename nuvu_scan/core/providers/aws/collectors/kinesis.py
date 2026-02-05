"""
AWS Kinesis Collector - Kinesis Data Firehose delivery streams.

Collects Firehose delivery streams and their configurations.
"""

import logging

from nuvu_scan.core.base import Asset, NormalizedCategory

logger = logging.getLogger(__name__)


class KinesisFirehoseCollector:
    """Collector for Kinesis Data Firehose delivery streams."""

    def __init__(self, session, regions: list[str], account_id: str):
        self.session = session
        self.regions = regions
        self.account_id = account_id

    def collect(self) -> list[Asset]:
        """Collect Firehose delivery streams."""
        assets = []

        for region in self.regions:
            try:
                firehose = self.session.client("firehose", region_name=region)
                assets.extend(self._collect_delivery_streams(firehose, region))
            except Exception as e:
                logger.warning(f"Error collecting Kinesis Firehose in {region}: {e}")

        return assets

    def _collect_delivery_streams(self, firehose, region: str) -> list[Asset]:
        """Collect Firehose delivery streams."""
        assets = []

        try:
            # List all delivery streams
            stream_names = []
            has_more = True
            exclusive_start = None

            while has_more:
                params = {"Limit": 100}
                if exclusive_start:
                    params["ExclusiveStartDeliveryStreamName"] = exclusive_start

                response = firehose.list_delivery_streams(**params)
                stream_names.extend(response.get("DeliveryStreamNames", []))
                has_more = response.get("HasMoreDeliveryStreams", False)
                if stream_names:
                    exclusive_start = stream_names[-1]

            # Get details for each stream
            for stream_name in stream_names:
                try:
                    details = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
                    stream = details.get("DeliveryStreamDescription", {})

                    stream_arn = stream.get("DeliveryStreamARN", "")
                    stream_status = stream.get("DeliveryStreamStatus", "unknown")
                    stream_type = stream.get("DeliveryStreamType", "DirectPut")

                    # Determine destination type
                    destinations = stream.get("Destinations", [])
                    destination_type = "unknown"
                    destination_details = {}

                    for dest in destinations:
                        if dest.get("S3DestinationDescription"):
                            destination_type = "S3"
                            s3_dest = dest["S3DestinationDescription"]
                            destination_details = {
                                "bucket_arn": s3_dest.get("BucketARN"),
                                "prefix": s3_dest.get("Prefix"),
                                "compression": s3_dest.get("CompressionFormat"),
                            }
                        elif dest.get("ExtendedS3DestinationDescription"):
                            destination_type = "ExtendedS3"
                            s3_dest = dest["ExtendedS3DestinationDescription"]
                            destination_details = {
                                "bucket_arn": s3_dest.get("BucketARN"),
                                "prefix": s3_dest.get("Prefix"),
                                "compression": s3_dest.get("CompressionFormat"),
                                "data_format": s3_dest.get(
                                    "DataFormatConversionConfiguration", {}
                                ).get("Enabled", False),
                            }
                        elif dest.get("RedshiftDestinationDescription"):
                            destination_type = "Redshift"
                            rs_dest = dest["RedshiftDestinationDescription"]
                            destination_details = {
                                "cluster_jdbcurl": rs_dest.get("ClusterJDBCURL"),
                                "copy_command": rs_dest.get("CopyCommand", {}).get("DataTableName"),
                            }
                        elif dest.get("ElasticsearchDestinationDescription"):
                            destination_type = "Elasticsearch"
                        elif dest.get("SplunkDestinationDescription"):
                            destination_type = "Splunk"
                        elif dest.get("HttpEndpointDestinationDescription"):
                            destination_type = "HTTP"

                    # Get tags
                    tags = {}
                    try:
                        tag_response = firehose.list_tags_for_delivery_stream(
                            DeliveryStreamName=stream_name
                        )
                        for tag in tag_response.get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                    except Exception:
                        pass

                    # Estimate cost - Firehose charges per GB ingested
                    # ~$0.029/GB for first 500TB, estimate based on typical usage
                    estimated_cost = 50.0  # Rough estimate, depends on volume

                    risk_flags = []
                    if stream_status != "ACTIVE":
                        risk_flags.append("not_active")

                    # Check encryption
                    encryption = stream.get("DeliveryStreamEncryptionConfiguration", {})
                    if encryption.get("Status") != "ENABLED":
                        risk_flags.append("no_encryption")

                    owner = (
                        tags.get("team")
                        or tags.get("owner")
                        or tags.get("Team")
                        or tags.get("Owner")
                    )

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="firehose_delivery_stream",
                            normalized_category=NormalizedCategory.STREAMING,
                            service="Kinesis Firehose",
                            region=region,
                            arn=stream_arn,
                            name=stream_name,
                            created_at=stream.get("CreateTimestamp", "").isoformat()
                            if stream.get("CreateTimestamp")
                            else None,
                            tags=tags,
                            cost_estimate_usd=estimated_cost,
                            usage_metrics={
                                "stream_name": stream_name,
                                "status": stream_status,
                                "stream_type": stream_type,
                                "destination_type": destination_type,
                                "destination_details": destination_details,
                                "version_id": stream.get("VersionId"),
                                "has_source_kinesis_stream": stream.get("Source", {}).get(
                                    "KinesisStreamSourceDescription"
                                )
                                is not None,
                            },
                            risk_flags=risk_flags if risk_flags else None,
                            ownership_confidence="high" if owner else "unknown",
                            suggested_owner=owner,
                        )
                    )

                except Exception as e:
                    logger.warning(f"Error getting details for stream {stream_name}: {e}")

        except Exception as e:
            logger.warning(f"Error collecting delivery streams: {e}")

        return assets
