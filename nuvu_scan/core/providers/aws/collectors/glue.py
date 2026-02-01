"""
AWS Glue Data Catalog collector.

Collects Glue databases, tables, crawlers, ETL jobs, and connections.
"""

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nuvu_scan.core.base import Asset, NormalizedCategory


class GlueCollector:
    """Collects AWS Glue Data Catalog resources."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or ["us-east-1"]  # Glue is regional but catalog is global
        self.region = self.regions[0] if self.regions else "us-east-1"
        self.glue_client = session.client("glue", region_name=self.region)
        # Cache crawler run times to associate with tables
        self._crawler_last_runs: dict[str, datetime | None] = {}
        self._db_to_crawler: dict[str, str] = {}

    def collect(self) -> list[Asset]:
        """Collect all Glue resources: databases, tables, crawlers, jobs, connections."""
        import sys

        assets = []

        # First, collect crawlers to build database-to-crawler mapping
        print("  → Collecting Glue crawlers...", file=sys.stderr)
        crawler_assets = self._collect_crawlers()
        assets.extend(crawler_assets)
        print(f"  → Found {len(crawler_assets)} crawlers", file=sys.stderr)

        # Collect ETL jobs
        print("  → Collecting Glue ETL jobs...", file=sys.stderr)
        job_assets = self._collect_jobs()
        assets.extend(job_assets)
        print(f"  → Found {len(job_assets)} jobs", file=sys.stderr)

        # Collect connections
        print("  → Collecting Glue connections...", file=sys.stderr)
        conn_assets = self._collect_connections()
        assets.extend(conn_assets)
        print(f"  → Found {len(conn_assets)} connections", file=sys.stderr)

        # Collect databases and tables (using crawler info for last_activity)
        print("  → Collecting Glue databases and tables...", file=sys.stderr)
        db_assets = self._collect_databases_and_tables()
        assets.extend(db_assets)
        print(f"  → Found {len(db_assets)} databases/tables", file=sys.stderr)

        return assets

    def _collect_crawlers(self) -> list[Asset]:
        """Collect Glue Crawlers with detailed status."""
        assets = []

        try:
            # List all crawlers
            paginator = self.glue_client.get_paginator("get_crawlers")

            for page in paginator.paginate():
                for crawler in page.get("Crawlers", []):
                    crawler_name = crawler.get("Name", "")
                    db_name = crawler.get("DatabaseName", "")
                    state = crawler.get("State", "UNKNOWN")

                    # Map database to crawler for later use
                    if db_name:
                        self._db_to_crawler[db_name] = crawler_name

                    # Get last crawl info
                    last_crawl = crawler.get("LastCrawl", {})
                    last_crawl_status = last_crawl.get("Status", "UNKNOWN")
                    last_crawl_time = last_crawl.get("StartTime")

                    if last_crawl_time:
                        self._crawler_last_runs[crawler_name] = last_crawl_time

                    # Get schedule info
                    schedule = crawler.get("Schedule", {})
                    schedule_expr = schedule.get("ScheduleExpression") if schedule else None
                    schedule_state = schedule.get("State") if schedule else None

                    # Determine if crawler is stale (no schedule OR hasn't run in 90+ days)
                    risk_flags = []
                    days_since_last_run = None

                    if last_crawl_time:
                        if isinstance(last_crawl_time, datetime):
                            last_dt = last_crawl_time
                        else:
                            last_dt = datetime.fromisoformat(
                                str(last_crawl_time).replace("Z", "+00:00")
                            )
                        now = datetime.now(timezone.utc)
                        days_since_last_run = (now - last_dt).days

                        if days_since_last_run > 90:
                            risk_flags.append("stale_crawler")

                    # No schedule and not recently run = potentially abandoned
                    if not schedule_expr and (
                        days_since_last_run is None or days_since_last_run > 30
                    ):
                        risk_flags.append("no_schedule")

                    # Never run
                    if not last_crawl_time:
                        risk_flags.append("never_run")

                    tags = self._get_crawler_tags(crawler_name)
                    ownership = self._infer_ownership(tags, crawler_name)

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="glue_crawler",
                            normalized_category=NormalizedCategory.DATA_PIPELINE,
                            service="Glue",
                            region=self.region,
                            arn=f"arn:aws:glue:{self.region}::crawler/{crawler_name}",
                            name=crawler_name,
                            created_at=crawler.get("CreationTime").isoformat()
                            if crawler.get("CreationTime")
                            else None,
                            tags=tags,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            last_activity_at=last_crawl_time.isoformat()
                            if last_crawl_time
                            else None,
                            usage_metrics={
                                "state": state,
                                "last_crawl_status": last_crawl_status,
                                "schedule_expression": schedule_expr,
                                "schedule_state": schedule_state,
                                "database_name": db_name,
                                "days_since_last_run": days_since_last_run,
                                "tables_created": last_crawl.get("TablesCreated", 0),
                                "tables_updated": last_crawl.get("TablesUpdated", 0),
                                "tables_deleted": last_crawl.get("TablesDeleted", 0),
                            },
                        )
                    )

        except ClientError as e:
            print(f"Error collecting Glue crawlers: {e}")

        return assets

    def _collect_jobs(self) -> list[Asset]:
        """Collect Glue ETL Jobs with run history."""
        assets = []

        try:
            # List all jobs
            paginator = self.glue_client.get_paginator("get_jobs")

            for page in paginator.paginate():
                for job in page.get("Jobs", []):
                    job_name = job.get("Name", "")

                    # Get last job run
                    last_run = None
                    last_run_status = None
                    days_since_last_run = None

                    try:
                        runs_response = self.glue_client.get_job_runs(
                            JobName=job_name, MaxResults=1
                        )
                        runs = runs_response.get("JobRuns", [])
                        if runs:
                            last_run = runs[0].get("StartedOn")
                            last_run_status = runs[0].get("JobRunState", "UNKNOWN")

                            if last_run:
                                if isinstance(last_run, datetime):
                                    last_dt = last_run
                                else:
                                    last_dt = datetime.fromisoformat(
                                        str(last_run).replace("Z", "+00:00")
                                    )
                                now = datetime.now(timezone.utc)
                                days_since_last_run = (now - last_dt).days
                    except ClientError:
                        pass

                    # Determine risk flags
                    risk_flags = []
                    if days_since_last_run is not None and days_since_last_run > 90:
                        risk_flags.append("stale_job")
                    if last_run is None:
                        risk_flags.append("never_run")
                    if last_run_status in ["FAILED", "ERROR", "TIMEOUT"]:
                        risk_flags.append("failed_job")

                    tags = self._get_job_tags(job_name)
                    ownership = self._infer_ownership(tags, job_name)

                    # Estimate cost based on DPU allocation
                    allocated_capacity = (
                        job.get("AllocatedCapacity", 0) or job.get("MaxCapacity", 0) or 2
                    )
                    # Glue ETL: ~$0.44/DPU-hour, assume average 1 hour run per day for active jobs
                    estimated_monthly_cost = 0.0
                    if days_since_last_run is not None and days_since_last_run < 30:
                        # Active job, estimate based on recent usage
                        runs_per_month = 30 if days_since_last_run < 7 else 4
                        estimated_monthly_cost = allocated_capacity * 0.44 * runs_per_month

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="glue_job",
                            normalized_category=NormalizedCategory.DATA_PIPELINE,
                            service="Glue",
                            region=self.region,
                            arn=f"arn:aws:glue:{self.region}::job/{job_name}",
                            name=job_name,
                            created_at=job.get("CreatedOn").isoformat()
                            if job.get("CreatedOn")
                            else None,
                            tags=tags,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            last_activity_at=last_run.isoformat() if last_run else None,
                            cost_estimate_usd=estimated_monthly_cost,
                            usage_metrics={
                                "job_type": job.get("Command", {}).get("Name", "unknown"),
                                "glue_version": job.get("GlueVersion", "unknown"),
                                "allocated_capacity": allocated_capacity,
                                "max_retries": job.get("MaxRetries", 0),
                                "timeout_minutes": job.get("Timeout"),
                                "last_run_status": last_run_status,
                                "days_since_last_run": days_since_last_run,
                            },
                        )
                    )

        except ClientError as e:
            print(f"Error collecting Glue jobs: {e}")

        return assets

    def _collect_connections(self) -> list[Asset]:
        """Collect Glue Connections (JDBC, etc.)."""
        assets = []

        try:
            response = self.glue_client.get_connections()

            for conn in response.get("ConnectionList", []):
                conn_name = conn.get("Name", "")
                conn_type = conn.get("ConnectionType", "UNKNOWN")

                # Get connection properties for governance insights
                conn_props = conn.get("ConnectionProperties", {})
                jdbc_url = conn_props.get("JDBC_CONNECTION_URL", "")

                # Detect external data sources
                risk_flags = []
                if "redshift" in jdbc_url.lower():
                    # Redshift connection
                    pass
                elif "rds" in jdbc_url.lower() or "aurora" in jdbc_url.lower():
                    # RDS/Aurora connection
                    pass
                elif jdbc_url and not any(x in jdbc_url.lower() for x in ["amazonaws.com", "aws"]):
                    # External (non-AWS) database connection
                    risk_flags.append("external_connection")

                # Check if connection has last tested time
                last_updated = conn.get("LastUpdatedTime")

                assets.append(
                    Asset(
                        provider="aws",
                        asset_type="glue_connection",
                        normalized_category=NormalizedCategory.DATA_PIPELINE,
                        service="Glue",
                        region=self.region,
                        arn=f"arn:aws:glue:{self.region}::connection/{conn_name}",
                        name=conn_name,
                        created_at=conn.get("CreationTime").isoformat()
                        if conn.get("CreationTime")
                        else None,
                        risk_flags=risk_flags,
                        last_activity_at=last_updated.isoformat() if last_updated else None,
                        usage_metrics={
                            "connection_type": conn_type,
                            "jdbc_url_masked": self._mask_jdbc_url(jdbc_url) if jdbc_url else None,
                            "physical_connection_requirements": bool(
                                conn.get("PhysicalConnectionRequirements")
                            ),
                        },
                    )
                )

        except ClientError as e:
            print(f"Error collecting Glue connections: {e}")

        return assets

    def _collect_databases_and_tables(self) -> list[Asset]:
        """Collect Glue databases and tables with improved activity tracking."""
        assets = []

        try:
            # List databases
            paginator = self.glue_client.get_paginator("get_databases")

            for page in paginator.paginate():
                for db_info in page.get("DatabaseList", []):
                    db_name = db_info["Name"]

                    # Get last activity from associated crawler
                    last_activity = None
                    crawler_name = self._db_to_crawler.get(db_name)
                    if crawler_name and crawler_name in self._crawler_last_runs:
                        crawler_time = self._crawler_last_runs[crawler_name]
                        if crawler_time:
                            last_activity = (
                                crawler_time.isoformat()
                                if isinstance(crawler_time, datetime)
                                else str(crawler_time)
                            )

                    # Create database asset
                    tags = self._get_tags(f"database/{db_name}")
                    ownership = self._infer_ownership(tags, db_name)

                    # Count tables in this database
                    table_count = 0
                    try:
                        table_paginator = self.glue_client.get_paginator("get_tables")
                        for table_page in table_paginator.paginate(DatabaseName=db_name):
                            table_count += len(table_page.get("TableList", []))
                    except ClientError:
                        pass

                    # Detect stale databases (no tables or no recent crawler activity)
                    risk_flags = []
                    if table_count == 0:
                        risk_flags.append("empty_database")
                    if not crawler_name:
                        risk_flags.append("no_crawler")

                    assets.append(
                        Asset(
                            provider="aws",
                            asset_type="glue_database",
                            normalized_category=NormalizedCategory.DATA_CATALOG,
                            service="Glue",
                            region=self.region,
                            arn=db_info.get("CatalogId", "") + "::" + db_name,
                            name=db_name,
                            created_at=(
                                db_info.get("CreateTime", "").isoformat()
                                if db_info.get("CreateTime")
                                else None
                            ),
                            tags=tags,
                            risk_flags=risk_flags,
                            ownership_confidence=ownership["confidence"],
                            suggested_owner=ownership["owner"],
                            last_activity_at=last_activity,
                            usage_metrics={
                                "table_count": table_count,
                                "associated_crawler": crawler_name,
                                "last_used": last_activity,
                                "days_since_last_use": self._calculate_days_since(last_activity),
                            },
                        )
                    )

                    # List tables in database
                    try:
                        table_paginator = self.glue_client.get_paginator("get_tables")
                        for table_page in table_paginator.paginate(DatabaseName=db_name):
                            for table_info in table_page.get("TableList", []):
                                table_name = table_info["Name"]
                                table_tags = self._get_tags(f"table/{db_name}/{table_name}")
                                table_ownership = self._infer_ownership(table_tags, table_name)

                                # Get table update time as activity indicator
                                table_updated = table_info.get("UpdateTime") or table_info.get(
                                    "CreateTime"
                                )
                                table_activity = (
                                    table_updated.isoformat() if table_updated else last_activity
                                )

                                # Check if table is empty/unused
                                partition_count = len(table_info.get("PartitionKeys", []))
                                storage = table_info.get("StorageDescriptor", {})

                                risk_flags = []
                                if partition_count == 0 and not storage:
                                    risk_flags.append("empty_table")

                                # Check for external tables (Spectrum)
                                location = storage.get("Location", "") if storage else ""
                                is_external = location.startswith("s3://") if location else False

                                assets.append(
                                    Asset(
                                        provider="aws",
                                        asset_type="glue_table",
                                        normalized_category=NormalizedCategory.DATA_CATALOG,
                                        service="Glue",
                                        region=self.region,
                                        arn=f"{db_info.get('CatalogId', '')}::{db_name}::{table_name}",
                                        name=f"{db_name}.{table_name}",
                                        created_at=(
                                            table_info.get("CreateTime", "").isoformat()
                                            if table_info.get("CreateTime")
                                            else None
                                        ),
                                        tags=table_tags,
                                        risk_flags=risk_flags,
                                        ownership_confidence=table_ownership["confidence"],
                                        suggested_owner=table_ownership["owner"],
                                        last_activity_at=table_activity,
                                        usage_metrics={
                                            "partition_count": partition_count,
                                            "is_external": is_external,
                                            "table_type": table_info.get("TableType", ""),
                                            "input_format": storage.get("InputFormat", "")
                                            if storage
                                            else "",
                                            "location": location[:50] + "..."
                                            if len(location) > 50
                                            else location,
                                            "last_used": table_activity,
                                            "days_since_last_use": self._calculate_days_since(
                                                table_activity
                                            ),
                                        },
                                    )
                                )
                    except ClientError:
                        pass

        except ClientError as e:
            print(f"Error collecting Glue resources: {e}")

        return assets

    def _get_tags(self, resource_arn: str) -> dict[str, str]:
        """Get tags for a Glue resource."""
        try:
            # Glue uses get_tags API
            response = self.glue_client.get_tags(ResourceArn=resource_arn)
            return response.get("Tags", {})
        except ClientError:
            return {}

    def _get_crawler_tags(self, crawler_name: str) -> dict[str, str]:
        """Get tags for a Glue crawler."""
        try:
            arn = f"arn:aws:glue:{self.region}:{self._get_account_id()}:crawler/{crawler_name}"
            response = self.glue_client.get_tags(ResourceArn=arn)
            return response.get("Tags", {})
        except ClientError:
            return {}

    def _get_job_tags(self, job_name: str) -> dict[str, str]:
        """Get tags for a Glue job."""
        try:
            arn = f"arn:aws:glue:{self.region}:{self._get_account_id()}:job/{job_name}"
            response = self.glue_client.get_tags(ResourceArn=arn)
            return response.get("Tags", {})
        except ClientError:
            return {}

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity()["Account"]
        except ClientError:
            return ""

    def _infer_ownership(self, tags: dict[str, str], name: str) -> dict[str, str]:
        """Infer ownership from tags."""
        owner = None
        confidence = "unknown"

        if "owner" in tags:
            owner = tags["owner"]
            confidence = "high"
        elif "team" in tags:
            owner = tags["team"]
            confidence = "medium"
        elif "Owner" in tags:
            owner = tags["Owner"]
            confidence = "high"
        elif "Team" in tags:
            owner = tags["Team"]
            confidence = "medium"

        return {"owner": owner, "confidence": confidence}

    def _mask_jdbc_url(self, jdbc_url: str) -> str:
        """Mask sensitive parts of JDBC URL."""
        import re

        # Mask password in JDBC URL
        masked = re.sub(r"password=[^&;]+", "password=***", jdbc_url, flags=re.IGNORECASE)
        masked = re.sub(r":[^:@]+@", ":***@", masked)
        return masked

    def _calculate_days_since(self, timestamp: str | None) -> int | None:
        """Calculate days since a timestamp."""
        if not timestamp:
            return None
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            return (now - dt).days
        except Exception:
            return None

    def get_usage_metrics(self, asset: Asset) -> dict[str, Any]:
        """Get usage metrics for Glue asset."""
        return asset.usage_metrics or {}

    def get_cost_estimate(self, asset: Asset) -> float:
        """Estimate cost for Glue asset."""
        if asset.cost_estimate_usd:
            return asset.cost_estimate_usd

        # Glue Data Catalog: $1 per 100,000 objects per month
        if asset.asset_type == "glue_table":
            return 0.01
        elif asset.asset_type == "glue_database":
            return 0.005
        elif asset.asset_type == "glue_crawler":
            # Crawlers: $0.44/DPU-hour, assume minimal usage if not active
            return 0.50  # Minimal monthly estimate
        elif asset.asset_type == "glue_connection":
            return 0.0  # Connections are free
        return 0.0
