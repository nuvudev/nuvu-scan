"""
Scan command for Nuvu CLI.
"""

import json
import os
import sys
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import click

from ...core import ScanConfig
from ...core.providers.aws import AWSScanner
from ...core.providers.gcp import GCPScanner
from ..formatters.csv import CSVFormatter
from ..formatters.html import HTMLFormatter
from ..formatters.json import JSONFormatter


@click.command(name="scan")
@click.option(
    "--provider",
    type=click.Choice(["aws", "gcp"], case_sensitive=False),
    default="aws",
    help="Cloud provider to scan (default: aws)",
)
@click.option(
    "--output-format",
    type=click.Choice(["html", "json", "csv"], case_sensitive=False),
    default="html",
    help="Output format (default: html)",
)
@click.option(
    "--output-file",
    type=click.Path(),
    help="Output file path (default: stdout or nuvu-scan-{timestamp}.{format})",
)
@click.option(
    "--region",
    multiple=True,
    help="Cloud provider region(s) to scan (can be specified multiple times, default: all regions)",
)
@click.option(
    "--access-key-id",
    envvar="AWS_ACCESS_KEY_ID",
    help="AWS access key ID (default: from AWS_ACCESS_KEY_ID env var)",
)
@click.option(
    "--secret-access-key",
    envvar="AWS_SECRET_ACCESS_KEY",
    help="AWS secret access key (default: from AWS_SECRET_ACCESS_KEY env var)",
)
@click.option(
    "--session-token",
    envvar="AWS_SESSION_TOKEN",
    help="AWS session token for temporary credentials (default: from AWS_SESSION_TOKEN env var)",
)
@click.option("--profile", help="AWS profile name (default: default profile)")
@click.option(
    "--role-arn",
    help="IAM role ARN to assume (e.g., arn:aws:iam::123456789012:role/MyRole)",
)
@click.option(
    "--role-session-name",
    default="nuvu-scan-session",
    help="Session name for role assumption (default: nuvu-scan-session)",
)
@click.option(
    "--external-id",
    help="External ID for role assumption (required if role requires it)",
)
@click.option(
    "--role-duration-seconds",
    type=int,
    default=3600,
    help="Duration in seconds for assumed role credentials (default: 3600)",
)
@click.option(
    "--gcp-credentials",
    envvar="GOOGLE_APPLICATION_CREDENTIALS",
    help="Path to GCP service account JSON key file (default: from GOOGLE_APPLICATION_CREDENTIALS env var)",
)
@click.option(
    "--gcp-project",
    help="GCP project ID (default: from service account key or GOOGLE_CLOUD_PROJECT env var)",
)
@click.option(
    "--push",
    is_flag=True,
    help="Push scan results to Nuvu Cloud (requires API key)",
)
@click.option(
    "--nuvu-cloud-url",
    envvar="NUVU_CLOUD_URL",
    default="https://nuvu.dev",
    show_default=True,
    help="Nuvu Cloud base URL",
)
@click.option(
    "--api-key",
    envvar="NUVU_API_KEY",
    help="Nuvu Cloud API key (from dashboard account settings)",
)
def scan_command(
    provider: str,
    output_format: str,
    output_file: str | None,
    region: tuple,
    access_key_id: str | None,
    secret_access_key: str | None,
    session_token: str | None,
    profile: str | None,
    role_arn: str | None,
    role_session_name: str,
    external_id: str | None,
    role_duration_seconds: int,
    gcp_credentials: str | None,
    gcp_project: str | None,
    push: bool,
    nuvu_cloud_url: str | None,
    api_key: str | None,
):
    """Scan cloud provider for data assets."""

    # Build credentials based on provider
    credentials = {}
    account_id = None

    if provider == "aws":
        # Build credentials dict
        credentials = {}

        # Get credentials from CLI args or environment
        if access_key_id and secret_access_key:
            credentials["access_key_id"] = access_key_id
            credentials["secret_access_key"] = secret_access_key
            # Add session token if provided
            if session_token:
                credentials["session_token"] = session_token
        elif profile:
            credentials["profile"] = profile
        else:
            # Try environment variables
            access_key_id = os.getenv("AWS_ACCESS_KEY_ID_NUVU") or os.getenv("AWS_ACCESS_KEY_ID")
            secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY_NUVU") or os.getenv(
                "AWS_SECRET_ACCESS_KEY"
            )
            session_token = os.getenv("AWS_SESSION_TOKEN_NUVU") or os.getenv("AWS_SESSION_TOKEN")

            if access_key_id and secret_access_key:
                credentials["access_key_id"] = access_key_id
                credentials["secret_access_key"] = secret_access_key
                if session_token:
                    credentials["session_token"] = session_token

        # Set region
        if region:
            credentials["region"] = region[0]
        elif "region" not in credentials:
            credentials["region"] = "us-east-1"

        # Add role assumption parameters if provided
        if role_arn:
            credentials["role_arn"] = role_arn
            credentials["role_session_name"] = role_session_name
            if external_id:
                credentials["external_id"] = external_id
            credentials["duration_seconds"] = role_duration_seconds

    elif provider == "gcp":
        # GCP credentials handling
        if gcp_credentials:
            credentials["service_account_key_file"] = gcp_credentials
        else:
            # Try environment variable
            gcp_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            if gcp_creds:
                credentials["service_account_key_file"] = gcp_creds
            else:
                click.echo(
                    "Error: GCP credentials required. Set GOOGLE_APPLICATION_CREDENTIALS "
                    "or use --gcp-credentials",
                    err=True,
                )
                sys.exit(1)

        # Get project ID
        if gcp_project:
            credentials["project_id"] = gcp_project
            account_id = gcp_project
        else:
            # Try environment variable
            project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
            if project_id:
                credentials["project_id"] = project_id
                account_id = project_id
            else:
                # Will try to get from service account key
                account_id = None

    # Create scan config
    config = ScanConfig(
        provider=provider,
        credentials=credentials,
        regions=list(region) if region else None,
        account_id=account_id,
    )

    # Get scanner instance
    if provider == "aws":
        scanner = AWSScanner(config)
    elif provider == "gcp":
        scanner = GCPScanner(config)
    else:
        click.echo(f"Provider {provider} not yet supported", err=True)
        sys.exit(1)

    # Run scan
    click.echo(f"Scanning {provider}...", err=True)
    try:
        result = scanner.scan()
        click.echo(f"Found {len(result.assets)} assets", err=True)

        # Provide helpful message if no assets found
        if len(result.assets) == 0:
            click.echo("\nNo assets found. This could mean:", err=True)
            if provider == "gcp":
                click.echo(
                    "  - The project has no GCS buckets, BigQuery datasets, Dataproc clusters, or Pub/Sub topics",
                    err=True,
                )
                click.echo(
                    "  - Resources might be in a different GCP project",
                    err=True,
                )
                click.echo(
                    "  - Required APIs might not be enabled (check GCP Console → APIs & Services)",
                    err=True,
                )
            elif provider == "aws":
                click.echo(
                    "  - The account has no S3 buckets, Glue databases, Athena workgroups, or Redshift clusters",
                    err=True,
                )
                click.echo(
                    "  - Resources might be in a different AWS account or region",
                    err=True,
                )
    except Exception as e:
        click.echo(f"Error during scan: {e}", err=True)
        sys.exit(1)

    # Format output
    if output_format == "html":
        formatter = HTMLFormatter()
        content = formatter.format(result)
        extension = "html"
    elif output_format == "json":
        formatter = JSONFormatter()
        content = formatter.format(result)
        extension = "json"
    elif output_format == "csv":
        formatter = CSVFormatter()
        content = formatter.format(result)
        extension = "csv"

    # Determine output file
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = f"nuvu-scan-{timestamp}.{extension}"

    # Write output
    if output_file == "-":
        click.echo(content)
    else:
        with open(output_file, "w") as f:
            f.write(content)
        click.echo(f"Report written to {output_file}", err=True)

    if push:
        if not nuvu_cloud_url:
            click.echo("Error: --nuvu-cloud-url or NUVU_CLOUD_URL is required for --push", err=True)
            sys.exit(1)
        if not api_key:
            click.echo("Error: --api-key or NUVU_API_KEY is required for --push", err=True)
            sys.exit(1)

        payload = json.loads(JSONFormatter().format(result))
        payload["scan_regions"] = list(region) if region else None
        payload["scan_all_regions"] = False if region else True

        import_url = nuvu_cloud_url.rstrip("/") + "/api/scans/import"
        request = Request(
            import_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )

        try:
            with urlopen(request) as response:
                response_body = response.read().decode("utf-8")
                click.echo(f"Scan uploaded to Nuvu Cloud: {response.status}", err=True)
                if response_body:
                    click.echo(response_body, err=True)
        except HTTPError as e:
            error_body = e.read().decode("utf-8")
            click.echo(f"Failed to upload scan: {e.code} {e.reason}", err=True)
            if error_body:
                click.echo(error_body, err=True)
            sys.exit(1)
        except URLError as e:
            click.echo(f"Failed to upload scan: {e.reason}", err=True)
            sys.exit(1)
