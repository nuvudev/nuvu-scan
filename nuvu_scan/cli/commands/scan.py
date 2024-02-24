"""
Scan command for Nuvu CLI.
"""

import os
import sys
from datetime import datetime

import click

from ...core import ScanConfig
from ...core.providers.aws import AWSScanner
from ..formatters.csv import CSVFormatter
from ..formatters.html import HTMLFormatter
from ..formatters.json import JSONFormatter


@click.command(name="scan")
@click.option(
    "--provider",
    type=click.Choice(["aws"], case_sensitive=False),
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
    help="AWS region(s) to scan (can be specified multiple times, default: all regions)",
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
@click.option("--profile", help="AWS profile name (default: default profile)")
def scan_command(
    provider: str,
    output_format: str,
    output_file: str | None,
    region: tuple,
    access_key_id: str | None,
    secret_access_key: str | None,
    profile: str | None,
):
    """Scan cloud provider for data assets."""

    # Build credentials
    credentials = {}
    if access_key_id and secret_access_key:
        credentials = {
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "region": region[0] if region else "us-east-1",
        }
    elif profile:
        credentials = {"profile": profile}
    else:
        # Try environment variables
        access_key_id = os.getenv("AWS_ACCESS_KEY_ID_NUVU") or os.getenv("AWS_ACCESS_KEY_ID")
        secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY_NUVU") or os.getenv(
            "AWS_SECRET_ACCESS_KEY"
        )

        if access_key_id and secret_access_key:
            credentials = {
                "access_key_id": access_key_id,
                "secret_access_key": secret_access_key,
                "region": region[0] if region else "us-east-1",
            }
        else:
            # Use default credentials (IAM role, etc.)
            credentials = {}

    # Create scan config
    config = ScanConfig(
        provider=provider, credentials=credentials, regions=list(region) if region else None
    )

    # Get scanner instance
    if provider == "aws":
        scanner = AWSScanner(config)
    else:
        click.echo(f"Provider {provider} not yet supported", err=True)
        sys.exit(1)

    # Run scan
    click.echo(f"Scanning {provider}...", err=True)
    try:
        result = scanner.scan()
        click.echo(f"Found {len(result.assets)} assets", err=True)
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
