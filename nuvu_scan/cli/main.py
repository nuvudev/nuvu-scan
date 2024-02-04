"""
Nuvu CLI entry point.

Usage:
    nuvu scan --provider aws
"""

import sys
import click
from .commands.scan import scan_command


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Nuvu - Multi-Cloud Data Asset Control CLI."""
    pass


# Register commands
cli.add_command(scan_command)


if __name__ == "__main__":
    cli()
