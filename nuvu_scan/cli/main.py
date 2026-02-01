"""
Nuvu CLI entry point.

Usage:
    nuvu scan --provider aws
"""

import click

from .. import __version__
from .commands.scan import scan_command


@click.group()
@click.version_option(version=__version__, prog_name="nuvu-scan")
def cli():
    """Nuvu - Multi-Cloud Data Asset Control CLI."""
    pass


# Register commands
cli.add_command(scan_command)


if __name__ == "__main__":
    cli()
