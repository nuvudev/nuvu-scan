"""AWS service collectors."""

from .athena import AthenaCollector
from .glue import GlueCollector
from .iam import IAMCollector
from .mwaa import MWAACollector
from .redshift import RedshiftCollector
from .s3 import S3Collector

__all__ = [
    "S3Collector",
    "GlueCollector",
    "AthenaCollector",
    "RedshiftCollector",
    "IAMCollector",
    "MWAACollector",
]
