"""
Supreme 2 Light Core Module
Core scanning engine, parallel execution, and reporting
"""

from supreme2l.core.parallel import Supreme2lParallelScanner
from supreme2l.core.reporter import Supreme2lReportGenerator

__all__ = ["Supreme2lParallelScanner", "Supreme2lReportGenerator"]
