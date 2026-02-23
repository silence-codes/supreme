"""
Supreme 2 Light Platform Detection & Installation
Cross-platform OS detection and linter installation
"""

from supreme2l.platform.detector import (
    PlatformDetector,
    PlatformInfo,
    OSType,
    PackageManager,
    WindowsEnvironment,
    get_platform_info,
    detect_platform,
)

__all__ = [
    'PlatformDetector',
    'PlatformInfo',
    'OSType',
    'PackageManager',
    'WindowsEnvironment',
    'get_platform_info',
    'detect_platform',
]
