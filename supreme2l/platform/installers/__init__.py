"""
Supreme 2 Light Platform-Specific Installers
Linter installation for Linux, macOS, and Windows
"""

from supreme2l.platform.installers.base import BaseInstaller, ToolMapper
from supreme2l.platform.installers.linux import (
    AptInstaller,
    YumInstaller,
    DnfInstaller,
    PacmanInstaller,
)
from supreme2l.platform.installers.macos import HomebrewInstaller
from supreme2l.platform.installers.windows import WingetInstaller, ChocolateyInstaller, WindowsCustomInstaller
from supreme2l.platform.installers.cross_platform import NpmInstaller, PipInstaller

__all__ = [
    'BaseInstaller',
    'ToolMapper',
    'AptInstaller',
    'YumInstaller',
    'DnfInstaller',
    'PacmanInstaller',
    'HomebrewInstaller',
    'WingetInstaller',
    'ChocolateyInstaller',
    'WindowsCustomInstaller',
    'NpmInstaller',
    'PipInstaller',
]
