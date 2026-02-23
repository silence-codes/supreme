#!/usr/bin/env python3
"""
Supreme 2 Light Linux Installers
Package installers for various Linux distributions
"""

from typing import List
import shutil
import subprocess

from supreme2l.platform.installers.base import BaseInstaller, ToolMapper


class AptInstaller(BaseInstaller):
    """Debian/Ubuntu package installer using apt"""

    def __init__(self):
        super().__init__('apt')

    def install(self, package: str, sudo: bool = True) -> bool:
        """Install package using apt with pip fallback for Python tools"""
        if not self.pm_path:
            return False

        settings = self.get_install_settings()
        auto_approve = settings.get('auto_approve', True)
        quiet_mode = settings.get('quiet_mode', True)

        package_name = ToolMapper.get_package_name(package, 'apt')

        # Try apt first if package mapping exists
        if package_name:
            cmd = []
            if sudo:
                cmd.append('sudo')
            cmd.extend(['apt-get', 'install'])
            if auto_approve:
                cmd.append('-y')
                cmd.extend([
                    '-o', 'Dpkg::Options::=--force-confdef',
                    '-o', 'Dpkg::Options::=--force-confold',
                ])
            if quiet_mode:
                cmd.append('--quiet')
            cmd.append(package_name)

            try:
                result = self.run_install_with_retries(cmd)
                if result.returncode == 0:
                    return True
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                # Package manager command failed - try fallbacks
                pass

        # Fallback to pip for Python tools
        if ToolMapper.is_python_tool(package):
            try:
                pip_cmd = ['pip3', 'install', '--no-input']
                if quiet_mode:
                    pip_cmd.append('--quiet')
                pip_cmd.append(package)
                result = self.run_install_with_retries(pip_cmd)
                return result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                # pip install failed - try npm fallback
                pass

        # Fallback to npm for npm tools
        if ToolMapper.is_npm_tool(package):
            if shutil.which('npm'):
                try:
                    npm_cmd = ['npm', 'install', '-g', package]
                    if quiet_mode:
                        npm_cmd.append('--silent')
                    result = self.run_install_with_retries(npm_cmd)
                    return result.returncode == 0
                except (subprocess.SubprocessError, FileNotFoundError, OSError):
                    # npm install failed
                    pass

        return False

    def is_installed(self, package: str) -> bool:
        """Check if package is installed via dpkg"""
        package_name = ToolMapper.get_package_name(package, 'apt')
        if not package_name:
            return False

        try:
            result = self.run_command(['dpkg', '-l', package_name], check=False)
            return result.returncode == 0 and 'ii' in result.stdout
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using apt"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'apt')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['apt', 'remove', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'apt')
        if not package_name:
            return f"# Package '{package}' not available via apt"
        prefix = "sudo " if sudo else ""
        return (
            f"{prefix}apt-get install -y "
            f"-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
            f"--quiet {package_name}"
        )


class YumInstaller(BaseInstaller):
    """RHEL/CentOS package installer using yum"""

    def __init__(self):
        super().__init__('yum')

    def install(self, package: str, sudo: bool = True) -> bool:
        if not self.pm_path:
            return False

        settings = self.get_install_settings()
        auto_approve = settings.get('auto_approve', True)
        quiet_mode = settings.get('quiet_mode', True)

        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['yum', 'install'])
        if auto_approve:
            cmd.append('-y')
        if quiet_mode:
            cmd.append('-q')
        cmd.append(package_name)

        try:
            result = self.run_install_with_retries(cmd)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return False

        try:
            result = self.run_command(['rpm', '-q', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using yum"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['yum', 'remove', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return f"# Package '{package}' not available via yum"
        prefix = "sudo " if sudo else ""
        return f"{prefix}yum install -y -q {package_name}"


class DnfInstaller(BaseInstaller):
    """Fedora/RHEL 8+ package installer using dnf"""

    def __init__(self):
        super().__init__('dnf')

    def install(self, package: str, sudo: bool = True) -> bool:
        if not self.pm_path:
            return False

        settings = self.get_install_settings()
        auto_approve = settings.get('auto_approve', True)
        quiet_mode = settings.get('quiet_mode', True)

        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['dnf', 'install'])
        if auto_approve:
            cmd.append('-y')
        if quiet_mode:
            cmd.append('--quiet')
        cmd.append(package_name)

        try:
            result = self.run_install_with_retries(cmd)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return False

        try:
            result = self.run_command(['rpm', '-q', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using dnf"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['dnf', 'remove', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return f"# Package '{package}' not available via dnf"
        prefix = "sudo " if sudo else ""
        return f"{prefix}dnf install -y --quiet {package_name}"


class PacmanInstaller(BaseInstaller):
    """Arch Linux package installer using pacman"""

    def __init__(self):
        super().__init__('pacman')

    def install(self, package: str, sudo: bool = True) -> bool:
        if not self.pm_path:
            return False

        settings = self.get_install_settings()
        auto_approve = settings.get('auto_approve', True)

        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['pacman', '-S'])
        if auto_approve:
            cmd.append('--noconfirm')
        cmd.append(package_name)

        try:
            result = self.run_install_with_retries(cmd)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return False

        try:
            result = self.run_command(['pacman', '-Q', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using pacman"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['pacman', '-R', '--noconfirm', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return f"# Package '{package}' not available via pacman"
        prefix = "sudo " if sudo else ""
        return f"{prefix}pacman -S --noconfirm {package_name}"
