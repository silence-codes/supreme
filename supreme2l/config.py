#!/usr/bin/env python3
"""
Supreme 2 Light Configuration Management
Handles .supreme2l.yml configuration files
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Supreme2lConfig:
    """Supreme 2 Light configuration structure"""

    # Version
    version: str = "0.11.9"

    # Scanner configuration
    scanners_enabled: List[str] = field(default_factory=list)  # Empty = all
    scanners_disabled: List[str] = field(default_factory=list)
    scanner_overrides: Dict[str, str] = field(default_factory=dict)  # file_path -> scanner_name

    # Severity settings
    fail_on: str = "high"  # critical, high, medium, low

    # Exclusion patterns - these are directories/paths that should NEVER be scanned
    # Users download Supreme 2 Light to scan THEIR code, not third-party dependencies
    exclude_paths: List[str] = field(default_factory=lambda: [
        # === JavaScript/Node.js dependencies ===
        "node_modules/",
        "bower_components/",

        # === Python virtual environments & dependencies ===
        "venv/",
        ".venv/",
        "env/",
        ".env/",
        "*-env/",           # Matches any-env/, supreme2l-env/, etc.
        "*_env/",           # Matches any_env/, python_env/, etc.
        "virtualenv/",
        ".virtualenv/",
        "site-packages/",   # CRITICAL: pip installed packages
        "dist-packages/",   # System-wide Python packages
        "lib/python*/",     # Virtual env lib directories
        "lib64/python*/",

        # === Ruby dependencies ===
        "vendor/bundle/",
        ".bundle/",

        # === Go dependencies ===
        "vendor/",

        # === Rust dependencies ===
        "target/",

        # === Java/Kotlin/Scala dependencies ===
        ".gradle/",
        ".m2/",
        "build/libs/",

        # === .NET dependencies ===
        "packages/",
        "bin/Debug/",
        "bin/Release/",
        "obj/",

        # === PHP dependencies ===
        "vendor/",

        # === Version control ===
        ".git/",
        ".svn/",
        ".hg/",

        # === Build/cache directories ===
        "__pycache__/",
        "*.egg-info/",
        "dist/",
        "build/",
        ".tox/",
        ".nox/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".cache/",
        ".coverage/",
        "htmlcov/",
        ".eggs/",

        # === IDE/Editor directories ===
        ".idea/",
        ".vscode/",
        "*.xcworkspace/",
        "*.xcodeproj/",

        # === Test fixtures (intentionally insecure) ===
        "tests/fixtures/",
        "test/fixtures/",
        "test-fixtures/",
        "__fixtures__/",
    ])

    exclude_files: List[str] = field(default_factory=lambda: [
        "*.min.js",
        "*.min.css",
        "*.bundle.js",
        "*.map",
    ])

    # IDE integration settings
    ide_claude_code_enabled: bool = False
    ide_claude_code_auto_scan: bool = True
    ide_claude_code_inline_annotations: bool = True

    ide_cursor_enabled: bool = False
    ide_vscode_enabled: bool = False
    ide_gemini_enabled: bool = False

    # Scan settings
    workers: Optional[int] = None  # None = auto-detect
    cache_enabled: bool = True

    # Scanner installation settings (non-interactive defaults for MCP/automation)
    scanner_installation_auto_approve: bool = True
    scanner_installation_quiet_mode: bool = True
    scanner_installation_retry_on_failure: int = 3

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Supreme2lConfig':
        """Create config from dictionary"""
        config = cls()

        # Basic settings
        config.version = data.get('version', config.version)
        config.fail_on = data.get('fail_on', config.fail_on)
        config.workers = data.get('workers', config.workers)
        config.cache_enabled = data.get('cache_enabled', config.cache_enabled)

        # Scanner installation settings
        scanner_installation = data.get('scanner_installation', {})
        config.scanner_installation_auto_approve = scanner_installation.get(
            'auto_approve',
            config.scanner_installation_auto_approve
        )
        config.scanner_installation_quiet_mode = scanner_installation.get(
            'quiet_mode',
            config.scanner_installation_quiet_mode
        )
        retry_count = scanner_installation.get(
            'retry_on_failure',
            config.scanner_installation_retry_on_failure
        )
        try:
            config.scanner_installation_retry_on_failure = max(1, int(retry_count))
        except (TypeError, ValueError):
            config.scanner_installation_retry_on_failure = 3

        # Scanners
        scanners = data.get('scanners', {})
        config.scanners_enabled = scanners.get('enabled', [])
        config.scanners_disabled = scanners.get('disabled', [])
        config.scanner_overrides = scanners.get('overrides', {})

        # Exclusions - MERGE user paths with mandatory exclusions (don't replace)
        exclude = data.get('exclude', {})
        if 'paths' in exclude:
            # Start with user's paths
            user_paths = set(exclude['paths'])
            # Add mandatory exclusions that MUST always be excluded
            mandatory = {
                'site-packages/', 'dist-packages/', 'node_modules/',
                'lib/python*/', 'lib64/python*/', '__pycache__/',
                '.git/', '.svn/', '.hg/', 'tests/fixtures/', 'test/fixtures/',
            }
            # Merge: user paths + mandatory
            config.exclude_paths = list(user_paths | mandatory)
        if 'files' in exclude:
            config.exclude_files = exclude['files']

        # IDE settings
        ide = data.get('ide', {})
        claude = ide.get('claude_code', {})
        config.ide_claude_code_enabled = claude.get('enabled', False)
        config.ide_claude_code_auto_scan = claude.get('auto_scan', True)
        config.ide_claude_code_inline_annotations = claude.get('inline_annotations', True)

        cursor = ide.get('cursor', {})
        config.ide_cursor_enabled = cursor.get('enabled', False)

        vscode = ide.get('vscode', {})
        config.ide_vscode_enabled = vscode.get('enabled', False)

        gemini = ide.get('gemini_cli', {})
        config.ide_gemini_enabled = gemini.get('enabled', False)

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for YAML export"""
        return {
            'version': self.version,
            'scanners': {
                'enabled': self.scanners_enabled,
                'disabled': self.scanners_disabled,
                'overrides': self.scanner_overrides,
            },
            'fail_on': self.fail_on,
            'exclude': {
                'paths': self.exclude_paths,
                'files': self.exclude_files,
            },
            'ide': {
                'claude_code': {
                    'enabled': self.ide_claude_code_enabled,
                    'auto_scan': self.ide_claude_code_auto_scan,
                    'inline_annotations': self.ide_claude_code_inline_annotations,
                },
                'cursor': {
                    'enabled': self.ide_cursor_enabled,
                },
                'vscode': {
                    'enabled': self.ide_vscode_enabled,
                },
                'gemini_cli': {
                    'enabled': self.ide_gemini_enabled,
                },
            },
            'workers': self.workers,
            'cache_enabled': self.cache_enabled,
            'scanner_installation': {
                'auto_approve': self.scanner_installation_auto_approve,
                'quiet_mode': self.scanner_installation_quiet_mode,
                'retry_on_failure': self.scanner_installation_retry_on_failure,
            },
        }


class ConfigManager:
    """Manage Supreme 2 Light configuration files"""

    DEFAULT_CONFIG_NAME = ".supreme2l.yml"

    @staticmethod
    def find_config(start_path: Path = None) -> Optional[Path]:
        """
        Find .supreme2l.yml by walking up directory tree

        Args:
            start_path: Starting directory (default: current directory)

        Returns:
            Path to .supreme2l.yml or None if not found
        """
        current = start_path or Path.cwd()

        # Walk up directory tree
        while current != current.parent:
            config_file = current / ConfigManager.DEFAULT_CONFIG_NAME
            if config_file.exists():
                return config_file
            current = current.parent

        return None

    @staticmethod
    def load_config(config_path: Path = None) -> Supreme2lConfig:
        """
        Load configuration from .supreme2l.yml

        Args:
            config_path: Path to config file (default: search from current dir)

        Returns:
            Supreme2lConfig object
        """
        if config_path is None:
            config_path = ConfigManager.find_config()

        # Return default config if no file found
        if config_path is None or not config_path.exists():
            return Supreme2lConfig()

        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)

            if data is None:
                return Supreme2lConfig()

            return Supreme2lConfig.from_dict(data)

        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
            return Supreme2lConfig()

    @staticmethod
    def save_config(config: Supreme2lConfig, config_path: Path) -> bool:
        """
        Save configuration to .supreme2l.yml

        Args:
            config: Supreme2lConfig object
            config_path: Path where to save

        Returns:
            True if successful
        """
        try:
            # Create directory if needed
            config_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert to dict and save as YAML
            with open(config_path, 'w') as f:
                yaml.dump(
                    config.to_dict(),
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    indent=2
                )

            return True

        except Exception as e:
            print(f"Error: Failed to save config to {config_path}: {e}")
            return False

    @staticmethod
    def create_default_config(project_root: Path) -> Path:
        """
        Create default .supreme2l.yml in project root

        Args:
            project_root: Project directory

        Returns:
            Path to created config file
        """
        config = Supreme2lConfig()
        config_path = project_root / ConfigManager.DEFAULT_CONFIG_NAME

        ConfigManager.save_config(config, config_path)

        return config_path
