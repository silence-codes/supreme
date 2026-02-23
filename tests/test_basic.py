"""
Basic tests for Supreme 2 Light
"""
import pytest
from supreme2l.cli import main


def test_import():
    """Test that we can import the main module"""
    # Using assert in tests is standard pytest practice
    assert main is not None


def test_version():
    """Test version is accessible"""
    from supreme2l import __version__
    # Using assert in tests is standard pytest practice
    assert __version__ == "2025.8.5.11"
