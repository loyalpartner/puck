"""
Pytest configuration for puck integration tests
"""

import pytest
import subprocess
import os


def pytest_configure(config):
    """Configure pytest"""
    # Check if running as root or with sudo capability
    if os.geteuid() != 0:
        print("\nWARNING: Tests require root privileges for ptrace.")
        print("Run with: sudo pytest tests/integration/")


@pytest.fixture(scope="session", autouse=True)
def check_prerequisites():
    """Check that prerequisites are met"""
    # Check for required tools
    for tool in ["gcc", "make", "cargo"]:
        result = subprocess.run(["which", tool], capture_output=True)
        if result.returncode != 0:
            pytest.skip(f"Required tool not found: {tool}")
