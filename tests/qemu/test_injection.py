"""
QEMU injection tests.

This module imports tests from tests/injection/ and runs them with
QEMU fixtures. The fixtures from tests/qemu/conftest.py (executor,
puck_binary, labrats, payloads) override the default host fixtures.
"""

# Import all test classes from tests/injection/
# They will use QEMU fixtures from this directory's conftest.py
from tests.injection.test_basic import TestInjection
from tests.injection.test_edge_cases import TestEdgeCases

# Re-export for pytest discovery
__all__ = ["TestInjection", "TestEdgeCases"]
