"""
Root pytest configuration for all tests.

This file ensures proper test discovery and fixture sharing between:
- tests/injection/  - Environment-agnostic injection tests
- tests/qemu/       - QEMU VM-based tests
"""

# Enable pytest to find tests in subdirectories
pytest_plugins = []
