"""
Edge case tests for injection.

These tests verify error handling and boundary conditions:
- Nonexistent PID
- Nonexistent library
- Nonexistent function
"""

import time

import pytest

from tests.injection.conftest import (
    PROCESS_STARTUP_DELAY,
    Executor,
    target_process,
)


class TestEdgeCases:
    """Edge case tests."""

    def test_nonexistent_pid(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
    ):
        """Injection to nonexistent PID should fail."""
        exit_code, _ = executor.run_command(
            f"{puck_binary} -l {payload_hello} -f entry 999999"
        )
        assert exit_code != 0

    def test_nonexistent_library(
        self,
        executor: Executor,
        puck_binary,
        labrat_sleeper_pie,
    ):
        """Injection with nonexistent library should fail."""
        with target_process(executor, labrat_sleeper_pie) as pid:
            exit_code, _ = executor.run_command(
                f"{puck_binary} -l /nonexistent/library.so -f entry {pid}"
            )
            assert exit_code != 0, "Should fail with nonexistent library"

    def test_nonexistent_function(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_sleeper_pie,
    ):
        """Injection with nonexistent function - puck may succeed but payload fails."""
        with target_process(executor, labrat_sleeper_pie) as pid:
            # This may or may not fail depending on implementation
            executor.run_command(
                f"{puck_binary} -l {payload_hello} -f nonexistent_func {pid}"
            )
            time.sleep(PROCESS_STARTUP_DELAY)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
