"""
Basic injection tests.

These tests verify core library injection functionality:
- PIE and non-PIE executables
- Multi-threaded targets
- Data argument passing
- Multiple injections
- Library unload verification
"""

import time

import pytest

from tests.injection.conftest import (
    INJECTION_DELAY,
    PROCESS_STARTUP_DELAY,
    THREAD_STARTUP_DELAY,
    Executor,
    inject_library,
    target_process,
    verify_injection,
)


class TestInjection:
    """Test library injection."""

    def test_basic_pie(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_sleeper_pie,
    ):
        """Inject into PIE executable."""
        marker = executor.gen_marker_path()
        with target_process(executor, labrat_sleeper_pie) as pid:
            exit_code, output = inject_library(
                executor, puck_binary, payload_hello, pid,
                data=marker,
            )
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            verify_injection(executor, marker, pid)

    def test_basic_nopie(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_sleeper_nopie,
    ):
        """Inject into non-PIE executable."""
        marker = executor.gen_marker_path()
        with target_process(executor, labrat_sleeper_nopie) as pid:
            exit_code, output = inject_library(
                executor, puck_binary, payload_hello, pid,
                data=marker,
            )
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            verify_injection(executor, marker, pid)

    def test_multithreaded(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_threaded_pie,
    ):
        """Inject into multi-threaded process."""
        marker = executor.gen_marker_path()
        with target_process(executor, labrat_threaded_pie, THREAD_STARTUP_DELAY) as pid:
            exit_code, output = inject_library(
                executor, puck_binary, payload_hello, pid,
                data=marker,
            )
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            verify_injection(executor, marker, pid)

    def test_injection_with_data(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_sleeper_pie,
    ):
        """Test injection with string data argument."""
        marker = executor.gen_marker_path()
        data_value = "hello_world"
        with target_process(executor, labrat_sleeper_pie) as pid:
            exit_code, output = inject_library(
                executor, puck_binary, payload_hello, pid,
                data=f"{marker}:{data_value}",
            )
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            verify_injection(executor, marker, pid, data=data_value)

    def test_multiple_injections(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_sleeper_pie,
    ):
        """Test multiple injection cycles."""
        with target_process(executor, labrat_sleeper_pie) as pid:
            for i in range(3):
                marker = executor.gen_marker_path()
                exit_code, output = inject_library(
                    executor, puck_binary, payload_hello, pid,
                    data=marker,
                )
                assert exit_code == 0, f"Injection {i+1} failed: {output}"
                time.sleep(PROCESS_STARTUP_DELAY)
                success, _ = executor.check_marker(marker, pid)
                assert success, f"Injection {i+1} did not execute"

    def test_library_unload(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_sleeper_pie,
    ):
        """Verify library is unloaded after entry() returns."""
        marker = executor.gen_marker_path()
        with target_process(executor, labrat_sleeper_pie) as pid:
            # Verify not loaded initially
            exit_code, output = executor.run_command(f"cat /proc/{pid}/maps | grep libhello")
            assert exit_code != 0 or "libhello" not in output

            exit_code, output = inject_library(
                executor, puck_binary, payload_hello, pid,
                data=marker,
            )
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)

            # Verify executed
            success, _ = executor.check_marker(marker, pid)
            assert success, "Payload did not execute"

            # Verify unloaded
            exit_code, output = executor.run_command(f"cat /proc/{pid}/maps | grep libhello")
            assert exit_code != 0 or "libhello" not in output, f"Library still loaded: {output}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
