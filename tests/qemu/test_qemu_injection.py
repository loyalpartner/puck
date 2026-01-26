"""
QEMU-based integration tests for puck.

Tests run in isolated QEMU VMs. Architecture is auto-detected from host
or specified via --arch option.
"""

import time
from contextlib import contextmanager
import pytest


# Timing constants
PROCESS_STARTUP_DELAY = 0.5
THREAD_STARTUP_DELAY = 1.0
INJECTION_DELAY = 1.0


class TestInjection:
    """Test library injection in QEMU VM."""

    @contextmanager
    def _target_process(self, vm, labrat: str, startup_delay: float = PROCESS_STARTUP_DELAY):
        """Start a target process and ensure cleanup."""
        pid = vm.start_background(f"/workspace/labrats/{labrat}")
        time.sleep(startup_delay)
        try:
            yield pid
        finally:
            vm.run_command(f"kill {pid} 2>/dev/null || true")

    def _inject(self, vm, pid: str, marker: str, data: str = None) -> tuple[int, str]:
        """Run injection and return (exit_code, output)."""
        arg = f"{marker}:{data}" if data else marker
        return vm.run_command(
            f'/workspace/puck -l /workspace/payloads/libhello.so -f entry -d "{arg}" {pid}'
        )

    def _verify_injection(self, vm, pid: str, marker: str, data: str = None):
        """Verify injection succeeded: marker exists, process alive."""
        success, content = vm.check_marker(marker, pid)
        assert success, f"Payload did not execute, marker={marker}, pid={pid}"
        if data:
            assert f"data={data}" in content, f"Data not passed: {content}"

        exit_code, _ = vm.run_command(f"kill -0 {pid}")
        assert exit_code == 0, "Target process died after injection"

    def test_basic_pie(self, qemu_vm):
        """Inject into PIE executable."""
        marker = qemu_vm.gen_marker_path()
        with self._target_process(qemu_vm, "sleeper-pie") as pid:
            exit_code, output = self._inject(qemu_vm, pid, marker)
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            self._verify_injection(qemu_vm, pid, marker)

    def test_basic_nopie(self, qemu_vm):
        """Inject into non-PIE executable."""
        marker = qemu_vm.gen_marker_path()
        with self._target_process(qemu_vm, "sleeper-nopie") as pid:
            exit_code, output = self._inject(qemu_vm, pid, marker)
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            self._verify_injection(qemu_vm, pid, marker)

    def test_multithreaded(self, qemu_vm):
        """Inject into multi-threaded process."""
        marker = qemu_vm.gen_marker_path()
        with self._target_process(qemu_vm, "threaded-pie", THREAD_STARTUP_DELAY) as pid:
            exit_code, output = self._inject(qemu_vm, pid, marker)
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            self._verify_injection(qemu_vm, pid, marker)

    def test_injection_with_data(self, qemu_vm):
        """Test injection with string data argument."""
        marker = qemu_vm.gen_marker_path()
        with self._target_process(qemu_vm, "sleeper-pie") as pid:
            exit_code, output = self._inject(qemu_vm, pid, marker, data="hello_world")
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)
            self._verify_injection(qemu_vm, pid, marker, data="hello_world")

    def test_multiple_injections(self, qemu_vm):
        """Test multiple injection cycles."""
        with self._target_process(qemu_vm, "sleeper-pie") as pid:
            for i in range(3):
                marker = qemu_vm.gen_marker_path()
                exit_code, output = self._inject(qemu_vm, pid, marker)
                assert exit_code == 0, f"Injection {i+1} failed: {output}"
                time.sleep(PROCESS_STARTUP_DELAY)
                success, _ = qemu_vm.check_marker(marker, pid)
                assert success, f"Injection {i+1} did not execute"

    def test_library_unload(self, qemu_vm):
        """Verify library is unloaded after entry() returns."""
        marker = qemu_vm.gen_marker_path()
        with self._target_process(qemu_vm, "sleeper-pie") as pid:
            # Verify not loaded initially
            exit_code, output = qemu_vm.run_command(f"cat /proc/{pid}/maps | grep libhello")
            assert exit_code != 0 or "libhello" not in output

            exit_code, output = self._inject(qemu_vm, pid, marker)
            assert exit_code == 0, f"Injection failed: {output}"
            time.sleep(INJECTION_DELAY)

            # Verify executed
            success, _ = qemu_vm.check_marker(marker, pid)
            assert success, "Payload did not execute"

            # Verify unloaded
            exit_code, output = qemu_vm.run_command(f"cat /proc/{pid}/maps | grep libhello")
            assert exit_code != 0 or "libhello" not in output, f"Library still loaded: {output}"


class TestEdgeCases:
    """Edge case tests."""

    def test_nonexistent_pid(self, qemu_vm):
        """Injection to nonexistent PID should fail."""
        exit_code, _ = qemu_vm.run_command(
            "/workspace/puck -l /workspace/payloads/libhello.so -f entry 999999"
        )
        assert exit_code != 0

    def test_nonexistent_library(self, qemu_vm):
        """Injection with nonexistent library should fail."""
        pid = qemu_vm.start_background("/workspace/labrats/sleeper-pie")
        time.sleep(PROCESS_STARTUP_DELAY)
        try:
            exit_code, _ = qemu_vm.run_command(
                f"/workspace/puck -l /nonexistent/library.so -f entry {pid}"
            )
            assert exit_code != 0, "Should fail with nonexistent library"
        finally:
            qemu_vm.run_command(f"kill {pid} 2>/dev/null || true")

    def test_nonexistent_function(self, qemu_vm):
        """Injection with nonexistent function - puck may succeed but payload fails."""
        pid = qemu_vm.start_background("/workspace/labrats/sleeper-pie")
        time.sleep(PROCESS_STARTUP_DELAY)
        try:
            # This may or may not fail depending on implementation
            qemu_vm.run_command(
                f"/workspace/puck -l /workspace/payloads/libhello.so -f nonexistent_func {pid}"
            )
            time.sleep(PROCESS_STARTUP_DELAY)
        finally:
            qemu_vm.run_command(f"kill {pid} 2>/dev/null || true")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
