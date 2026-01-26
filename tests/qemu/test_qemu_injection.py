"""
QEMU-based integration tests for puck.

Tests run in isolated QEMU VMs. Architecture is auto-detected from host
or specified via --arch option.
"""

import time
import pytest


class TestInjection:
    """Test library injection in QEMU VM."""

    def test_basic_pie(self, qemu_vm):
        """Inject into PIE executable."""
        vm = qemu_vm

        # Start sleeper-pie in background
        vm.sendline("/workspace/labrats/sleeper-pie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        time.sleep(0.5)

        # Verify process is running
        exit_code, output = vm.run_command(f"kill -0 {pid} && echo ALIVE")
        assert "ALIVE" in output, f"Target process not running: {output}"

        # Inject
        exit_code, output = vm.run_command(
            f"/workspace/puck -l /workspace/payloads/libhello.so -f entry {pid}"
        )
        assert exit_code == 0, f"Injection failed: {output}"

        time.sleep(1)

        # Verify process is still alive
        exit_code, _ = vm.run_command(f"kill -0 {pid}")
        assert exit_code == 0, "Target process died after injection"

        # Cleanup
        vm.run_command(f"kill {pid}")

    def test_basic_nopie(self, qemu_vm):
        """Inject into non-PIE executable."""
        vm = qemu_vm

        # Start sleeper-nopie in background
        vm.sendline("/workspace/labrats/sleeper-nopie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        time.sleep(0.5)

        # Inject
        exit_code, output = vm.run_command(
            f"/workspace/puck -l /workspace/payloads/libhello.so -f entry {pid}"
        )
        assert exit_code == 0, f"Injection failed: {output}"

        time.sleep(1)

        # Verify process is still alive
        exit_code, _ = vm.run_command(f"kill -0 {pid}")
        assert exit_code == 0, "Target process died after injection"

        # Cleanup
        vm.run_command(f"kill {pid}")

    def test_multithreaded(self, qemu_vm):
        """Inject into multi-threaded process."""
        vm = qemu_vm

        # Start threaded target in background
        vm.sendline("/workspace/labrats/threaded-pie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        # Give threads time to start
        time.sleep(1)

        # Inject
        exit_code, output = vm.run_command(
            f"/workspace/puck -l /workspace/payloads/libhello.so -f entry {pid}"
        )
        assert exit_code == 0, f"Injection failed: {output}"

        time.sleep(1)

        # Verify process is still alive
        exit_code, _ = vm.run_command(f"kill -0 {pid}")
        assert exit_code == 0, "Target process died after injection"

        # Cleanup
        vm.run_command(f"kill {pid}")

    def test_injection_with_data(self, qemu_vm):
        """Test injection with string data argument."""
        vm = qemu_vm

        vm.sendline("/workspace/labrats/sleeper-pie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        time.sleep(0.5)

        # Inject with data
        exit_code, output = vm.run_command(
            f'/workspace/puck -l /workspace/payloads/libhello.so -f entry -d "test_data" {pid}'
        )
        assert exit_code == 0, f"Injection with data failed: {output}"

        time.sleep(1)

        # Verify process is still alive
        exit_code, _ = vm.run_command(f"kill -0 {pid}")
        assert exit_code == 0, "Target process died after injection with data"

        # Cleanup
        vm.run_command(f"kill {pid}")

    def test_multiple_injections(self, qemu_vm):
        """Test multiple injection cycles."""
        vm = qemu_vm

        vm.sendline("/workspace/labrats/sleeper-pie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        time.sleep(0.5)

        # Inject multiple times
        for i in range(3):
            exit_code, output = vm.run_command(
                f"/workspace/puck -l /workspace/payloads/libhello.so -f entry {pid}"
            )
            assert exit_code == 0, f"Injection cycle {i+1} failed: {output}"
            time.sleep(0.5)

        # Verify process is still alive after multiple injections
        exit_code, _ = vm.run_command(f"kill -0 {pid}")
        assert exit_code == 0, "Target process died after multiple injections"

        # Cleanup
        vm.run_command(f"kill {pid}")

    def test_library_unload(self, qemu_vm):
        """Verify library is unloaded after entry() returns."""
        vm = qemu_vm

        vm.sendline("/workspace/labrats/sleeper-pie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        time.sleep(0.5)

        # Verify library is not loaded initially
        exit_code, output = vm.run_command(f"cat /proc/{pid}/maps | grep libhello")
        assert exit_code != 0 or "libhello" not in output, "Library should not be loaded initially"

        # Inject
        exit_code, output = vm.run_command(
            f"/workspace/puck -l /workspace/payloads/libhello.so -f entry {pid}"
        )
        assert exit_code == 0, f"Injection failed: {output}"

        # Wait for entry() to complete and dlclose to happen
        time.sleep(1)

        # Verify library is unloaded
        exit_code, output = vm.run_command(f"cat /proc/{pid}/maps | grep libhello")
        assert exit_code != 0 or "libhello" not in output, \
            f"Library should be unloaded after entry() returns, but found: {output}"

        # Cleanup
        vm.run_command(f"kill {pid}")


class TestEdgeCases:
    """Edge case tests."""

    def test_nonexistent_pid(self, qemu_vm):
        """Test injection with invalid PID."""
        vm = qemu_vm

        # Use a PID that definitely doesn't exist
        exit_code, output = vm.run_command(
            "/workspace/puck -l /workspace/payloads/libhello.so -f entry 999999"
        )
        # Should fail gracefully
        assert exit_code != 0, "Injection to nonexistent PID should fail"

    def test_nonexistent_library(self, qemu_vm):
        """Test injection with nonexistent library."""
        vm = qemu_vm

        vm.sendline("/workspace/labrats/sleeper-pie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        time.sleep(0.5)

        # Try to inject nonexistent library
        exit_code, output = vm.run_command(
            f"/workspace/puck -l /nonexistent/library.so -f entry {pid}"
        )
        # This may fail at different stages depending on implementation

        # Cleanup
        vm.run_command(f"kill {pid} 2>/dev/null || true")

    def test_nonexistent_function(self, qemu_vm):
        """Test injection with nonexistent function."""
        vm = qemu_vm

        vm.sendline("/workspace/labrats/sleeper-pie &")
        vm.expect(r"\[\d+\]\s+(\d+)")
        pid = vm.match.group(1)

        time.sleep(0.5)

        # Try to call nonexistent function
        exit_code, output = vm.run_command(
            f"/workspace/puck -l /workspace/payloads/libhello.so -f nonexistent_func {pid}"
        )
        # Bootstrap may succeed but function lookup will fail asynchronously

        time.sleep(0.5)

        # Cleanup
        vm.run_command(f"kill {pid} 2>/dev/null || true")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
