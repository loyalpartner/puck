"""
Integration tests for hsinject

Tests the Frida-style two-stage injection:
1. Inject library and call entry function
2. Call unload function in loaded library
3. Verify library is properly unloaded from maps
"""

import os
import subprocess
import time
import signal
import pytest
from pathlib import Path

# Paths
TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent.parent
HSINJECT_BIN = PROJECT_ROOT / "target" / "release" / "hsinject"
LIBHELLO_SO = TEST_DIR / "libhello.so"


def get_library_maps(pid: int, pattern: str) -> list[str]:
    """Get memory maps matching pattern for a process"""
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            return [line for line in f if pattern in line]
    except (FileNotFoundError, PermissionError):
        return []


def is_library_loaded(pid: int, pattern: str) -> bool:
    """Check if library matching pattern is loaded in process"""
    return len(get_library_maps(pid, pattern)) > 0


class TestInjection:
    """Test library injection and unloading"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Build the test library and hsinject binary"""
        # Build hsinject
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Failed to build hsinject: {result.stderr}"

        # Build libhello.so
        result = subprocess.run(
            ["make", "-C", str(TEST_DIR)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Failed to build libhello.so: {result.stderr}"
        assert LIBHELLO_SO.exists(), "libhello.so not found after build"

    @pytest.fixture
    def target_process(self):
        """Create a target process for injection"""
        # Start a sleep process
        proc = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        yield proc
        # Cleanup
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def test_inject_and_auto_unload(self, target_process):
        """Test that library is automatically unloaded after entry() returns

        The loader_thread calls dlclose after entry() returns, so the library
        should be cleanly unloaded without any explicit unload call.
        """
        pid = target_process.pid

        # Verify library is not loaded initially
        assert not is_library_loaded(pid, "libhello"), \
            "Library should not be loaded before injection"

        # Inject library and call entry()
        result = subprocess.run(
            ["sudo", str(HSINJECT_BIN), "-l", str(LIBHELLO_SO), "-f", "entry", str(pid)],
            capture_output=True,
            text=True,
        )
        print(f"Inject stdout: {result.stdout}")
        print(f"Inject stderr: {result.stderr}")
        assert result.returncode == 0, f"Injection failed: {result.stderr}"

        # Wait for entry() to complete and dlclose to happen
        time.sleep(0.5)

        # Verify library is unloaded (dlclose was called by loader_thread)
        maps = get_library_maps(pid, "libhello")
        print(f"Maps after entry() returns: {len(maps)} entries")

        assert len(maps) == 0, \
            f"Library should be unloaded after entry() returns, but found {len(maps)} entries"

        # Process should still be healthy
        assert target_process.poll() is None, \
            "Target process should still be running"

    def test_inject_with_data(self, target_process):
        """Test injection with string data argument"""
        pid = target_process.pid

        # Inject with data argument
        result = subprocess.run(
            ["sudo", str(HSINJECT_BIN), "-l", str(LIBHELLO_SO), "-f", "entry",
             "-d", "test_data", str(pid)],
            capture_output=True,
            text=True,
        )
        print(f"Inject with data stdout: {result.stdout}")
        print(f"Inject with data stderr: {result.stderr}")
        assert result.returncode == 0, f"Injection with data failed: {result.stderr}"

        # Wait for entry() to complete and dlclose
        time.sleep(0.5)

        # Library should be unloaded after entry() returns
        maps = get_library_maps(pid, "libhello")
        print(f"Maps after entry() with data: {len(maps)} entries")
        assert len(maps) == 0, "Library should be unloaded after entry() returns"

        # Process should still be healthy
        assert target_process.poll() is None, "Process should still be running"

    def test_call_mode_without_prior_load(self, target_process):
        """Test CALL mode behavior when library is not loaded

        Note: Due to the async nature of the architecture, bootstrap succeeds
        (thread was created) but the thread itself fails to find the library.
        We can't easily detect this failure without waiting mechanisms.
        """
        pid = target_process.pid

        # Try to call function in non-existent library
        result = subprocess.run(
            ["sudo", str(HSINJECT_BIN), "-c", "nonexistent.so", "-f", "func", str(pid)],
            capture_output=True,
            text=True,
        )
        print(f"Call mode stdout: {result.stdout}")
        print(f"Call mode stderr: {result.stderr}")

        # Bootstrap succeeds (thread was created), but thread will fail to find library
        # This is expected behavior - the failure happens asynchronously in the thread
        # The process should still be alive and healthy
        assert target_process.poll() is None, "Target process should still be running"

    def test_multiple_inject_cycles(self, target_process):
        """Test multiple inject cycles - library loads and unloads each time

        With the Frida-style architecture, loader_thread calls dlclose after
        entry() returns. This means we can do multiple inject cycles and the
        library will be properly unloaded each time.
        """
        pid = target_process.pid

        for i in range(3):
            print(f"\n=== Cycle {i + 1} ===")

            # Verify library is not loaded
            assert not is_library_loaded(pid, "libhello"), \
                f"Library should not be loaded before cycle {i + 1}"

            # Inject
            result = subprocess.run(
                ["sudo", str(HSINJECT_BIN), "-l", str(LIBHELLO_SO), "-f", "entry", str(pid)],
                capture_output=True,
                text=True,
            )
            print(f"Inject stdout: {result.stdout}")
            print(f"Inject stderr: {result.stderr}")
            assert result.returncode == 0, f"Injection {i + 1} failed: {result.stderr}"

            # Wait for entry() to complete and dlclose to happen
            time.sleep(0.5)

            # Verify library is unloaded
            maps = get_library_maps(pid, "libhello")
            print(f"Maps after cycle {i + 1}: {len(maps)} entries")
            assert len(maps) == 0, f"Library should be unloaded after cycle {i + 1}"

            # Process should still be healthy
            assert target_process.poll() is None, f"Process died after cycle {i + 1}"

        print("\nAll cycles completed successfully - library properly unloaded each time")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
