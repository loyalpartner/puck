"""
Tests for injection into processes with inaccessible /proc/self/auxv.

Processes with file capabilities (e.g., sway with cap_sys_nice=ep) or
processes that call prctl(PR_SET_DUMPABLE, 0) have their /proc/PID/*
files owned by root. This causes the bootstrapper's open("/proc/self/auxv")
to fail with EACCES from within the process.

The fix: the injector reads /proc/PID/auxv from its side (running as root
via sudo) and passes AT_PHDR/AT_PHNUM as fallback values in BootstrapContext.
"""

import os
import subprocess
import time

import pytest

from tests.injection.conftest import (
    INJECTION_DELAY,
    Executor,
    inject_library,
    target_process,
    verify_injection,
)


def _sudo_available() -> bool:
    """Check if sudo is available without password."""
    result = subprocess.run(
        ["sudo", "-n", "true"],
        capture_output=True,
        timeout=5,
    )
    return result.returncode == 0


class TestUndumpableProcess:
    """Test injection into undumpable processes (dumpable=0).

    The undumpable labrat calls prctl(PR_SET_DUMPABLE, 0), which makes
    /proc/PID/* root-owned -- the same effect as file capabilities.
    """

    def test_inject_undumpable_pie(
        self,
        executor: Executor,
        puck_binary,
        payload_hello,
        labrat_undumpable_pie,
    ):
        """Inject into an undumpable PIE process.

        Reproduces the scenario where:
        1. Process has dumpable=0 (like sway with cap_sys_nice=ep)
        2. /proc/PID/auxv is root-owned
        3. Bootstrapper's open("/proc/self/auxv") returns EACCES
        4. Injector provides fallback AT_PHDR/AT_PHNUM via BootstrapContext
        """
        if os.geteuid() != 0 and not _sudo_available():
            pytest.skip("sudo required for undumpable process injection")

        marker = executor.gen_marker_path()
        with target_process(executor, labrat_undumpable_pie) as pid:
            exit_code, output = inject_library(
                executor, puck_binary, payload_hello, pid,
                data=marker,
                sudo=True,
            )
            assert exit_code == 0, f"Injection into undumpable process failed: {output}"
            time.sleep(INJECTION_DELAY)
            verify_injection(executor, marker, pid)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
