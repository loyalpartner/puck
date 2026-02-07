"""
Pytest configuration and fixtures for injection tests.

This module provides environment-agnostic fixtures that work on both:
- Host machine (direct execution via subprocess)
- QEMU VMs (via QemuExecutor provided by tests/qemu/)

The key abstraction is the Executor protocol which handles command execution,
process management, and marker file verification.
"""

import os
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional, Protocol, runtime_checkable

import pytest


# Timing constants
PROCESS_STARTUP_DELAY = 0.5
THREAD_STARTUP_DELAY = 1.0
INJECTION_DELAY = 1.0


# Paths (can be overridden via environment variables)
PROJECT_ROOT = Path(__file__).parent.parent.parent
LABRATS_DIR = Path(os.environ.get("LABRATS_DIR", PROJECT_ROOT / "tests" / "qemu" / "labrats"))
PAYLOADS_DIR = Path(os.environ.get("PAYLOADS_DIR", PROJECT_ROOT / "tests" / "qemu" / "payloads"))


def _get_host_arch() -> str:
    """Get the host architecture."""
    import platform
    machine = platform.machine()
    if machine in ("x86_64", "AMD64"):
        return "x86_64"
    elif machine in ("aarch64", "arm64"):
        return "aarch64"
    return machine


@runtime_checkable
class Executor(Protocol):
    """Protocol for command execution abstraction.

    Implementations:
    - HostExecutor: Direct execution on host machine
    - QemuExecutor: Execution inside QEMU VM (provided by tests/qemu/)
    """

    def run_command(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        """Run a command and return (exit_code, output)."""
        ...

    def start_background(self, cmd: str) -> str:
        """Start a command in background and return its PID."""
        ...

    def kill_process(self, pid: str) -> None:
        """Kill a process by PID."""
        ...

    def gen_marker_path(self) -> str:
        """Generate a unique marker file path."""
        ...

    def check_marker(self, marker_path: str, expected_pid: str = None, retries: int = 5) -> tuple[bool, str]:
        """Check if marker file exists and contains expected content."""
        ...


class HostExecutor:
    """Executor for running commands directly on the host machine."""

    def __init__(self, arch: str):
        self.arch = arch
        self._pids: list[int] = []

    def run_command(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        """Run a command and return (exit_code, output)."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout + result.stderr
            return result.returncode, output.strip()
        except subprocess.TimeoutExpired:
            return -1, "Command timed out"
        except Exception as e:
            return -1, str(e)

    def start_background(self, cmd: str) -> str:
        """Start a command in background and return its PID."""
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._pids.append(process.pid)

        # Verify process is running
        time.sleep(0.1)
        if process.poll() is not None:
            raise RuntimeError(f"Process exited immediately: {cmd}")

        return str(process.pid)

    def kill_process(self, pid: str) -> None:
        """Kill a process by PID."""
        try:
            os.kill(int(pid), signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass

    def gen_marker_path(self) -> str:
        """Generate a unique marker file path."""
        return f"/tmp/puck_marker_{os.urandom(4).hex()}"

    def check_marker(self, marker_path: str, expected_pid: str = None, retries: int = 5) -> tuple[bool, str]:
        """Check if marker file exists and contains expected content."""
        for _ in range(retries):
            try:
                with open(marker_path, "r") as f:
                    content = f.read()
                if expected_pid is None or f"pid={expected_pid}" in content:
                    return True, content
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        return False, ""

    def cleanup(self) -> None:
        """Clean up any started processes."""
        for pid in self._pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        self._pids.clear()


def _get_puck_binary(arch: str) -> Path:
    """Get path to puck binary for given architecture."""
    env_path = os.environ.get("PUCK_BIN")
    if env_path:
        return Path(env_path)

    if arch == "x86_64":
        return PROJECT_ROOT / "target" / "release" / "puck"
    else:
        return PROJECT_ROOT / "target" / f"{arch}-unknown-linux-gnu" / "release" / "puck"


def _get_labrat_path(name: str, arch: str) -> Path:
    """Get path to labrat binary."""
    return LABRATS_DIR / f"{name}-{arch}"


def _get_payload_path(name: str, arch: str) -> Path:
    """Get path to payload library."""
    return PAYLOADS_DIR / f"{name}-{arch}.so"


@pytest.fixture(scope="session")
def arch() -> str:
    """Get the target architecture."""
    return os.environ.get("TEST_ARCH", _get_host_arch())


@pytest.fixture(scope="session")
def puck_binary(arch) -> Path:
    """Return path to puck binary."""
    path = _get_puck_binary(arch)
    if not path.exists():
        pytest.skip(f"Puck binary not found: {path}. Run: make build")
    return path


@pytest.fixture(scope="session")
def payload_hello(arch) -> Path:
    """Return path to libhello.so payload."""
    path = _get_payload_path("libhello", arch)
    if not path.exists():
        pytest.skip(f"Payload not found: {path}. Run: make -C tests/qemu/payloads all-{arch}")
    return path


@pytest.fixture(scope="session")
def labrat_sleeper_pie(arch) -> Path:
    """Return path to sleeper-pie labrat."""
    path = _get_labrat_path("sleeper-pie", arch)
    if not path.exists():
        pytest.skip(f"Labrat not found: {path}. Run: make -C tests/qemu/labrats all-{arch}")
    return path


@pytest.fixture(scope="session")
def labrat_sleeper_nopie(arch) -> Path:
    """Return path to sleeper-nopie labrat."""
    path = _get_labrat_path("sleeper-nopie", arch)
    if not path.exists():
        pytest.skip(f"Labrat not found: {path}. Run: make -C tests/qemu/labrats all-{arch}")
    return path


@pytest.fixture(scope="session")
def labrat_threaded_pie(arch) -> Path:
    """Return path to threaded-pie labrat."""
    path = _get_labrat_path("threaded-pie", arch)
    if not path.exists():
        pytest.skip(f"Labrat not found: {path}. Run: make -C tests/qemu/labrats all-{arch}")
    return path


@pytest.fixture(scope="session")
def labrat_undumpable_pie(arch) -> Path:
    """Return path to undumpable-pie labrat."""
    path = _get_labrat_path("undumpable-pie", arch)
    if not path.exists():
        pytest.skip(f"Labrat not found: {path}. Run: make -C tests/qemu/labrats all-{arch}")
    return path


@pytest.fixture(scope="session")
def host_executor(arch) -> Generator[HostExecutor, None, None]:
    """Provide a HostExecutor for direct host execution."""
    executor = HostExecutor(arch)
    yield executor
    executor.cleanup()


@pytest.fixture
def executor(request, host_executor) -> Executor:
    """Provide the appropriate executor based on environment.

    If running in QEMU (qemu_executor fixture available), use that.
    Otherwise, use the host executor.
    """
    # Check if qemu_executor is available (set by tests/qemu/conftest.py)
    qemu_executor = request.config._qemu_executor if hasattr(request.config, "_qemu_executor") else None
    if qemu_executor is not None:
        return qemu_executor
    return host_executor


@contextmanager
def target_process(
    executor: Executor,
    labrat_path: Path,
    startup_delay: float = PROCESS_STARTUP_DELAY,
) -> Generator[str, None, None]:
    """Context manager to start a target process and ensure cleanup.

    Args:
        executor: The executor to use for running commands
        labrat_path: Path to the labrat binary
        startup_delay: Time to wait after starting the process

    Yields:
        The PID of the started process as a string
    """
    pid = executor.start_background(str(labrat_path))
    time.sleep(startup_delay)
    try:
        yield pid
    finally:
        executor.kill_process(pid)


def inject_library(
    executor: Executor,
    puck_binary: Path,
    payload_path: Path,
    pid: str,
    function: str = "entry",
    data: str = None,
    timeout: int = 60,
    sudo: bool = False,
) -> tuple[int, str]:
    """Run library injection and return (exit_code, output).

    Args:
        executor: The executor to use
        puck_binary: Path to puck binary
        payload_path: Path to the payload .so file
        pid: Target process PID
        function: Function to call in the payload
        data: Optional data argument to pass
        timeout: Command timeout in seconds
        sudo: Whether to run with sudo (needed for undumpable processes)

    Returns:
        Tuple of (exit_code, output)
    """
    prefix = "sudo " if sudo else ""
    cmd = f"{prefix}{puck_binary} -l {payload_path} -f {function}"
    if data:
        cmd += f' -d "{data}"'
    cmd += f" {pid}"
    return executor.run_command(cmd, timeout=timeout)


def verify_injection(
    executor: Executor,
    marker: str,
    pid: str,
    data: str = None,
) -> None:
    """Verify injection succeeded: marker exists, process alive.

    Raises:
        AssertionError: If verification fails
    """
    success, content = executor.check_marker(marker, pid)
    assert success, f"Payload did not execute, marker={marker}, pid={pid}"
    if data:
        assert f"data={data}" in content, f"Data not passed: {content}"

    # Verify process is still alive
    exit_code, _ = executor.run_command(f"kill -0 {pid}")
    assert exit_code == 0, "Target process died after injection"
