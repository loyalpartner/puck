"""
Pytest configuration and fixtures for QEMU-based integration tests.

This module provides:
- QEMU VM management with pexpect
- QemuExecutor implementing the Executor protocol from tests/injection/
- Build artifacts for target architectures
- virtio-9p workspace sharing

Tests from tests/injection/ can run inside QEMU VMs by using the
executor fixture, which will be the QemuExecutor when running QEMU tests.
"""

import os
import subprocess
import shutil
import tempfile
import time
from pathlib import Path
from typing import Generator, Optional

import pytest
import pexpect


# Paths
TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent.parent
IMAGES_DIR = TEST_DIR / "images"
LABRATS_DIR = TEST_DIR / "labrats"
PAYLOADS_DIR = TEST_DIR / "payloads"
SCRIPTS_DIR = TEST_DIR / "scripts"

# Image filenames
IMAGES = {
    "x86_64": "debian-12-nocloud-amd64.qcow2",
    "aarch64": "debian-12-nocloud-arm64.qcow2",
}

# QEMU configurations
QEMU_CONFIG = {
    "x86_64": {
        "qemu": "qemu-system-x86_64",
        "machine": "-M q35",
        "cpu": "qemu64",
        "cpu_kvm": "host",
        "use_kvm": True,
    },
    "aarch64": {
        "qemu": "qemu-system-aarch64",
        "machine": "-M virt",
        "cpu": "cortex-a72",
        "use_kvm": False,
        # UEFI firmware paths (try in order)
        "bios_paths": [
            "/usr/share/edk2-armvirt/aarch64/QEMU_EFI.fd",  # Arch Linux
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",      # Debian/Ubuntu
            "/usr/share/AAVMF/AAVMF_CODE.fd",               # Fedora
        ],
    },
}

# Rust target triples
RUST_TARGETS = {
    "x86_64": "x86_64-unknown-linux-gnu",
    "aarch64": "aarch64-unknown-linux-gnu",
}


def _get_host_arch() -> str:
    """Get the host architecture."""
    import platform
    machine = platform.machine()
    if machine in ("x86_64", "AMD64"):
        return "x86_64"
    elif machine in ("aarch64", "arm64"):
        return "aarch64"
    else:
        return machine


def pytest_addoption(parser):
    """Add custom command-line options."""
    parser.addoption(
        "--arch",
        action="store",
        default=None,
        help="Run tests only for specified architecture (x86_64 or aarch64)",
    )
    parser.addoption(
        "--skip-build",
        action="store_true",
        default=False,
        help="Skip building binaries (use pre-built)",
    )


class QemuExecutor:
    """Executor implementation for QEMU VMs.

    Implements the Executor protocol from tests/injection/conftest.py
    """

    def __init__(
        self,
        arch: str,
        session: pexpect.spawn,
        workspace: Path,
    ):
        self.arch = arch
        self.session = session
        self.workspace = workspace
        self._boot_complete = False

    def wait_for_boot(self, timeout: int = 300) -> None:
        """Wait for VM to boot and reach login prompt."""
        if self._boot_complete:
            return

        # Wait for login prompt
        self.session.expect("login:", timeout=timeout)
        self.session.sendline("root")

        # Wait for shell prompt
        self.session.expect(r"[#\$]", timeout=30)
        self._boot_complete = True

    def run_command(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        """Run a command in the VM and return (exit_code, output)."""
        # Use a unique marker to find end of output
        marker = f"__END_{os.urandom(4).hex()}__"

        # Run command and capture exit code
        self.session.sendline(f"{cmd}; echo {marker}$?")

        # Wait for marker with exit code
        self.session.expect(f"{marker}(\\d+)", timeout=timeout)
        exit_code = int(self.session.match.group(1))

        # Get output (everything before the marker)
        # Note: session uses encoding="utf-8", so before is already a string
        output = self.session.before

        # Clean up: strip the echoed command from output
        lines = output.split("\n")
        if lines and cmd in lines[0]:
            lines = lines[1:]
        output = "\n".join(lines).strip()

        return exit_code, output

    def start_background(self, cmd: str) -> str:
        """Start a command in background and return its PID reliably."""
        # Use run_command to get PID via $! - more reliable than parsing backgrounding output
        exit_code, output = self.run_command(f"{cmd} & sleep 0.1 && echo $!")
        pid = output.strip().split('\n')[-1].strip()

        # Verify PID is valid
        if not pid.isdigit():
            raise RuntimeError(f"Failed to get PID for: {cmd}, output: {output}")

        # Verify process exists
        exit_code, _ = self.run_command(f"kill -0 {pid}")
        if exit_code != 0:
            raise RuntimeError(f"Process {pid} not running after start")

        return pid

    def kill_process(self, pid: str) -> None:
        """Kill a process by PID."""
        self.run_command(f"kill {pid} 2>/dev/null || true")

    def gen_marker_path(self) -> str:
        """Generate a unique marker file path for this injection."""
        return f"/tmp/marker_{os.urandom(4).hex()}"

    def check_marker(self, marker_path: str, expected_pid: str = None, retries: int = 5) -> tuple[bool, str]:
        """Check if marker file exists and contains expected content.

        Retries several times to handle timing issues.
        Returns (success, content) tuple.
        """
        output = ""
        for _ in range(retries):
            exit_code, output = self.run_command(f"cat {marker_path} 2>/dev/null")
            if exit_code == 0:
                if expected_pid is None or f"pid={expected_pid}" in output:
                    return True, output
            time.sleep(0.2)
        return False, output

    def mount_workspace(self) -> None:
        """Mount the virtio-9p workspace."""
        self.run_command("mkdir -p /workspace")
        exit_code, _ = self.run_command("mount -t 9p workspace /workspace")
        if exit_code != 0:
            raise RuntimeError("Failed to mount workspace")

    def sendline(self, line: str) -> None:
        """Send a line to the VM."""
        self.session.sendline(line)

    def expect(self, pattern, timeout: int = 30):
        """Wait for pattern in VM output."""
        return self.session.expect(pattern, timeout=timeout)

    @property
    def match(self):
        """Get the last match object."""
        return self.session.match

    @property
    def before(self):
        """Get text before last match."""
        return self.session.before

    def shutdown(self) -> None:
        """Gracefully shutdown the VM."""
        try:
            self.session.sendline("poweroff")
            self.session.expect(pexpect.EOF, timeout=30)
        except (pexpect.TIMEOUT, pexpect.EOF):
            pass
        finally:
            self.session.close()


def _check_kvm_available() -> bool:
    """Check if KVM is available."""
    kvm_path = Path("/dev/kvm")
    return kvm_path.exists() and os.access(kvm_path, os.R_OK | os.W_OK)


def _find_uefi_firmware(bios_paths: list[str]) -> Optional[str]:
    """Find the first available UEFI firmware path."""
    for path in bios_paths:
        if Path(path).exists():
            return path
    return None


def _start_qemu(
    arch: str,
    image_path: Path,
    workspace: Path,
) -> pexpect.spawn:
    """Start a QEMU VM and return the pexpect session."""
    config = QEMU_CONFIG[arch]
    qemu_cmd = config["qemu"]

    # Check QEMU is available
    if shutil.which(qemu_cmd) is None:
        pytest.skip(f"{qemu_cmd} not found")

    # Determine CPU type based on KVM availability
    use_kvm = config["use_kvm"] and _check_kvm_available()
    cpu = config.get("cpu_kvm", config["cpu"]) if use_kvm else config["cpu"]

    # Build command
    cmd_parts = [
        qemu_cmd,
        config["machine"],
        "-cpu", cpu,
        "-m", "1024",
        "-smp", "2",
        "-drive", f"file={image_path},format=qcow2,if=virtio,snapshot=on",
        "-nographic",
        "-serial", "mon:stdio",
        "-virtfs", f"local,path={workspace},mount_tag=workspace,security_model=none,id=workspace",
    ]

    # Add KVM if available
    if use_kvm:
        cmd_parts.insert(2, "-enable-kvm")

    # Add UEFI firmware for aarch64
    if "bios_paths" in config:
        bios = _find_uefi_firmware(config["bios_paths"])
        if bios is None:
            pytest.skip(f"UEFI firmware not found for {arch}. Install edk2-armvirt or qemu-efi-aarch64")
        cmd_parts.extend(["-bios", bios])

    cmd = " ".join(cmd_parts)
    return pexpect.spawn(cmd, encoding="utf-8", timeout=120)


@pytest.fixture(scope="session")
def check_qemu_images():
    """Check that required QEMU images exist."""
    missing = []
    for arch, filename in IMAGES.items():
        image_path = IMAGES_DIR / filename
        if not image_path.exists():
            missing.append(arch)

    if missing:
        pytest.skip(
            f"QEMU images not found for: {', '.join(missing)}. "
            f"Run: ./tests/qemu/scripts/setup-images.sh"
        )


@pytest.fixture(scope="session")
def build_artifacts(request):
    """Build puck and test binaries for all architectures."""
    if request.config.getoption("--skip-build"):
        return

    # Build puck for x86_64 (native)
    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build puck: {result.stderr}")

    # Build labrats for x86_64
    result = subprocess.run(
        ["make", "all-x86_64"],
        cwd=LABRATS_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build labrats: {result.stderr}")

    # Build payloads for x86_64
    result = subprocess.run(
        ["make", "all-x86_64"],
        cwd=PAYLOADS_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build payloads: {result.stderr}")


@pytest.fixture(scope="session")
def build_artifacts_aarch64(request):
    """Build puck and test binaries for aarch64."""
    if request.config.getoption("--skip-build"):
        return

    # Check for cross-compiler
    if shutil.which("aarch64-linux-gnu-gcc") is None:
        pytest.skip("aarch64-linux-gnu-gcc not found (cross-compiler required)")

    # Build puck for aarch64
    result = subprocess.run(
        ["cargo", "build", "--release", "--target", RUST_TARGETS["aarch64"]],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build puck for aarch64: {result.stderr}")

    # Build labrats for aarch64
    result = subprocess.run(
        ["make", "all-aarch64"],
        cwd=LABRATS_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build labrats for aarch64: {result.stderr}")

    # Build payloads for aarch64
    result = subprocess.run(
        ["make", "all-aarch64"],
        cwd=PAYLOADS_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build payloads for aarch64: {result.stderr}")


def _get_puck_binary(arch: str) -> Path:
    """Get path to puck binary for given architecture."""
    if arch == "x86_64":
        return PROJECT_ROOT / "target" / "release" / "puck"
    else:
        return PROJECT_ROOT / "target" / RUST_TARGETS[arch] / "release" / "puck"


def _setup_workspace(arch: str) -> Path:
    """Create and populate a workspace directory for the VM."""
    workspace = Path(tempfile.mkdtemp(prefix=f"puck-qemu-{arch}-"))

    # Copy puck binary
    puck_src = _get_puck_binary(arch)
    if puck_src.exists():
        shutil.copy(puck_src, workspace / "puck")

    # Copy labrats
    labrats_dest = workspace / "labrats"
    labrats_dest.mkdir()
    for labrat in LABRATS_DIR.glob(f"*-{arch}"):
        shutil.copy(labrat, labrats_dest / labrat.name.replace(f"-{arch}", ""))

    # Copy payloads
    payloads_dest = workspace / "payloads"
    payloads_dest.mkdir()
    for payload in PAYLOADS_DIR.glob(f"*-{arch}.so"):
        shutil.copy(payload, payloads_dest / payload.name.replace(f"-{arch}", ""))

    return workspace


@pytest.fixture(scope="session")
def _qemu_executor_session(request, check_qemu_images) -> Generator[QemuExecutor, None, None]:
    """Session-scoped QEMU executor. Starts once and is shared across all tests."""
    # Get architecture from command line or auto-detect
    arch = request.config.getoption("--arch", default=None)
    if arch is None:
        arch = _get_host_arch()

    # Ensure binaries are built
    if arch == "x86_64":
        request.getfixturevalue("build_artifacts")
    else:
        request.getfixturevalue("build_artifacts_aarch64")

    image_path = IMAGES_DIR / IMAGES[arch]
    if not image_path.exists():
        pytest.skip(f"Image not found: {image_path}. Run: make setup-qemu-{arch}")

    workspace = _setup_workspace(arch)

    try:
        session = _start_qemu(arch, image_path, workspace)
        executor = QemuExecutor(arch, session, workspace)
        executor.wait_for_boot()
        executor.mount_workspace()
        yield executor
    finally:
        if "executor" in locals():
            executor.shutdown()
        shutil.rmtree(workspace, ignore_errors=True)


def _cleanup_vm_processes(executor: QemuExecutor) -> None:
    """Kill all processes started from /workspace."""
    executor.run_command("pkill -9 -f '/workspace/' 2>/dev/null || true")
    time.sleep(0.1)


@pytest.fixture
def qemu_executor(_qemu_executor_session) -> Generator[QemuExecutor, None, None]:
    """Per-test fixture that provides the shared executor with cleanup between tests."""
    executor = _qemu_executor_session
    _cleanup_vm_processes(executor)
    yield executor
    _cleanup_vm_processes(executor)


# Compatibility alias for existing code
qemu_vm = qemu_executor


@pytest.fixture(scope="session")
def arch(request) -> str:
    """Get the target architecture for QEMU tests."""
    arch = request.config.getoption("--arch", default=None)
    if arch is None:
        arch = _get_host_arch()
    return arch


@pytest.fixture
def executor(qemu_executor) -> QemuExecutor:
    """Provide the QEMU executor as the executor for tests/injection/ tests."""
    return qemu_executor


@pytest.fixture(scope="session")
def puck_binary(arch) -> Path:
    """Return path to puck binary inside VM workspace."""
    return Path("/workspace/puck")


@pytest.fixture(scope="session")
def payload_hello(arch) -> Path:
    """Return path to libhello.so payload inside VM workspace."""
    return Path("/workspace/payloads/libhello.so")


@pytest.fixture(scope="session")
def labrat_sleeper_pie(arch) -> Path:
    """Return path to sleeper-pie labrat inside VM workspace."""
    return Path("/workspace/labrats/sleeper-pie")


@pytest.fixture(scope="session")
def labrat_sleeper_nopie(arch) -> Path:
    """Return path to sleeper-nopie labrat inside VM workspace."""
    return Path("/workspace/labrats/sleeper-nopie")


@pytest.fixture(scope="session")
def labrat_threaded_pie(arch) -> Path:
    """Return path to threaded-pie labrat inside VM workspace."""
    return Path("/workspace/labrats/threaded-pie")
