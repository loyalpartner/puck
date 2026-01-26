#!/bin/bash
#
# Launch QEMU VM for testing
#
# Usage:
#   ./run-vm.sh <arch> [workspace]
#
# Example:
#   ./run-vm.sh x86_64 /path/to/workspace
#   ./run-vm.sh aarch64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/../images"

ARCH="${1:-x86_64}"
WORKSPACE="${2:-}"

# Determine image and QEMU settings based on architecture
case "$ARCH" in
    x86_64|amd64)
        QEMU="qemu-system-x86_64"
        IMAGE="${IMAGES_DIR}/debian-12-nocloud-amd64.qcow2"

        # Use KVM if available
        if [[ -e /dev/kvm ]] && [[ -r /dev/kvm ]] && [[ -w /dev/kvm ]]; then
            MACHINE="-M q35 -enable-kvm"
            CPU="-cpu host"
        else
            MACHINE="-M q35"
            CPU="-cpu qemu64"
        fi
        ;;
    aarch64|arm64)
        QEMU="qemu-system-aarch64"
        IMAGE="${IMAGES_DIR}/debian-12-nocloud-arm64.qcow2"
        MACHINE="-M virt"
        CPU="-cpu cortex-a72"
        ;;
    *)
        echo "Unknown architecture: $ARCH" >&2
        echo "Supported: x86_64, aarch64" >&2
        exit 1
        ;;
esac

# Check QEMU is installed
if ! command -v "$QEMU" &>/dev/null; then
    echo "Error: $QEMU not found" >&2
    echo "Install with: sudo pacman -S qemu-full  # or equivalent" >&2
    exit 1
fi

# Check image exists
if [[ ! -f "$IMAGE" ]]; then
    echo "Error: Image not found: $IMAGE" >&2
    echo "Run setup-images.sh first" >&2
    exit 1
fi

# Build QEMU command
QEMU_CMD=(
    "$QEMU"
    $MACHINE
    $CPU
    -m 1024
    -smp 2
    -drive "file=$IMAGE,format=qcow2,if=virtio,snapshot=on"
    -nographic
    -serial mon:stdio
)

# Add virtio-9p for workspace sharing if specified
if [[ -n "$WORKSPACE" ]]; then
    if [[ ! -d "$WORKSPACE" ]]; then
        echo "Error: Workspace directory not found: $WORKSPACE" >&2
        exit 1
    fi
    QEMU_CMD+=(
        -virtfs "local,path=$WORKSPACE,mount_tag=workspace,security_model=none,id=workspace"
    )
    echo "Sharing workspace: $WORKSPACE -> /workspace (mount with: mount -t 9p workspace /workspace)"
fi

echo "Starting QEMU ($ARCH)..."
echo "Command: ${QEMU_CMD[*]}"
echo ""
echo "Login: root (no password)"
echo "Mount workspace: mount -t 9p workspace /workspace"
echo "Shutdown: poweroff"
echo ""

exec "${QEMU_CMD[@]}"
