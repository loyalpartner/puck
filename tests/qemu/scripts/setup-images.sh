#!/bin/bash
#
# Download Debian cloud images for QEMU testing
#
# Usage:
#   ./setup-images.sh           # Download both architectures
#   ./setup-images.sh x86_64    # Download x86_64 only
#   ./setup-images.sh aarch64   # Download aarch64 only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/../images"
DEBIAN_VERSION="12"
DEBIAN_URL="https://cloud.debian.org/images/cloud/bookworm/latest"

# Image filenames
IMAGE_AMD64="debian-${DEBIAN_VERSION}-nocloud-amd64.qcow2"
IMAGE_ARM64="debian-${DEBIAN_VERSION}-nocloud-arm64.qcow2"

download_image() {
    local arch="$1"
    local file
    local url

    case "$arch" in
        x86_64|amd64)
            file="$IMAGE_AMD64"
            ;;
        aarch64|arm64)
            file="$IMAGE_ARM64"
            ;;
        *)
            echo "Unknown architecture: $arch" >&2
            echo "Supported: x86_64, aarch64" >&2
            return 1
            ;;
    esac

    url="${DEBIAN_URL}/${file}"
    local dest="${IMAGES_DIR}/${file}"

    if [[ -f "$dest" ]]; then
        echo "Image already exists: $dest"
        return 0
    fi

    echo "Downloading $file..."
    mkdir -p "$IMAGES_DIR"

    if command -v wget &>/dev/null; then
        wget --progress=bar:force -O "$dest" "$url"
    elif command -v curl &>/dev/null; then
        curl -L --progress-bar -o "$dest" "$url"
    else
        echo "Error: neither wget nor curl found" >&2
        return 1
    fi

    echo "Downloaded: $dest"
}

verify_image() {
    local arch="$1"
    local file

    case "$arch" in
        x86_64|amd64)
            file="$IMAGE_AMD64"
            ;;
        aarch64|arm64)
            file="$IMAGE_ARM64"
            ;;
    esac

    local dest="${IMAGES_DIR}/${file}"

    if [[ ! -f "$dest" ]]; then
        echo "Image not found: $dest" >&2
        return 1
    fi

    # Basic sanity check - file should be at least 100MB
    local size
    size=$(stat -f%z "$dest" 2>/dev/null || stat -c%s "$dest" 2>/dev/null)
    if [[ "$size" -lt 100000000 ]]; then
        echo "Warning: Image seems too small (${size} bytes): $dest" >&2
        return 1
    fi

    echo "Verified: $dest (${size} bytes)"
}

main() {
    local arches=("$@")

    if [[ ${#arches[@]} -eq 0 ]]; then
        arches=("x86_64" "aarch64")
    fi

    echo "Setting up QEMU images in: $IMAGES_DIR"
    echo ""

    for arch in "${arches[@]}"; do
        download_image "$arch"
        verify_image "$arch"
        echo ""
    done

    echo "Setup complete!"
    echo ""
    echo "Images directory contents:"
    ls -lh "$IMAGES_DIR"
}

main "$@"
