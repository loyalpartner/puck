# Puck - Linux library injector
#
# Usage:
#   make build              # Build for native architecture
#   make build-aarch64      # Cross-compile for aarch64
#   make test               # Run host integration tests
#   make test-qemu-x86_64   # Run QEMU tests for x86_64
#   make test-qemu-aarch64  # Run QEMU tests for aarch64
#   make clean              # Clean all build artifacts

.PHONY: all build build-aarch64 test test-qemu-x86_64 test-qemu-aarch64 \
        setup-qemu-x86_64 setup-qemu-aarch64 clean

# Directories
BOOTSTRAPPER_DIR := bootstrapper
QEMU_TEST_DIR := tests/qemu
INTEGRATION_TEST_DIR := tests/integration

# Rust targets
TARGET_AARCH64 := aarch64-unknown-linux-gnu

# Python (use uv)
UV := uv
PYTEST := $(UV) run pytest

# Default target
all: build

#
# Build targets
#

build:
	cargo build --release
	$(MAKE) -C $(BOOTSTRAPPER_DIR)

build-aarch64:
	cargo build --release --target $(TARGET_AARCH64)
	$(MAKE) -C $(BOOTSTRAPPER_DIR) ARCH=aarch64

#
# Host integration tests (requires sudo)
#

test: build
	$(MAKE) -C $(INTEGRATION_TEST_DIR)
	sudo $(PYTEST) $(INTEGRATION_TEST_DIR) -v

#
# QEMU tests
#

# Setup: download VM images
setup-qemu-x86_64:
	$(QEMU_TEST_DIR)/scripts/setup-images.sh x86_64

setup-qemu-aarch64:
	$(QEMU_TEST_DIR)/scripts/setup-images.sh aarch64

# Build test artifacts for QEMU
$(QEMU_TEST_DIR)/.built-x86_64: build
	$(MAKE) -C $(QEMU_TEST_DIR)/labrats all-x86_64
	$(MAKE) -C $(QEMU_TEST_DIR)/payloads all-x86_64
	touch $@

$(QEMU_TEST_DIR)/.built-aarch64: build-aarch64
	$(MAKE) -C $(QEMU_TEST_DIR)/labrats all-aarch64
	$(MAKE) -C $(QEMU_TEST_DIR)/payloads all-aarch64
	touch $@

# Run QEMU tests
test-qemu-x86_64: $(QEMU_TEST_DIR)/.built-x86_64
	@if [ ! -f $(QEMU_TEST_DIR)/images/debian-12-nocloud-amd64.qcow2 ]; then \
		echo "Error: QEMU image not found. Run 'make setup-qemu-x86_64' first."; \
		exit 1; \
	fi
	cd $(QEMU_TEST_DIR) && $(PYTEST) -v --arch x86_64

test-qemu-aarch64: $(QEMU_TEST_DIR)/.built-aarch64
	@if [ ! -f $(QEMU_TEST_DIR)/images/debian-12-nocloud-arm64.qcow2 ]; then \
		echo "Error: QEMU image not found. Run 'make setup-qemu-aarch64' first."; \
		exit 1; \
	fi
	cd $(QEMU_TEST_DIR) && $(PYTEST) -v --arch aarch64

#
# Convenience aliases
#

test-x86_64: test-qemu-x86_64
test-aarch64: test-qemu-aarch64

#
# Clean
#

clean:
	cargo clean
	$(MAKE) -C $(BOOTSTRAPPER_DIR) clean
	$(MAKE) -C $(QEMU_TEST_DIR)/labrats clean
	$(MAKE) -C $(QEMU_TEST_DIR)/payloads clean
	$(MAKE) -C $(INTEGRATION_TEST_DIR) clean 2>/dev/null || true
	rm -f $(QEMU_TEST_DIR)/.built-*

#
# Help
#

help:
	@echo "Puck - Linux library injector"
	@echo ""
	@echo "Build:"
	@echo "  make build            Build for native architecture"
	@echo "  make build-aarch64    Cross-compile for aarch64"
	@echo ""
	@echo "Test:"
	@echo "  make test             Run host integration tests (requires sudo)"
	@echo "  make test-x86_64      Run QEMU tests for x86_64"
	@echo "  make test-aarch64     Run QEMU tests for aarch64"
	@echo ""
	@echo "Setup:"
	@echo "  make setup-qemu-x86_64   Download x86_64 VM image"
	@echo "  make setup-qemu-aarch64  Download aarch64 VM image"
	@echo ""
	@echo "Other:"
	@echo "  make clean            Clean all build artifacts"
	@echo "  make help             Show this help"
