# Puck - Linux library injector

.PHONY: build build-aarch64 zigbuild zigbuild-aarch64 test test-host test-qemu test-x86_64 test-aarch64 setup clean help

# Build
build:
	cargo build --release --package puck-cli
	$(MAKE) -C puck/bootstrapper

build-aarch64:
	cargo build --release --package puck-cli --target aarch64-unknown-linux-gnu
	$(MAKE) -C puck/bootstrapper ARCH=aarch64

# Zigbuild (for older glibc compatibility)
zigbuild:
	cargo zigbuild --release --package puck-cli --target x86_64-unknown-linux-gnu.2.28
	$(MAKE) -C puck/bootstrapper

zigbuild-aarch64:
	cargo zigbuild --release --package puck-cli --target aarch64-unknown-linux-gnu.2.28
	$(MAKE) -C puck/bootstrapper ARCH=aarch64

# Test
test: test-qemu

# Host tests (requires root, runs directly on host machine)
test-host: build
	$(MAKE) -C tests/qemu/labrats all-x86_64
	$(MAKE) -C tests/qemu/payloads all-x86_64
	sudo $$(which uv) run pytest tests/injection -v

# QEMU tests (default, isolated environment)
test-qemu: test-x86_64

test-x86_64: build
	$(MAKE) -C tests/qemu/labrats all-x86_64
	$(MAKE) -C tests/qemu/payloads all-x86_64
	uv run pytest tests/qemu -v --arch x86_64

test-aarch64: build-aarch64
	$(MAKE) -C tests/qemu/labrats all-aarch64
	$(MAKE) -C tests/qemu/payloads all-aarch64
	uv run pytest tests/qemu -v --arch aarch64

# Setup VM images
setup:
	tests/qemu/scripts/setup-images.sh x86_64
	tests/qemu/scripts/setup-images.sh aarch64

# Clean
clean:
	cargo clean
	$(MAKE) -C puck/bootstrapper clean
	$(MAKE) -C tests/qemu/labrats clean
	$(MAKE) -C tests/qemu/payloads clean

# Help
help:
	@echo "make build           - Build for x86_64"
	@echo "make build-aarch64   - Build for aarch64"
	@echo "make zigbuild        - Build for x86_64 (glibc 2.28+)"
	@echo "make zigbuild-aarch64 - Build for aarch64 (glibc 2.28+)"
	@echo "make test            - Run tests (default: QEMU)"
	@echo "make test-host       - Run tests on host (prompts for sudo)"
	@echo "make test-qemu       - Run QEMU tests (alias for test-x86_64)"
	@echo "make test-x86_64     - Run QEMU tests for x86_64"
	@echo "make test-aarch64    - Run QEMU tests for aarch64"
	@echo "make setup           - Download VM images"
	@echo "make clean           - Clean all"
