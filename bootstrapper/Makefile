# Bootstrapper shellcode build system
#
# Builds position-independent shellcode for process injection.
# Currently x86_64 only, can be extended to other architectures.

CC := gcc
LD := ld
OBJCOPY := objcopy

# Common flags
CFLAGS_COMMON := -O2 -fPIC -fno-stack-protector -fno-builtin -nostdlib -Wall -Wextra -I$(CURDIR)

# Architecture-specific settings
ARCH ?= x86_64

ifeq ($(ARCH),x86_64)
    CFLAGS := $(CFLAGS_COMMON) -m64
    LDFLAGS := -m elf_x86_64
    LINKER_SCRIPT := linker.ld
    TARGET := bootstrapper-x86_64.bin
else ifeq ($(ARCH),x86)
    CFLAGS := $(CFLAGS_COMMON) -m32
    LDFLAGS := -m elf_i386
    LINKER_SCRIPT := linker.ld
    TARGET := bootstrapper-x86.bin
else ifeq ($(ARCH),aarch64)
    CC := aarch64-linux-gnu-gcc
    LD := aarch64-linux-gnu-ld
    OBJCOPY := aarch64-linux-gnu-objcopy
    CFLAGS := $(CFLAGS_COMMON)
    LDFLAGS := -m aarch64linux
    LINKER_SCRIPT := linker-aarch64.ld
    TARGET := bootstrapper-aarch64.bin
else ifeq ($(ARCH),arm)
    CC := arm-linux-gnueabihf-gcc
    LD := arm-linux-gnueabihf-ld
    OBJCOPY := arm-linux-gnueabihf-objcopy
    CFLAGS := $(CFLAGS_COMMON)
    LDFLAGS := -m armelf_linux_eabi
    LINKER_SCRIPT := linker.ld
    TARGET := bootstrapper-arm.bin
endif

# Source files
SRCS := bootstrapper.c elf-parser.c syscall.c

# Output directory (overridden by build.rs)
OUT_DIR ?= $(CURDIR)

# All intermediate files go to OUT_DIR
OBJS := $(addprefix $(OUT_DIR)/,$(SRCS:.c=.o))
ELF := $(OUT_DIR)/bootstrapper.elf

.PHONY: all clean x86_64 x86 arm64 arm all-arch info

all: $(OUT_DIR)/$(TARGET)

# Build for specific architectures
x86_64:
	$(MAKE) ARCH=x86_64

x86:
	$(MAKE) ARCH=x86

arm64:
	$(MAKE) ARCH=aarch64

arm:
	$(MAKE) ARCH=arm

# Build all architectures (requires cross-compilers)
all-arch: x86_64
	@echo "Note: x86, arm, arm64 require cross-compilers"
	@echo "Install with: apt install gcc-multilib gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf"

# Compile C to object files
$(OUT_DIR)/%.o: %.c
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Link object files
$(ELF): $(OBJS) $(LINKER_SCRIPT)
	$(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(OBJS)

# Extract raw binary
$(OUT_DIR)/$(TARGET): $(ELF)
	$(OBJCOPY) -O binary $< $@
	@ls -l $@ | awk '{print "Built $@ (" $$5 " bytes)"}'

clean:
	rm -f $(OUT_DIR)/*.o $(OUT_DIR)/*.elf $(OUT_DIR)/bootstrapper-*.bin

info:
	@echo "ARCH=$(ARCH)"
	@echo "CC=$(CC)"
	@echo "OUT_DIR=$(OUT_DIR)"
	@echo "TARGET=$(TARGET)"
