# Build labrats (target processes) for injection testing
#
# Usage:
#   make all-x86_64    # Build for x86_64
#   make all-aarch64   # Build for aarch64 (requires cross-compiler)
#   make clean

CC_x86_64 := gcc
CC_aarch64 := aarch64-linux-gnu-gcc

CFLAGS := -Wall -Wextra -O2
LDFLAGS := -lpthread

SOURCES := sleeper.c threaded.c undumpable.c
TARGETS_PIE := $(SOURCES:.c=-pie)
TARGETS_NOPIE := $(SOURCES:.c=-nopie)
ALL_TARGETS := $(TARGETS_PIE) $(TARGETS_NOPIE)

.PHONY: all-x86_64 all-aarch64 clean

all-x86_64: CC := $(CC_x86_64)
all-x86_64: ARCH := x86_64
all-x86_64: $(ALL_TARGETS)

all-aarch64: CC := $(CC_aarch64)
all-aarch64: ARCH := aarch64
all-aarch64: $(ALL_TARGETS)

%-pie: %.c
	$(CC) $(CFLAGS) -fPIE -pie -o $@-$(ARCH) $< $(LDFLAGS)

%-nopie: %.c
	$(CC) $(CFLAGS) -fno-PIE -no-pie -o $@-$(ARCH) $< $(LDFLAGS)

clean:
	rm -f *-x86_64 *-aarch64

# Convenience targets
x86_64: all-x86_64
aarch64: all-aarch64
