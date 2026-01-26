# Build test payload libraries for injection testing
#
# Usage:
#   make all-x86_64    # Build for x86_64
#   make all-aarch64   # Build for aarch64 (requires cross-compiler)
#   make clean

CC_x86_64 := gcc
CC_aarch64 := aarch64-linux-gnu-gcc

CFLAGS := -Wall -Wextra -O2 -fPIC
LDFLAGS := -shared -ldl -lpthread

SOURCES := libhello.c
TARGETS := $(SOURCES:.c=.so)

.PHONY: all-x86_64 all-aarch64 clean

all-x86_64: CC := $(CC_x86_64)
all-x86_64: ARCH := x86_64
all-x86_64: $(TARGETS)

all-aarch64: CC := $(CC_aarch64)
all-aarch64: ARCH := aarch64
all-aarch64: $(TARGETS)

%.so: %.c
	$(CC) $(CFLAGS) -o $(@:.so=-$(ARCH).so) $< $(LDFLAGS)

clean:
	rm -f *-x86_64.so *-aarch64.so

# Convenience targets
x86_64: all-x86_64
aarch64: all-aarch64
