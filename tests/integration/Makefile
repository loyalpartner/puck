CC = gcc
CFLAGS = -fPIC -shared -Wall -Wextra -O2
LDFLAGS = -ldl -lpthread

.PHONY: all clean

all: libhello.so

libhello.so: libhello.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f libhello.so
