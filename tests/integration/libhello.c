/*
 * Simple test library for hsinject integration tests
 *
 * The loader_thread in bootstrapper handles dlclose after entry() returns,
 * so this library just needs to do its work and return.
 */

#include <stdio.h>
#include <unistd.h>

/*
 * Entry point called after injection
 *
 * Does some work and returns. The loader will call dlclose after this returns,
 * properly unloading the library from the process.
 */
__attribute__((visibility("default")))
void *entry(void *arg) {
    fprintf(stderr, "[libhello] entry() called with arg=%p\n", arg);

    /* Simulate some work */
    usleep(1000);  /* 1ms */

    fprintf(stderr, "[libhello] entry() returning\n");
    return NULL;
}
