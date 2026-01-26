/*
 * Simple test library for QEMU injection tests
 *
 * The loader_thread in bootstrapper handles dlclose after entry() returns,
 * so this library just needs to do its work and return.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

/*
 * Entry point called after injection
 *
 * Prints debug info and returns. The loader will call dlclose after this,
 * properly unloading the library from the process.
 */
__attribute__((visibility("default")))
void *entry(void *arg) {
    fprintf(stderr, "[libhello] entry() called with arg=%p\n", arg);

    if (arg != NULL) {
        fprintf(stderr, "[libhello] arg string: %s\n", (char *)arg);
    }

    /* Simulate some work */
    usleep(1000);  /* 1ms */

    fprintf(stderr, "[libhello] entry() returning\n");
    return NULL;
}

/*
 * Alternative entry point that returns a marker value
 * Used to verify return value handling
 */
__attribute__((visibility("default")))
void *entry_with_result(void *arg) {
    (void)arg;
    fprintf(stderr, "[libhello] entry_with_result() called\n");
    return (void *)0xDEADBEEF;
}

/*
 * Entry point that takes longer to complete
 * Used to test concurrent injection scenarios
 */
__attribute__((visibility("default")))
void *entry_slow(void *arg) {
    (void)arg;
    fprintf(stderr, "[libhello] entry_slow() starting\n");
    sleep(2);
    fprintf(stderr, "[libhello] entry_slow() done\n");
    return NULL;
}
