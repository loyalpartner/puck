/*
 * Simple sleeper process for injection testing
 *
 * This is a minimal target process that just sleeps, providing
 * a stable target for library injection tests.
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static volatile int running = 1;

static void sigterm_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    signal(SIGTERM, sigterm_handler);

    fprintf(stderr, "[sleeper] started, pid=%d\n", getpid());

    while (running) {
        sleep(60);
    }

    fprintf(stderr, "[sleeper] exiting\n");
    return 0;
}
