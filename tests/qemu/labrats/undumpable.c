/*
 * Undumpable sleeper process for injection testing
 *
 * Calls prctl(PR_SET_DUMPABLE, 0) to make /proc/PID/ root-owned.
 * This simulates the effect of file capabilities (e.g., sway with
 * cap_sys_nice=ep) where the kernel sets dumpable=0 on exec.
 *
 * When dumpable=0, the bootstrapper's open("/proc/self/auxv") returns
 * EACCES, requiring the injector to provide fallback AT_PHDR/AT_PHNUM.
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>

static volatile int running = 1;

static void sigterm_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    signal(SIGTERM, sigterm_handler);

    /* Make this process undumpable.
     * Effect: /proc/PID/ becomes owned by root:root,
     * even when running as a normal user. */
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        perror("prctl(PR_SET_DUMPABLE, 0)");
        return 1;
    }

    fprintf(stderr, "[undumpable] started, pid=%d (dumpable=0)\n", getpid());

    while (running) {
        sleep(60);
    }

    fprintf(stderr, "[undumpable] exiting\n");
    return 0;
}
