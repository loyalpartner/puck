/*
 * Multi-threaded process for injection testing
 *
 * Tests that injection works correctly when multiple threads exist.
 * The bootstrapper must handle thread synchronization properly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#define NUM_THREADS 4

static volatile int running = 1;

static void sigterm_handler(int sig) {
    (void)sig;
    running = 0;
}

static void *worker(void *arg) {
    int id = *(int *)arg;
    free(arg);

    fprintf(stderr, "[threaded] worker %d started\n", id);

    while (running) {
        sleep(1);
    }

    fprintf(stderr, "[threaded] worker %d exiting\n", id);
    return NULL;
}

int main(void) {
    pthread_t threads[NUM_THREADS];

    signal(SIGTERM, sigterm_handler);

    fprintf(stderr, "[threaded] started, pid=%d\n", getpid());

    for (int i = 0; i < NUM_THREADS; i++) {
        int *id = malloc(sizeof(int));
        *id = i;
        if (pthread_create(&threads[i], NULL, worker, id) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    fprintf(stderr, "[threaded] all %d workers started\n", NUM_THREADS);

    while (running) {
        sleep(60);
    }

    fprintf(stderr, "[threaded] signaling workers to exit\n");

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    fprintf(stderr, "[threaded] exiting\n");
    return 0;
}
