/*
 * Test payload for QEMU injection tests
 *
 * Creates a marker file to verify injection succeeded.
 * arg format: "/path/to/marker" or "/path/to/marker:extra_data"
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

__attribute__((visibility("default")))
void *entry(void *arg) {
    if (arg == NULL) {
        fprintf(stderr, "[libhello] no marker path\n");
        return NULL;
    }

    /* Parse "marker_path" or "marker_path:data" */
    char *marker_path = (char *)arg;
    char *data = strchr(marker_path, ':');
    if (data) {
        *data++ = '\0';
    }

    /* Write marker file */
    FILE *f = fopen(marker_path, "w");
    if (f) {
        fprintf(f, "pid=%d\n", getpid());
        if (data) {
            fprintf(f, "data=%s\n", data);
        }
        fclose(f);
    }

    return NULL;
}
