/* Bootstrapper context and types for hsinject
 *
 * Combines Frida-style bootstrapper + loader:
 * - Resolves libc symbols
 * - Loads library and calls function in a new thread
 * - Supports calling functions in already-loaded libraries
 *
 * x86_64 Linux / glibc only
 */

#ifndef BOOTSTRAPPER_H
#define BOOTSTRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <elf.h>

/* Bootstrap operation mode */
typedef enum {
    /* Load library and call function (dlopen + dlsym + call) */
    BOOTSTRAP_MODE_LOAD = 0,
    /* Call function in already-loaded library (find in link_map + call) */
    BOOTSTRAP_MODE_CALL = 1,
} BootstrapMode;

/* Bootstrap status codes */
typedef enum {
    BOOTSTRAP_SUCCESS = 0,
    BOOTSTRAP_AUXV_PARSE_FAILED = 1,
    BOOTSTRAP_RDEBUG_NOT_FOUND = 2,
    BOOTSTRAP_LIBC_NOT_FOUND = 3,
    BOOTSTRAP_SYMBOL_RESOLUTION_FAILED = 4,
    BOOTSTRAP_DLOPEN_FAILED = 5,
    BOOTSTRAP_DLSYM_FAILED = 6,
    BOOTSTRAP_PTHREAD_FAILED = 7,
    BOOTSTRAP_LIBRARY_NOT_LOADED = 8,
} BootstrapStatus;

/* Resolved libc API addresses (internal use) */
typedef struct {
    uint64_t dlopen;
    uint64_t dlclose;
    uint64_t dlsym;
    uint64_t dlerror;
    uint64_t pthread_create;
    uint64_t pthread_detach;
} LibcApi;

/* Bootstrap context - passed to/from bootstrapper
 *
 * Memory layout (224 bytes total):
 * - Input fields (set by injector)
 * - Output fields (set by bootstrapper)
 */
typedef struct {
    /* === Input fields (set by injector) === */

    /* Operation mode: LOAD or CALL */
    uint32_t mode;

    /* Padding for alignment */
    uint32_t _pad0;

    /* Pointer to null-terminated library path (for LOAD mode)
     * or library name pattern to find (for CALL mode) */
    uint64_t library_path;

    /* Pointer to null-terminated function name */
    uint64_t function_name;

    /* Pointer to argument data (passed to function as first arg) */
    uint64_t argument;

    /* === Output fields (set by bootstrapper) === */

    /* Result status */
    uint32_t status;

    /* Padding */
    uint32_t _pad1;

    /* Handle returned by dlopen (for LOAD mode) */
    uint64_t handle;

    /* Resolved libc APIs (for debugging/advanced use) */
    LibcApi libc;

    /* Reserved for future use */
    uint64_t _reserved[16];
} BootstrapContext;

/* Link map structure (glibc) */
typedef struct _LinkMap {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct _LinkMap *l_next;
    struct _LinkMap *l_prev;
} LinkMap;

/* r_debug structure (glibc) */
typedef struct {
    int r_version;
    LinkMap *r_map;
    Elf64_Addr r_brk;
    int r_state;
    Elf64_Addr r_ldbase;
} RDebug;

/* Auxiliary vector types */
#define AT_NULL   0
#define AT_PHDR   3
#define AT_PHNUM  5

/* Dynamic section tags */
#define DT_DEBUG    21

/* Open flags */
#define O_RDONLY    0

/* dlopen flags */
#define RTLD_NOW    0x2

/* Entry point */
__attribute__((section(".text.bootstrap")))
__attribute__((visibility("default")))
uint32_t bootstrap(BootstrapContext *ctx);

#endif /* BOOTSTRAPPER_H */
