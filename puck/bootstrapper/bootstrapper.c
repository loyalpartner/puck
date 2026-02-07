/* Bootstrapper + Loader for hsinject
 *
 * Combines Frida-style bootstrapper and loader:
 * 1. Resolves libc symbols (dlopen, dlsym, pthread_create, etc.)
 * 2. Creates a new thread that loads library and calls function
 * 3. All dlopen/dlsym happen in the new thread (single reference)
 *
 * Supported architectures: x86_64, aarch64
 * Linux / glibc only
 */

#include "bootstrapper.h"
#include "elf-parser.h"
#include "syscall.h"

#include <sys/syscall.h>

/* Syscall numbers - architecture specific */
#if defined(__x86_64__)
#  ifndef __NR_read
#    define __NR_read 0
#  endif
#  ifndef __NR_open
#    define __NR_open 2
#  endif
#  ifndef __NR_close
#    define __NR_close 3
#  endif
#elif defined(__aarch64__)
#  ifndef __NR_read
#    define __NR_read 63
#  endif
#  ifndef __NR_openat
#    define __NR_openat 56
#  endif
#  ifndef __NR_close
#    define __NR_close 57
#  endif
#  ifndef AT_FDCWD
#    define AT_FDCWD -100
#  endif
#endif

/* Function pointer types */
typedef void *(*dlopen_fn)(const char *filename, int flags);
typedef void *(*dlsym_fn)(void *handle, const char *symbol);
typedef int (*dlclose_fn)(void *handle);
typedef int (*pthread_create_fn)(void *thread, const void *attr,
                                  void *(*start)(void *), void *arg);
typedef int (*pthread_detach_fn)(void *thread);

/* Loader thread context - must be 16-byte aligned for aarch64 ABI */
typedef struct __attribute__((aligned(16))) {
    BootstrapContext *ctx;
    LibcApi *libc;
    RDebug *r_debug;
} LoaderContext;

/* Forward declarations */
static void *loader_thread(void *arg);
static void *call_thread(void *arg);

/* String comparison - null terminated */
static int str_eq(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (*s1++ != *s2++)
            return 0;
    }
    return *s1 == *s2;
}

/* Check if haystack contains needle */
static int str_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle)
        return 0;

    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (!*n)
            return 1;
        haystack++;
    }
    return 0;
}

/* Parse /proc/self/auxv */
static int parse_auxv(const Elf64_Phdr **phdr_out, size_t *phnum_out) {
    /* Buffer must be 8-byte aligned for Elf64_auxv_t access on aarch64 */
    unsigned char buf[512] __attribute__((aligned(8)));

#if defined(__x86_64__)
    int fd = frida_syscall_3(__NR_open, (size_t)"/proc/self/auxv", O_RDONLY, 0);
#elif defined(__aarch64__)
    /* aarch64 uses openat instead of open */
    int fd = frida_syscall_4(__NR_openat, AT_FDCWD, (size_t)"/proc/self/auxv", O_RDONLY, 0);
#endif
    if (fd < 0)
        return 0;

    ssize_t n = frida_syscall_3(__NR_read, fd, (size_t)buf, sizeof(buf));
    frida_syscall_1(__NR_close, fd);

    if (n <= 0)
        return 0;

    *phdr_out = NULL;
    *phnum_out = 0;

    const Elf64_auxv_t *auxv = (const Elf64_auxv_t *)buf;
    size_t count = n / sizeof(Elf64_auxv_t);

    for (size_t i = 0; i < count; i++) {
        switch (auxv[i].a_type) {
            case AT_NULL:
                goto done;
            case AT_PHDR:
                *phdr_out = (const Elf64_Phdr *)auxv[i].a_un.a_val;
                break;
            case AT_PHNUM:
                *phnum_out = auxv[i].a_un.a_val;
                break;
        }
    }

done:
    return (*phdr_out != NULL && *phnum_out > 0);
}

/* Compute load bias (difference between actual and expected load address) */
static uint64_t compute_load_bias(const Elf64_Phdr *phdr, size_t phnum) {
    uint64_t actual_base = frida_elf_compute_base_from_phdrs(phdr, sizeof(Elf64_Phdr), phnum, 4096);
    uint64_t expected_base = 0;

    for (size_t i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
            expected_base = phdr[i].p_vaddr;
            break;
        }
    }

    return actual_base - expected_base;
}

/* Find r_debug via DT_DEBUG */
static RDebug *find_r_debug(const Elf64_Phdr *phdr, size_t phnum, uint64_t load_bias) {
    const Elf64_Dyn *dynamic = NULL;

    for (size_t i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (const Elf64_Dyn *)(load_bias + phdr[i].p_vaddr);
            break;
        }
    }

    if (!dynamic)
        return NULL;

    for (const Elf64_Dyn *d = dynamic; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_DEBUG) {
            RDebug *r = (RDebug *)d->d_un.d_ptr;
            if (r)
                return r;
        }
    }

    return NULL;
}

/* Find library base address by pattern */
static uint64_t find_library(RDebug *r_debug, const char *pattern1, const char *pattern2) {
    LinkMap *map = r_debug->r_map;

    while (map) {
        if (map->l_name) {
            if (str_contains(map->l_name, pattern1) ||
                (pattern2 && str_contains(map->l_name, pattern2))) {
                return map->l_addr;
            }
        }
        map = map->l_next;
    }

    return 0;
}

/* Find libc base address */
static uint64_t find_libc(RDebug *r_debug) {
    return find_library(r_debug, "libc.so", "libc-");
}

/* Find libpthread base address (for older glibc) */
static uint64_t find_libpthread(RDebug *r_debug) {
    return find_library(r_debug, "libpthread.so", "libpthread-");
}

/* Context for symbol enumeration callback - aligned for aarch64 */
typedef struct __attribute__((aligned(16))) {
    const char *name;
    void *result;
} SymbolLookupCtx;

/* Callback for frida_elf_enumerate_exports */
static bool symbol_found_cb(const FridaElfExportDetails *details, void *user_data) {
    SymbolLookupCtx *ctx = (SymbolLookupCtx *)user_data;

    if (str_eq(details->name, ctx->name)) {
        ctx->result = details->address;
        return false;
    }

    return true;
}

/* Find symbol in library using Frida's ELF parser */
static void *find_symbol(uint64_t lib_base, const char *name) {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)lib_base;

    if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F')
        return NULL;

    SymbolLookupCtx ctx = { .name = name, .result = NULL };
    frida_elf_enumerate_exports(ehdr, symbol_found_cb, &ctx);

    return ctx.result;
}

/* Resolve libc symbols */
static int resolve_libc_symbols(uint64_t libc_base, uint64_t pthread_base, LibcApi *api) {
    /* dlopen: try dlopen first, then __libc_dlopen_mode */
    api->dlopen = (uint64_t)find_symbol(libc_base, "dlopen");
    if (!api->dlopen)
        api->dlopen = (uint64_t)find_symbol(libc_base, "__libc_dlopen_mode");
    if (!api->dlopen)
        return 0;

    /* dlsym: try dlsym first, then __libc_dlsym */
    api->dlsym = (uint64_t)find_symbol(libc_base, "dlsym");
    if (!api->dlsym)
        api->dlsym = (uint64_t)find_symbol(libc_base, "__libc_dlsym");
    if (!api->dlsym)
        return 0;

    /* dlclose: try dlclose first, then __libc_dlclose */
    api->dlclose = (uint64_t)find_symbol(libc_base, "dlclose");
    if (!api->dlclose)
        api->dlclose = (uint64_t)find_symbol(libc_base, "__libc_dlclose");
    if (!api->dlclose)
        return 0;

    /* dlerror is optional */
    api->dlerror = (uint64_t)find_symbol(libc_base, "dlerror");

    /* pthread_create: try libc first (glibc 2.34+), then libpthread */
    api->pthread_create = (uint64_t)find_symbol(libc_base, "pthread_create");
    if (!api->pthread_create && pthread_base)
        api->pthread_create = (uint64_t)find_symbol(pthread_base, "pthread_create");
    if (!api->pthread_create)
        return 0;

    /* pthread_detach: try libc first, then libpthread */
    api->pthread_detach = (uint64_t)find_symbol(libc_base, "pthread_detach");
    if (!api->pthread_detach && pthread_base)
        api->pthread_detach = (uint64_t)find_symbol(pthread_base, "pthread_detach");
    if (!api->pthread_detach)
        return 0;

    return 1;
}

/* Loader thread: dlopen + dlsym + call function + dlclose */
static void *loader_thread(void *arg) {
    LoaderContext *lctx = (LoaderContext *)arg;
    BootstrapContext *ctx = lctx->ctx;
    LibcApi *libc = lctx->libc;

    dlopen_fn do_dlopen = (dlopen_fn)libc->dlopen;
    dlclose_fn do_dlclose = (dlclose_fn)libc->dlclose;
    dlsym_fn do_dlsym = (dlsym_fn)libc->dlsym;
    pthread_detach_fn do_pthread_detach = (pthread_detach_fn)libc->pthread_detach;

    /* Detach this thread so it doesn't need to be joined */
    void *self;
#if defined(__x86_64__)
    __asm__ volatile ("mov %%fs:0, %0" : "=r" (self));
#elif defined(__aarch64__)
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (self));
#endif
    if (do_pthread_detach && self)
        do_pthread_detach(self);

    /* dlopen the library */
    const char *path = (const char *)ctx->library_path;
    void *handle = do_dlopen(path, RTLD_NOW);
    if (!handle) {
        ctx->status = BOOTSTRAP_DLOPEN_FAILED;
        return NULL;
    }
    ctx->handle = (uint64_t)handle;

    /* dlsym to find the function */
    const char *func_name = (const char *)ctx->function_name;
    void *(*entry)(void *) = do_dlsym(handle, func_name);
    if (!entry) {
        ctx->status = BOOTSTRAP_DLSYM_FAILED;
        return NULL;
    }

    /* Call the function */
    void *func_arg = (void *)ctx->argument;
    entry(func_arg);

    /* Close the library after entry returns.
     * This is safe because we're executing in the bootstrapper shellcode,
     * not in the library being unloaded. */
    do_dlclose(handle);

    ctx->status = BOOTSTRAP_SUCCESS;
    return NULL;
}

/* Call thread: call function in already-loaded library */
static void *call_thread(void *arg) {
    LoaderContext *lctx = (LoaderContext *)arg;
    BootstrapContext *ctx = lctx->ctx;
    LibcApi *libc = lctx->libc;
    RDebug *r_debug = lctx->r_debug;

    pthread_detach_fn do_pthread_detach = (pthread_detach_fn)libc->pthread_detach;

    /* Detach this thread */
    void *self;
#if defined(__x86_64__)
    __asm__ volatile ("mov %%fs:0, %0" : "=r" (self));
#elif defined(__aarch64__)
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (self));
#endif
    if (do_pthread_detach && self)
        do_pthread_detach(self);

    /* Find the library in link_map */
    const char *lib_pattern = (const char *)ctx->library_path;
    uint64_t lib_base = 0;

    LinkMap *map = r_debug->r_map;
    while (map) {
        if (map->l_name && str_contains(map->l_name, lib_pattern)) {
            lib_base = map->l_addr;
            break;
        }
        map = map->l_next;
    }

    if (!lib_base) {
        ctx->status = BOOTSTRAP_LIBRARY_NOT_LOADED;
        return NULL;
    }

    /* Find the function using ELF parser */
    const char *func_name = (const char *)ctx->function_name;
    void *(*entry)(void *) = find_symbol(lib_base, func_name);
    if (!entry) {
        ctx->status = BOOTSTRAP_DLSYM_FAILED;
        return NULL;
    }

    /* Call the function */
    void *func_arg = (void *)ctx->argument;
    entry(func_arg);

    ctx->status = BOOTSTRAP_SUCCESS;
    return NULL;
}

/* Main bootstrap entry point */
__attribute__((section(".text.bootstrap")))
__attribute__((visibility("default")))
uint32_t bootstrap(BootstrapContext *ctx) {
    if (!ctx) {
        /* No context to write status to - just trap immediately */
#if defined(__x86_64__)
        __asm__ volatile ("int3");
#elif defined(__aarch64__)
        __asm__ volatile ("brk #0");
#endif
        return BOOTSTRAP_AUXV_PARSE_FAILED;
    }

    /* Step 1: Parse /proc/self/auxv to get AT_PHDR and AT_PHNUM */
    const Elf64_Phdr *phdr;
    size_t phnum;

    /* Check if injector provided fallback values in context */
    if (ctx->fallback_phdr && ctx->fallback_phnum) {
        phdr = (const Elf64_Phdr *)ctx->fallback_phdr;
        phnum = ctx->fallback_phnum;
    } else if (!parse_auxv(&phdr, &phnum)) {
        ctx->status = BOOTSTRAP_AUXV_PARSE_FAILED;
        goto trap;
    }

    /* Step 2: Compute load bias */
    uint64_t load_bias = compute_load_bias(phdr, phnum);

    /* Step 3: Find r_debug */
    RDebug *r_debug = find_r_debug(phdr, phnum, load_bias);
    if (!r_debug) {
        ctx->status = BOOTSTRAP_RDEBUG_NOT_FOUND;
        goto trap;
    }

    /* Step 4: Find libc */
    uint64_t libc_base = find_libc(r_debug);
    if (!libc_base) {
        ctx->status = BOOTSTRAP_LIBC_NOT_FOUND;
        goto trap;
    }

    /* Step 5: Find libpthread (for older glibc) */
    uint64_t pthread_base = find_libpthread(r_debug);

    /* Step 6: Resolve libc symbols */
    if (!resolve_libc_symbols(libc_base, pthread_base, &ctx->libc)) {
        ctx->status = BOOTSTRAP_SYMBOL_RESOLUTION_FAILED;
        goto trap;
    }

    /* Step 7: Create loader/call thread based on mode */
    pthread_create_fn do_pthread_create = (pthread_create_fn)ctx->libc.pthread_create;

    /* Static loader context (on stack, but thread will copy what it needs) */
    LoaderContext lctx = {
        .ctx = ctx,
        .libc = &ctx->libc,
        .r_debug = r_debug,
    };

    void *thread;
    int ret;

    if (ctx->mode == BOOTSTRAP_MODE_LOAD) {
        ret = do_pthread_create(&thread, NULL, loader_thread, &lctx);
    } else {
        ret = do_pthread_create(&thread, NULL, call_thread, &lctx);
    }

    if (ret != 0) {
        ctx->status = BOOTSTRAP_PTHREAD_FAILED;
        goto trap;
    }

    /* Note: Thread is detached and will set ctx->status when done.
     * We return success here to indicate thread was created.
     * The injector should wait a bit for the thread to complete. */
    ctx->status = BOOTSTRAP_SUCCESS;

trap:
    /* Trap to return control to injector.
     * ALL exit paths must come here - using ret would jump to 0x0
     * since we have no valid return address on the stack. */
#if defined(__x86_64__)
    __asm__ volatile ("int3");
#elif defined(__aarch64__)
    __asm__ volatile ("brk #0");
#endif

    return ctx->status;
}
