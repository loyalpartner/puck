# Frida Linux Injection Architecture

This document describes Frida's process injection architecture on Linux, based on analysis of frida-core source code.

## Overview

Frida uses a sophisticated **two-stage injection mechanism**:
- **Stage 1 (Bootstrapper)**: Initializes runtime environment and allocates memory
- **Stage 2 (Loader)**: Injects the agent library and establishes communication

```
┌─────────────────────────────────────────────────────────────────┐
│                         Injector Process                         │
├─────────────────────────────────────────────────────────────────┤
│  SeizeSession (ptrace)  →  InjectSession  →  RemoteCall         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Target Process                           │
├─────────────────────────────────────────────────────────────────┤
│  Bootstrapper  →  Loader  →  Agent (frida-agent.so)             │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

| Component | File | Purpose |
|-----------|------|---------|
| SeizeSession | frida-helper-backend.vala | Base class for ptrace control |
| InjectSession | frida-helper-backend.vala | Manages injection process |
| RemoteCall | frida-helper-backend.vala | Executes functions in target |
| Bootstrapper | bootstrapper.c | Initializes libc and memory |
| ELF Parser | elf-parser.c | Symbol resolution |
| Loader | inject-glue.c | Agent loading and thread creation |

---

## Stage 1: Bootstrapper

### FridaBootstrapContext Structure

The bootstrapper receives a context structure containing all necessary configuration:

```c
typedef struct {
    // Input parameters
    FridaBootstrapStatus bootstrap_status;
    FridaRuntimeFlavor runtime_flavor;  // GLIBC, MUSL, UCLIBC, ANDROID
    size_t page_size;
    size_t allocation_size;
    FridaUnwindFlags unwind_flags;

    // Output results (filled by bootstrapper)
    void * allocation_base;
    int ctrlfds[2];           // Control file descriptors
    FridaLibcApi libc;        // Resolved libc function pointers
} FridaBootstrapContext;
```

### FridaLibcApi Structure

Contains pointers to all required libc functions:

```c
typedef struct {
    // Memory management
    FridaMmapFunc mmap;
    FridaMunmapFunc munmap;

    // Dynamic linking
    FridaDlopenFunc dlopen;
    FridaDlcloseFunc dlclose;
    FridaDlsymFunc dlsym;
    FridaDlerrorFunc dlerror;

    // Threading
    FridaPthreadCreateFunc pthread_create;
    FridaPthreadDetachFunc pthread_detach;

    // IPC
    FridaSocketpairFunc socketpair;
    FridaCloneFunc clone;
    FridaWriteFunc write;

    // Process control
    FridaOpenFunc open;
    FridaCloseFunc close;
    FridaReadFunc read;
    FridaExitFunc exit;

    // Signal handling
    FridaSigprocmaskFunc sigprocmask;

    // Android-specific
    FridaPropertyGetFunc __system_property_get;
} FridaLibcApi;
```

### Bootstrap Execution Flow

The `frida_bootstrap()` function executes in three phases:

```c
void frida_bootstrap(FridaBootstrapContext * ctx) {
    // Phase 1: Allocate memory for loader
    ctx->allocation_base = mmap(NULL, ctx->allocation_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ctx->allocation_base == MAP_FAILED) {
        ctx->bootstrap_status = FRIDA_BOOTSTRAP_ALLOCATION_ERROR;
        return;
    }

    // Phase 2: Probe process to find libc
    FridaProbeResult probe_result = frida_probe_process(ctx);
    if (probe_result != FRIDA_PROBE_SUCCESS) {
        ctx->bootstrap_status = FRIDA_BOOTSTRAP_LIBC_UNSUPPORTED;
        return;
    }

    // Phase 3: Create control socket pair
    if (ctx->libc.socketpair != NULL) {
        ctx->libc.socketpair(AF_UNIX, SOCK_STREAM, 0, ctx->ctrlfds);
    }

    ctx->bootstrap_status = FRIDA_BOOTSTRAP_SUCCESS;
}
```

### Process Probing: frida_probe_process()

This function discovers the process layout and resolves libc symbols:

```c
static FridaProbeResult frida_probe_process(FridaBootstrapContext * ctx) {
    FridaProcessLayout layout = { 0 };

    // Step 1: Parse /proc/self/auxv to find dynamic linker
    frida_parse_auxv(&layout);

    // Step 2: Find r_debug structure via DT_DEBUG
    frida_find_rdebug(&layout);

    // Step 3: Traverse link map to find libc
    frida_find_libc(&layout, &ctx->libc);

    // Step 4: Resolve all required symbols
    return frida_resolve_libc_symbols(&layout, &ctx->libc);
}
```

### Auxiliary Vector Parsing

Frida reads `/proc/self/auxv` to find critical addresses:

```c
static void frida_parse_auxv(FridaProcessLayout * layout) {
    int fd = open("/proc/self/auxv", O_RDONLY);
    ElfW(auxv_t) entry;

    while (read(fd, &entry, sizeof(entry)) == sizeof(entry)) {
        switch (entry.a_type) {
            case AT_PHDR:   // Program headers address
                layout->phdr = (void *)entry.a_un.a_val;
                break;
            case AT_PHNUM:  // Number of program headers
                layout->phnum = entry.a_un.a_val;
                break;
            case AT_BASE:   // Dynamic linker base address
                layout->interpreter_base = (void *)entry.a_un.a_val;
                break;
            case AT_ENTRY:  // Program entry point
                layout->entry = (void *)entry.a_un.a_val;
                break;
        }
    }
    close(fd);
}
```

### Link Map Traversal

Frida traverses the dynamic linker's link map to find libraries:

```c
static void frida_find_libc(FridaProcessLayout * layout, FridaLibcApi * api) {
    struct r_debug * r = layout->r_debug;
    struct link_map * map;

    for (map = r->r_map; map != NULL; map = map->l_next) {
        // Check if this is libc
        FridaLibcFlavor flavor;
        if (frida_path_is_libc(map->l_name, &flavor)) {
            layout->libc = (void *)map->l_addr;
            layout->libc_flavor = flavor;
            break;
        }
    }
}

static bool frida_path_is_libc(const char * path, FridaLibcFlavor * flavor) {
    // Check for various libc patterns
    if (strstr(path, "libc.so") || strstr(path, "libc-")) {
        // Detect flavor: GLIBC, MUSL, UCLIBC, ANDROID
        if (strstr(path, "musl")) {
            *flavor = FRIDA_LIBC_MUSL;
        } else if (strstr(path, "uclibc")) {
            *flavor = FRIDA_LIBC_UCLIBC;
        } else {
            *flavor = FRIDA_LIBC_GLIBC;
        }
        return true;
    }
    return false;
}
```

### Finding r_debug via DT_DEBUG

```c
static void frida_find_rdebug(FridaProcessLayout * layout) {
    // Find PT_DYNAMIC segment
    ElfW(Phdr) * phdr = layout->phdr;
    for (int i = 0; i < layout->phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            ElfW(Dyn) * dyn = (void *)(layout->executable_base + phdr[i].p_vaddr);

            // Search for DT_DEBUG entry
            while (dyn->d_tag != DT_NULL) {
                if (dyn->d_tag == DT_DEBUG) {
                    layout->r_debug = (struct r_debug *)dyn->d_un.d_ptr;
                    return;
                }
                dyn++;
            }
        }
    }
}
```

---

## Remote Call Implementation

### RemoteCallBuilder (Vala)

```vala
private class RemoteCallBuilder : Object {
    private uint64 target_address;
    private Gee.ArrayList<Argument> arguments;
    private Gum.CpuContext saved_context;

    public RemoteCallBuilder(uint64 func_addr, Gum.CpuContext ctx) {
        this.target_address = func_addr;
        this.arguments = new Gee.ArrayList<Argument>();
        this.saved_context = ctx;
    }

    public RemoteCallBuilder add_argument(uint64 value) {
        arguments.add(new Argument.from_raw(value));
        return this;
    }

    public RemoteCallBuilder add_argument_indirect(uint64 ptr) {
        arguments.add(new Argument.from_pointer(ptr));
        return this;
    }

    public RemoteCall build(InjectSession session) {
        return new RemoteCall(session, target_address, arguments, saved_context);
    }
}
```

### x86_64 Calling Convention

```
Arguments: rdi, rsi, rdx, rcx, r8, r9 (first 6)
           Stack for 7th and beyond
Return:    rax
Stack:     16-byte aligned before CALL instruction
Red zone:  128 bytes below RSP (must be preserved)
```

### Register Setup (x86_64)

```vala
private void setup_registers_x64(Gum.CpuContext ctx, uint64 func, Argument[] args) {
    // Set instruction pointer
    ctx.rip = func;

    // Clear direction flag (DF must be 0 for ABI)
    ctx.eflags &= ~(1 << 10);

    // Set up argument registers
    switch (args.length) {
        default:  // 6+ arguments go on stack
        case 6: ctx.r9 = args[5].value;
        case 5: ctx.r8 = args[4].value;
        case 4: ctx.rcx = args[3].value;
        case 3: ctx.rdx = args[2].value;
        case 2: ctx.rsi = args[1].value;
        case 1: ctx.rdi = args[0].value;
        case 0: break;
    }
}
```

### DUMMY_RETURN_ADDRESS Technique

This is the core technique for detecting function completion:

```vala
private const uint64 DUMMY_RETURN_ADDRESS = 0x320;
private const size_t RED_ZONE_SIZE = 128;
private const size_t STACK_ALIGNMENT = 16;

private async uint64 execute_remote_call(uint64 func, Argument[] args) {
    var ctx = saved_context;

    // Step 1: Reserve red zone and align stack
    ctx.rsp -= RED_ZONE_SIZE;
    ctx.rsp &= ~(STACK_ALIGNMENT - 1);  // 16-byte align

    // Step 2: Push dummy return address
    ctx.rsp -= 8;
    yield session.write_memory(ctx.rsp, DUMMY_RETURN_ADDRESS.to_bytes());

    // Step 3: Set up registers for call
    setup_registers_x64(ctx, func, args);

    // Step 4: Execute
    yield session.set_registers(ctx);
    yield session.continue_execution();

    // Step 5: Wait for SIGSEGV at dummy address
    var status = yield session.wait_for_signal();

    if (status.signal == Signal.SIGSEGV) {
        var result_ctx = yield session.get_registers();
        if (result_ctx.rip == DUMMY_RETURN_ADDRESS) {
            return result_ctx.rax;  // Return value
        }
    }

    throw new Error.PROCESS_CRASHED("Unexpected signal");
}
```

### Preventing Syscall Restart

Frida clears the `orig_rax` register to prevent the kernel from restarting interrupted syscalls:

```vala
private void prevent_syscall_restart(ref Gum.CpuContext ctx) {
    // On x86_64, setting orig_rax to -1 prevents syscall restart
    ctx.orig_rax = -1;
}
```

### ARM64 Register Setup

```vala
private void setup_registers_arm64(Gum.CpuContext ctx, uint64 func, Argument[] args) {
    ctx.pc = func;

    // Arguments in x0-x7
    switch (args.length) {
        default:
        case 8: ctx.x[7] = args[7].value;
        case 7: ctx.x[6] = args[6].value;
        case 6: ctx.x[5] = args[5].value;
        case 5: ctx.x[4] = args[4].value;
        case 4: ctx.x[3] = args[3].value;
        case 3: ctx.x[2] = args[2].value;
        case 2: ctx.x[1] = args[1].value;
        case 1: ctx.x[0] = args[0].value;
        case 0: break;
    }

    // Set link register to dummy address
    ctx.lr = DUMMY_RETURN_ADDRESS;
}
```

---

## ELF Symbol Resolution

### frida_elf_enumerate_exports()

```c
void frida_elf_enumerate_exports(const ElfW(Ehdr) * ehdr,
    FridaFoundElfSymbolFunc callback, void * user_data)
{
    // Step 1: Locate PT_DYNAMIC segment
    ElfW(Phdr) * phdr = (void *)((char *)ehdr + ehdr->e_phoff);
    ElfW(Dyn) * dynamic = NULL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (void *)((char *)ehdr + phdr[i].p_vaddr);
            break;
        }
    }

    if (dynamic == NULL)
        return;

    // Step 2: Extract symbol table and string table
    ElfW(Sym) * symtab = NULL;
    char * strtab = NULL;
    size_t syment = sizeof(ElfW(Sym));
    ElfW(Word) * hash = NULL;

    for (ElfW(Dyn) * d = dynamic; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:
                symtab = (void *)((char *)ehdr + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (void *)((char *)ehdr + d->d_un.d_ptr);
                break;
            case DT_SYMENT:
                syment = d->d_un.d_val;
                break;
            case DT_HASH:
                hash = (void *)((char *)ehdr + d->d_un.d_ptr);
                break;
        }
    }

    // Step 3: Determine symbol count from hash table
    size_t num_symbols = 0;
    if (hash != NULL) {
        num_symbols = hash[1];  // nchain in ELF hash table
    }

    // Step 4: Iterate and filter symbols
    for (size_t i = 0; i < num_symbols; i++) {
        ElfW(Sym) * sym = &symtab[i];

        // Filter: must be defined, global/weak, and a function/object
        if (sym->st_shndx == SHN_UNDEF)
            continue;

        unsigned char bind = ELF_ST_BIND(sym->st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK)
            continue;

        unsigned char type = ELF_ST_TYPE(sym->st_info);
        if (type != STT_FUNC && type != STT_OBJECT)
            continue;

        // Build symbol info and invoke callback
        FridaElfSymbolInfo info = {
            .name = strtab + sym->st_name,
            .address = (void *)((char *)ehdr + sym->st_value),
            .size = sym->st_size,
            .type = type,
            .bind = bind,
        };

        if (!callback(&info, user_data))
            return;  // Callback requested stop
    }
}
```

### GNU Hash Support

Modern ELF files use GNU hash for faster lookups:

```c
static size_t frida_count_symbols_gnu_hash(ElfW(Word) * gnu_hash) {
    uint32_t nbuckets = gnu_hash[0];
    uint32_t symoffset = gnu_hash[1];
    uint32_t bloom_size = gnu_hash[2];
    // uint32_t bloom_shift = gnu_hash[3];

    uint64_t * bloom = (uint64_t *)&gnu_hash[4];
    uint32_t * buckets = (uint32_t *)&bloom[bloom_size];
    uint32_t * chain = &buckets[nbuckets];

    // Find the largest index in buckets
    uint32_t max_idx = 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] > max_idx)
            max_idx = buckets[i];
    }

    if (max_idx == 0)
        return symoffset;

    // Walk the chain to find the end
    while ((chain[max_idx - symoffset] & 1) == 0)
        max_idx++;

    return max_idx + 1;
}
```

### Finding Library Base Address

Frida parses `/proc/<pid>/maps` to find library base:

```c
static void * frida_find_library_base(pid_t pid, const char * name) {
    char maps_path[32];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE * fp = fopen(maps_path, "r");
    char line[512];

    void * base = NULL;

    while (fgets(line, sizeof(line), fp)) {
        // Parse: start-end perms offset dev inode pathname
        uint64_t start, end, offset;
        char perms[5], pathname[256];

        if (sscanf(line, "%lx-%lx %4s %lx %*s %*d %255s",
                   &start, &end, perms, &offset, pathname) >= 5) {

            if (strstr(pathname, name) && perms[2] == 'x') {
                // Found executable segment
                // Base = segment_start - file_offset
                base = (void *)(start - offset);
                break;
            }
        }
    }

    fclose(fp);
    return base;
}
```

### Symbol Offset Calculation

```c
// Example: Finding mmap in libc
//
// /proc/1234/maps shows:
// 7fe5fd2d1000-7fe5fd40f000 r-xp 00022000 /lib/libc.so.6
//                               ^^^^^^^^
//                               file offset
//
// base = 0x7fe5fd2d1000 - 0x22000 = 0x7fe5fd2af000
// symbol_addr = base + symbol_offset_from_elf
```

---

## Stage 2: Loader

### HelperLoaderContext Structure

The loader receives this context after bootstrap:

```c
typedef struct {
    // From bootstrapper
    FridaLibcApi * libc;

    // Agent information
    const char * agent_path;
    const char * agent_entrypoint;
    const char * agent_data;

    // Control channel
    int ctrlfd_rx;  // Receive commands
    int ctrlfd_tx;  // Send responses

    // Execution mode
    FridaLoaderMode mode;  // RELAUNCH or FROM_SCRATCH

    // Thread state
    pthread_t worker_thread;
    FridaAgentContext * agent_ctx;
} HelperLoaderContext;
```

### Loader Entry Point

```c
void frida_loader_main(HelperLoaderContext * ctx) {
    // Step 1: Load the agent library
    void * agent_handle = ctx->libc->dlopen(
        ctx->agent_path,
        RTLD_NOW | RTLD_GLOBAL
    );

    if (agent_handle == NULL) {
        char * error = ctx->libc->dlerror();
        frida_send_error(ctx, error);
        return;
    }

    // Step 2: Find the entrypoint
    FridaAgentEntrypoint entrypoint = ctx->libc->dlsym(
        agent_handle,
        ctx->agent_entrypoint
    );

    if (entrypoint == NULL) {
        frida_send_error(ctx, "Entrypoint not found");
        ctx->libc->dlclose(agent_handle);
        return;
    }

    // Step 3: Create worker thread
    int result = ctx->libc->pthread_create(
        &ctx->worker_thread,
        NULL,
        (void *(*)(void *))frida_agent_worker,
        ctx
    );

    if (result != 0) {
        frida_send_error(ctx, "Failed to create thread");
        return;
    }

    // Step 4: Detach thread (runs independently)
    ctx->libc->pthread_detach(ctx->worker_thread);

    // Step 5: Notify success
    frida_send_success(ctx, agent_handle);
}
```

### Control FD Communication Protocol

The loader communicates with the injector via socketpair:

```c
// Message format
typedef struct {
    uint8_t type;
    uint32_t length;
    uint8_t payload[];
} FridaMessage;

// Message types
enum {
    FRIDA_MSG_ACK = 1,
    FRIDA_MSG_ERROR = 2,
    FRIDA_MSG_LOAD = 3,
    FRIDA_MSG_UNLOAD = 4,
};

static void frida_send_success(HelperLoaderContext * ctx, void * handle) {
    FridaMessage msg = {
        .type = FRIDA_MSG_ACK,
        .length = sizeof(void *),
    };
    ctx->libc->write(ctx->ctrlfd_tx, &msg, sizeof(msg));
    ctx->libc->write(ctx->ctrlfd_tx, &handle, sizeof(handle));
}

static void frida_send_error(HelperLoaderContext * ctx, const char * error) {
    size_t len = strlen(error);
    FridaMessage msg = {
        .type = FRIDA_MSG_ERROR,
        .length = len,
    };
    ctx->libc->write(ctx->ctrlfd_tx, &msg, sizeof(msg));
    ctx->libc->write(ctx->ctrlfd_tx, error, len);
}
```

### Loader Modes

```c
typedef enum {
    // RELAUNCH: Loader was already loaded, just reinitialize
    FRIDA_LOADER_MODE_RELAUNCH,

    // FROM_SCRATCH: First time loading, full initialization
    FRIDA_LOADER_MODE_FROM_SCRATCH,
} FridaLoaderMode;

void frida_loader_main(HelperLoaderContext * ctx) {
    if (ctx->mode == FRIDA_LOADER_MODE_RELAUNCH) {
        // Agent already loaded, just reconnect
        frida_reconnect_agent(ctx);
    } else {
        // Full loading sequence
        frida_load_agent_from_scratch(ctx);
    }
}
```

### Agent Worker Thread

```c
static void * frida_agent_worker(void * data) {
    HelperLoaderContext * ctx = data;

    // Block signals in worker thread
    sigset_t mask;
    sigfillset(&mask);
    ctx->libc->sigprocmask(SIG_BLOCK, &mask, NULL);

    // Create agent context
    ctx->agent_ctx = frida_agent_context_new(
        ctx->ctrlfd_rx,
        ctx->ctrlfd_tx
    );

    // Call the agent entrypoint
    FridaAgentEntrypoint entry = ctx->libc->dlsym(
        ctx->agent_handle,
        ctx->agent_entrypoint
    );

    entry(ctx->agent_ctx, ctx->agent_data);

    // Cleanup
    frida_agent_context_free(ctx->agent_ctx);

    return NULL;
}
```

---

## Memory Layout

After complete injection, memory is organized as:

```
┌────────────────────────────────────┐  ← allocation_base (from bootstrap mmap)
│     Loader Code Section            │  (page-aligned, RX)
│     - frida_loader_main            │
│     - frida_agent_worker           │
│     - Message handling code        │
├────────────────────────────────────┤
│     Data Section                   │  (RW)
│     - HelperLoaderContext          │
│     - FridaLibcApi pointers        │
│     - Agent path string            │
│     - Entrypoint name              │
│     - Init data                    │
├────────────────────────────────────┤
│     Stack (64KB)                   │
│     (grows downward)               │
│     - Used by loader               │
│     - Used by worker thread        │
└────────────────────────────────────┘
```

---

## Memory Access Methods

### 1. process_vm_readv/writev (Preferred)

```c
ssize_t frida_read_memory(pid_t pid, void * addr, void * buf, size_t size) {
    struct iovec local  = { .iov_base = buf, .iov_len = size };
    struct iovec remote = { .iov_base = addr, .iov_len = size };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

ssize_t frida_write_memory(pid_t pid, void * addr, void * buf, size_t size) {
    struct iovec local  = { .iov_base = buf, .iov_len = size };
    struct iovec remote = { .iov_base = addr, .iov_len = size };
    return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}
```

Efficient bulk transfer, available since Linux 3.2.

### 2. ptrace PEEKDATA/POKEDATA (Fallback)

```c
int frida_read_memory_ptrace(pid_t pid, void * addr, void * buf, size_t size) {
    size_t offset = 0;

    while (offset < size) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
        if (errno != 0)
            return -1;

        size_t remaining = size - offset;
        size_t to_copy = (remaining < sizeof(long)) ? remaining : sizeof(long);
        memcpy(buf + offset, &word, to_copy);
        offset += sizeof(long);
    }

    return 0;
}
```

Slower but universally available.

---

## Process Attachment

### PTRACE_SEIZE vs PTRACE_ATTACH

```c
static int frida_seize_process(pid_t tid) {
    // Try SEIZE first (Linux 3.4+, non-stop mode)
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK;

    if (ptrace(PTRACE_SEIZE, tid, NULL, options) == 0) {
        // SEIZE succeeded, now interrupt the process
        ptrace(PTRACE_INTERRUPT, tid, NULL, NULL);
        return 0;
    }

    // Fallback to ATTACH (sends SIGSTOP)
    if (ptrace(PTRACE_ATTACH, tid) == 0) {
        return 0;
    }

    return -1;
}
```

### Multi-Thread Handling

```c
static int frida_suspend_all_threads(pid_t pid, FridaThreadList * threads) {
    char task_path[32];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

    DIR * dir = opendir(task_path);
    struct dirent * entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        pid_t tid = atoi(entry->d_name);

        if (ptrace(PTRACE_ATTACH, tid) == 0) {
            int status;
            waitpid(tid, &status, 0);
            frida_thread_list_add(threads, tid);
        }
    }

    closedir(dir);
    return threads->count;
}
```

---

## Error Handling

### Bootstrap Status Codes

| Status | Meaning |
|--------|---------|
| SUCCESS | Bootstrap completed successfully |
| ALLOCATION_ERROR | mmap failed |
| LIBC_UNSUPPORTED | Unknown libc flavor |
| AUXV_NOT_FOUND | Cannot parse /proc/self/auxv |
| TOO_EARLY | libc not yet loaded in process |
| RDEBUG_NOT_FOUND | Cannot find r_debug structure |

### Runtime Detection

Frida detects the C library flavor:

| Flavor | Detection Pattern | Special Handling |
|--------|------------------|------------------|
| GLIBC | libc.so.6, libc-2.*.so | Standard resolution |
| MUSL | musl, ld-musl | Different symbol names |
| UCLIBC | uclibc | Embedded systems |
| ANDROID | /system/lib/libc.so | Bionic quirks |

---

## Architecture Support

| Architecture | Argument Registers | Return Reg | Special Handling |
|--------------|-------------------|------------|------------------|
| x86_64 | rdi, rsi, rdx, rcx, r8, r9 | rax | Red zone (128 bytes) |
| ARM64 | x0-x7 | x0 | Frame pointer in x29 |
| ARM | r0-r3 | r0 | Thumb mode (LSB of PC) |
| MIPS | a0-a3 | v0 | t9 for function pointer |
| x86 | Stack-based | eax | - |

---

## Key Differences from hsinject

| Feature | Frida | hsinject |
|---------|-------|----------|
| Bootstrap | Two-stage with code swap | Direct mmap syscall |
| Symbol resolution | Full export enumeration | Direct symbol lookup |
| Agent loading | Custom loader with threads | Simple dlopen |
| Communication | Unix socket channel | None (return value only) |
| libc detection | Auto-detect flavor | Assumes glibc |
| Platform support | Linux, macOS, Windows, iOS, Android | Linux x86_64 only |
| Thread handling | Full multi-thread support | Basic thread stop |

---

## Code Swap Technique

Frida uses `ProcessCodeSwapScope` for temporary code injection:

```vala
class ProcessCodeSwapScope {
    private uint64 address;
    private uint8[] original_code;

    public ProcessCodeSwapScope(InjectSession session, uint64 addr, uint8[] code) {
        this.address = addr;

        // Save original code
        this.original_code = session.read_memory(addr, code.length);

        // Write new code
        session.write_memory(addr, code);
    }

    public void restore() {
        session.write_memory(address, original_code);
    }
}
```

This allows Frida to temporarily replace code at any location, execute it, and restore the original code without allocating new memory.

---

## References

- frida-core/src/linux/frida-helper-backend.vala
- frida-core/src/linux/helpers/bootstrapper.c
- frida-core/src/linux/helpers/elf-parser.c
- frida-core/src/linux/helpers/inject-glue.c
- frida-core/lib/inject/inject.vala
