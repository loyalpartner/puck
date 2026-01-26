# Puck

A Rust library for Linux process injection, inspired by Frida's injection mechanism.

## Features

- **Library injection**: Inject shared libraries (.so) into running processes
- **Function calling**: Call a specific function after injection
- **Multi-arch**: Supports x86_64 and aarch64 architectures

## Usage

### As a CLI tool

```bash
# Inject a shared library and call entry()
sudo puck -l ./libhook.so -f entry <pid>

# With string argument
sudo puck -l ./libhook.so -f my_init -d "config=debug" <pid>

# Call function in already-loaded library
sudo puck -c libc.so.6 -f puts -d "hello" <pid>
```

### As a library

```rust
use puck::inject_and_call;

// Inject library and call function
inject_and_call(pid, "/path/to/hook.so", "entry", None)?;

// With string argument
inject_and_call_with_string(pid, "/path/to/hook.so", "my_init", "config=debug")?;
```

## Building

```bash
# Build
make build

# Build for aarch64
make build-aarch64

# Run tests (QEMU)
make test-x86_64
make test-aarch64
```

## Architecture Support

- [x] x86_64
- [x] aarch64

## License

MIT
