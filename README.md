# hsinject

A Rust library for Linux process injection, inspired by Frida's injection mechanism.

## Features

- **Library injection**: Inject shared libraries (.so) into running processes
- **Shellcode injection**: Inject raw shellcode
- **Entry point support**: Call a specific function after injection
- **x86_64 support**: Currently supports x86_64 architecture

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hsinject = { git = "https://github.com/user/hsinject" }
```

## Usage

### As a library

```rust
use hsinject::{inject, Payload, InjectOptions};

// Simple library injection
let result = inject(
    1234,
    Payload::Library("/path/to/hook.so".into()),
    InjectOptions::default(),
)?;

// With entry point
let result = inject(
    1234,
    Payload::Library("/path/to/hook.so".into()),
    InjectOptions {
        entry_point: Some("my_init".into()),
        argument: Some("config=debug".into()),
    },
)?;

println!("Injected! handle=0x{:x}", result.handle);
```

### As a CLI tool

```bash
# Inject a shared library
sudo hsinject -p 1234 -l ./libhook.so

# With entry point and argument
sudo hsinject -p 1234 -l ./libhook.so -e my_init -a "config=debug"

# Inject shellcode
sudo hsinject -p 1234 -s ./payload.bin

# Verbose output
sudo hsinject -p 1234 -l ./libhook.so -v
```

## Building

```bash
# Build all
cargo build --release

# Build with musl
cargo build --release --target x86_64-unknown-linux-musl

# Run tests (requires root)
sudo cargo test -- --ignored
```

## Architecture Support

- [x] x86_64
- [ ] aarch64
- [ ] arm
- [ ] x86

## License

MIT
