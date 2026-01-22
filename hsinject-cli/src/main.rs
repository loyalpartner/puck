use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

use hsinject::{inject, InjectOptions, Payload};

#[derive(Parser)]
#[command(name = "hsinject")]
#[command(about = "Inject shared libraries or shellcode into running processes")]
#[command(version)]
struct Cli {
    /// Target process ID
    #[arg(short, long)]
    pid: i32,

    /// Path to shared library (.so) to inject
    #[arg(short, long, group = "payload")]
    library: Option<PathBuf>,

    /// Path to raw shellcode file to inject
    #[arg(short, long, group = "payload")]
    shellcode: Option<PathBuf>,

    /// Entry point function name (for library injection)
    #[arg(short, long)]
    entry: Option<String>,

    /// Argument to pass to entry point function
    #[arg(short, long)]
    arg: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let payload = match (&cli.library, &cli.shellcode) {
        (Some(lib), None) => {
            if cli.verbose {
                eprintln!("[*] Loading library: {}", lib.display());
            }
            Payload::Library(lib.clone())
        }
        (None, Some(sc)) => {
            let data = std::fs::read(sc)
                .with_context(|| format!("failed to read shellcode file: {}", sc.display()))?;
            if cli.verbose {
                eprintln!("[*] Loading shellcode: {} ({} bytes)", sc.display(), data.len());
            }
            Payload::Shellcode(data)
        }
        (Some(_), Some(_)) => {
            bail!("cannot specify both --library and --shellcode");
        }
        (None, None) => {
            bail!("must specify either --library or --shellcode");
        }
    };

    let options = InjectOptions {
        entry_point: cli.entry.clone(),
        argument: cli.arg.clone(),
    };

    if cli.verbose {
        eprintln!("[*] Target PID: {}", cli.pid);
        if let Some(ref ep) = options.entry_point {
            eprintln!("[*] Entry point: {}", ep);
        }
        if let Some(ref arg) = options.argument {
            eprintln!("[*] Argument: {}", arg);
        }
        eprintln!("[*] Attaching to process...");
    }

    let result = inject(cli.pid, payload, options)
        .with_context(|| format!("failed to inject into process {}", cli.pid))?;

    if cli.verbose {
        eprintln!("[+] Injection successful!");
        eprintln!("    PID: {}", result.pid);
        if result.handle != 0 {
            eprintln!("    Handle: 0x{:x}", result.handle);
        }
        if result.retval != 0 {
            eprintln!("    Return value: 0x{:x}", result.retval);
        }
    } else {
        println!("0x{:x}", result.handle);
    }

    Ok(())
}
