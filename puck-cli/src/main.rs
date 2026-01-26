//! CLI for library injection with optional function call

use std::path::PathBuf;

fn print_usage(prog: &str) {
    eprintln!("Usage: {} [OPTIONS] <pid>", prog);
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -l, --library <path>     Shared library to inject (required for LOAD mode)");
    eprintln!("  -c, --call <pattern>     Call function in already-loaded library (CALL mode)");
    eprintln!("  -f, --function <name>    Function to call after injection");
    eprintln!("  -d, --data <string>      String data to pass to the function");
    eprintln!("  -a, --args <arg>...      Numeric arguments for the function");
    eprintln!("  -h, --help               Show this help");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} -l ./payload.so -f entry 1234", prog);
    eprintln!("  {} -l ./payload.so -f init -d \"config\" 1234", prog);
    eprintln!("  {} -c libpayload.so -f unload 1234", prog);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = &args[0];

    let mut library: Option<PathBuf> = None;
    let mut call_pattern: Option<String> = None;  // For CALL mode
    let mut function: Option<String> = None;
    let mut data: Option<String> = None;
    let mut func_args: Vec<u64> = Vec::new();
    let mut pid: Option<i32> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage(prog);
                std::process::exit(0);
            }
            "-l" | "--library" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -l requires an argument");
                    std::process::exit(1);
                }
                library = Some(PathBuf::from(&args[i]));
            }
            "-c" | "--call" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -c requires an argument");
                    std::process::exit(1);
                }
                call_pattern = Some(args[i].clone());
            }
            "-f" | "--function" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -f requires an argument");
                    std::process::exit(1);
                }
                function = Some(args[i].clone());
            }
            "-d" | "--data" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -d requires an argument");
                    std::process::exit(1);
                }
                data = Some(args[i].clone());
            }
            "-a" | "--args" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -a requires an argument");
                    std::process::exit(1);
                }
                let arg = &args[i];
                let val = if arg.starts_with("0x") || arg.starts_with("0X") {
                    u64::from_str_radix(&arg[2..], 16).expect("Invalid hex argument")
                } else {
                    arg.parse().expect("Invalid numeric argument")
                };
                func_args.push(val);
            }
            arg if arg.starts_with('-') => {
                eprintln!("Error: Unknown option: {}", arg);
                print_usage(prog);
                std::process::exit(1);
            }
            _ => {
                // Positional argument: PID
                if pid.is_some() {
                    eprintln!("Error: Multiple PIDs specified");
                    std::process::exit(1);
                }
                pid = Some(args[i].parse().expect("Invalid PID"));
            }
        }
        i += 1;
    }

    // Validate required arguments
    let pid = match pid {
        Some(p) => p,
        None => {
            eprintln!("Error: PID is required");
            print_usage(prog);
            std::process::exit(1);
        }
    };

    // Handle CALL mode (call function in already-loaded library)
    if let Some(pattern) = call_pattern {
        let func_name = match function {
            Some(f) => f,
            None => {
                eprintln!("Error: -f/--function is required for CALL mode");
                std::process::exit(1);
            }
        };

        println!("Calling {}() in library matching '{}' in process {}",
                 func_name, pattern, pid);

        match puck::call_in_loaded_library(pid, &pattern, &func_name, data.as_deref()) {
            Ok(()) => {
                println!("Success!");
                println!("  {}() started in new thread", func_name);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // LOAD mode: require library path
    let library = match library {
        Some(l) => l,
        None => {
            eprintln!("Error: -l/--library or -c/--call is required");
            print_usage(prog);
            std::process::exit(1);
        }
    };

    // If -d is provided without -f, use a default function name "entry"
    if data.is_some() && function.is_none() {
        function = Some("entry".to_string());
    }

    // Require function name for LOAD mode
    let func_name = match function {
        Some(f) => f,
        None => {
            eprintln!("Error: -f/--function is required");
            print_usage(prog);
            std::process::exit(1);
        }
    };

    // Execute based on what was provided
    if let Some(data_str) = data {
        // Inject and call function with string data
        println!("Injecting {} into process {} and calling {}(\"{}\")",
                 library.display(), pid, func_name, data_str);

        match inject_with_string_arg(pid, &library, &func_name, &data_str) {
            Ok(result) => {
                println!("Success!");
                println!("  handle = 0x{:x}", result.handle);
                println!("  {}() started in new thread", func_name);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Inject and call function with no args or numeric args
        println!("Injecting {} into process {} and calling {}()",
                 library.display(), pid, func_name);

        match puck::inject_and_call(pid, &library, &func_name, &func_args) {
            Ok(result) => {
                println!("Success!");
                println!("  handle = 0x{:x}", result.handle);
                println!("  {}() started in new thread", func_name);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

/// Inject library and call a function with a string argument
fn inject_with_string_arg(
    pid: i32,
    library_path: &std::path::Path,
    function_name: &str,
    data: &str,
) -> Result<puck::InjectionCallResult, puck::Error> {
    puck::inject_and_call_with_string(pid, library_path, function_name, data)
}
