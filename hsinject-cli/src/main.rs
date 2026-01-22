use clap::Parser;

#[derive(Parser)]
#[command(name = "hsinject")]
#[command(about = "Inject shared libraries or shellcode into running processes")]
struct Cli {
    /// Target process ID
    #[arg(short, long)]
    pid: i32,
}

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();
    println!("hsinject stub");
    Ok(())
}
