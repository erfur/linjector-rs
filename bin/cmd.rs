use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// pid of the target process
    #[arg(short, long)]
    pid: i32,

    /// path of the library to inject
    #[arg(short, long)]
    lib_path: String,

    /// logcat mode
    #[arg(short, long)]
    logcat: bool,
}

fn main() {
    let args = Args::parse();

    linjector_rs::inject_code_to_pid(args.pid, args.lib_path);
}