use clap::Parser;

/// Inject code into a running process using /proc/mem
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// pid of the target process
    #[arg(short, long)]
    pid: i32,

    /// path of the library/shellcode to inject
    #[arg(short, long)]
    file: String,

    /// type of injection
    #[arg(short, long)]
    injection_type: Option<String>,

    /// function to hijack for injection,
    /// in the form "lib.so!symbol_name"
    #[arg(long)]
    func_sym: Option<String>,

    /// variable to hijack for injection,
    /// in the form "lib.so!symbol_name"
    #[arg(long)]
    var_sym: Option<String>,

    /// print logs to logcat (TODO)
    #[arg(long)]
    logcat: bool,
}

fn main() -> Result<(), linjector_rs::InjectionError> {
    let args = Args::parse();

    let mut injector = linjector_rs::Injector::new(args.pid)?;
    injector.set_file_path(args.file)?;

    match args.injection_type.as_deref() {
        Some("raw_dlopen") => {
            injector.use_raw_dlopen()?;
        }
        Some("memfd_dlopen") => {
            injector.use_memfd_dlopen()?;
        }
        Some("raw_shellcode") => {
            injector.use_raw_shellcode()?;
        }
        _ => {
            eprintln!("Invalid injection type");
            std::process::exit(1);
        }
    }

    if let Some(func_sym) = &args.func_sym {
        let sym_pair: Vec<&str> = func_sym.split('!').collect();
        if sym_pair.len() != 2 {
            eprintln!("Invalid function symbol format, use lib.so!symbol_name");
            std::process::exit(1);
        }
        injector.set_func_sym(sym_pair[0], sym_pair[1])?;
    }

    if let Some(var_sym) = &args.var_sym {
        let sym_pair: Vec<&str> = var_sym.split('!').collect();
        if sym_pair.len() != 2 {
            eprintln!("Invalid variable symbol format, use lib.so!symbol_name");
            std::process::exit(1);
        }
        injector.set_var_sym(sym_pair[0], sym_pair[1])?;
    }

    // if either func_sym or var_sym is not provided, use default symbols
    if args.func_sym.is_none() || args.var_sym.is_none() {
        injector.set_default_syms()?;
    }

    injector.inject()?;

    Ok(())
}
