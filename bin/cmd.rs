use android_logger::Config;
use clap::{Parser, ValueEnum};
use log::{error, info, warn, LevelFilter};
use simple_logger::SimpleLogger;

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
    #[arg(short, long, value_enum, default_value_t = InjectionType::RawDlopen)]
    injection_type: InjectionType,

    /// function to hijack for injection,
    /// in the form "lib.so!symbol_name"
    #[arg(long)]
    func_sym: Option<String>,

    /// variable to hijack for injection,
    /// in the form "lib.so!symbol_name"
    #[arg(long)]
    var_sym: Option<String>,

    /// enable debug logs
    #[arg(short, long)]
    debug: bool,

    /// print logs to logcat (TODO)
    #[arg(long)]
    logcat: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum InjectionType {
    /// Use dlopen to inject a library
    RawDlopen,
    /// Use memfd_create and dlopen to inject a library
    MemfdDlopen,
    /// Inject raw shellcode
    RawShellcode,
}

fn main() {
    let args = Args::parse();

    if args.logcat {
        if args.debug {
            android_logger::init_once(Config::default().with_max_level(LevelFilter::Debug));
        } else {
            android_logger::init_once(Config::default().with_max_level(LevelFilter::Info));
        }
    } else {
        if args.debug {
            SimpleLogger::new()
                .with_level(LevelFilter::Debug)
                .init()
                .unwrap();
        } else {
            SimpleLogger::new()
                .with_level(LevelFilter::Info)
                .init()
                .unwrap();
        }
    }

    let mut injector = match linjector_rs::Injector::new(args.pid) {
        Ok(injector) => injector,
        Err(e) => {
            error!("Error creating injector: {:?}", e);
            std::process::exit(1);
        }
    };

    match injector.set_file_path(args.file) {
        Ok(_) => {}
        Err(e) => {
            error!("Error setting file path: {:?}", e);
            std::process::exit(1);
        }
    }

    match args.injection_type {
        InjectionType::RawDlopen => {
            injector.use_raw_dlopen().unwrap();
        }
        InjectionType::MemfdDlopen => {
            injector.use_memfd_dlopen().unwrap();
        }
        InjectionType::RawShellcode => {
            injector.use_raw_shellcode().unwrap();
        }
    }

    if let Some(func_sym) = &args.func_sym {
        let sym_pair: Vec<&str> = func_sym.split('!').collect();
        if sym_pair.len() != 2 {
            error!("Invalid function symbol format, use lib.so!symbol_name");
            std::process::exit(1);
        }
        match injector.set_func_sym(sym_pair[0], sym_pair[1]) {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting function symbol: {:?}", e);
                std::process::exit(1);
            }
        };
    }

    if let Some(var_sym) = &args.var_sym {
        let sym_pair: Vec<&str> = var_sym.split('!').collect();
        if sym_pair.len() != 2 {
            error!("Invalid variable symbol format, use lib.so!symbol_name");
            std::process::exit(1);
        }
        match injector.set_var_sym(sym_pair[0], sym_pair[1]) {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting variable symbol: {:?}", e);
                std::process::exit(1);
            }
        };
    }

    // if either func_sym or var_sym is not provided, use default symbols
    if args.func_sym.is_none() || args.var_sym.is_none() {
        warn!("function or variable symbol not specified, using defaults");
        match injector.set_default_syms() {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting default symbols: {:?}", e);
                std::process::exit(1);
            }
        };
    }

    match injector.inject() {
        Ok(_) => {
            info!("injection successful");
        }
        Err(e) => {
            error!("Error injecting: {:?}", e);
            std::process::exit(1);
        }
    }
}
