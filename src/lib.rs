use std::collections::HashMap;

mod remote_mem;
mod remote_module;
mod remote_proc;
mod shellcode;
pub mod utils;

#[macro_use]
extern crate log;
extern crate android_logger;

#[derive(Debug)]
pub enum InjectionError {
    RemoteProcessError,
    RemoteMemoryError,
    RemoteModuleError,
    ModuleNotFound,
    SymbolNotFound,
    FileError,
    CommandError,
    ShellcodeError,
}

pub struct Injector {
    pub pid: i32,
    remote_proc: remote_proc::RemoteProc,
    pub file_path: String,
    modules: HashMap<String, remote_module::RemoteModule>,
    pub syms: HashMap<String, usize>,
}

impl Injector {
    pub fn new(pid: i32) -> Result<Injector, InjectionError> {
        let remote_proc = remote_proc::RemoteProc::new(pid)?;
        let file_path = String::new();
        let modules = HashMap::new();
        let syms = HashMap::new();

        Ok(Injector {
            pid,
            remote_proc,
            file_path,
            modules,
            syms,
        })
    }

    pub fn set_file_path(&mut self, file_path: String) -> Result<&mut Self, InjectionError> {
        // check if the file exists in the filesystem
        let file = std::fs::File::open(&file_path);
        if file.is_err() {
            error!("File not found: {}", file_path);
            return Err(InjectionError::FileError);
        }

        self.file_path = file_path;
        Ok(self)
    }

    fn prepare_file(&self) -> Result<String, InjectionError> {
        let file_path = utils::move_file_to_tmp(self.file_path.as_str())?;
        utils::fix_file_context(file_path.as_str())?;
        utils::fix_file_permissions(file_path.as_str())?;
        utils::print_file_hexdump(file_path.as_str())?;
        Ok(file_path)
    }

    pub fn set_func_sym(&mut self, module_name: &str, sym_name: &str) -> Result<&mut Self, InjectionError> {
        let module = self.remote_proc.get_module(module_name)?;
        let sym = module.dlsym_from_fs(sym_name)?;
        self.modules.insert(module_name.to_string(), module);
        self.syms.insert(sym_name.to_string(), sym);
        Ok(self)
    }

    pub fn set_var_sym(&mut self, module_name: &str, sym_name: &str) -> Result<&mut Self, InjectionError> {
        let module = self.remote_proc.get_module(module_name)?;
        let sym = module.dlsym_from_fs(sym_name)?;
        self.modules.insert(module_name.to_string(), module);
        self.syms.insert(sym_name.to_string(), sym);
        Ok(self)
    }

    pub fn inject_code(&self) -> Result<(), InjectionError> {
        let file_path = self.prepare_file()?;
        inject_code_to_pid(self.pid, file_path);
        Ok(())
    }
}

pub fn inject_code_to_pid(pid: i32, file_path: String) {
    let proc = remote_proc::RemoteProc::new(pid).unwrap();
    let libc = proc.get_module("libc.so").unwrap();
    let libdl = proc.get_module("libdl.so").unwrap();
    // let liblasso = proc.get_module("liblasso.so");

    debug!("{}, 0x{:x}", &libc.name, &libc.vm_addr);
    debug!("{}, 0x{:x}", &libdl.name, &libdl.vm_addr);

    let timezone_sym = libc.dlsym_from_fs("timezone").unwrap();
    let malloc_sym = libc.dlsym_from_fs("malloc").unwrap();
    // let timezone_sym = liblasso.dlsym_from_fs("test_var");
    // let malloc_sym = liblasso.dlsym_from_fs("Java_com_github_erfur_lasso_MainActivity_testFunction");
    let dlopen_sym = libdl.dlsym_from_fs("dlopen").unwrap();
    let sprintf_sym = libc.dlsym_from_fs("sprintf").unwrap();

    debug!("timezone_sym: 0x{:x}", timezone_sym);
    debug!("malloc_sym:   0x{:x}", malloc_sym);
    debug!("dlopen_sym:   0x{:x}", dlopen_sym);
    debug!("sprintf_sym:  0x{:x}", sprintf_sym);

    let second_stage = shellcode::raw_dlopen_shellcode(
        dlopen_sym,
        file_path,
        malloc_sym,
    ).unwrap();

    let first_stage = shellcode::main_shellcode(timezone_sym, second_stage.len()).unwrap();

    let malloc_original_bytes = proc.rm.read_mem(malloc_sym, first_stage.len()).unwrap();
    let timezone_original_bytes = proc.rm.read_mem(timezone_sym, 0x8).unwrap();

    info!("write first stage shellcode");
    proc.rm.write_mem(timezone_sym, &vec![0x0; 0x8]).unwrap();
    proc.rm.write_mem(malloc_sym, &first_stage).unwrap();

    info!("wait for shellcode to trigger");
    let mut new_map: u64;
    loop {
        let data = proc.rm.read_mem(timezone_sym, 0x8).unwrap();
        // u64 from val
        new_map = u64::from_le_bytes(data[0..8].try_into().unwrap());
        if (new_map & 0x1 != 0) && (new_map & 0xffff_ffff_ffff_fff0 != 0) {
            break;
        }
    }

    new_map &= 0xffff_ffff_ffff_fff0;
    info!("new map: 0x{:x}", new_map);

    info!("overwrite malloc with loop");
    proc.rm.write_mem(malloc_sym, &shellcode::self_jmp().unwrap()).unwrap();

    // wait for 100ms
    std::thread::sleep(std::time::Duration::from_millis(100));

    info!("restore original bytes");
    proc.rm.write_code(malloc_sym, &malloc_original_bytes, 1).unwrap();
    proc.rm.write_mem(timezone_sym, &timezone_original_bytes).unwrap();

    info!("overwrite new map");
    proc.rm.write_code(new_map as usize, &second_stage, 1).unwrap();

    info!("injectCode done.");
}
