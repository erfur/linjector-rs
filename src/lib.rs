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
    target_func_sym_name: String,
    target_func_sym_addr: usize,
    target_var_sym_name: String,
    target_var_sym_addr: usize,
    injection_type: InjectionType,
}

enum InjectionType {
    RawDlopen,
    MemFdDlopen,
    RawShellcode,
}

impl Injector {
    pub fn new(pid: i32) -> Result<Injector, InjectionError> {
        Ok(Injector {
            pid,
            remote_proc: remote_proc::RemoteProc::new(pid)?,
            file_path: String::new(),
            modules: HashMap::new(),
            syms: HashMap::new(),
            target_func_sym_name: String::new(),
            target_func_sym_addr: 0,
            target_var_sym_name: String::new(),
            target_var_sym_addr: 0,
            injection_type: InjectionType::RawDlopen,
        })
    }

    pub fn set_file_path(&mut self, file_path: String) -> Result<&mut Self, InjectionError> {
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

    fn add_sym(&mut self, module_name: &str, sym_name: &str) -> Result<usize, InjectionError> {
        debug!("add_sym: {}!{}", module_name, sym_name);

        if !self.modules.contains_key(module_name) {
            let module = self.remote_proc.get_module(module_name)?;
            self.modules.insert(module_name.to_string(), module);
        }

        let module = self.modules.get(module_name).unwrap();
        debug!("add_sym: {} 0x{:x}", module_name, module.vm_addr);

        if !self.syms.contains_key(sym_name) {
            let sym = module.dlsym_from_fs(sym_name)?;
            self.syms.insert(sym_name.to_string(), sym);
        }

        debug!(
            "add_sym: {} 0x{:x}",
            sym_name,
            self.syms.get(sym_name).unwrap()
        );
        Ok(*self.syms.get(sym_name).unwrap())
    }

    pub fn set_func_sym(
        &mut self,
        module_name: &str,
        sym_name: &str,
    ) -> Result<&mut Self, InjectionError> {
        let sym_addr = self.add_sym(module_name, sym_name)?;
        self.target_func_sym_name = sym_name.to_string();
        debug!("set_func_sym: {} 0x{:x}", sym_name, sym_addr);
        Ok(self)
    }

    pub fn set_var_sym(
        &mut self,
        module_name: &str,
        sym_name: &str,
    ) -> Result<&mut Self, InjectionError> {
        let sym_addr = self.add_sym(module_name, sym_name)?;
        self.target_var_sym_name = sym_name.to_string();
        debug!("set_var_sym: {} 0x{:x}", sym_name, sym_addr);
        Ok(self)
    }

    pub fn set_default_syms(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym("libc.so", "malloc")?;
        self.set_var_sym("libc.so", "timezone")?;
        Ok(self)
    }

    pub fn set_test_syms(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym(
            "liblasso.so",
            "Java_com_github_erfur_lasso_MainActivity_testFunction",
        )?;
        self.set_var_sym("liblasso.so", "test_var")?;
        Ok(self)
    }

    fn set_dlopen_syms(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym("libdl.so", "dlopen")?;
        Ok(self)
    }

    fn set_sprintf_syms(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym("libc.so", "sprintf")?;
        Ok(self)
    }

    pub fn use_raw_dlopen(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_dlopen_syms()?;
        self.injection_type = InjectionType::RawDlopen;
        Ok(self)
    }

    pub fn use_memfd_dlopen(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_dlopen_syms()?;
        self.set_sprintf_syms()?;
        self.injection_type = InjectionType::MemFdDlopen;
        Ok(self)
    }

    pub fn use_raw_shellcode(&mut self) -> Result<&mut Self, InjectionError> {
        self.injection_type = InjectionType::RawShellcode;
        Ok(self)
    }

    pub fn inject(&mut self) -> Result<(), InjectionError> {
        let file_path = self.prepare_file()?;
        let proc = remote_proc::RemoteProc::new(self.pid)?;

        if self.target_func_sym_name.is_empty() || self.target_var_sym_name.is_empty() {
            warn!("target_func_sym or target_var_sym is empty, using defaults");
            self.set_default_syms()?;
        }

        info!("build second stage shellcode");
        let second_stage: Vec<u8>;
        match self.injection_type {
            InjectionType::RawDlopen => {
                second_stage = shellcode::raw_dlopen_shellcode(
                    *self.syms.get("dlopen").unwrap(),
                    file_path,
                    *self.syms.get("malloc").unwrap(),
                )
                .unwrap();
            }
            InjectionType::MemFdDlopen => {
                second_stage = shellcode::memfd_dlopen_shellcode(
                    *self.syms.get("dlopen").unwrap(),
                    *self.syms.get("malloc").unwrap(),
                    &std::fs::read(file_path.as_str()).unwrap(),
                    *self.syms.get("sprintf").unwrap(),
                )
                .unwrap();
            }
            InjectionType::RawShellcode => {
                second_stage = shellcode::raw_shellcode().unwrap();
            }
        }

        info!("build first stage shellcode");
        let first_stage =
            shellcode::main_shellcode(self.target_var_sym_addr, second_stage.len()).unwrap();

        info!("read original bytes");
        let func_original_bytes = proc
            .rm
            .read_mem(self.target_func_sym_addr, first_stage.len())
            .unwrap();
        let var_original_bytes = proc.rm.read_mem(self.target_var_sym_addr, 0x8).unwrap();

        info!("write first stage shellcode");
        proc.rm
            .write_mem(self.target_var_sym_addr, &vec![0x0; 0x8])
            .unwrap();
        proc.rm
            .write_mem(self.target_func_sym_addr, &first_stage)
            .unwrap();

        info!("wait for shellcode to trigger");
        let mut new_map: u64;
        loop {
            let data = proc.rm.read_mem(self.target_var_sym_addr, 0x8).unwrap();
            // u64 from val
            new_map = u64::from_le_bytes(data[0..8].try_into().unwrap());
            if (new_map & 0x1 != 0) && (new_map & 0xffff_ffff_ffff_fff0 != 0) {
                break;
            }
        }

        new_map &= 0xffff_ffff_ffff_fff0;
        info!("new map: 0x{:x}", new_map);

        info!("overwrite malloc with loop");
        proc.rm
            .write_mem(self.target_func_sym_addr, &shellcode::self_jmp().unwrap())
            .unwrap();

        // wait for 100ms
        std::thread::sleep(std::time::Duration::from_millis(100));

        info!("restore original bytes");
        proc.rm
            .write_code(self.target_func_sym_addr, &func_original_bytes, 1)
            .unwrap();
        proc.rm
            .write_mem(self.target_var_sym_addr, &var_original_bytes)
            .unwrap();

        info!("overwrite new map");
        proc.rm
            .write_code(new_map as usize, &second_stage, 1)
            .unwrap();

        info!("injection done.");
        Ok(())
    }
}
