use crate::InjectionError;

pub(crate) struct RemoteModule {
    pub name: String,
    pub vm_addr: usize,
    #[allow(dead_code)]
    pub bytes: Vec<u8>,
}

impl RemoteModule {
    pub fn new(name: &str, vm_addr: usize, bytes: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            vm_addr,
            bytes,
        }
    }

    pub fn dlsym_from_fs(&self, symbol_name: &str) -> Result<usize, InjectionError> {
        let bytes = std::fs::read(&self.name).map_err(|_| InjectionError::FileError)?;
        let elf = goblin::elf::Elf::parse(&bytes).map_err(|_| InjectionError::RemoteModuleError)?;

        let result = elf
            .syms
            .iter()
            .find(|sym| symbol_name == elf.strtab.get_at(sym.st_name).unwrap());

        if result.is_some() {
            let offset = result.unwrap().st_value as usize;
            return Ok(offset + self.vm_addr);
        }

        warn!(
            "symbol not found in .symtab, trying .dynsym: {}",
            symbol_name
        );

        let result = elf
            .dynsyms
            .iter()
            .find(|sym| symbol_name == elf.dynstrtab.get_at(sym.st_name).unwrap());

        if result.is_none() {
            error!("symbol not found: {}", symbol_name);
            return Err(InjectionError::SymbolNotFound);
        }

        let offset = result.unwrap().st_value as usize;
        Ok(offset + self.vm_addr)
    }

    fn _dlsym_from_mem(&self, _symbol_name: &str) -> Result<usize, InjectionError> {
        unimplemented!("dlsym_from_mem");
    }
}
