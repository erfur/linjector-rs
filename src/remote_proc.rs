use proc_maps::{get_process_maps, MapRange, Pid};

use crate::{remote_mem::RemoteMem, remote_module::RemoteModule, InjectionError};

pub(crate) struct RemoteProc {
    pid: i32,
    pub mem: RemoteMem,
}

impl RemoteProc {
    pub fn new(pid: i32) -> Result<Self, InjectionError> {
        let mem = RemoteMem::new(pid)?;
        Ok(Self { pid, mem })
    }

    fn maps(&self) -> Result<Vec<MapRange>, InjectionError> {
        get_process_maps(self.pid as Pid).map_err(|_| InjectionError::RemoteProcessError)
    }

    fn maps_by_name(&self, name: &str) -> Result<Vec<MapRange>, InjectionError> {
        let maps = self.maps()?;
        let mut maps_by_name: Vec<MapRange> = Vec::new();
        for map in maps {
            match map.filename() {
                None => continue,
                Some(filename) => {
                    if filename.ends_with(name) {
                        maps_by_name.push(map);
                    }
                }
            }
        }

        if maps_by_name.is_empty() {
            return Err(InjectionError::ModuleNotFound);
        }

        Ok(maps_by_name)
    }

    fn module_bytes(&self, module_name: &str) -> Result<Vec<u8>, InjectionError> {
        let maps = self.maps_by_name(module_name)?;
        let mut module_bytes: Vec<u8> = Vec::new();
        for map in maps {
            // debug!("map: {:?}", map);
            module_bytes.resize(map.offset, 0);
            let mut buf = self.mem.read(map.start(), map.size())?;
            module_bytes.append(&mut buf);
        }

        Ok(module_bytes)
    }

    pub fn module(&self, module_name: &str) -> Result<RemoteModule, InjectionError> {
        let maps = self.maps_by_name(module_name)?;
        Ok(RemoteModule::new(
            maps[0].filename().unwrap().to_str().unwrap(),
            maps[0].start(),
            self.module_bytes(module_name)?,
        ))
    }
}
