use nix::sys::uio::{pread, pwrite};
use std::fs::{File, OpenOptions};

use crate::InjectionError;

#[derive(Debug)]
pub(crate) struct RemoteMem {
    fd: File,
}

impl RemoteMem {
    pub fn new(pid: i32) -> Result<Self, InjectionError> {
        let mem_path: String = format!("/proc/{}/mem", pid);
        // open file in read-write mode
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mem_path)
            .map_err(|_| InjectionError::RemoteMemoryError)?;

        Ok(Self { fd })
    }

    pub fn read(&self, addr: usize, len: usize) -> Result<Vec<u8>, InjectionError> {
        let mut buf = vec![0; len];
        self.read_vec(addr, &mut buf)?;
        Ok(buf)
    }

    pub fn read_vec(&self, addr: usize, buf: &mut Vec<u8>) -> Result<(), InjectionError> {
        pread(&self.fd, buf, addr as i64).map_err(|_| InjectionError::RemoteMemoryError)?;
        Ok(())
    }

    pub fn write(&self, addr: usize, buf: &Vec<u8>) -> Result<(), InjectionError> {
        match pwrite(&self.fd, &buf, addr as i64) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("error while writing into remote memory: {:?}", e);
                return Err(InjectionError::RemoteMemoryError);
            }
        }
    }

    /// Write code into remote memory, leaving the first `skip` instructions to last.
    /// This is (hopefully) useful when overwriting code that is currently being executed.
    pub fn write_code(
        &self,
        addr: usize,
        buf: &Vec<u8>,
        skip: usize,
    ) -> Result<(), InjectionError> {
        let skip_offset = skip * 4;
        match pwrite(&self.fd, &buf[skip_offset..], (addr + skip_offset) as i64) {
            Ok(_) => {}
            Err(e) => {
                error!("error while writing into remote memory: {:?}", e);
                return Err(InjectionError::RemoteMemoryError);
            }
        }

        match pwrite(&self.fd, &buf[..skip_offset], (addr) as i64) {
            Ok(_) => {}
            Err(e) => {
                error!("error while writing into remote memory: {:?}", e);
                return Err(InjectionError::RemoteMemoryError);
            }
        }

        Ok(())
    }
}

#[cfg(test)]

mod tests {
    use proc_maps::{get_process_maps, Pid};

    use super::*;

    #[test]
    fn test_read_mem() {
        let remote_mem = RemoteMem::new(std::process::id() as i32).unwrap();
        let buf = remote_mem.read(0x7f7f7f7f7f7f, 0x10);
        println!("{:?}", buf);
    }

    #[test]
    fn test_list_self_maps() {
        let pid: u32 = std::process::id();
        let maps = get_process_maps(Pid::from(pid as u16)).unwrap();
        for map in maps {
            println!("{:?}", map);
        }
    }
}
