use hxdmp::hexdump;
use std::io::{ErrorKind, Read};
use std::process::Output;
use std::str::from_utf8;

use crate::InjectionError;

use glob::glob;
use std::time::Duration;
use std::thread;

const HEXDUMP_BUFFER_SIZE: usize = 0x200;
const TMP_DIR_PATH: &str = "/data/local/tmp";

pub fn print_file_hexdump(file_path: &str) -> Result<(), InjectionError> {
    let mut file = match std::fs::File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Error opening file: {}", e);
            return Err(InjectionError::FileError);
        }
    };

    let mut in_buffer = [0; HEXDUMP_BUFFER_SIZE];
    let mut out_buffer = Vec::new();

    match file.read_exact(&mut in_buffer) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == ErrorKind::UnexpectedEof {
                // ignore
            } else {
                error!("Error reading file: {}", e);
                return Err(InjectionError::FileError);
            }
        }
    }

    hexdump(&in_buffer, &mut out_buffer).unwrap();

    debug!("Hexdump of file: {}", String::from_utf8_lossy(&out_buffer));
    Ok(())
}

pub fn verify_elf_file(file_path: &str) -> Result<(), InjectionError> {
    let file = match std::fs::File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Error opening file: {}", e);
            return Err(InjectionError::FileError);
        }
    };

    let mut magic = [0; 4];
    match file.take(4).read_exact(&mut magic) {
        Ok(_) => {}
        Err(e) => {
            error!("Error reading file: {}", e);
            return Err(InjectionError::FileError);
        }
    }

    if magic != [0x7f, 0x45, 0x4c, 0x46] {
        error!("File is not an ELF file");
        return Err(InjectionError::FileError);
    }

    Ok(())
}

pub fn copy_file_to_tmp(file_path: &str) -> Result<String, InjectionError> {
    // get absolute path
    let file_path_absolute = match std::path::Path::new(file_path).canonicalize() {
        Ok(path) => path,
        Err(e) => {
            error!("Error getting file path: {}", e);
            return Err(InjectionError::FileError);
        }
    };

    info!("File path: {}", file_path_absolute.to_str().unwrap());

    // skip if the file is already in /dev/local/tmp
    if file_path_absolute.starts_with(TMP_DIR_PATH) {
        info!("File is already in {}", TMP_DIR_PATH);
        return Ok(String::from(file_path_absolute.to_str().unwrap()));
    }

    let file_name = match file_path_absolute.file_name() {
        Some(name) => name.to_str().unwrap(),
        None => {
            error!("Error getting file name");
            return Err(InjectionError::FileError);
        }
    };

    // copy file to /data/local/tmp so that the target app can access it
    let tmp_file_path = std::path::Path::new(TMP_DIR_PATH)
        .join(file_name)
        .as_os_str()
        .to_str()
        .unwrap()
        .to_string();

    info!("Copying file {} to {}", file_path, tmp_file_path);
    match std::fs::copy(file_path, &tmp_file_path) {
        Ok(_) => {
            info!("File copied successfully");
            Ok(tmp_file_path)
        }
        Err(e) => {
            error!("Error copying file: {}", e);
            Err(InjectionError::FileError)
        }
    }
}

pub fn fix_file_context(file_path: &str) -> Result<(), InjectionError> {
    // set file context to apk_data_file for dlopen to succeed
    info!("Fixing file context for {}", file_path);
    match std::process::Command::new("chcon")
        .arg("u:object_r:apk_data_file:s0")
        .arg(file_path)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                error!(
                    "Error running chcon: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Err(InjectionError::CommandError)
            } else {
                info!("File context fixed");
                Ok(())
            }
        }
        Err(e) => {
            error!("Error running chcon: {}", e);
            Err(InjectionError::CommandError)
        }
    }
}

pub fn fix_file_permissions(file_path: &str) -> Result<(), InjectionError> {
    // add executable permission to file
    info!("Fixing file permissions for {}", file_path);
    match std::process::Command::new("chmod")
        .arg("+r")
        .arg(file_path)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                error!(
                    "Error running chmod: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Err(InjectionError::CommandError)
            } else {
                info!("File permissions fixed");
                Ok(())
            }
        }
        Err(e) => {
            error!("Error running chmod: {}", e);
            Err(InjectionError::CommandError)
        }
    }
}

pub fn execute_command(program: &str, args: &Vec<&str>) -> Result<Output, InjectionError> {
    match std::process::Command::new(program)
        .args(args)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                error!(
                    "Error running cmd {} {:?} err: {}", program, args, 
                    String::from_utf8_lossy(&output.stderr)
                );
                Err(InjectionError::CommandError)
            } else {
                info!("Running cmd successfully: {} {:?}", program, args);
                Ok(output)
            }
        }
        Err(e) => {
            error!("Error running cmd {} {:?} err: {}", program, args, e);
            Err(InjectionError::CommandError)
        }
    }
}

pub fn get_pid_by_package(pkg_name: &str) -> std::io::Result<u32> {
    for entry in glob("/proc/*/cmdline").unwrap() {
        match entry {
            Ok(path) => {
                let mut file = std::fs::File::open(&path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let tmp_name = contents.trim_end_matches('\0');
                if tmp_name == pkg_name {
                    let path_str = path.to_str().unwrap();
                    let pid_str = path_str.split("/").nth(2).unwrap();
                    let pid = pid_str.parse::<u32>().unwrap();
                    return Ok(pid);
                }
            },
            Err(err) => println!("{:?}", err),
        }
    }
    Ok(0)
}

pub fn get_pid_by_package_with_polling(pkg_name: &str) -> u32{
    let mut _pid: u32 = 0;

    let count = 100;
    for _i in 0..count {
        _pid = get_pid_by_package(pkg_name).unwrap();
        if _pid > 0 {
            break;
        }
        thread::sleep(Duration::from_micros(500));
    }

    return _pid;
}

pub fn restart_app_and_get_pid(pkg_name: &str) -> u32 {
    let _ = execute_command("am", &vec!["force-stop", pkg_name]);
    // check if this command can start the application
    let _ = execute_command("monkey", &vec!["-p", pkg_name, "-c", "android.intent.category.LAUNCHER", "1"]);

    let mut _pid = get_pid_by_package_with_polling(pkg_name);

    if _pid <= 0 {
        // try another way to start the application
        let get_main_activity_result = execute_command("cmd", &vec!["package", "resolve-activity", "--brief", pkg_name, "|", "tail", "-n", "1"]).unwrap();
        let result_str = from_utf8(&get_main_activity_result.stdout).unwrap();
        let last_line = result_str.lines().last().unwrap();
        let _ = execute_command("am", &vec!["start", last_line]);
        _pid = get_pid_by_package_with_polling(pkg_name);
    }
    return _pid;
}

