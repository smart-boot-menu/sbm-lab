use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn lab_root(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Ok(value) = std::env::var("SBM_LAB_ROOT") {
        return Ok(PathBuf::from(value));
    }
    let mut cursor = std::env::current_dir()?;
    loop {
        if cursor.join("profiles").is_dir() && cursor.join("Cargo.toml").is_file() {
            let text = fs::read_to_string(cursor.join("Cargo.toml")).unwrap_or_default();
            if text.contains("sbm-lab") {
                return Ok(cursor);
            }
        }
        if !cursor.pop() {
            break;
        }
    }
    Err(Error::message(
        "could not find the sbm-lab root; set SBM_LAB_ROOT or pass --root",
    ))
}

pub fn which(name: &str) -> Option<PathBuf> {
    let extra = [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ];
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let candidate = Path::new(dir).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for dir in extra {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn tool_version(bin: &Path) -> Option<String> {
    let output = Command::new(bin).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

pub fn pe_machine(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().ok()?) as usize;
    if bytes.len() < pe + 6 || &bytes[pe..pe + 4] != b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes(bytes[pe + 4..pe + 6].try_into().ok()?))
}

/// Exclusive lock so two agents sharing one checkout cannot rebuild the same
/// fixture or key directory at the same time. Drop releases the lock.
pub struct FileLock {
    file: File,
}

impl FileLock {
    pub fn exclusive(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(Error::message(format!("could not lock {}", path.display())));
        }
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Refuse host disks and other non-regular nodes. QEMU is only ever pointed
/// at files the lab created.
pub fn reject_host_device(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if text.starts_with("/dev/") || text.contains("/dev/disk") || text.contains("/dev/rdisk") {
        return Err(Error::message(format!("refusing host device path {text}")));
    }
    if text.contains(',') {
        return Err(Error::message(format!(
            "refusing path with a comma, which QEMU would split: {text}"
        )));
    }
    if path.exists() {
        let file_type = path.metadata()?.file_type();
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
        {
            return Err(Error::message(format!(
                "refusing non-regular file {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn short_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{nanos:x}-{pid:x}-{seq:x}")
}

pub fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

pub fn test_scratch(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/sbm-lab-tests")
        .join(format!("{name}-{n}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_dev_paths() {
        assert!(reject_host_device(Path::new("/dev/disk0")).is_err());
        assert!(reject_host_device(Path::new("/tmp/a,b")).is_err());
    }
}
