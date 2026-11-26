//! Cloud-image builder the lab can boot without writing the downloaded image.
//!
//! The seed is a NoCloud volume. `sbm-core`'s `scripts/provision-builder.sh` is
//! what a person runs inside the guest. This module only makes the guest reach
//! a serial marker.

use crate::error::{Error, Result};
use crate::fatimg::build_fat32;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn find_build_image(root: &Path) -> Result<PathBuf> {
    let locked = root.join("var/build-vm/image.lock");
    if locked.is_file() {
        let text = fs::read_to_string(&locked)?;
        if let Some(name) = lock_value(&text, "file") {
            let path = root.join("var/build-vm").join(name);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    if let Some(path) = newest_image(&root.join("var/build-vm")) {
        return Ok(path);
    }
    let sibling = root.join("../sbm-core/build/builder");
    if let Some(path) = fedora_base(&sibling) {
        return Ok(path);
    }
    Err(Error::message(
        "no build VM image; run `sbm-lab setup --build-vm` or place the Fedora cloud qcow2 at ../sbm-core/build/builder/",
    ))
}

pub fn image_format(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic == b"QFI\xfb" {
        Ok("qcow2".into())
    } else {
        Ok("raw".into())
    }
}

pub fn cloud_seed() -> Result<Vec<u8>> {
    let user = b"\
#cloud-config
hostname: sbm-builder
package_update: false
package_upgrade: false
users:
  - name: builder
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: wheel
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: builder
ssh_pwauth: true
bootcmd:
  - sh -c 'echo SBM-LAB-MARKER:build-vm-ready | tee /dev/console /dev/ttyS0 /dev/ttyAMA0 >/dev/null || true'
";
    let meta = b"instance-id: sbm-lab-builder\nlocal-hostname: sbm-builder\n";
    let files = [
        ("user-data".to_string(), user.as_slice()),
        ("meta-data".to_string(), meta.as_slice()),
    ];
    build_fat32(48 * 1024 * 1024, "cidata", &files)
}

fn lock_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        let Some((name, rest)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != key {
            continue;
        }
        return Some(rest.trim().trim_matches('"'));
    }
    None
}

fn newest_image(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if name.ends_with(".img") || name.ends_with(".qcow2") {
            found.push(path);
        }
    }
    found.sort();
    found.into_iter().next()
}

fn fedora_base(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name()?.to_str()?;
        if name.starts_with("Fedora-Cloud-Base") && name.ends_with(".qcow2") {
            found.push(path);
        }
    }
    found.sort();
    found.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fatimg::read_fat_file;

    #[test]
    fn seed_is_cidata_and_prints_the_marker() {
        let bytes = cloud_seed().unwrap();
        let user = read_fat_file(&bytes, "user-data").unwrap();
        let text = String::from_utf8(user).unwrap();
        assert!(text.starts_with("#cloud-config"));
        assert!(text.contains("SBM-LAB-MARKER:build-vm-ready"));
        assert_eq!(bytes.len(), 48 * 1024 * 1024);
    }
}
