//! ESP layout for the real SBM UEFI menu.
//!
//! OS-looking paths are copies of the SBM fixture EFI. They are not Windows,
//! Ubuntu, Fedora, or a recovery distribution. A Core UKI is placed in slot A
//! only when the caller passes one.

use crate::accel::Arch;
use crate::error::{Error, Result};
use crate::fatimg::build_fat32;
use crate::gpt::{PartitionSpec, build_gpt, esp_guid};
use crate::util::{pe_machine, reject_host_device, sha256_bytes};
use std::fs;
use std::path::{Path, PathBuf};

pub const NOT_AN_OS: &str = "\
THIS IS NOT AN OPERATING SYSTEM.\n\
The EFI files under EFI/Microsoft, EFI/ubuntu, EFI/systemd, and EFI/Linux\n\
are copies of the SBM fixture EFI. They are not Windows, Ubuntu, Fedora,\n\
or an SBM Core recovery image.\n";

pub const PAYLOAD_FIXTURE: &str = "synthetic-fixture";
pub const PAYLOAD_CORE: &str = "sbm-core-uki";

pub struct MenuDisk {
    pub bytes: Vec<u8>,
    pub payload_class: String,
}

pub fn build_menu_disk(root: &Path, arch: Arch, core: Option<&Path>) -> Result<MenuDisk> {
    let menu = read_pe(&find_menu(root, arch)?, arch)?;
    let fixture = read_pe(&find_fixture(root, arch)?, arch)?;
    let (recovery, class) = if let Some(path) = core {
        reject_host_device(path)?;
        (read_pe(path, arch)?, PAYLOAD_CORE.to_string())
    } else {
        (fixture.clone(), PAYLOAD_FIXTURE.to_string())
    };
    let files = menu_files(arch, &menu, &fixture, &recovery, &class);
    let fat_size = fat_bytes(&files);
    let borrowed: Vec<(String, &[u8])> = files
        .iter()
        .map(|(path, bytes)| (path.clone(), bytes.as_slice()))
        .collect();
    let fat = build_fat32(fat_size, "SBMESP", &borrowed)?;
    let disk = build_gpt(
        "sbm",
        &[PartitionSpec {
            name: "ESP".into(),
            type_guid: esp_guid(),
            size_bytes: fat.len() as u64,
            payload: fat,
        }],
        false,
    )?;
    Ok(MenuDisk {
        bytes: disk.bytes,
        payload_class: class,
    })
}

pub fn find_menu(root: &Path, arch: Arch) -> Result<PathBuf> {
    first_file(&menu_candidates(root, arch)).ok_or_else(|| {
        Error::message(format!(
            "SBM UEFI menu for {arch} is missing; expected {}",
            menu_candidates(root, arch)
                .into_iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(" or ")
        ))
    })
}

pub fn find_fixture(root: &Path, arch: Arch) -> Result<PathBuf> {
    first_file(&fixture_candidates(root, arch)).ok_or_else(|| {
        Error::message(format!(
            "SBM fixture EFI for {arch} is missing; expected sbm-fixture-{arch}.efi"
        ))
    })
}

pub fn find_core_uki(root: &Path, arch: Arch) -> Option<PathBuf> {
    let mut found = Vec::new();
    for dir in core_dirs(root) {
        walk_artifacts(&dir, &mut found);
    }
    found.into_iter().find(|path| core_matches(path, arch))
}

fn menu_files(
    arch: Arch,
    menu: &[u8],
    fixture: &[u8],
    recovery: &[u8],
    class: &str,
) -> Vec<(String, Vec<u8>)> {
    let (boot, tag, bls) = match arch {
        Arch::X86_64 => ("BOOTX64.EFI", "x64", "x64"),
        Arch::Aarch64 => ("BOOTAA64.EFI", "aa64", "aa64"),
        Arch::Ia32 => ("BOOTIA32.EFI", "ia32", "ia32"),
    };
    let uki_path = format!("EFI/sbm/recovery/slot-a/sbm-core-{arch}.efi");
    let manifest = serde_json::json!({
        "schema_version": "1.0",
        "active_slot": "slot-a",
        "slots": [{
            "slot_name": "slot-a",
            "uki_efi_path": format!("\\{}", uki_path.replace('/', "\\")),
            "sha256": sha256_bytes(recovery),
            "version": format!("0.1.0-{class}"),
            "healthy": true,
        }],
    });
    let policy = "{\n  \"schema_version\": \"1.0\",\n  \"policy_revision\": 0,\n  \"timeout_seconds\": 65535,\n  \"max_failed_attempts\": 3,\n  \"network_policy_timeout_ms\": 3000,\n  \"allow_remote_boot_select\": false,\n  \"offline_behavior\": \"use_local_policy\"\n}\n";
    let nsh = format!("echo -off\r\nfs0:\\EFI\\BOOT\\{boot}\r\n");
    let bls_conf = format!(
        "title Fedora Linux\nlinux \\EFI\\Linux\\fedora.efi\noptions quiet\narchitecture {bls}\n"
    );
    vec![
        ("startup.nsh".into(), nsh.into_bytes()),
        (format!("EFI/BOOT/{boot}"), menu.to_vec()),
        ("EFI/Microsoft/Boot/bootmgfw.efi".into(), fixture.to_vec()),
        (format!("EFI/ubuntu/shim{tag}.efi"), fixture.to_vec()),
        (format!("EFI/ubuntu/grub{tag}.efi"), fixture.to_vec()),
        (format!("EFI/ubuntu/mm{tag}.efi"), fixture.to_vec()),
        (
            format!("EFI/systemd/systemd-boot{tag}.efi"),
            fixture.to_vec(),
        ),
        ("EFI/Linux/fedora.efi".into(), fixture.to_vec()),
        ("EFI/sbm/sbm.efi".into(), fixture.to_vec()),
        ("loader/entries/fedora.conf".into(), bls_conf.into_bytes()),
        (uki_path, recovery.to_vec()),
        (
            "EFI/sbm/recovery/manifest.json".into(),
            manifest.to_string().into_bytes(),
        ),
        ("EFI/sbm/policy.json".into(), policy.as_bytes().to_vec()),
        (
            "EFI/sbm-lab/not-an-os.txt".into(),
            NOT_AN_OS.as_bytes().to_vec(),
        ),
        (
            "EFI/sbm-lab/payload-class.txt".into(),
            format!("{class}\n").into_bytes(),
        ),
        ("EFI/sbm/state/smoke".into(), b"1\n".to_vec()),
    ]
}

fn fat_bytes(files: &[(String, Vec<u8>)]) -> u64 {
    let payload: u64 = files.iter().map(|(_, bytes)| bytes.len() as u64).sum();
    let need = payload
        .saturating_add(16 * 1024 * 1024)
        .max(48 * 1024 * 1024);
    let mib = 1024 * 1024;
    need.div_ceil(mib) * mib
}

fn read_pe(path: &Path, arch: Arch) -> Result<Vec<u8>> {
    reject_host_device(path)?;
    let bytes = fs::read(path)?;
    if let Some(machine) = pe_machine(&bytes) {
        let expected = match arch {
            Arch::X86_64 => 0x8664,
            Arch::Aarch64 => 0xAA64,
            Arch::Ia32 => 0x14C,
        };
        if machine != expected {
            return Err(Error::message(format!(
                "{} is PE machine {machine:#x}, not {expected:#x} for {arch}",
                path.display()
            )));
        }
    }
    Ok(bytes)
}

fn menu_candidates(root: &Path, arch: Arch) -> Vec<PathBuf> {
    let (name, triple) = match arch {
        Arch::X86_64 => ("sbm-x86_64.efi", "x86_64-unknown-uefi"),
        Arch::Aarch64 => ("sbm-aarch64.efi", "aarch64-unknown-uefi"),
        Arch::Ia32 => ("sbm-ia32.efi", "i686-unknown-uefi"),
    };
    let mut paths = Vec::new();
    if let Ok(extra) = std::env::var("SBM_LAB_ARTIFACTS") {
        paths.push(PathBuf::from(extra).join(name));
    }
    paths.push(root.join("../sbm-uefi/artifacts").join(name));
    paths.push(root.join("sbm-uefi-src/artifacts").join(name));
    paths.push(
        root.join("../sbm-uefi/target")
            .join(triple)
            .join("release/sbm.efi"),
    );
    paths
}

fn fixture_candidates(root: &Path, arch: Arch) -> Vec<PathBuf> {
    let (name, triple) = match arch {
        Arch::X86_64 => ("sbm-fixture-x86_64.efi", "x86_64-unknown-uefi"),
        Arch::Aarch64 => ("sbm-fixture-aarch64.efi", "aarch64-unknown-uefi"),
        Arch::Ia32 => ("sbm-fixture-ia32.efi", "i686-unknown-uefi"),
    };
    let mut paths = Vec::new();
    if let Ok(extra) = std::env::var("SBM_LAB_ARTIFACTS") {
        paths.push(PathBuf::from(extra).join(name));
    }
    paths.push(root.join("../sbm-uefi/artifacts").join(name));
    paths.push(root.join("sbm-uefi-src/artifacts").join(name));
    paths.push(
        root.join("../sbm-uefi/target")
            .join(triple)
            .join("release/sbm-fixture.efi"),
    );
    paths
}

fn core_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(extra) = std::env::var("SBM_LAB_ARTIFACTS") {
        dirs.push(PathBuf::from(extra));
    }
    dirs.push(root.join("var/artifacts"));
    dirs.push(root.join("../sbm-core/image"));
    dirs.push(root.join("../sbm-core/build"));
    dirs.push(root.join("../install/out"));
    dirs
}

fn walk_artifacts(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name == "target" || name == "builder" || name.starts_with('.') {
                continue;
            }
            walk_artifacts(&path, found);
            continue;
        }
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if matches!(ext, "efi" | "uki") {
            found.push(path);
        }
    }
}

fn core_matches(path: &Path, arch: Arch) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.contains("fixture") || name.contains("sbm-x86_64") || name.contains("sbm-aarch64") {
        return false;
    }
    if !(name.contains("uki") || name.contains("core")) {
        return false;
    }
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Some(machine) = pe_machine(&bytes) else {
        return false;
    };
    let expected = match arch {
        Arch::X86_64 => 0x8664,
        Arch::Aarch64 => 0xAA64,
        Arch::Ia32 => 0x14C,
    };
    machine == expected && bytes.len() > 256 * 1024
}

fn first_file(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|path| path.is_file()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fatimg::read_fat_file;
    use crate::gpt::validate_gpt;

    #[test]
    fn menu_manifest_hashes_the_recovery_bytes() {
        let menu = b"menu-bytes".to_vec();
        let fixture = b"fixture-bytes".to_vec();
        let files = menu_files(Arch::X86_64, &menu, &fixture, &fixture, PAYLOAD_FIXTURE);
        let manifest = files
            .iter()
            .find(|(path, _)| path == "EFI/sbm/recovery/manifest.json")
            .map(|(_, bytes)| String::from_utf8(bytes.clone()).unwrap())
            .unwrap();
        let hash = sha256_bytes(&fixture);
        assert!(manifest.contains(&hash));
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(manifest["slots"].as_array().unwrap().len(), 1);
        assert_eq!(
            manifest["slots"][0]["uki_efi_path"],
            r"\EFI\sbm\recovery\slot-a\sbm-core-x86_64.efi"
        );
        assert!(files.iter().any(|(path, _)| path == "EFI/BOOT/BOOTX64.EFI"));
        assert!(files.iter().any(|(path, bytes)| {
            path == "EFI/sbm-lab/not-an-os.txt" && bytes.starts_with(b"THIS IS NOT")
        }));
    }

    #[test]
    fn formatted_menu_disk_roundtrips_the_class_file() {
        let menu = vec![0u8; 64];
        let fixture = b"fixture".to_vec();
        let files = menu_files(Arch::Aarch64, &menu, &fixture, &fixture, PAYLOAD_FIXTURE);
        let borrowed: Vec<(String, &[u8])> = files
            .iter()
            .map(|(path, bytes)| (path.clone(), bytes.as_slice()))
            .collect();
        let fat = build_fat32(48 * 1024 * 1024, "SBMESP", &borrowed).unwrap();
        let disk = build_gpt(
            "sbm",
            &[PartitionSpec {
                name: "ESP".into(),
                type_guid: esp_guid(),
                size_bytes: fat.len() as u64,
                payload: fat,
            }],
            false,
        )
        .unwrap();
        let parts = validate_gpt(&disk.bytes).unwrap();
        let part = &parts[0];
        let off = (part.start_lba * 512) as usize;
        let end = ((part.end_lba + 1) * 512) as usize;
        let class = read_fat_file(&disk.bytes[off..end], "EFI/sbm-lab/payload-class.txt").unwrap();
        assert_eq!(class, b"synthetic-fixture\n");
    }
}
