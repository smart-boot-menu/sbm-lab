use crate::accel::Arch;
use crate::error::{Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FirmwarePair {
    pub code: PathBuf,
    pub vars_template: PathBuf,
    pub description: String,
    pub secure_boot: bool,
    pub requires_smm: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct FwFile {
    filename: String,
}

#[derive(Debug, Clone, Deserialize)]
struct FwMapping {
    executable: Option<FwFile>,
    #[serde(rename = "nvram-template")]
    nvram_template: Option<FwFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct FwTarget {
    architecture: String,
    machines: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FwDesc {
    description: Option<String>,
    #[serde(rename = "interface-types")]
    interface_types: Option<Vec<String>>,
    mapping: FwMapping,
    targets: Option<Vec<FwTarget>>,
    features: Option<Vec<String>>,
}

pub fn firmware_search_dirs(qemu_bin: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(value) = std::env::var("SBM_LAB_FIRMWARE") {
        dirs.push(PathBuf::from(&value).join("firmware"));
        dirs.push(PathBuf::from(value));
    }
    if let Some(bin) = qemu_bin
        && let Some(parent) = bin.parent()
    {
        dirs.push(parent.join("../share/qemu/firmware"));
        dirs.push(parent.join("../share/qemu"));
    }
    for path in [
        "/opt/homebrew/share/qemu/firmware",
        "/opt/homebrew/share/qemu",
        "/usr/local/share/qemu/firmware",
        "/usr/local/share/qemu",
        "/usr/share/qemu/firmware",
        "/usr/share/OVMF",
        "/usr/share/AAVMF",
        "/usr/share/qemu-efi-aarch64",
        "/usr/share/edk2/ovmf",
        "/usr/share/edk2/aarch64",
    ] {
        dirs.push(PathBuf::from(path));
    }
    dirs
}

pub fn select_firmware(
    qemu_bin: Option<&Path>,
    arch: Arch,
    secure_boot: bool,
    machine: &str,
) -> Result<FirmwarePair> {
    let mut matches = Vec::new();
    for dir in firmware_search_dirs(qemu_bin) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(desc) = serde_json::from_str::<FwDesc>(&text) else {
                continue;
            };
            if let Some(pair) = pair_from_desc(&desc, arch, secure_boot, machine) {
                matches.push(pair);
            }
        }
    }
    if let Some(pair) = matches.into_iter().next() {
        return Ok(pair);
    }
    fallback_firmware(qemu_bin, arch, secure_boot)
}

fn pair_from_desc(
    desc: &FwDesc,
    arch: Arch,
    secure_boot: bool,
    machine: &str,
) -> Option<FirmwarePair> {
    let interfaces = desc.interface_types.clone().unwrap_or_default();
    if !interfaces.iter().any(|t| t == "uefi") {
        return None;
    }
    let features = desc.features.clone().unwrap_or_default();
    if features
        .iter()
        .any(|f| f.starts_with("amd-sev") || f.contains("tdx"))
        && secure_boot
    {
        // sev/tdx features on the stock descriptor are capabilities, not requirements.
    }
    let requires_smm = features.iter().any(|f| f == "requires-smm");
    let is_secure = features.iter().any(|f| f == "secure-boot");
    if secure_boot != is_secure {
        return None;
    }
    let arch_name = match arch {
        Arch::X86_64 => "x86_64",
        Arch::Aarch64 => "aarch64",
        Arch::Ia32 => "i386",
    };
    let targets = desc.targets.clone().unwrap_or_default();
    let arch_ok = targets.iter().any(|t| t.architecture == arch_name);
    if !arch_ok {
        return None;
    }
    let machine_ok = targets.iter().any(|t| {
        t.machines
            .iter()
            .any(|pattern| machine_matches(pattern, machine))
    });
    if !machine_ok {
        return None;
    }
    let code = desc.mapping.executable.as_ref()?.filename.clone();
    let vars = desc.mapping.nvram_template.as_ref()?.filename.clone();
    let code = PathBuf::from(code);
    let vars = PathBuf::from(vars);
    if !code.is_file() || !vars.is_file() {
        return None;
    }
    Some(FirmwarePair {
        code,
        vars_template: vars,
        description: desc.description.clone().unwrap_or_default(),
        secure_boot: is_secure,
        requires_smm,
    })
}

fn machine_matches(pattern: &str, machine: &str) -> bool {
    match machine {
        "q35" => pattern.contains("q35"),
        "pc" => pattern.contains("i440fx") || pattern == "pc",
        "virt" => pattern.contains("virt"),
        _ => pattern.trim_end_matches('*') == machine || pattern.contains(machine),
    }
}

fn fallback_firmware(
    qemu_bin: Option<&Path>,
    arch: Arch,
    secure_boot: bool,
) -> Result<FirmwarePair> {
    let dirs = firmware_search_dirs(qemu_bin);
    let (code_names, vars_names): (&[&str], &[&str]) = match (arch, secure_boot) {
        (Arch::X86_64, false) => (
            &["edk2-x86_64-code.fd", "OVMF_CODE_4M.fd", "OVMF_CODE.fd"][..],
            &["edk2-i386-vars.fd", "OVMF_VARS_4M.fd", "OVMF_VARS.fd"][..],
        ),
        (Arch::X86_64, true) => (
            &[
                "edk2-x86_64-secure-code.fd",
                "OVMF_CODE_4M.secboot.fd",
                "OVMF_CODE.secboot.fd",
            ][..],
            &["edk2-i386-vars.fd", "OVMF_VARS_4M.fd", "OVMF_VARS.fd"][..],
        ),
        (Arch::Aarch64, _) => (
            &["edk2-aarch64-code.fd", "AAVMF_CODE.fd", "QEMU_EFI.fd"][..],
            &["edk2-arm-vars.fd", "AAVMF_VARS.fd"][..],
        ),
        (Arch::Ia32, false) => (
            &["edk2-i386-code.fd", "OVMF_CODE.fd"][..],
            &["edk2-i386-vars.fd", "OVMF_VARS.fd"][..],
        ),
        (Arch::Ia32, true) => (
            &["edk2-i386-secure-code.fd"][..],
            &["edk2-i386-vars.fd"][..],
        ),
    };
    let code = find_named(&dirs, code_names).ok_or_else(|| {
        Error::message(format!(
            "no UEFI code firmware for {arch} secure={secure_boot}"
        ))
    })?;
    let vars = find_named(&dirs, vars_names)
        .ok_or_else(|| Error::message(format!("no UEFI variable template for {arch}")))?;
    Ok(FirmwarePair {
        code,
        vars_template: vars,
        description: "filename fallback".into(),
        secure_boot,
        requires_smm: secure_boot && matches!(arch, Arch::X86_64 | Arch::Ia32),
    })
}

fn find_named(dirs: &[PathBuf], names: &[&str]) -> Option<PathBuf> {
    for dir in dirs {
        for name in names {
            let path = dir.join(name);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

pub fn copy_vars(template: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = fs::read(template)?;
    fs::write(dest, bytes)?;
    Ok(())
}

pub fn uboot_binary(root: &Path) -> Option<PathBuf> {
    let candidates = [
        root.join("var/firmware/u-boot-qemu-arm64.bin"),
        root.join("var/src/u-boot-2026.10/u-boot.bin"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}
