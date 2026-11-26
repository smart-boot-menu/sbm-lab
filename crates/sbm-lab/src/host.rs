use crate::accel::{AccelRequest, Arch, select_accel};
use crate::error::Result;
use crate::firmware::{select_firmware, uboot_binary};
use crate::util::{tool_version, which};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub path: Option<String>,
    pub version: Option<String>,
    pub accels: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub schema: &'static str,
    pub os: String,
    pub arch: String,
    pub hv_support: bool,
    pub kvm_usable: bool,
    pub tools: Vec<ToolInfo>,
    pub firmware: Vec<String>,
    pub uboot: Option<String>,
    pub x86_64_accel: String,
    pub aarch64_accel: String,
    pub x86_64_note: String,
    pub aarch64_note: String,
    pub ok: bool,
    pub warnings: Vec<String>,
}

pub fn doctor(root: &Path) -> Result<DoctorReport> {
    let facts = host_facts();
    let mut tools = Vec::new();
    let mut warnings = Vec::new();
    for name in [
        "qemu-system-x86_64",
        "qemu-system-aarch64",
        "qemu-system-i386",
        "qemu-img",
        "swtpm",
    ] {
        let path = which(name);
        let accels = path
            .as_ref()
            .filter(|_| name.starts_with("qemu-system"))
            .map(|p| qemu_accels(p))
            .unwrap_or_default();
        let version = path.as_ref().and_then(|p| tool_version(p));
        if path.is_none()
            && matches!(
                name,
                "qemu-system-x86_64" | "qemu-system-aarch64" | "qemu-img"
            )
        {
            warnings.push(format!("{name} is not installed"));
        }
        if name == "swtpm" && path.is_none() {
            warnings.push("swtpm is not installed; TPM profiles will be skipped".into());
        }
        tools.push(ToolInfo {
            name: name.into(),
            path: path.map(|p| p.display().to_string()),
            version,
            accels,
        });
    }
    let x86 = select_accel(
        &facts_for(&facts, "x86_64"),
        Arch::X86_64,
        AccelRequest::Auto,
    );
    let arm = select_accel(
        &facts_for(&facts, "aarch64"),
        Arch::Aarch64,
        AccelRequest::Auto,
    );
    let mut firmware = Vec::new();
    if let Some(bin) = which("qemu-system-x86_64") {
        match select_firmware(Some(&bin), Arch::X86_64, false, "q35") {
            Ok(pair) => firmware.push(format!(
                "x86_64 {} + {}",
                pair.code.display(),
                pair.vars_template.display()
            )),
            Err(err) => warnings.push(err.to_string()),
        }
    }
    if let Some(bin) = which("qemu-system-aarch64") {
        match select_firmware(Some(&bin), Arch::Aarch64, false, "virt") {
            Ok(pair) => firmware.push(format!(
                "aarch64 {} + {}",
                pair.code.display(),
                pair.vars_template.display()
            )),
            Err(err) => warnings.push(err.to_string()),
        }
    }
    let uboot = uboot_binary(root).map(|p| p.display().to_string());
    if uboot.is_none() {
        warnings.push("U-Boot qemu_arm64 binary is absent; run sbm-lab setup --uboot".into());
    }
    let ok = which("qemu-system-x86_64").is_some()
        && which("qemu-system-aarch64").is_some()
        && which("qemu-img").is_some()
        && !firmware.is_empty();
    Ok(DoctorReport {
        schema: "sbm-lab.doctor.v1",
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hv_support: facts.hv_support,
        kvm_usable: facts.kvm_usable,
        tools,
        firmware,
        uboot,
        x86_64_accel: x86
            .as_ref()
            .map(|c| c.accel.as_str().to_string())
            .unwrap_or_else(|_| "unavailable".into()),
        aarch64_accel: arm
            .as_ref()
            .map(|c| c.accel.as_str().to_string())
            .unwrap_or_else(|_| "unavailable".into()),
        x86_64_note: x86
            .as_ref()
            .map(|c| c.note.clone())
            .unwrap_or_else(|e| e.to_string()),
        aarch64_note: arm
            .as_ref()
            .map(|c| c.note.clone())
            .unwrap_or_else(|e| e.to_string()),
        ok,
        warnings,
    })
}

pub struct LiveHost {
    pub hv_support: bool,
    pub kvm_usable: bool,
}

pub fn host_facts() -> LiveHost {
    LiveHost {
        hv_support: sysctl_hv(),
        kvm_usable: Path::new("/dev/kvm").exists() && std::fs::File::open("/dev/kvm").is_ok(),
    }
}

fn facts_for(live: &LiveHost, qemu_name: &str) -> crate::accel::HostFacts {
    let bin = which(if qemu_name == "aarch64" {
        "qemu-system-aarch64"
    } else {
        "qemu-system-x86_64"
    });
    crate::accel::HostFacts {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hv_support: live.hv_support,
        kvm_usable: live.kvm_usable,
        qemu_accels: bin.map(|p| qemu_accels(&p)).unwrap_or_default(),
    }
}

fn qemu_accels(bin: &Path) -> Vec<String> {
    let Ok(output) = std::process::Command::new(bin)
        .arg("-accel")
        .arg("help")
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(' '))
        .map(str::to_string)
        .collect()
}

fn sysctl_hv() -> bool {
    let Ok(output) = std::process::Command::new("sysctl")
        .args(["-n", "kern.hv_support"])
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).trim() == "1"
}
