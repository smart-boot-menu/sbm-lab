use serde::{Deserialize, Serialize};
use std::fmt;

/// Guest CPU architecture the lab can boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
    Ia32,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Ia32 => "ia32",
        }
    }

    /// Host `std::env::consts::ARCH` value that matches this guest.
    pub fn host_arch(self) -> &'static str {
        match self {
            Self::X86_64 | Self::Ia32 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    pub fn qemu_binary(self) -> &'static str {
        match self {
            Self::X86_64 => "qemu-system-x86_64",
            Self::Aarch64 => "qemu-system-aarch64",
            Self::Ia32 => "qemu-system-i386",
        }
    }

    pub fn boot_file(self) -> &'static str {
        match self {
            Self::X86_64 => "EFI/BOOT/BOOTX64.EFI",
            Self::Aarch64 => "EFI/BOOT/BOOTAA64.EFI",
            Self::Ia32 => "EFI/BOOT/BOOTIA32.EFI",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accel {
    Hvf,
    Kvm,
    Tcg,
}

impl Accel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hvf => "hvf",
            Self::Kvm => "kvm",
            Self::Tcg => "tcg",
        }
    }
}

impl fmt::Display for Accel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccelRequest {
    #[default]
    Auto,
    Hvf,
    Kvm,
    Tcg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    /// Hardware-accelerated virtualization (HVF or KVM). Not a bare-metal run.
    AcceleratedVirtualization,
    /// QEMU TCG. Not representative of physical hardware, especially cross-ISA.
    Emulation,
}

impl ExecutionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceleratedVirtualization => "accelerated_virtualization",
            Self::Emulation => "emulation",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostFacts {
    pub os: String,
    pub arch: String,
    pub hv_support: bool,
    pub kvm_usable: bool,
    pub qemu_accels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccelChoice {
    pub accel: Accel,
    pub execution_class: ExecutionClass,
    pub representative_of_physical_hardware: bool,
    pub note: String,
}

pub fn select_accel(
    host: &HostFacts,
    guest: Arch,
    request: AccelRequest,
) -> Result<AccelChoice, String> {
    let same = host.arch == guest.host_arch() || (guest == Arch::Ia32 && host.arch == "x86_64");
    let has = |name: &str| host.qemu_accels.iter().any(|a| a == name);
    let accel = match request {
        AccelRequest::Tcg => Accel::Tcg,
        AccelRequest::Hvf => {
            if same && host.hv_support && has("hvf") {
                Accel::Hvf
            } else {
                return Err(format!(
                    "HVF cannot run a {guest} guest on {} (hv_support={}, qemu hvf={})",
                    host.arch,
                    host.hv_support,
                    has("hvf")
                ));
            }
        }
        AccelRequest::Kvm => {
            if same && host.kvm_usable && has("kvm") {
                Accel::Kvm
            } else {
                return Err(format!("KVM cannot run a {guest} guest on {}", host.arch));
            }
        }
        AccelRequest::Auto => {
            if same && host.hv_support && has("hvf") {
                Accel::Hvf
            } else if same && host.kvm_usable && has("kvm") {
                Accel::Kvm
            } else {
                Accel::Tcg
            }
        }
    };
    let execution_class = match accel {
        Accel::Tcg => ExecutionClass::Emulation,
        Accel::Hvf | Accel::Kvm => ExecutionClass::AcceleratedVirtualization,
    };
    let note = match (accel, same) {
        (Accel::Tcg, false) => {
            "TCG is cross-architecture emulation and is not representative of physical hardware."
                .to_string()
        }
        (Accel::Tcg, true) => {
            "TCG is software emulation and is not representative of physical hardware.".to_string()
        }
        _ => "Hardware-accelerated virtualization. This is not a physical-machine measurement."
            .to_string(),
    };
    Ok(AccelChoice {
        accel,
        execution_class,
        representative_of_physical_hardware: false,
        note,
    })
}

/// aarch64 TCG on an x86 CI runner needs longer than the HVF timeout.
/// Same-architecture boots keep the requested timeout, including x86 TCG.
pub fn effective_timeout(host_arch: &str, guest: Arch, requested: u64) -> u64 {
    if host_arch == guest.host_arch() {
        requested
    } else {
        requested.max(720)
    }
}

pub fn cpu_model(accel: Accel, guest: Arch, host_arch: &str) -> &'static str {
    match (accel, guest) {
        (Accel::Hvf | Accel::Kvm, Arch::Aarch64) => "host",
        // `-cpu max` enables pointer authentication. AAVMF 2025.11 on an x86
        // GitHub runner printed only the version line for the whole 720 s
        // smoke timeout and the 1200 s product timeout. cortex-a57 is the
        // CPU that image is built for. Same-architecture TCG stays on `max`;
        // the measured U-Boot TCG boot on this Mac used that model.
        (Accel::Tcg, Arch::Aarch64) if host_arch != guest.host_arch() => "cortex-a57",
        (Accel::Tcg, Arch::Aarch64) => "max",
        (_, Arch::Ia32) => "qemu32",
        _ => "qemu64",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac_m5() -> HostFacts {
        HostFacts {
            os: "macos".into(),
            arch: "aarch64".into(),
            hv_support: true,
            kvm_usable: false,
            qemu_accels: vec!["hvf".into(), "tcg".into()],
        }
    }

    #[test]
    fn cross_arch_timeout_grows_and_native_does_not() {
        assert_eq!(effective_timeout("x86_64", Arch::Aarch64, 240), 720);
        assert_eq!(effective_timeout("aarch64", Arch::Aarch64, 240), 240);
        assert_eq!(effective_timeout("aarch64", Arch::X86_64, 180), 720);
        assert_eq!(effective_timeout("x86_64", Arch::X86_64, 180), 180);
    }

    #[test]
    fn apple_silicon_keeps_x86_on_tcg() {
        let choice = select_accel(&mac_m5(), Arch::X86_64, AccelRequest::Auto).unwrap();
        assert_eq!(choice.accel, Accel::Tcg);
        assert_eq!(choice.execution_class, ExecutionClass::Emulation);
        assert!(!choice.representative_of_physical_hardware);
        assert!(select_accel(&mac_m5(), Arch::X86_64, AccelRequest::Hvf).is_err());
    }

    #[test]
    fn apple_silicon_uses_hvf_for_aarch64() {
        let choice = select_accel(&mac_m5(), Arch::Aarch64, AccelRequest::Auto).unwrap();
        assert_eq!(choice.accel, Accel::Hvf);
        assert_eq!(cpu_model(choice.accel, Arch::Aarch64, "aarch64"), "host");
        assert!(!choice.representative_of_physical_hardware);
    }

    #[test]
    fn cross_arch_tcg_avoids_cpu_max() {
        assert_eq!(cpu_model(Accel::Tcg, Arch::Aarch64, "x86_64"), "cortex-a57");
        assert_eq!(cpu_model(Accel::Tcg, Arch::Aarch64, "aarch64"), "max");
        assert_eq!(cpu_model(Accel::Kvm, Arch::Aarch64, "aarch64"), "host");
    }

    #[test]
    fn x86_host_without_kvm_uses_tcg() {
        let host = HostFacts {
            os: "linux".into(),
            arch: "x86_64".into(),
            hv_support: false,
            kvm_usable: false,
            qemu_accels: vec!["tcg".into(), "kvm".into()],
        };
        let choice = select_accel(&host, Arch::X86_64, AccelRequest::Auto).unwrap();
        assert_eq!(choice.accel, Accel::Tcg);
    }
}
