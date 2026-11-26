use crate::accel::{Accel, Arch, cpu_model};
use crate::error::{Error, Result};
use crate::profile::GpuKind;
use crate::util::reject_host_device;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AttachedDisk {
    pub id: String,
    pub path: PathBuf,
    pub format: String,
    pub bootindex: u32,
    pub blkdebug: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub bin: PathBuf,
    pub arch: Arch,
    pub accel: Accel,
    pub machine: String,
    pub memory_mib: u32,
    pub cpus: u32,
    pub secure_boot: bool,
    pub requires_smm: bool,
    pub code: Option<PathBuf>,
    pub vars: Option<PathBuf>,
    pub bios: Option<PathBuf>,
    pub disks: Vec<AttachedDisk>,
    pub usb_disks: Vec<AttachedDisk>,
    pub gpu: GpuKind,
    pub network: Option<NetworkAttach>,
    pub tpm_socket: Option<PathBuf>,
    pub guest_agent_socket: Option<PathBuf>,
    pub serial_socket: PathBuf,
    pub qmp_socket: PathBuf,
    pub debugcon: Option<PathBuf>,
    pub graphical: bool,
}

#[derive(Debug, Clone)]
pub struct NetworkAttach {
    pub mode: String,
    pub connect: Option<String>,
}

pub fn qemu_args(plan: &LaunchPlan) -> Result<Vec<String>> {
    for disk in plan.disks.iter().chain(plan.usb_disks.iter()) {
        reject_host_device(&disk.path)?;
        if let Some(cfg) = &disk.blkdebug {
            reject_host_device(cfg)?;
        }
    }
    if let Some(code) = &plan.code {
        reject_host_device(code)?;
    }
    if let Some(vars) = &plan.vars {
        reject_host_device(vars)?;
    }
    let mut args = Vec::new();
    let mut machine = plan.machine.clone();
    if (plan.requires_smm || (plan.secure_boot && matches!(plan.arch, Arch::X86_64 | Arch::Ia32)))
        && !machine.contains("smm=")
    {
        machine.push_str(",smm=on");
    }
    args.push("-machine".into());
    args.push(machine);
    args.push("-accel".into());
    args.push(plan.accel.as_str().into());
    args.push("-cpu".into());
    args.push(cpu_model(plan.accel, plan.arch).into());
    args.push("-m".into());
    args.push(plan.memory_mib.to_string());
    args.push("-smp".into());
    args.push(plan.cpus.to_string());
    args.push("-display".into());
    args.push(if plan.graphical {
        "cocoa".into()
    } else {
        "none".into()
    });
    args.push("-nodefaults".into());
    args.push("-no-reboot".into());
    match (plan.arch, plan.gpu) {
        (Arch::X86_64 | Arch::Ia32, GpuKind::Virtio) => {
            args.push("-vga".into());
            args.push("none".into());
            args.push("-device".into());
            args.push("virtio-vga".into());
        }
        (Arch::X86_64 | Arch::Ia32, GpuKind::Software) => {
            args.push("-device".into());
            args.push("VGA".into());
        }
        (Arch::Aarch64, GpuKind::Virtio) => {
            args.push("-device".into());
            args.push("virtio-gpu-pci".into());
        }
        (Arch::Aarch64, GpuKind::Software) => {
            args.push("-device".into());
            args.push("ramfb".into());
        }
    }
    if plan.bios.is_none() {
        if let Some(code) = &plan.code {
            args.push("-drive".into());
            args.push(format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                code.display()
            ));
        }
        if let Some(vars) = &plan.vars {
            args.push("-drive".into());
            args.push(format!(
                "if=pflash,format=raw,unit=1,file={}",
                vars.display()
            ));
        }
    }
    if plan.secure_boot && matches!(plan.arch, Arch::X86_64 | Arch::Ia32) {
        args.push("-global".into());
        args.push("driver=cfi.pflash01,property=secure,value=on".into());
    }
    if let Some(bios) = &plan.bios {
        reject_host_device(bios)?;
        args.push("-bios".into());
        args.push(bios.display().to_string());
    }
    args.push("-serial".into());
    args.push(format!("file:{}", plan.serial_socket.display()));
    if let Some(debug) = &plan.debugcon {
        args.push("-chardev".into());
        args.push(format!("file,id=debugcon,path={}", debug.display()));
        args.push("-device".into());
        args.push("isa-debugcon,iobase=0x402,chardev=debugcon".into());
    }
    args.push("-qmp".into());
    args.push(format!(
        "unix:{},server=on,wait=off",
        plan.qmp_socket.display()
    ));
    args.push("-device".into());
    args.push("qemu-xhci,id=xhci".into());
    args.push("-device".into());
    args.push("usb-kbd,bus=xhci.0".into());
    args.push("-device".into());
    args.push("usb-tablet,bus=xhci.0".into());
    for disk in &plan.disks {
        push_disk(&mut args, disk, false)?;
    }
    for disk in &plan.usb_disks {
        push_disk(&mut args, disk, true)?;
    }
    if let Some(net) = &plan.network {
        match net.mode.as_str() {
            "none" => {}
            "slow" => {
                let connect = net
                    .connect
                    .as_deref()
                    .ok_or_else(|| Error::message("slow network is missing a proxy address"))?;
                args.push("-netdev".into());
                args.push(format!("socket,id=net0,connect={connect}"));
                args.push("-device".into());
                args.push("virtio-net-pci,netdev=net0,id=nic0,mac=52:54:00:12:34:56".into());
            }
            _ => {
                args.push("-netdev".into());
                args.push("user,id=net0".into());
                args.push("-device".into());
                args.push("virtio-net-pci,netdev=net0,id=nic0,mac=52:54:00:12:34:56".into());
            }
        }
    }
    if let Some(sock) = &plan.tpm_socket {
        args.push("-chardev".into());
        args.push(format!("socket,id=chrtpm,path={}", sock.display()));
        args.push("-tpmdev".into());
        args.push("emulator,id=tpm0,chardev=chrtpm".into());
        args.push("-device".into());
        let device = if plan.arch == Arch::Aarch64 {
            "tpm-tis-device,tpmdev=tpm0"
        } else {
            "tpm-tis,tpmdev=tpm0"
        };
        args.push(device.into());
    }
    if let Some(sock) = &plan.guest_agent_socket {
        args.push("-device".into());
        args.push("virtio-serial-pci,id=vserial".into());
        args.push("-chardev".into());
        args.push(format!(
            "socket,id=qga,path={},server=on,wait=off",
            sock.display()
        ));
        args.push("-device".into());
        args.push("virtserialport,bus=vserial.0,chardev=qga,name=org.qemu.guest_agent.0".into());
    }
    Ok(args)
}

fn push_disk(args: &mut Vec<String>, disk: &AttachedDisk, usb: bool) -> Result<()> {
    let file = if let Some(cfg) = &disk.blkdebug {
        format!("blkdebug:{}:{}", cfg.display(), disk.path.display())
    } else {
        disk.path.display().to_string()
    };
    args.push("-drive".into());
    args.push(format!(
        "if=none,id={},format={},file={}",
        disk.id, disk.format, file
    ));
    args.push("-device".into());
    if usb {
        args.push(format!(
            "usb-storage,bus=xhci.0,drive={},removable=on,bootindex={}",
            disk.id, disk.bootindex
        ));
    } else {
        args.push(format!(
            "virtio-blk-pci,drive={},bootindex={}",
            disk.id, disk.bootindex
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(arch: Arch, accel: Accel) -> LaunchPlan {
        LaunchPlan {
            bin: PathBuf::from("qemu"),
            arch,
            accel,
            machine: if arch == Arch::Aarch64 {
                "virt".into()
            } else {
                "q35".into()
            },
            memory_mib: 512,
            cpus: 1,
            secure_boot: false,
            requires_smm: false,
            code: Some(PathBuf::from(
                "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
            )),
            vars: Some(PathBuf::from("/tmp/vars.fd")),
            bios: None,
            disks: vec![],
            usb_disks: vec![],
            gpu: GpuKind::Software,
            network: None,
            tpm_socket: None,
            guest_agent_socket: None,
            serial_socket: PathBuf::from("/tmp/serial.sock"),
            qmp_socket: PathBuf::from("/tmp/qmp.sock"),
            debugcon: None,
            graphical: false,
        }
    }

    #[test]
    fn x86_on_tcg_does_not_request_hvf() {
        let args = qemu_args(&plan(Arch::X86_64, Accel::Tcg)).unwrap();
        assert!(args.windows(2).any(|w| w == ["-accel", "tcg"]));
        assert!(!args.iter().any(|a| a == "hvf"));
        assert!(args.windows(2).any(|w| w == ["-cpu", "qemu64"]));
    }

    #[test]
    fn aarch64_hvf_uses_host_cpu() {
        let mut p = plan(Arch::Aarch64, Accel::Hvf);
        p.code = Some(PathBuf::from(
            "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        ));
        let args = qemu_args(&p).unwrap();
        assert!(args.windows(2).any(|w| w == ["-accel", "hvf"]));
        assert!(args.windows(2).any(|w| w == ["-cpu", "host"]));
        assert!(args.iter().any(|a| a == "ramfb"));
    }

    #[test]
    fn host_device_disk_is_rejected() {
        let mut p = plan(Arch::X86_64, Accel::Tcg);
        p.disks.push(AttachedDisk {
            id: "d0".into(),
            path: PathBuf::from("/dev/disk0"),
            format: "raw".into(),
            bootindex: 0,
            blkdebug: None,
        });
        assert!(qemu_args(&p).is_err());
    }
}
