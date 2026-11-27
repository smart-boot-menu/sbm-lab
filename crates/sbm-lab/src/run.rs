use crate::accel::{AccelRequest, Arch, HostFacts, effective_timeout, select_accel};
use crate::builder::{cloud_seed, find_build_image, image_format};
use crate::error::{Error, Result};
use crate::fatimg::{build_fat32, read_fat_file};
use crate::firmware::{copy_vars, select_firmware, uboot_binary};
use crate::fixtures::build_fixture;
use crate::gpt::{PartitionSpec, SECTOR, build_gpt, esp_guid, validate_gpt};
use crate::host::host_facts;
use crate::launch::{AttachedDisk, LaunchPlan, NetworkAttach, qemu_args};
use crate::markers::{boot_target_paths, firmware_banner, log_tail, parse_markers};
use crate::product::build_menu_disk;
use crate::profile::{BootKind, NetworkMode, Profile, Role};
use crate::proxy::DelayProxy;
use crate::qmp::Qmp;
use crate::resources::{
    AdmitRequest, clamp_launch, clear_noted_qemu_pid, hold_for_run, note_qemu_pid, tie_to_parent,
    workload_for,
};
use crate::util::{
    FileLock, env_u32, pe_machine, reject_host_device, sha256_file, short_id, which, write_file,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub profile: Profile,
    pub fixture: Option<String>,
    pub efi: Option<PathBuf>,
    pub core: Option<PathBuf>,
    pub extra_disks: Vec<PathBuf>,
    pub secure_boot: Option<bool>,
    pub tpm: Option<bool>,
    pub graphical: bool,
    pub network: Option<NetworkMode>,
    pub timeout_secs: u64,
    pub keep: bool,
    pub keep_failed: bool,
    pub memory_mib: Option<u32>,
    pub cpus: Option<u32>,
    pub screenshot: Option<PathBuf>,
    pub send_key: Option<String>,
    pub chainload: bool,
    pub journal: bool,
    pub corrupt_vars: bool,
    pub io_error: bool,
    pub drop_link: bool,
    pub inject_probe: bool,
    pub artifacts_dir: Option<PathBuf>,
    pub accel: AccelRequest,
    pub boot: BootKind,
    pub send_key_after: String,
    pub stop_on_expect: bool,
    pub expect: Vec<String>,
    pub stop_on_serial: Vec<String>,
    pub require_files: Vec<String>,
    pub reset_after: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SafetyReport {
    pub backing_hashes_unchanged: bool,
    pub firmware_code_unchanged: bool,
    pub firmware_template_unchanged: bool,
    pub physical_disks_passed_through: bool,
}

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub schema: &'static str,
    pub id: String,
    pub profile: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub arch: String,
    pub accel: String,
    pub execution_class: String,
    pub representative_of_physical_hardware: bool,
    pub execution_note: String,
    pub firmware_banner: Option<String>,
    pub markers: Vec<String>,
    pub boot_targets: Vec<String>,
    pub screenshot: Option<String>,
    pub guest_screenshot: Option<String>,
    pub serial_log: String,
    pub duration_ms: u64,
    pub stages_ms: BTreeMap<String, u64>,
    pub qemu_argv: Vec<String>,
    pub safety: SafetyReport,
    pub kept: bool,
    pub run_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_class: Option<String>,
}

struct Slot(PathBuf);
impl Drop for Slot {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn execute_run(root: &Path, opts: &RunOptions) -> Result<RunReport> {
    let _slot = acquire_slot(root)?;
    let id = short_id();
    let run_dir = root.join("var/runs").join(&id);
    fs::create_dir_all(&run_dir)?;
    let arch = opts.profile.arch;
    let secure = opts.secure_boot.unwrap_or(opts.profile.secure_boot);
    let tpm = opts.tpm.unwrap_or(opts.profile.tpm);
    let network = opts.network.unwrap_or(opts.profile.network);
    let requested_memory = opts
        .memory_mib
        .unwrap_or(opts.profile.memory_mib)
        .min(env_u32("SBM_LAB_MAX_MEMORY_MIB", 8192));
    let requested_cpus = opts
        .cpus
        .unwrap_or(opts.profile.cpus)
        .clamp(1, env_u32("SBM_LAB_MAX_CPUS", 4));
    let workload = workload_for(
        opts.profile.role,
        opts.profile.gpu,
        opts.graphical || opts.core.is_some(),
    );
    let (memory, cpus) = clamp_launch(
        workload,
        requested_memory,
        requested_cpus,
        opts.memory_mib.is_some(),
        opts.cpus.is_some(),
    )?;
    let mut budget = hold_for_run(
        root,
        &AdmitRequest {
            owner_pid: 0,
            repo: root.display().to_string(),
            workload,
            memory_mib: memory,
            cpus,
            detached: false,
        },
    )?;
    let qemu_name = arch.qemu_binary();
    let qemu_bin =
        which(qemu_name).ok_or_else(|| Error::message(format!("{qemu_name} is not installed")))?;
    let live = host_facts();
    let accels = qemu_accel_list(&qemu_bin);
    let facts = HostFacts {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hv_support: live.hv_support,
        kvm_usable: live.kvm_usable,
        qemu_accels: accels,
    };
    let request = if opts.accel == AccelRequest::Auto {
        opts.profile.accel
    } else {
        opts.accel
    };
    let choice = select_accel(&facts, arch, request).map_err(Error::message)?;
    let machine = if arch == Arch::Aarch64 {
        "virt,gic-version=3".into()
    } else if opts.profile.machine == "virt" {
        "virt".into()
    } else {
        opts.profile.machine.clone()
    };
    let (code, vars_template, requires_smm, bios) = if opts.profile.id == "legacy-bios" {
        (None, None, false, None)
    } else if opts.profile.id == "uboot-efi" {
        let bios = uboot_binary(root)
            .ok_or_else(|| Error::message("U-Boot binary is missing; run sbm-lab setup --uboot"))?;
        (None, None, false, Some(bios))
    } else {
        let fw = select_firmware(
            Some(&qemu_bin),
            arch,
            secure,
            &machine_key(&opts.profile.machine, arch),
        )?;
        let vars = if let Some(rel) = &opts.profile.vars_template {
            let path = root.join(rel);
            if !path.is_file() {
                return Err(Error::message(format!(
                    "variable template {} is missing; run sbm-lab setup --secure-boot",
                    path.display()
                )));
            }
            path
        } else {
            fw.vars_template
        };
        (Some(fw.code), Some(vars), fw.requires_smm, None)
    };
    let code_hash = code.as_ref().map(|p| sha256_file(p)).transpose()?;
    let vars_hash = vars_template.as_ref().map(|p| sha256_file(p)).transpose()?;
    let vars_copy = if let Some(template) = &vars_template {
        let dest = run_dir.join("vars.fd");
        copy_vars(template, &dest)?;
        if opts.corrupt_vars {
            corrupt_middle(&dest)?;
        }
        Some(dest)
    } else {
        None
    };
    let mut backing_hashes = Vec::new();
    let mut disks = Vec::new();
    let mut usb_disks = Vec::new();
    let mut payload_class = None;
    let boot = if opts.boot == BootKind::Probe {
        opts.profile.boot
    } else {
        opts.boot
    };
    if opts.profile.role == Role::BuildVm {
        let image = find_build_image(root)?;
        reject_host_device(&image)?;
        let hash = sha256_file(&image)?;
        backing_hashes.push((image.clone(), hash));
        let overlay = run_dir.join("build-vm.qcow2");
        qemu_img_overlay(&image, &overlay, &image_format(&image)?)?;
        disks.push(AttachedDisk {
            id: "root".into(),
            path: overlay,
            format: "qcow2".into(),
            bootindex: 0,
            blkdebug: None,
            serial: None,
        });
        let seed = run_dir.join("cidata.raw");
        fs::write(&seed, cloud_seed()?)?;
        disks.push(AttachedDisk {
            id: "cidata".into(),
            path: seed,
            format: "raw".into(),
            bootindex: 1,
            blkdebug: None,
            serial: None,
        });
    } else if opts.inject_probe
        && opts.profile.id != "legacy-bios"
        && opts.profile.id != "ia32-uefi"
    {
        let probe = if boot == BootKind::SbmMenu {
            let built = build_menu_disk(root, arch, opts.core.as_deref())?;
            payload_class = Some(built.payload_class);
            let path = run_dir.join("probe.raw");
            fs::write(&path, built.bytes)?;
            if opts.core.is_some() {
                let scratch = run_dir.join("scratch.raw");
                File::create(&scratch)?.set_len(64 * 1024 * 1024)?;
                disks.push(AttachedDisk {
                    id: "scratch".into(),
                    path: scratch,
                    format: "raw".into(),
                    bootindex: 2,
                    blkdebug: None,
                    serial: None,
                });
            }
            path
        } else {
            build_probe_disk(root, &run_dir, arch, opts)?
        };
        disks.push(AttachedDisk {
            id: "probe".into(),
            path: probe,
            format: "raw".into(),
            bootindex: 0,
            blkdebug: None,
            serial: None,
        });
    }
    let fixture_names = if let Some(name) = &opts.fixture {
        vec![name.clone()]
    } else {
        opts.profile.disks.clone()
    };
    for (index, name) in fixture_names.iter().enumerate() {
        let backing = ensure_fixture(root, name)?;
        let hash = sha256_file(&backing)?;
        backing_hashes.push((backing.clone(), hash));
        let overlay = run_dir.join(format!("overlay-{index}.qcow2"));
        qemu_img_overlay(&backing, &overlay, "qcow2")?;
        let format = "qcow2".to_string();
        let blkdebug = if opts.io_error {
            let cfg = run_dir.join(format!("blkdebug-{index}.cfg"));
            fs::write(
                &cfg,
                "[inject-error]\nevent = \"read_aio\"\nerrno = \"5\"\nonce = \"off\"\n",
            )?;
            Some(cfg)
        } else {
            None
        };
        let attached = AttachedDisk {
            id: format!("disk{index}"),
            path: overlay,
            format,
            bootindex: (index as u32) + 1,
            blkdebug,
            serial: None,
        };
        if opts.profile.usb && index + 1 == fixture_names.len() {
            usb_disks.push(attached);
        } else {
            disks.push(attached);
        }
    }
    for (index, extra) in opts.extra_disks.iter().enumerate() {
        reject_host_device(extra)?;
        disks.push(AttachedDisk {
            id: format!("extra{index}"),
            path: extra.clone(),
            format: if extra.extension().and_then(|s| s.to_str()) == Some("qcow2") {
                "qcow2".into()
            } else {
                "raw".into()
            },
            bootindex: 10 + index as u32,
            blkdebug: None,
            serial: None,
        });
    }
    let serial_log = run_dir.join("serial-qemu.log");
    let qmp_socket = run_dir.join("qmp.sock");
    check_socket_len(&qmp_socket)?;
    let debugcon = if matches!(arch, Arch::X86_64 | Arch::Ia32) {
        Some(run_dir.join("debugcon.log"))
    } else {
        None
    };
    let mut proxy = None;
    let network_attach = match network {
        NetworkMode::None => None,
        NetworkMode::User => Some(NetworkAttach {
            mode: "user".into(),
            connect: None,
        }),
        NetworkMode::Slow => {
            let started = DelayProxy::start(Duration::from_millis(200))?;
            let connect = started.addr.clone();
            proxy = Some(started);
            Some(NetworkAttach {
                mode: "slow".into(),
                connect: Some(connect),
            })
        }
    };
    let tpm_socket = if tpm {
        let sock = run_dir.join("swtpm.sock");
        check_socket_len(&sock)?;
        Some(sock)
    } else {
        None
    };
    let plan = LaunchPlan {
        bin: qemu_bin.clone(),
        arch,
        host_arch: facts.arch.clone(),
        accel: choice.accel,
        machine,
        memory_mib: memory,
        cpus,
        secure_boot: secure,
        requires_smm,
        code: code.clone(),
        vars: vars_copy.clone(),
        bios: bios.clone(),
        disks,
        usb_disks,
        gpu: opts.profile.gpu,
        network: network_attach,
        tpm_socket: tpm_socket.clone(),
        guest_agent_socket: if opts.profile.guest_agent {
            Some(run_dir.join("qga.sock"))
        } else {
            None
        },
        serial_socket: serial_log.clone(),
        qmp_socket: qmp_socket.clone(),
        debugcon: debugcon.clone(),
        graphical: opts.graphical,
        allow_reboot: opts.reset_after.is_some(),
    };
    let argv = qemu_args(&plan)?;
    fs::write(run_dir.join("qemu.argv"), argv.join("\n"))?;
    let mut swtpm = if let Some(sock) = &tpm_socket {
        let bin = which("swtpm").ok_or_else(|| Error::message("swtpm is not installed"))?;
        Some(start_swtpm(
            &bin,
            &run_dir.join("tpm"),
            sock,
            &run_dir.join("swtpm.log"),
        )?)
    } else {
        None
    };
    let stdout = File::create(run_dir.join("qemu.stdout"))?;
    let stderr_path = run_dir.join("qemu.stderr");
    let stderr = File::create(&stderr_path)?;
    let mut command = Command::new(&qemu_bin);
    tie_to_parent(&mut command);
    let mut child = command
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    budget.attach_qemu(child.id())?;
    note_qemu_pid(child.id());
    let started = Instant::now();
    let mut failure = None;
    let timeout_secs = effective_timeout(&facts.arch, arch, opts.timeout_secs);
    let observed = match observe(
        &mut child,
        &run_dir,
        &serial_log,
        &qmp_socket,
        opts,
        started,
        timeout_secs,
    ) {
        Ok(value) => value,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            budget.mark_reaped();
            failure = Some(err.to_string());
            Observed::default()
        }
    };
    if child.try_wait().ok().flatten().is_some() {
        budget.mark_reaped();
    }
    if let Some(proc) = swtpm.as_mut() {
        let _ = proc.kill();
        let _ = proc.wait();
    }
    let _ = proxy;
    let stderr_tail = fs::read_to_string(&stderr_path).unwrap_or_default();
    if failure.is_none()
        && !stderr_tail.is_empty()
        && observed.serial.is_empty()
        && observed.exit_code.is_some_and(|c| c != 0)
    {
        failure = Some(stderr_tail.chars().take(2000).collect());
    }
    let mut text = observed.serial.clone();
    if let Some(debug) = &debugcon
        && let Ok(extra) = fs::read_to_string(debug)
    {
        text.push_str(&extra);
    }
    let probe_raw = run_dir.join("probe.raw");
    let mut guest_shot = None;
    if probe_raw.is_file() {
        if let Ok(bytes) = read_probe_file(&probe_raw, "EFI/sbm-lab/result.txt") {
            text.push_str(&String::from_utf8_lossy(&bytes));
        }
        if let Ok(bytes) = read_probe_file(&probe_raw, "EFI/sbm-lab/payload-result.txt") {
            text.push_str(&String::from_utf8_lossy(&bytes));
        }
        if let Ok(bytes) = read_probe_file(&probe_raw, "EFI/sbm-lab/gop.ppm") {
            let dest = run_dir.join("guest-gop.ppm");
            let _ = fs::write(&dest, &bytes);
            guest_shot = Some(dest.display().to_string());
        }
    }
    fs::write(run_dir.join("serial.log"), &text)?;
    let mut seen_markers = Vec::new();
    let markers: Vec<_> = parse_markers(&text)
        .into_iter()
        .filter(|marker| {
            if seen_markers.contains(&marker.raw) {
                false
            } else {
                seen_markers.push(marker.raw.clone());
                true
            }
        })
        .collect();
    let banner = firmware_banner(&text).or_else(|| {
        debugcon.as_ref().and_then(|p| {
            fs::read_to_string(p)
                .ok()
                .as_deref()
                .and_then(firmware_banner)
        })
    });
    let code_ok = match (&code, &code_hash) {
        (Some(path), Some(hash)) => sha256_file(path).ok().as_ref() == Some(hash),
        _ => true,
    };
    let vars_ok = match (&vars_template, &vars_hash) {
        (Some(path), Some(hash)) => sha256_file(path).ok().as_ref() == Some(hash),
        _ => true,
    };
    let backing_ok = backing_hashes
        .iter()
        .all(|(path, hash)| sha256_file(path).ok().as_ref() == Some(hash));
    let safety = SafetyReport {
        backing_hashes_unchanged: backing_ok,
        firmware_code_unchanged: code_ok,
        firmware_template_unchanged: vars_ok,
        physical_disks_passed_through: false,
    };
    if !backing_ok || !code_ok || !vars_ok {
        failure.get_or_insert_with(|| "firmware or fixture backing file changed".into());
    }
    if failure.is_none()
        && opts.inject_probe
        && opts.profile.role != Role::BuildVm
        && boot == BootKind::Probe
        && opts.profile.id != "legacy-bios"
        && opts.profile.id != "ia32-uefi"
        && !markers.iter().any(|marker| marker.name == "efi-launched")
        && banner.is_none()
    {
        failure = Some("guest did not emit efi-launched".into());
    }
    if failure.is_none()
        && opts.profile.role == Role::BuildVm
        && !markers.iter().any(|marker| marker.name == "build-vm-ready")
    {
        failure = Some("build VM did not emit build-vm-ready".into());
    }
    if failure.is_none() && probe_raw.is_file() {
        for path in &opts.require_files {
            if read_probe_file(&probe_raw, path).is_err() {
                failure = Some(format!("boot disk is missing {path}"));
                break;
            }
        }
    }
    let shot = run_dir.join("screenshot.ppm");
    let screenshot = shot.is_file().then(|| shot.display().to_string());
    if let Some(dest) = &opts.screenshot
        && shot.is_file()
    {
        let _ = fs::copy(&shot, dest);
    }
    let success = failure.is_none();
    let kept = if success {
        opts.keep
    } else {
        opts.keep_failed || opts.keep
    };
    let report = RunReport {
        schema: "sbm-lab.run.v1",
        id: id.clone(),
        profile: opts.profile.id.clone(),
        success,
        failure_reason: failure,
        arch: arch.to_string(),
        accel: choice.accel.to_string(),
        execution_class: choice.execution_class.as_str().into(),
        representative_of_physical_hardware: false,
        execution_note: choice.note,
        firmware_banner: banner,
        markers: markers.iter().map(|m| m.raw.clone()).collect(),
        boot_targets: boot_target_paths(&markers),
        screenshot,
        guest_screenshot: guest_shot,
        serial_log: run_dir.join("serial.log").display().to_string(),
        duration_ms: started.elapsed().as_millis() as u64,
        stages_ms: observed.stages,
        qemu_argv: argv,
        safety,
        kept,
        run_dir: run_dir.display().to_string(),
        payload_class,
    };
    write_file(
        &run_dir.join("result.json"),
        serde_json::to_string_pretty(&report)?.as_bytes(),
    )?;
    if let Some(dir) = &opts.artifacts_dir {
        fs::create_dir_all(dir)?;
        let _ = fs::copy(
            run_dir.join("result.json"),
            dir.join(format!("{id}-result.json")),
        );
        let _ = fs::copy(
            run_dir.join("serial.log"),
            dir.join(format!("{id}-serial.log")),
        );
        if shot.is_file() {
            let _ = fs::copy(&shot, dir.join(format!("{id}-screenshot.ppm")));
        }
    }
    if !kept {
        let _ = fs::remove_file(run_dir.join("probe.raw"));
        for entry in fs::read_dir(&run_dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("qcow2") {
                let _ = fs::remove_file(path);
            }
        }
        let _ = fs::remove_file(run_dir.join("vars.fd"));
    }
    Ok(report)
}

#[derive(Default)]
struct Observed {
    serial: String,
    stages: BTreeMap<String, u64>,
    exit_code: Option<i32>,
}

fn observe(
    child: &mut Child,
    run_dir: &Path,
    serial_socket: &Path,
    qmp_socket: &Path,
    opts: &RunOptions,
    started: Instant,
    timeout_secs: u64,
) -> Result<Observed> {
    let deadline = started + Duration::from_secs(timeout_secs.max(1));
    let mut serial = open_serial(serial_socket, deadline)?;
    let mut qmp = connect_qmp(qmp_socket, deadline).ok();
    let mut buf = String::new();
    let mut stages = BTreeMap::new();
    let mut shot = false;
    let mut keyed = false;
    let mut dropped = false;
    let mut reset = false;
    let mut exit_code = None;
    let mut expect = opts.expect.clone();
    if opts.profile.role == Role::BuildVm && !expect.iter().any(|name| name == "build-vm-ready") {
        expect.push("build-vm-ready".into());
    }
    let stop_when_expected = opts.stop_on_expect || opts.profile.role == Role::BuildVm;
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            clear_noted_qemu_pid(child.id());
            if opts.journal {
                return Err(Error::message("timed out before journal-begin"));
            }
            break;
        }
        if let Some(status) = child.try_wait()? {
            clear_noted_qemu_pid(child.id());
            exit_code = status.code();
            break;
        }
        let mut tmp = [0u8; 4096];
        match serial.read(&mut tmp) {
            Ok(0) => std::thread::sleep(Duration::from_millis(20)),
            Ok(n) => {
                buf.push_str(&String::from_utf8_lossy(&tmp[..n]));
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
        let markers = parse_markers(&buf);
        for marker in &markers {
            stages
                .entry(marker.name.clone())
                .or_insert_with(|| started.elapsed().as_millis() as u64);
        }
        let names: Vec<&str> = markers.iter().map(|m| m.name.as_str()).collect();
        let key_after = if opts.send_key_after.is_empty() {
            "waiting-for-key"
        } else {
            opts.send_key_after.as_str()
        };
        if (names.contains(&"gop-ready")
            || names.contains(&"menu_ready")
            || names.contains(&"first_frame"))
            && !shot
            && let Some(qmp) = qmp.as_mut()
        {
            let path = run_dir.join("screenshot.ppm");
            let _ = qmp.screendump(&path);
            shot = path.is_file();
        }
        if names.contains(&key_after)
            && !keyed
            && let Some(key) = &opts.send_key
            && let Some(qmp) = qmp.as_mut()
        {
            let _ = qmp.send_key(key);
            keyed = true;
        }
        if opts.drop_link
            && !dropped
            && let Some(qmp) = qmp.as_mut()
        {
            let _ = qmp.set_link("nic0", false);
            dropped = true;
        }
        if opts.journal && names.contains(&"journal-begin") {
            std::thread::sleep(Duration::from_millis(200));
            let _ = child.kill();
            let _ = child.wait();
            clear_noted_qemu_pid(child.id());
            break;
        }
        if names.contains(&"halt") && !opts.journal {
            std::thread::sleep(Duration::from_millis(200));
            if let Some(qmp) = qmp.as_mut() {
                let _ = qmp.quit();
            }
            let _ = child.wait();
            clear_noted_qemu_pid(child.id());
            break;
        }
        if let Some(after) = &opts.reset_after
            && !reset
            && names.contains(&after.as_str())
            && let Some(qmp) = qmp.as_mut()
        {
            let _ = qmp.system_reset();
            reset = true;
        }
        if opts
            .stop_on_serial
            .iter()
            .any(|needle| buf.contains(needle))
        {
            std::thread::sleep(Duration::from_millis(200));
            if let Some(qmp) = qmp.as_mut() {
                let _ = qmp.quit();
            }
            let _ = child.wait();
            clear_noted_qemu_pid(child.id());
            break;
        }
        let ready = !expect.is_empty()
            && expect.iter().all(|name| {
                markers
                    .iter()
                    .any(|marker| marker.name == *name || marker.raw.starts_with(name))
            });
        let menu_ready_count = markers
            .iter()
            .filter(|marker| marker.name == "menu_ready")
            .count();
        let reset_satisfied = opts.reset_after.is_none() || (reset && menu_ready_count >= 2);
        if stop_when_expected && ready && reset_satisfied {
            std::thread::sleep(Duration::from_millis(200));
            if let Some(qmp) = qmp.as_mut() {
                let _ = qmp.quit();
            }
            let _ = child.wait();
            clear_noted_qemu_pid(child.id());
            break;
        }
    }
    if !shot && let Some(qmp) = qmp.as_mut() {
        let _ = qmp.screendump(&run_dir.join("screenshot.ppm"));
    }
    Ok(Observed {
        serial: buf,
        stages,
        exit_code,
    })
}

fn open_serial(path: &Path, deadline: Instant) -> Result<File> {
    loop {
        if Instant::now() > deadline {
            return Err(Error::message(format!(
                "timed out waiting for {}",
                path.display()
            )));
        }
        match File::open(path) {
            Ok(file) => return Ok(file),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn connect_qmp(path: &Path, deadline: Instant) -> Result<Qmp> {
    loop {
        if Instant::now() > deadline {
            return Err(Error::message("timed out connecting to qmp"));
        }
        match Qmp::connect(path) {
            Ok(qmp) => return Ok(qmp),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn build_probe_disk(root: &Path, run_dir: &Path, arch: Arch, opts: &RunOptions) -> Result<PathBuf> {
    let boot_name = arch.boot_file();
    let efi_path = if let Some(path) = &opts.efi {
        reject_host_device(path)?;
        path.clone()
    } else {
        probe_efi(root, arch).ok_or_else(|| {
            Error::message(format!(
                "probe EFI for {arch} is missing; run sbm-lab setup"
            ))
        })?
    };
    let efi_bytes = fs::read(&efi_path)?;
    if let Some(machine) = pe_machine(&efi_bytes) {
        let expected = match arch {
            Arch::X86_64 => 0x8664,
            Arch::Aarch64 => 0xAA64,
            Arch::Ia32 => 0x14C,
        };
        if machine != expected {
            return Err(Error::message(format!(
                "{} is PE machine {machine:#x}, not {expected:#x} for {arch}",
                efi_path.display()
            )));
        }
    }
    let boot_efi = boot_name.rsplit('/').next().unwrap_or("BOOTX64.EFI");
    let nsh = format!("echo -off\r\nfs0:\\EFI\\BOOT\\{boot_efi}\r\n");
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (boot_name.into(), efi_bytes),
        ("startup.nsh".into(), nsh.into_bytes()),
        ("EFI/sbm-lab/role.txt".into(), b"probe\n".to_vec()),
    ];
    if opts.chainload
        && let Some(payload) = payload_efi(root, arch)
    {
        files.push(("EFI/sbm-lab/payload.efi".into(), fs::read(payload)?));
        files.push(("EFI/sbm-lab/auto-chainload".into(), b"1\n".to_vec()));
    }
    if opts.send_key.is_some() {
        files.push(("EFI/sbm-lab/wait-key".into(), b"1\n".to_vec()));
    }
    if opts.journal {
        files.push(("EFI/sbm-lab/journal-loop".into(), b"1\n".to_vec()));
    }
    if let Some(core) = &opts.core {
        reject_host_device(core)?;
        let bytes = fs::read(core)?;
        files.push(("EFI/Linux/sbm-core.efi".into(), bytes));
        files.push((
            "EFI/Linux/sbm-core.uki-note".into(),
            b"attached by sbm-lab --core\n".to_vec(),
        ));
    }
    let mut manifest = String::new();
    for (path, _) in &files {
        manifest.push_str(path);
        manifest.push('\n');
    }
    files.push(("EFI/sbm-lab/manifest.txt".into(), manifest.into_bytes()));
    let borrowed: Vec<(String, &[u8])> = files
        .iter()
        .map(|(p, b)| (p.clone(), b.as_slice()))
        .collect();
    let fat = build_fat32(48 * 1024 * 1024, "PROBE", &borrowed)?;
    let disk = build_gpt(
        "probe",
        &[PartitionSpec {
            name: "ESP".into(),
            type_guid: esp_guid(),
            size_bytes: fat.len() as u64,
            payload: fat,
        }],
        false,
    )?;
    let path = run_dir.join("probe.raw");
    fs::write(&path, &disk.bytes)?;
    Ok(path)
}

pub fn probe_efi(root: &Path, arch: Arch) -> Option<PathBuf> {
    let target = match arch {
        Arch::X86_64 => "x86_64-unknown-uefi",
        Arch::Aarch64 => "aarch64-unknown-uefi",
        Arch::Ia32 => return None,
    };
    let path = root
        .join("fixtures/efi-probe/target")
        .join(target)
        .join("release/efi-probe.efi");
    path.is_file().then_some(path)
}

fn payload_efi(root: &Path, arch: Arch) -> Option<PathBuf> {
    let target = match arch {
        Arch::X86_64 => "x86_64-unknown-uefi",
        Arch::Aarch64 => "aarch64-unknown-uefi",
        Arch::Ia32 => return None,
    };
    let path = root
        .join("fixtures/efi-probe/target")
        .join(target)
        .join("release/efi-payload.efi");
    path.is_file().then_some(path)
}

fn read_probe_file(image: &Path, fat_path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(image)?;
    let parts = validate_gpt(&bytes)?;
    let Some(part) = parts.first() else {
        return Err(Error::message("probe disk has no partition"));
    };
    let off = (part.start_lba * SECTOR) as usize;
    let end = ((part.end_lba + 1) * SECTOR) as usize;
    if end > bytes.len() {
        return Err(Error::message("probe partition is out of range"));
    }
    read_fat_file(&bytes[off..end], fat_path)
}

pub fn ensure_fixture(root: &Path, id: &str) -> Result<PathBuf> {
    let dir = root.join("var/fixtures");
    fs::create_dir_all(&dir)?;
    let _lock = FileLock::exclusive(&dir.join(".lock"))?;
    let qcow = dir.join(format!("{id}.qcow2"));
    if qcow.is_file() {
        return Ok(qcow);
    }
    let fixture = build_fixture(id, &dir)?;
    let raw = dir.join(format!("{id}.raw"));
    fs::write(&raw, &fixture.disk.bytes)?;
    fs::write(
        dir.join(format!("{id}.json")),
        serde_json::to_string_pretty(&fixture.manifest)?,
    )?;
    qemu_img_convert(&raw, &qcow)?;
    Ok(qcow)
}

fn qemu_img_convert(raw: &Path, qcow: &Path) -> Result<()> {
    let bin = which("qemu-img").ok_or_else(|| Error::message("qemu-img is not installed"))?;
    let status = Command::new(bin)
        .args(["convert", "-f", "raw", "-O", "qcow2"])
        .arg(raw)
        .arg(qcow)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(Error::message("qemu-img convert failed"));
    }
    Ok(())
}

fn qemu_img_overlay(backing: &Path, overlay: &Path, format: &str) -> Result<()> {
    reject_host_device(backing)?;
    let bin = which("qemu-img").ok_or_else(|| Error::message("qemu-img is not installed"))?;
    let backing = fs::canonicalize(backing)?;
    let status = Command::new(bin)
        .args(["create", "-f", "qcow2", "-b"])
        .arg(&backing)
        .args(["-F", format])
        .arg(overlay)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(Error::message(format!(
            "qemu-img create overlay failed for {}",
            backing.display()
        )));
    }
    Ok(())
}

fn start_swtpm(bin: &Path, dir: &Path, sock: &Path, log: &Path) -> Result<Child> {
    fs::create_dir_all(dir)?;
    if let Some(setup) = which("swtpm_setup") {
        let _ = Command::new(setup)
            .args([
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", dir.display()),
                "--create-ek-cert",
                "--create-platform-cert",
                "--lock-nvram",
                "--not-overwrite",
            ])
            .status();
    }
    let child = Command::new(bin)
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", dir.display()),
            "--ctrl",
            &format!("type=unixio,path={}", sock.display()),
            "--flags",
            "not-need-init,startup-clear",
            "--log",
            &format!("file={},level=2", log.display()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child)
}

fn corrupt_middle(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let len = file.metadata()?.len();
    if len < 16 {
        return Ok(());
    }
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(len / 2))?;
    file.write_all(&[0xA5])?;
    Ok(())
}

fn machine_key(machine: &str, arch: Arch) -> String {
    if arch == Arch::Aarch64 {
        "virt".into()
    } else if machine.contains("pc") && !machine.contains("q35") {
        "pc".into()
    } else {
        "q35".into()
    }
}

fn qemu_accel_list(bin: &Path) -> Vec<String> {
    let Ok(output) = Command::new(bin).args(["-accel", "help"]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(' '))
        .map(str::to_string)
        .collect()
}

fn check_socket_len(path: &Path) -> Result<()> {
    if path.as_os_str().len() >= 100 {
        return Err(Error::message(format!(
            "socket path is too long for macOS: {}",
            path.display()
        )));
    }
    Ok(())
}

fn acquire_slot(root: &Path) -> Result<Slot> {
    let max = env_u32("SBM_LAB_MAX_CONCURRENT", 2).max(1) as usize;
    let dir = root.join("var/runs");
    fs::create_dir_all(&dir)?;
    for _ in 0..2 {
        for i in 0..max {
            let path = dir.join(format!(".slot-{i}"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id())?;
                    return Ok(Slot(path));
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Ok(text) = fs::read_to_string(&path)
                        && let Ok(pid) = text.trim().parse::<i32>()
                        && !pid_alive(pid)
                    {
                        let _ = fs::remove_file(&path);
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
    Err(Error::message(
        "too many concurrent sbm-lab runs; raise SBM_LAB_MAX_CONCURRENT or run sbm-lab clean --stop",
    ))
}

fn pid_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

#[derive(Clone, Copy)]
pub struct ScenarioCheck<'a> {
    pub expect: &'a [String],
    pub require: &'a [String],
    pub forbid: &'a [String],
    pub serial_contains: &'a [String],
    pub mode: &'a str,
    pub screenshot: &'a str,
    pub forbid_markers: &'a [String],
    pub serial_contains_any: &'a [String],
    pub reset_after: Option<&'a str>,
}

/// Scenario assertions are the contract for `sbm-lab test`. A denial
/// scenario passes when Secure Boot prints `Access Denied` and the probe
/// never emits `efi-launched`. That serial has no `edk2-` banner on Ubuntu
/// OVMF, so the generic launch check must not keep the run failed.
pub fn apply_scenario(mut report: RunReport, check: &ScenarioCheck<'_>) -> RunReport {
    match scenario_passed(&report, check) {
        Ok(()) => {
            let generic =
                report.failure_reason.as_deref() == Some("guest did not emit efi-launched");
            let expects_launch = check
                .expect
                .iter()
                .any(|name| name == "efi-launched" || name.starts_with("efi-launched "));
            if generic && !expects_launch {
                report.success = true;
                report.failure_reason = None;
            }
            report
        }
        Err(err) => {
            let previous = report.failure_reason.clone();
            report.success = false;
            report.failure_reason = Some(match previous {
                Some(previous) if !previous.is_empty() => format!("{previous}; {err}"),
                _ => err.to_string(),
            });
            report
        }
    }
}

pub fn scenario_passed(report: &RunReport, check: &ScenarioCheck<'_>) -> Result<()> {
    let ScenarioCheck {
        expect,
        require,
        forbid,
        serial_contains,
        mode,
        screenshot,
        forbid_markers,
        serial_contains_any,
        reset_after,
    } = *check;
    if !report.safety.backing_hashes_unchanged
        || !report.safety.firmware_template_unchanged
        || report.safety.physical_disks_passed_through
    {
        return Err(Error::message("safety check failed"));
    }
    if mode == "observe" || mode == "power-loss" {
        if mode == "power-loss" && !report.markers.iter().any(|m| m.contains("journal-begin")) {
            return Err(Error::message("power-loss did not observe journal-begin"));
        }
        return Ok(());
    }
    if mode == "serial" {
        let text = fs::read_to_string(&report.serial_log).unwrap_or_default();
        for needle in serial_contains {
            if !text.contains(needle) {
                return Err(Error::message(format!("serial missing {needle}")));
            }
        }
        return Ok(());
    }
    for name in expect {
        if !report.markers.iter().any(|m| m.starts_with(name)) {
            return Err(Error::message(format!(
                "missing marker {name}\n{}",
                evidence(report)
            )));
        }
    }
    for name in forbid_markers {
        if report.markers.iter().any(|m| m.starts_with(name)) {
            return Err(Error::message(format!(
                "forbidden marker {name} was present\n{}",
                evidence(report)
            )));
        }
    }
    if reset_after.is_some() {
        let ready = report
            .markers
            .iter()
            .filter(|marker| marker.starts_with("menu_ready"))
            .count();
        if ready < 2 {
            return Err(Error::message(format!(
                "reset did not return to the menu\n{}",
                evidence(report)
            )));
        }
    }
    let serial = fs::read_to_string(&report.serial_log).unwrap_or_default();
    for needle in serial_contains {
        if !serial.contains(needle) {
            return Err(Error::message(format!(
                "serial missing {needle}\n{}",
                evidence(report)
            )));
        }
    }
    if !serial_contains_any.is_empty()
        && !serial_contains_any
            .iter()
            .any(|needle| serial.contains(needle))
    {
        return Err(Error::message(format!(
            "serial missing any of {}\n{}",
            serial_contains_any.join(", "),
            evidence(report)
        )));
    }
    let joined = report.boot_targets.join("\n") + &report.markers.join("\n");
    for needle in require {
        if !joined.contains(needle) {
            return Err(Error::message(format!("missing boot path {needle}")));
        }
    }
    for needle in forbid {
        if joined.contains(needle) {
            return Err(Error::message(format!(
                "forbidden path {needle} was present"
            )));
        }
    }
    if screenshot == "qmp" {
        let Some(path) = &report.screenshot else {
            return Err(Error::message("QMP screenshot was not captured"));
        };
        let bytes = fs::read(path)?;
        if !crate::proxy::ppm_has_variance(&bytes)? {
            return Err(Error::message("screenshot is blank"));
        }
    }
    if screenshot == "any" {
        let qmp_ok = report
            .screenshot
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .is_some_and(|b| crate::proxy::ppm_has_variance(&b).unwrap_or(false));
        let guest_ok = report
            .guest_screenshot
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .is_some_and(|b| crate::proxy::ppm_has_variance(&b).unwrap_or(false));
        if !qmp_ok && !guest_ok {
            return Err(Error::message(
                "neither QMP nor guest screenshot was captured",
            ));
        }
    }
    Ok(())
}

fn evidence(report: &RunReport) -> String {
    let serial = fs::read_to_string(&report.serial_log).unwrap_or_default();
    let stderr =
        fs::read_to_string(Path::new(&report.run_dir).join("qemu.stderr")).unwrap_or_default();
    format!(
        "serial:\n{}\nqemu.stderr:\n{}",
        log_tail(&serial, 12),
        log_tail(&stderr, 8)
    )
}

#[cfg(test)]
mod tests {
    use super::{RunReport, SafetyReport, ScenarioCheck, apply_scenario};
    use std::fs;

    fn denied(serial: &std::path::Path, reason: Option<&str>) -> RunReport {
        RunReport {
            schema: "sbm-lab.run/v1",
            id: "deny".into(),
            profile: "secure".into(),
            success: false,
            failure_reason: reason.map(str::to_string),
            arch: "x86_64".into(),
            accel: "tcg".into(),
            execution_class: "emulated".into(),
            representative_of_physical_hardware: false,
            execution_note: String::new(),
            firmware_banner: None,
            markers: Vec::new(),
            boot_targets: Vec::new(),
            screenshot: None,
            guest_screenshot: None,
            serial_log: serial.display().to_string(),
            duration_ms: 1,
            stages_ms: Default::default(),
            qemu_argv: Vec::new(),
            safety: SafetyReport {
                backing_hashes_unchanged: true,
                firmware_code_unchanged: true,
                firmware_template_unchanged: true,
                physical_disks_passed_through: false,
            },
            kept: true,
            run_dir: serial.parent().unwrap().display().to_string(),
            payload_class: None,
        }
    }

    #[test]
    fn access_denied_without_a_firmware_banner_passes_a_denial_scenario() {
        let dir = std::env::temp_dir().join(format!("sbm-deny-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let serial = dir.join("serial.log");
        fs::write(
            &serial,
            "BdsDxe: failed to load Boot0002 ... Access Denied -- rejected probably by Secure Boot\n",
        )
        .unwrap();
        let check = ScenarioCheck {
            expect: &[],
            require: &[],
            forbid: &[],
            serial_contains: &[],
            mode: "markers",
            screenshot: "off",
            forbid_markers: &["efi-launched".into()],
            serial_contains_any: &["Access Denied".into(), "Security Violation".into()],
            reset_after: None,
        };
        let report = apply_scenario(
            denied(&serial, Some("guest did not emit efi-launched")),
            &check,
        );
        assert!(report.success, "{:?}", report.failure_reason);
        assert!(report.failure_reason.is_none());

        let still = apply_scenario(
            denied(&serial, Some("guest did not emit efi-launched")),
            &ScenarioCheck {
                expect: &["efi-launched".into()],
                ..check
            },
        );
        assert!(!still.success);
        let _ = fs::remove_dir_all(&dir);
    }
}
