//! End-to-end integration and negative-security test harness for SBM media images.
//!
//! Boots a disposable QCOW2 overlay (or disposable raw copy for negative tamper
//! tests) of a real SBM `.raw` image as removable USB storage alongside a decoy
//! ESP (enumerated first) and two blank virtual disks (1 GiB and 2 GiB), with
//! zero virtual NICs and `-no-reboot` disabled. Drives the full user flow via QMP:
//!
//! 1. Firmware -> SBM UEFI graphical menu (`01-uefi-menu.ppm`, `< 250 ms` on HVF/KVM)
//! 2. QMP `c` -> Manage Computer -> `verify_done ... result=ok` -> native Core UKI chainload
//! 3. Linux `dm-verity` `/dev/mapper/root` EROFS + `SBM_PROTECT` -> `sbm-cored` + `labwc` + Iced `sbm-ui` (`02-core-ui.ppm`)
//! 4. QMP click `Open GParted` -> GParted window (`03-gparted.ppm`) + device selector (`04-gparted-devices.ppm`)
//! 5. QMP close GParted (`Ctrl+Q`) -> click `Reboot` -> click `Confirm` -> QMP `RESET` event
//! 6. Same SBM UEFI menu returns, confirms attempt (`05-post-reboot-menu.ppm`)
//! 7. Verifies screenshot pixel variance, overlay ESP state, decoy ESP & fixture disk immutability, and input SHA-256 hashes.

use crate::accel::{Accel, AccelRequest, Arch, HostFacts, effective_timeout, select_accel};
use crate::error::{Error, Result};
use crate::fatimg::{build_fat32, read_fat_file_from_path};
use crate::firmware::{copy_vars, select_firmware};
use crate::gpt::{PartitionSpec, SECTOR, build_gpt, esp_guid, validate_gpt_file};
use crate::host::host_facts;
use crate::launch::{AttachedDisk, LaunchPlan, qemu_args};
use crate::markers::{Marker, parse_markers};
use crate::product::find_fixture;
use crate::profile::GpuKind;
use crate::qmp::Qmp;
use crate::resources::{
    AdmitRequest, Workload, clamp_launch, hold_for_run, note_qemu_pid, tie_to_parent,
};
use crate::util::{reject_host_device, sha256_file, short_id, which, write_file};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Release gate latency budget for `SBM_MARK menu_ready us=<N>` on accelerated
/// virtualization (HVF/KVM): `< 250 ms` (`250_000 us`).
pub const MENU_READY_BUDGET_US: u64 = 250_000;

/// Minimum RGB luminance standard deviation required to consider a PPM screenshot
/// non-blank (rejects flat black/white/solid-color captures).
const MIN_SCREENSHOT_LUMA_STDDEV: f64 = 5.0;

#[derive(Debug, Clone)]
pub struct IntegrationOptions {
    pub image: PathBuf,
    pub arch: Arch,
    pub gpu: GpuKind,
    pub memory_mib: u32,
    pub cpus: u32,
    pub timeout_secs: u64,
    pub artifacts_dir: Option<PathBuf>,
    pub keep: bool,
}

#[derive(Debug, Serialize)]
pub struct IntegrationReport {
    pub schema: &'static str,
    pub id: String,
    pub arch: String,
    pub gpu: String,
    pub accel: String,
    pub execution_class: String,
    pub image: String,
    pub image_sha256: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub menu_ready_1_us: Option<u64>,
    pub menu_ready_2_us: Option<u64>,
    pub verify_done_us: Option<u64>,
    pub verify_done_ok: bool,
    pub latency_budget_applicable: bool,
    pub latency_budget_met: Option<bool>,
    pub gates: BTreeMap<String, bool>,
    pub stages_ms: BTreeMap<String, u64>,
    pub duration_ms: u64,
    pub screenshots: BTreeMap<String, String>,
    pub screenshot_non_blank: BTreeMap<String, bool>,
    pub gparted_visual_delta: Option<f64>,
    pub qmp_events: Vec<Value>,
    pub qmp_actions: Vec<String>,
    pub last_attempt: Option<Value>,
    pub current_handoff_present: bool,
    pub boot_success_consumed: bool,
    pub decoy_esp_unchanged: bool,
    pub fixture_disks_unchanged: bool,
    pub inputs_unchanged: bool,
    pub qemu_argv: Vec<String>,
    pub serial_log: String,
    pub run_dir: String,
}

pub fn run_integration(root: &Path, opts: &IntegrationOptions) -> Result<IntegrationReport> {
    reject_host_device(&opts.image)?;
    if !opts.image.is_file() {
        return Err(Error::message(format!(
            "integration image {} does not exist",
            opts.image.display()
        )));
    }
    let id = format!("int-{}-{}", opts.arch, short_id());
    let run_dir = root.join("var/runs").join(&id);
    fs::create_dir_all(&run_dir)?;

    let (memory, cpus) = clamp_launch(Workload::Graphical, opts.memory_mib, opts.cpus, true, true)?;
    let mut budget = hold_for_run(
        root,
        &AdmitRequest {
            owner_pid: 0,
            repo: root.display().to_string(),
            workload: Workload::Graphical,
            memory_mib: memory,
            cpus,
            detached: false,
        },
    )?;

    let qemu_name = opts.arch.qemu_binary();
    let qemu_bin =
        which(qemu_name).ok_or_else(|| Error::message(format!("{qemu_name} is not installed")))?;
    let live = host_facts();
    let accels = query_accels(&qemu_bin);
    let facts = HostFacts {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hv_support: live.hv_support,
        kvm_usable: live.kvm_usable,
        qemu_accels: accels,
    };
    let choice = select_accel(&facts, opts.arch, AccelRequest::Auto).map_err(Error::message)?;
    let machine = match opts.arch {
        Arch::Aarch64 => "virt,gic-version=3".to_string(),
        _ => "q35".to_string(),
    };
    let fw = select_firmware(
        Some(&qemu_bin),
        opts.arch,
        false,
        if opts.arch == Arch::Aarch64 {
            "virt"
        } else {
            "q35"
        },
    )?;

    // Record immutable input hashes before launch.
    let image_hash_before = sha256_file(&opts.image)?;
    let code_hash_before = sha256_file(&fw.code)?;
    let vars_hash_before = sha256_file(&fw.vars_template)?;

    let vars_copy = run_dir.join("vars.fd");
    copy_vars(&fw.vars_template, &vars_copy)?;

    // Build decoy ESP disk (attached BEFORE the USB SBM disk so Linux enumerates it first).
    let decoy_raw = run_dir.join("decoy-esp.raw");
    let decoy_bytes = build_decoy_esp(root, opts.arch)?;
    fs::write(&decoy_raw, &decoy_bytes)?;
    let decoy_hash_before = sha256_file(&decoy_raw)?;

    // Disposable 1 GiB and 2 GiB inspectable virtual disks; hash before launch to
    // prove GParted inspection leaves both disks byte-for-byte unchanged.
    let disk1g = run_dir.join("disk-1g.qcow2");
    let disk2g = run_dir.join("disk-2g.qcow2");
    qemu_img_create_blank(&disk1g, "1G")?;
    qemu_img_create_blank(&disk2g, "2G")?;
    let disk1g_hash_before = sha256_file(&disk1g)?;
    let disk2g_hash_before = sha256_file(&disk2g)?;

    // Disposable QCOW2 overlay of the real unchanged raw image.
    let usb_overlay = run_dir.join("sbm-usb.qcow2");
    qemu_img_create_overlay(&opts.image, &usb_overlay)?;

    let serial_log = run_dir.join("serial.log");
    let qmp_sock = run_dir.join("qmp.sock");
    let debugcon =
        matches!(opts.arch, Arch::X86_64 | Arch::Ia32).then(|| run_dir.join("debugcon.log"));

    let plan = LaunchPlan {
        bin: qemu_bin.clone(),
        arch: opts.arch,
        host_arch: facts.arch.clone(),
        accel: choice.accel,
        machine,
        memory_mib: memory,
        cpus,
        secure_boot: false,
        requires_smm: fw.requires_smm,
        code: Some(fw.code.clone()),
        vars: Some(vars_copy),
        bios: None,
        // VirtIO disks enumerated first by Linux: decoy ESP (vda), 1 GiB (vdb), 2 GiB (vdc).
        disks: vec![
            AttachedDisk {
                id: "decoy".into(),
                path: decoy_raw.clone(),
                format: "raw".into(),
                bootindex: 1,
                blkdebug: None,
                serial: Some("SBMDECOY".into()),
            },
            AttachedDisk {
                id: "disk1g".into(),
                path: disk1g.clone(),
                format: "qcow2".into(),
                bootindex: 2,
                blkdebug: None,
                serial: Some("SBMTEST1G".into()),
            },
            AttachedDisk {
                id: "disk2g".into(),
                path: disk2g.clone(),
                format: "qcow2".into(),
                bootindex: 3,
                blkdebug: None,
                serial: Some("SBMTEST2G".into()),
            },
        ],
        // Bootable removable USB medium (bootindex=0) -> enumerated as /dev/sda after vda..vdc.
        usb_disks: vec![AttachedDisk {
            id: "sbmusb".into(),
            path: usb_overlay.clone(),
            format: "qcow2".into(),
            bootindex: 0,
            blkdebug: None,
            serial: None,
        }],
        gpu: opts.gpu,
        network: None,
        tpm_socket: None,
        guest_agent_socket: None,
        serial_socket: serial_log.clone(),
        qmp_socket: qmp_sock.clone(),
        debugcon: debugcon.clone(),
        graphical: false,
        allow_reboot: true,
    };

    let argv = qemu_args(&plan)?;
    fs::write(run_dir.join("qemu.argv"), argv.join("\n"))?;
    let stdout = File::create(run_dir.join("qemu.stdout"))?;
    let stderr = File::create(run_dir.join("qemu.stderr"))?;
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
    let timeout_secs = effective_timeout(&facts.arch, opts.arch, opts.timeout_secs);
    let deadline = started + Duration::from_secs(timeout_secs.max(60));

    let mut state = FlowState {
        is_tcg: choice.accel == Accel::Tcg,
        ..FlowState::default()
    };
    let flow_res = drive_flow(
        &mut child,
        &run_dir,
        &serial_log,
        &qmp_sock,
        started,
        deadline,
        &mut state,
    );
    let _ = child.kill();
    let _ = child.wait();
    budget.mark_reaped();
    drop(budget);

    // Post-shutdown inspection of ESP state on overlay, decoy ESP, and fixture disks.
    let mut failure = flow_res.err().map(|e| e.to_string());
    let decoy_hash_after = sha256_file(&decoy_raw)?;
    let decoy_esp_unchanged = decoy_hash_before == decoy_hash_after;

    let disk1g_hash_after = sha256_file(&disk1g)?;
    let disk2g_hash_after = sha256_file(&disk2g)?;
    let fixture_disks_unchanged =
        disk1g_hash_before == disk1g_hash_after && disk2g_hash_before == disk2g_hash_after;

    let image_hash_after = sha256_file(&opts.image)?;
    let code_hash_after = sha256_file(&fw.code)?;
    let vars_hash_after = sha256_file(&fw.vars_template)?;
    let inputs_unchanged = image_hash_before == image_hash_after
        && code_hash_before == code_hash_after
        && vars_hash_before == vars_hash_after;

    let (last_attempt, current_handoff_present, boot_success_consumed) =
        inspect_overlay_esp(&opts.image, &usb_overlay, &run_dir).unwrap_or((None, false, false));

    let confirmed_in_json = last_attempt.as_ref().is_some_and(|v| {
        v.get("status").and_then(|s| s.as_str()) == Some("confirmed")
            && v.get("consecutive_failures").and_then(|n| n.as_u64()) == Some(0)
    });

    let serial_text = fs::read_to_string(&serial_log).unwrap_or_default();
    let markers = parse_markers(&serial_text);
    let menu_ready_us = parse_menu_ready_us(&markers);
    let menu_ready_count = menu_ready_us.len();
    let menu_ready_1_us = menu_ready_us.first().copied();
    let menu_ready_2_us = menu_ready_us.get(1).copied();
    let (verify_done_ok, verify_done_us) = parse_verify_done(&markers);

    let latency_budget_applicable = matches!(choice.accel, Accel::Hvf | Accel::Kvm);
    let latency_budget_met = if latency_budget_applicable {
        Some(menu_ready_1_us.is_some_and(|us| us < MENU_READY_BUDGET_US))
    } else {
        None
    };

    // Verify non-blank pixel variance on every captured screenshot.
    let mut screenshot_non_blank = BTreeMap::new();
    for (stage, path) in &state.screenshots {
        let non_blank = ppm_is_non_blank(Path::new(path)).unwrap_or(false);
        screenshot_non_blank.insert(stage.clone(), non_blank);
    }
    let shot_ok = |name: &str| screenshot_non_blank.get(name).copied().unwrap_or(false);

    // Measure visual delta between 02-core-ui and 03-gparted to verify GParted mapped.
    let gparted_visual_delta = match (
        state.screenshots.get("02-core-ui"),
        state.screenshots.get("03-gparted"),
    ) {
        (Some(ui), Some(gp)) => ppm_diff_ratio(Path::new(ui), Path::new(gp)).ok(),
        _ => None,
    };

    let dm_verity_active = serial_text.contains("/dev/mapper/root")
        && (serial_text.contains("systemd-veritysetup@root")
            || serial_text.contains("Using verity root device /dev/mapper/root")
            || serial_text.contains("dm-verity"));
    let backing_protected = serial_text.contains("SBM_PROTECT status=backing-protected");
    let no_dev_smoke = !serial_text.contains("SBM_SMOKE_BEGIN");

    let mut gates: BTreeMap<String, bool> = BTreeMap::new();
    gates.insert(
        "gate1_uefi_menu".into(),
        menu_ready_count >= 1 && shot_ok("01-uefi-menu") && latency_budget_met.unwrap_or(true),
    );
    gates.insert(
        "gate2_discovered_targets".into(),
        serial_text.contains("SBM Core") && serial_text.contains("Fedora"),
    );
    gates.insert(
        "gate3_manage_computer_handoff".into(),
        verify_done_ok && current_handoff_present && serial_text.contains("handoff_verified=true"),
    );
    gates.insert(
        "gate4_real_linux_core".into(),
        serial_text.contains("Linux version")
            && serial_text.contains("SBM_BOOT_METRICS")
            && (serial_text.contains("backing=/dev/sd") || serial_text.contains("backing=/dev/vd"))
            && dm_verity_active
            && backing_protected,
    );
    gates.insert(
        "gate5_management_ui".into(),
        serial_text.contains("SBM_UI_READY")
            && serial_text.contains("SBM_BOOT_SUCCESS_WRITTEN")
            && shot_ok("02-core-ui")
            && no_dev_smoke,
    );
    gates.insert(
        "gate6_gparted_and_disks".into(),
        serial_text.contains("SBM_GPARTED_LAUNCHED")
            && shot_ok("03-gparted")
            && shot_ok("04-gparted-devices")
            && gparted_visual_delta.is_some_and(|delta| delta >= 0.05),
    );
    gates.insert(
        "gate7_reboot_and_confirmation".into(),
        state.saw_reset_event
            && menu_ready_count >= 2
            && serial_text.contains("attempt confirmed")
            && confirmed_in_json
            && boot_success_consumed
            && shot_ok("05-post-reboot-menu"),
    );
    gates.insert("gate8_offline".into(), !argv.iter().any(|a| a == "-netdev"));
    gates.insert(
        "gate9_integrity_and_decoy".into(),
        inputs_unchanged && decoy_esp_unchanged && fixture_disks_unchanged,
    );

    if failure.is_none() {
        let failed_gates: Vec<&str> = gates
            .iter()
            .filter(|(_, ok)| !**ok)
            .map(|(k, _)| k.as_str())
            .collect();
        if !failed_gates.is_empty() {
            failure = Some(format!("failed gates: {}", failed_gates.join(", ")));
        }
    }

    let report = IntegrationReport {
        schema: "sbm-lab.integration.v2",
        id: id.clone(),
        arch: opts.arch.to_string(),
        gpu: match opts.gpu {
            GpuKind::Virtio => "virtio".into(),
            GpuKind::Software => "software".into(),
        },
        accel: choice.accel.to_string(),
        execution_class: choice.execution_class.as_str().into(),
        image: opts.image.display().to_string(),
        image_sha256: image_hash_before,
        success: failure.is_none(),
        failure_reason: failure,
        menu_ready_1_us,
        menu_ready_2_us,
        verify_done_us,
        verify_done_ok,
        latency_budget_applicable,
        latency_budget_met,
        gates,
        stages_ms: state.stages_ms,
        duration_ms: started.elapsed().as_millis() as u64,
        screenshots: state.screenshots.clone(),
        screenshot_non_blank,
        gparted_visual_delta,
        qmp_events: state.qmp_events,
        qmp_actions: state.qmp_actions,
        last_attempt,
        current_handoff_present,
        boot_success_consumed,
        decoy_esp_unchanged,
        fixture_disks_unchanged,
        inputs_unchanged,
        qemu_argv: argv,
        serial_log: serial_log.display().to_string(),
        run_dir: run_dir.display().to_string(),
    };
    write_file(
        &run_dir.join("result.json"),
        serde_json::to_string_pretty(&report)?.as_bytes(),
    )?;

    if let Some(dir) = &opts.artifacts_dir {
        let dest = dir.join(format!("{}-{id}", opts.arch));
        fs::create_dir_all(&dest)?;
        for name in ["result.json", "serial.log", "qemu.stderr", "qemu.argv"] {
            let src = run_dir.join(name);
            if src.is_file() {
                let _ = fs::copy(&src, dest.join(name));
            }
        }
        for (stage, path) in &state.screenshots {
            let src = PathBuf::from(path);
            if src.is_file() {
                let _ = fs::copy(&src, dest.join(format!("{stage}.ppm")));
            }
        }
        let esp_dir = run_dir.join("esp-state");
        if esp_dir.is_dir() {
            let out_esp = dest.join("esp-state");
            let _ = fs::create_dir_all(&out_esp);
            for entry in fs::read_dir(&esp_dir).into_iter().flatten().flatten() {
                let _ = fs::copy(entry.path(), out_esp.join(entry.file_name()));
            }
        }
    }

    if !opts.keep && report.success {
        for name in [
            "sbm-usb.qcow2",
            "disk-1g.qcow2",
            "disk-2g.qcow2",
            "decoy-esp.raw",
            "vars.fd",
            "esp-part.raw",
        ] {
            let _ = fs::remove_file(run_dir.join(name));
        }
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// Tier 2 automated negative security & bound LocalBootRequest scenarios
// ---------------------------------------------------------------------------

pub const NEGATIVE_SCENARIOS: &[&str] = &[
    "tampered-uki",
    "corrupt-verity",
    "invalid-handoff",
    "stale-boot-success",
    "local-boot-request-negative",
    "local-boot-request-positive",
];

#[derive(Debug, Clone)]
pub struct NegativeOptions {
    pub image: PathBuf,
    pub arch: Arch,
    pub scenario: Option<String>,
    pub memory_mib: u32,
    pub cpus: u32,
    pub timeout_secs: u64,
    pub artifacts_dir: Option<PathBuf>,
    pub keep: bool,
}

#[derive(Debug, Serialize)]
pub struct NegativeReport {
    pub schema: &'static str,
    pub id: String,
    pub scenario: String,
    pub arch: String,
    pub accel: String,
    pub execution_class: String,
    pub image: String,
    pub image_sha256: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub assertions: BTreeMap<String, bool>,
    pub duration_ms: u64,
    pub inputs_unchanged: bool,
    pub decoy_esp_unchanged: bool,
    pub serial_log: String,
    pub run_dir: String,
}

pub fn parse_negative_scenarios(filter: Option<&str>) -> Result<Vec<&'static str>> {
    match filter {
        None | Some("all") => Ok(NEGATIVE_SCENARIOS.to_vec()),
        Some(name) => NEGATIVE_SCENARIOS
            .iter()
            .copied()
            .find(|s| *s == name)
            .map(|s| vec![s])
            .ok_or_else(|| {
                Error::message(format!(
                    "unknown negative scenario {name}; expected one of: {}",
                    NEGATIVE_SCENARIOS.join(", ")
                ))
            }),
    }
}

pub fn run_integration_negative(
    root: &Path,
    opts: &NegativeOptions,
) -> Result<Vec<NegativeReport>> {
    reject_host_device(&opts.image)?;
    if !opts.image.is_file() {
        return Err(Error::message(format!(
            "integration image {} does not exist",
            opts.image.display()
        )));
    }
    let scenarios = parse_negative_scenarios(opts.scenario.as_deref())?;
    let mut reports = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        reports.push(run_one_negative(root, opts, scenario)?);
    }
    Ok(reports)
}

fn run_one_negative(root: &Path, opts: &NegativeOptions, scenario: &str) -> Result<NegativeReport> {
    let id = format!("n-{}", short_id());
    let run_dir = root.join("var/runs").join(&id);
    fs::create_dir_all(&run_dir)?;

    let needs_linux = matches!(scenario, "corrupt-verity" | "invalid-handoff");
    let workload = if needs_linux {
        Workload::Graphical
    } else {
        Workload::Efi
    };
    let req_mem = if needs_linux {
        opts.memory_mib.min(4096)
    } else {
        1024
    };
    let req_cpus = if needs_linux { opts.cpus.min(2) } else { 1 };
    let (memory, cpus) = clamp_launch(workload, req_mem, req_cpus, false, false)?;
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

    let qemu_name = opts.arch.qemu_binary();
    let qemu_bin =
        which(qemu_name).ok_or_else(|| Error::message(format!("{qemu_name} is not installed")))?;
    let live = host_facts();
    let accels = query_accels(&qemu_bin);
    let facts = HostFacts {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hv_support: live.hv_support,
        kvm_usable: live.kvm_usable,
        qemu_accels: accels,
    };
    let choice = select_accel(&facts, opts.arch, AccelRequest::Auto).map_err(Error::message)?;
    let is_tcg = choice.accel == Accel::Tcg;
    let machine = match opts.arch {
        Arch::Aarch64 => "virt,gic-version=3".to_string(),
        _ => "q35".to_string(),
    };
    let fw = select_firmware(
        Some(&qemu_bin),
        opts.arch,
        false,
        if opts.arch == Arch::Aarch64 {
            "virt"
        } else {
            "q35"
        },
    )?;

    let image_hash_before = sha256_file(&opts.image)?;
    let code_hash_before = sha256_file(&fw.code)?;
    let vars_hash_before = sha256_file(&fw.vars_template)?;
    let vars_copy = run_dir.join("vars.fd");
    copy_vars(&fw.vars_template, &vars_copy)?;

    // Build disposable decoy ESP so BLS targets (and decoy immutability) are always testable.
    let decoy_raw = run_dir.join("decoy-esp.raw");
    let decoy_bytes = build_decoy_esp(root, opts.arch)?;
    fs::write(&decoy_raw, &decoy_bytes)?;
    let decoy_hash_before = sha256_file(&decoy_raw)?;
    let (decoy_esp_guid, decoy_esp_offset, decoy_esp_len) = decoy_esp_info(&decoy_raw)?;

    // Copy the immutable release image to a disposable raw copy inside run_dir so
    // we can inject scenario-specific mutations without touching the original.
    let work_img = run_dir.join("sbm-work.raw");
    fs::copy(&opts.image, &work_img)?;

    let parts = validate_gpt_file(&work_img)?;
    let esp = parts
        .iter()
        .find(|p| p.type_guid == esp_guid())
        .ok_or_else(|| Error::message("image missing GPT ESP"))?;
    let esp_offset = esp.start_lba * SECTOR;
    let esp_len = (esp.end_lba - esp.start_lba + 1) * SECTOR;

    let uki_rel = uki_esp_path(opts.arch);
    let boot_rel = match opts.arch {
        Arch::Aarch64 => "EFI/BOOT/BOOTAA64.EFI",
        Arch::X86_64 => "EFI/BOOT/BOOTX64.EFI",
        Arch::Ia32 => "EFI/BOOT/BOOTIA32.EFI",
    };

    match scenario {
        "tampered-uki" => {
            let mut uki = read_esp_slice_file(&work_img, esp_offset, esp_len, uki_rel)?;
            let mid = uki.len() / 2;
            uki[mid] ^= 0xFF;
            mcopy_into_esp(&work_img, esp_offset, &run_dir, uki_rel, &uki)?;
        }
        "corrupt-verity" => {
            let root_part = find_root_partition(&parts, opts.arch)?;
            let byte_pos = root_part.start_lba * SECTOR + 1024;
            let mut file = OpenOptions::new().read(true).write(true).open(&work_img)?;
            file.seek(SeekFrom::Start(byte_pos))?;
            let mut b = [0u8; 1];
            file.read_exact(&mut b)?;
            b[0] ^= 0xFF;
            file.seek(SeekFrom::Start(byte_pos))?;
            file.write_all(&b)?;
            file.sync_all()?;
        }
        "invalid-handoff" => {
            // Boot the real Core UKI directly (bypassing sbm-uefi so the 5 volatile
            // EFI handoff variables are absent) while planting a fake current.json
            // on the ESP. Core MUST mark handoff_verified=false and decline boot-success.
            let uki = read_esp_slice_file(&work_img, esp_offset, esp_len, uki_rel)?;
            mcopy_into_esp(&work_img, esp_offset, &run_dir, boot_rel, &uki)?;
            let fake_handoff = serde_json::json!({
                "schema_version": "1.0",
                "attempt_id": "11111111-1111-4111-8111-111111111111",
                "boot_esp_uuid": "00000000-0000-4000-8000-000000000000",
                "selected_target_id": "sbm-core:slot-a",
                "discovered_targets": []
            });
            mcopy_into_esp(
                &work_img,
                esp_offset,
                &run_dir,
                "EFI/sbm/handoff/current.json",
                serde_json::to_string_pretty(&fake_handoff)?.as_bytes(),
            )?;
        }
        "stale-boot-success" => {
            let attempt = serde_json::json!({
                "schema_version": "1.0",
                "attempt_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "target_id": "sbm-core:slot-a",
                "slot": "slot-a",
                "timestamp_unix": 1795000000,
                "consecutive_failures": 1,
                "status": "started"
            });
            let stale_success = serde_json::json!({
                "schema_version": "1.0",
                "attempt_id": "local",
                "target_id": "sbm-core:slot-a",
                "confirmed_by": "sbm-core-uki",
                "confirmed_at_unix": 1795000005
            });
            mcopy_into_esp(
                &work_img,
                esp_offset,
                &run_dir,
                "EFI/sbm/state/last_attempt.json",
                serde_json::to_string_pretty(&attempt)?.as_bytes(),
            )?;
            mcopy_into_esp(
                &work_img,
                esp_offset,
                &run_dir,
                "EFI/sbm/state/boot-success.json",
                serde_json::to_string_pretty(&stale_success)?.as_bytes(),
            )?;
        }
        "local-boot-request-negative" => {
            let attempt = serde_json::json!({
                "schema_version": "1.0",
                "attempt_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "target_id": "sbm-core:slot-a",
                "slot": "slot-a",
                "timestamp_unix": 1795000000,
                "consecutive_failures": 0,
                "status": "confirmed"
            });
            let bad_req = serde_json::json!({
                "schema_version": "1.0",
                "request_id": "22222222-2222-4222-8222-222222222222",
                "attempt_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "requested_by": "sbm-core-uki",
                "requested_at_unix": 1795000010,
                "command": {
                    "action": "boot_target",
                    "target_id": format!("bls:{decoy_esp_guid}:fedora"),
                    "one_shot": true
                }
            });
            mcopy_into_esp(
                &work_img,
                esp_offset,
                &run_dir,
                "EFI/sbm/state/last_attempt.json",
                serde_json::to_string_pretty(&attempt)?.as_bytes(),
            )?;
            mcopy_into_esp(
                &work_img,
                esp_offset,
                &run_dir,
                "EFI/sbm/handoff/requested-command.json",
                serde_json::to_string_pretty(&bad_req)?.as_bytes(),
            )?;
        }
        "local-boot-request-positive" => {
            let attempt = serde_json::json!({
                "schema_version": "1.0",
                "attempt_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "target_id": "sbm-core:slot-a",
                "slot": "slot-a",
                "timestamp_unix": 1795000000,
                "consecutive_failures": 0,
                "status": "confirmed"
            });
            let good_req = serde_json::json!({
                "schema_version": "1.0",
                "request_id": "33333333-3333-4333-8333-333333333333",
                "attempt_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "requested_by": "sbm-core-uki",
                "requested_at_unix": 1795000010,
                "command": {
                    "action": "boot_target",
                    "target_id": format!("bls:{decoy_esp_guid}:fedora"),
                    "one_shot": true
                }
            });
            mcopy_into_esp(
                &work_img,
                esp_offset,
                &run_dir,
                "EFI/sbm/state/last_attempt.json",
                serde_json::to_string_pretty(&attempt)?.as_bytes(),
            )?;
            mcopy_into_esp(
                &work_img,
                esp_offset,
                &run_dir,
                "EFI/sbm/handoff/requested-command.json",
                serde_json::to_string_pretty(&good_req)?.as_bytes(),
            )?;
        }
        other => {
            return Err(Error::message(format!(
                "unsupported negative scenario {other}"
            )));
        }
    }

    let serial_log = run_dir.join("serial.log");
    let qmp_sock = run_dir.join("qmp.sock");
    let debugcon =
        matches!(opts.arch, Arch::X86_64 | Arch::Ia32).then(|| run_dir.join("debugcon.log"));

    let plan = LaunchPlan {
        bin: qemu_bin.clone(),
        arch: opts.arch,
        host_arch: facts.arch.clone(),
        accel: choice.accel,
        machine,
        memory_mib: memory,
        cpus,
        secure_boot: false,
        requires_smm: fw.requires_smm,
        code: Some(fw.code.clone()),
        vars: Some(vars_copy),
        bios: None,
        disks: vec![AttachedDisk {
            id: "decoy".into(),
            path: decoy_raw.clone(),
            format: "raw".into(),
            bootindex: 1,
            blkdebug: None,
            serial: Some("SBMDECOY".into()),
        }],
        usb_disks: vec![AttachedDisk {
            id: "sbmusb".into(),
            path: work_img.clone(),
            format: "raw".into(),
            bootindex: 0,
            blkdebug: None,
            serial: None,
        }],
        gpu: if needs_linux {
            GpuKind::Virtio
        } else {
            GpuKind::Software
        },
        network: None,
        tpm_socket: None,
        guest_agent_socket: None,
        serial_socket: serial_log.clone(),
        qmp_socket: qmp_sock.clone(),
        debugcon,
        graphical: false,
        allow_reboot: false,
    };

    let argv = qemu_args(&plan)?;
    fs::write(run_dir.join("qemu.argv"), argv.join("\n"))?;
    let stdout = File::create(run_dir.join("qemu.stdout"))?;
    let stderr = File::create(run_dir.join("qemu.stderr"))?;
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
    let timeout_secs = effective_timeout(&facts.arch, opts.arch, opts.timeout_secs);
    let deadline = started + Duration::from_secs(timeout_secs.max(45));

    let drive_res = drive_negative(
        scenario,
        is_tcg,
        &mut child,
        &run_dir,
        &serial_log,
        &qmp_sock,
        deadline,
    );
    let _ = child.kill();
    let _ = child.wait();
    budget.mark_reaped();
    drop(budget);

    let serial_text = fs::read_to_string(&serial_log).unwrap_or_default();
    let markers = parse_markers(&serial_text);
    let decoy_hash_after = sha256_file(&decoy_raw)?;
    // In local-boot-request-positive, the chainloaded fixture binary on the decoy
    // ESP intentionally writes EFI/sbm/test/chainload-ok.txt to prove it ran.
    // Verify zero SBM state writes landed on the decoy ESP and its marker stayed
    // intact; for every other scenario require strict byte-for-byte immutability.
    let decoy_esp_unchanged = if scenario == "local-boot-request-positive" {
        let marker_ok = read_esp_slice_file(
            &decoy_raw,
            decoy_esp_offset,
            decoy_esp_len,
            "EFI/decoy-marker.txt",
        )
        .ok()
        .is_some_and(|b| String::from_utf8_lossy(&b).contains("SBM decoy ESP"));
        let sbm_state_absent = [
            "EFI/sbm/state/last_attempt.json",
            "EFI/sbm/state/boot-success.json",
            "EFI/sbm/handoff/current.json",
            "EFI/sbm/handoff/requested-command.json",
        ]
        .iter()
        .all(|rel| {
            read_esp_slice_file(&decoy_raw, decoy_esp_offset, decoy_esp_len, rel).is_err()
        });
        marker_ok && sbm_state_absent
    } else {
        decoy_hash_before == decoy_hash_after
    };
    let inputs_unchanged = sha256_file(&opts.image)? == image_hash_before
        && sha256_file(&fw.code)? == code_hash_before
        && sha256_file(&fw.vars_template)? == vars_hash_before;

    let mut assertions: BTreeMap<String, bool> = BTreeMap::new();
    assertions.insert("inputs_unchanged".into(), inputs_unchanged);
    assertions.insert("decoy_esp_unchanged".into(), decoy_esp_unchanged);
    assertions.insert(
        "offline_no_nic".into(),
        !argv.iter().any(|a| a == "-netdev"),
    );

    match scenario {
        "tampered-uki" => {
            let verify_failed = markers.iter().any(|m| {
                m.name == "verify_done"
                    && m.fields.get("result").map(String::as_str) == Some("failed")
            });
            assertions.insert("verify_done_failed".into(), verify_failed);
            assertions.insert(
                "linux_never_started".into(),
                !serial_text.contains("Linux version"),
            );
        }
        "corrupt-verity" => {
            let (verify_ok, _) = parse_verify_done(&markers);
            let verity_error = serial_text.contains("corrupted")
                || serial_text.contains("I/O error")
                || serial_text.contains("Failed to mount")
                || serial_text.contains("sysroot.mount")
                || serial_text.contains("verity");
            assertions.insert("uki_verified_before_mount".into(), verify_ok);
            assertions.insert(
                "linux_started".into(),
                serial_text.contains("Linux version"),
            );
            assertions.insert("verity_rejected_mount".into(), verity_error);
            assertions.insert(
                "ui_never_ready".into(),
                !serial_text.contains("SBM_UI_READY"),
            );
            assertions.insert(
                "boot_success_never_written".into(),
                !serial_text.contains("SBM_BOOT_SUCCESS_WRITTEN"),
            );
        }
        "invalid-handoff" => {
            let boot_success_absent = read_esp_slice_file(
                &work_img,
                esp_offset,
                esp_len,
                "EFI/sbm/state/boot-success.json",
            )
            .is_err();
            assertions.insert(
                "handoff_unverified".into(),
                serial_text.contains("handoff_verified=false"),
            );
            assertions.insert(
                "boot_success_declined".into(),
                serial_text.contains("SBM_BOOT_SUCCESS_DECLINED")
                    && !serial_text.contains("SBM_BOOT_SUCCESS_WRITTEN"),
            );
            assertions.insert("boot_success_file_absent".into(), boot_success_absent);
        }
        "stale-boot-success" => {
            let attempt_json = read_esp_slice_file(
                &work_img,
                esp_offset,
                esp_len,
                "EFI/sbm/state/last_attempt.json",
            )
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            let still_unconfirmed = attempt_json.as_ref().is_some_and(|v| {
                v.get("status").and_then(|s| s.as_str()) != Some("confirmed")
                    && v.get("consecutive_failures").and_then(|n| n.as_u64()) != Some(0)
            });
            let success_removed = read_esp_slice_file(
                &work_img,
                esp_offset,
                esp_len,
                "EFI/sbm/state/boot-success.json",
            )
            .is_err();
            assertions.insert(
                "attempt_confirm_rejected".into(),
                serial_text.contains("attempt confirm rejected")
                    && !serial_text.contains("attempt confirmed"),
            );
            assertions.insert("attempt_not_confirmed_in_json".into(), still_unconfirmed);
            assertions.insert("stale_report_removed".into(), success_removed);
        }
        "local-boot-request-negative" => {
            let req_removed = read_esp_slice_file(
                &work_img,
                esp_offset,
                esp_len,
                "EFI/sbm/handoff/requested-command.json",
            )
            .is_err();
            assertions.insert(
                "request_rejected".into(),
                serial_text.contains("request rejected"),
            );
            assertions.insert("request_deleted_before_act".into(), req_removed);
            assertions.insert(
                "target_not_launched".into(),
                !serial_text.contains("fixture_started"),
            );
        }
        "local-boot-request-positive" => {
            let req_removed = read_esp_slice_file(
                &work_img,
                esp_offset,
                esp_len,
                "EFI/sbm/handoff/requested-command.json",
            )
            .is_err();
            assertions.insert(
                "policy_core_request".into(),
                serial_text.contains("policy reason=core-request"),
            );
            assertions.insert("request_deleted_before_act".into(), req_removed);
            let chainload_marker = read_esp_slice_file(
                &decoy_raw,
                decoy_esp_offset,
                decoy_esp_len,
                "EFI/sbm/test/chainload-ok.txt",
            )
            .ok()
            .is_some_and(|b| String::from_utf8_lossy(&b).contains("chainload-ok"));
            assertions.insert(
                "requested_target_launched".into(),
                serial_text.contains("fixture_started") && chainload_marker,
            );
        }
        _ => {}
    }

    let mut failure = drive_res.err().map(|e| e.to_string());
    if failure.is_none() {
        let failed: Vec<&str> = assertions
            .iter()
            .filter(|(_, ok)| !**ok)
            .map(|(k, _)| k.as_str())
            .collect();
        if !failed.is_empty() {
            failure = Some(format!("failed assertions: {}", failed.join(", ")));
        }
    }

    let report = NegativeReport {
        schema: "sbm-lab.integration-negative.v1",
        id: id.clone(),
        scenario: scenario.to_string(),
        arch: opts.arch.to_string(),
        accel: choice.accel.to_string(),
        execution_class: choice.execution_class.as_str().into(),
        image: opts.image.display().to_string(),
        image_sha256: image_hash_before,
        success: failure.is_none(),
        failure_reason: failure,
        assertions,
        duration_ms: started.elapsed().as_millis() as u64,
        inputs_unchanged,
        decoy_esp_unchanged,
        serial_log: serial_log.display().to_string(),
        run_dir: run_dir.display().to_string(),
    };
    write_file(
        &run_dir.join("result.json"),
        serde_json::to_string_pretty(&report)?.as_bytes(),
    )?;

    if let Some(dir) = &opts.artifacts_dir {
        let dest = dir.join(format!("neg-{}-{scenario}-{id}", opts.arch));
        fs::create_dir_all(&dest)?;
        for name in [
            "result.json",
            "serial.log",
            "qemu.stderr",
            "qemu.argv",
            "refusal.ppm",
        ] {
            let src = run_dir.join(name);
            if src.is_file() {
                let _ = fs::copy(&src, dest.join(name));
            }
        }
    }

    if !opts.keep && report.success {
        for name in ["sbm-work.raw", "decoy-esp.raw", "vars.fd"] {
            let _ = fs::remove_file(run_dir.join(name));
        }
    }

    Ok(report)
}

fn drive_negative(
    scenario: &str,
    is_tcg: bool,
    child: &mut Child,
    run_dir: &Path,
    serial_log: &Path,
    qmp_sock: &Path,
    deadline: Instant,
) -> Result<()> {
    let mut serial = wait_open_child(child, serial_log, deadline)?;
    let mut qmp = wait_qmp(qmp_sock, deadline)?;
    let mut buf = String::new();

    match scenario {
        "tampered-uki" => {
            wait_until(child, &mut serial, &mut buf, deadline, |text| {
                parse_markers(text).iter().any(|m| m.name == "menu_ready")
            })?;
            thread::sleep(Duration::from_millis(300));
            qmp.send_key("c")?;
            wait_until(child, &mut serial, &mut buf, deadline, |text| {
                parse_markers(text).iter().any(|m| m.name == "verify_done")
            })?;
            thread::sleep(Duration::from_secs(2));
            let _ = qmp.screendump(&run_dir.join("refusal.ppm"));
        }
        "corrupt-verity" => {
            wait_until(child, &mut serial, &mut buf, deadline, |text| {
                parse_markers(text).iter().any(|m| m.name == "menu_ready")
            })?;
            thread::sleep(Duration::from_millis(300));
            qmp.send_key("c")?;
            wait_until(child, &mut serial, &mut buf, deadline, |text| {
                text.contains("Linux version")
            })?;
            // Wait for dm-verity corruption / failed root mount (never reaches SBM_UI_READY).
            let observe_end = Instant::now() + Duration::from_secs(if is_tcg { 70 } else { 25 });
            let effective_end = observe_end.min(deadline);
            let _ = wait_until(child, &mut serial, &mut buf, effective_end, |text| {
                text.contains("data block")
                    || text.contains("Failed to mount")
                    || text.contains("emergency")
                    || text.contains("SBM_UI_READY")
            });
            thread::sleep(Duration::from_secs(2));
        }
        "invalid-handoff" => {
            wait_until(child, &mut serial, &mut buf, deadline, |text| {
                text.contains("SBM_BOOT_SUCCESS_DECLINED")
                    || text.contains("SBM_BOOT_SUCCESS_WRITTEN")
            })?;
            thread::sleep(Duration::from_secs(1));
        }
        "stale-boot-success" | "local-boot-request-negative" => {
            wait_until(child, &mut serial, &mut buf, deadline, |text| {
                parse_markers(text).iter().any(|m| m.name == "menu_ready")
            })?;
            thread::sleep(Duration::from_millis(800));
            let _ = qmp.screendump(&run_dir.join("refusal.ppm"));
        }
        "local-boot-request-positive" => {
            wait_until(child, &mut serial, &mut buf, deadline, |text| {
                text.contains("fixture_started")
                    || text.contains("request rejected")
                    || parse_markers(text).iter().any(|m| m.name == "menu_ready")
            })?;
            // If menu_ready appeared first on 0-second countdown, give chainload a moment.
            if !buf.contains("fixture_started") && !buf.contains("request rejected") {
                let extra = Instant::now() + Duration::from_secs(if is_tcg { 20 } else { 8 });
                let _ = wait_until(child, &mut serial, &mut buf, extra.min(deadline), |text| {
                    text.contains("fixture_started")
                });
            }
            thread::sleep(Duration::from_millis(400));
        }
        _ => {}
    }

    let _ = qmp.quit();
    Ok(())
}

fn uki_esp_path(arch: Arch) -> &'static str {
    match arch {
        Arch::Aarch64 => "EFI/sbm/recovery/slot-a/sbm-core-aarch64.efi",
        Arch::X86_64 => "EFI/sbm/recovery/slot-a/sbm-core-x86_64.efi",
        Arch::Ia32 => "EFI/sbm/recovery/slot-a/sbm-core-ia32.efi",
    }
}

fn find_root_partition(
    parts: &[crate::gpt::PlacedPartition],
    arch: Arch,
) -> Result<&crate::gpt::PlacedPartition> {
    let want_guid = match arch {
        Arch::Aarch64 => "b921b045-1df0-41c3-af44-4c6f280d3fae",
        Arch::X86_64 => "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
        Arch::Ia32 => "44479540-f297-41b2-9af7-d131d5f0458a",
    };
    if let Ok(guid) = crate::gpt::parse_guid(want_guid)
        && let Some(p) = parts.iter().find(|p| p.type_guid == guid)
    {
        return Ok(p);
    }
    parts
        .get(1)
        .ok_or_else(|| Error::message("image has no root partition"))
}

fn read_esp_slice_file(img: &Path, esp_offset: u64, esp_len: u64, rel: &str) -> Result<Vec<u8>> {
    let file = File::open(img)?;
    let normalized = rel.replace('\\', "/");
    let trimmed = normalized.trim_matches('/');
    sbm_media::esp::read_file(&file, esp_offset, esp_len, trimmed, esp_len, "sbm-lab")
        .map_err(|e| Error::message(format!("fat read {trimmed}: {e}")))?
        .ok_or_else(|| Error::message(format!("open {trimmed}: not found")))
}

fn mcopy_into_esp(
    img: &Path,
    esp_offset: u64,
    run_dir: &Path,
    rel: &str,
    data: &[u8],
) -> Result<()> {
    let mcopy = which("mcopy").ok_or_else(|| Error::message("mcopy (mtools) is not installed"))?;
    let mmd = which("mmd").ok_or_else(|| Error::message("mmd (mtools) is not installed"))?;
    let spec = format!("{}@@{esp_offset}", img.display());

    // Ensure parent directories exist on the FAT32 ESP.
    let normalized = rel.replace('\\', "/");
    let trimmed = normalized.trim_matches('/');
    let components: Vec<&str> = trimmed.split('/').collect();
    if components.len() > 1 {
        let mut cur = String::new();
        for dir in &components[..components.len() - 1] {
            if !cur.is_empty() {
                cur.push('/');
            }
            cur.push_str(dir);
            let _ = Command::new(&mmd)
                .args(["-i", &spec, "-D", "s", &format!("::/{cur}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    let tmp = run_dir.join(format!("mcopy-{}.bin", short_id()));
    fs::write(&tmp, data)?;
    let out = Command::new(&mcopy)
        .args(["-i", &spec, "-o"])
        .arg(&tmp)
        .arg(format!("::/{trimmed}"))
        .output()?;
    let _ = fs::remove_file(&tmp);
    if !out.status.success() {
        return Err(Error::message(format!(
            "mcopy to ::/{trimmed} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn decoy_esp_info(decoy_raw: &Path) -> Result<(String, u64, u64)> {
    let file = File::open(decoy_raw)?;
    let size = file.metadata()?.len();
    let table = sbm_media::gpt::read_gpt_strict(&file, size, "decoy")
        .map_err(|e| Error::message(format!("read decoy gpt: {e}")))?;
    let esp = table
        .partitions
        .iter()
        .find(|p| p.type_guid == sbm_media::gpt::types::esp())
        .ok_or_else(|| Error::message("decoy image missing ESP"))?;
    let offset = esp.first_lba * SECTOR;
    let len = (esp.last_lba - esp.first_lba + 1) * SECTOR;
    Ok((esp.unique_guid.to_string().to_ascii_lowercase(), offset, len))
}

// ---------------------------------------------------------------------------
// Positive flow driver & helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FlowState {
    is_tcg: bool,
    stages_ms: BTreeMap<String, u64>,
    screenshots: BTreeMap<String, String>,
    qmp_events: Vec<Value>,
    qmp_actions: Vec<String>,
    saw_reset_event: bool,
}

fn drive_flow(
    child: &mut Child,
    run_dir: &Path,
    serial_log: &Path,
    qmp_sock: &Path,
    started: Instant,
    deadline: Instant,
    state: &mut FlowState,
) -> Result<()> {
    let is_tcg = state.is_tcg;
    let mut serial = wait_open(serial_log, deadline)?;
    let mut qmp = wait_qmp(qmp_sock, deadline)?;
    let mut buf = String::new();

    // Stage 1: Wait for first SBM UEFI menu_ready
    wait_until(child, &mut serial, &mut buf, deadline, |text| {
        parse_markers(text).iter().any(|m| m.name == "menu_ready")
    })
    .map_err(|e| Error::message(format!("stage1 uefi menu_ready: {e}")))?;
    state
        .stages_ms
        .insert("uefi_menu_1".into(), started.elapsed().as_millis() as u64);
    thread::sleep(Duration::from_millis(600));
    capture(&mut qmp, run_dir, "01-uefi-menu", state)?;

    // Stage 2: Press 'c' for Manage Computer
    qmp.send_key("c")?;
    state
        .qmp_actions
        .push("send-key: c (Manage Computer)".into());

    // Stage 3: Wait for Linux Core SBM_UI_READY and SBM_BOOT_SUCCESS_WRITTEN
    wait_until(child, &mut serial, &mut buf, deadline, |text| {
        text.contains("SBM_UI_READY")
            && (text.contains("SBM_BOOT_SUCCESS_WRITTEN")
                || text.contains("SBM_BOOT_SUCCESS_DECLINED"))
    })
    .map_err(|e| Error::message(format!("stage3 core ui_ready: {e}")))?;
    state
        .stages_ms
        .insert("core_ui_ready".into(), started.elapsed().as_millis() as u64);
    thread::sleep(Duration::from_secs(if is_tcg { 6 } else { 3 }));
    let ui_ppm = capture(&mut qmp, run_dir, "02-core-ui", state)?;

    // Stage 4: Find "Open GParted" (2nd blue button) and click it
    let (w, h, px) = read_ppm(&ui_ppm)?;
    let (gx, gy) = find_nth_colored_button(&px, w, h, ColorKind::Blue, 1)
        .unwrap_or(((w as f32 * 0.36) as u32, (h as f32 * 0.48) as u32));
    qmp.click_abs(gx, gy, w, h)?;
    state
        .qmp_actions
        .push(format!("click_abs({gx}, {gy}) Open GParted"));

    wait_until(child, &mut serial, &mut buf, deadline, |text| {
        text.contains("SBM_GPARTED_LAUNCHED")
    })
    .map_err(|e| Error::message(format!("stage4 gparted launch: {e}")))?;
    state.stages_ms.insert(
        "gparted_launched".into(),
        started.elapsed().as_millis() as u64,
    );
    // Poll until GParted finishes scanning disks and maps its main window.
    let gp_wait_deadline = Instant::now() + Duration::from_secs(if is_tcg { 60 } else { 15 });
    let mut dropdown = None;
    let initial_wait = Duration::from_secs(if is_tcg { 12 } else { 5 });
    thread::sleep(initial_wait);
    let gp_ppm = loop {
        let candidate = capture(&mut qmp, run_dir, "03-gparted", state)?;
        let (gw, gh, gpx) = read_ppm(&candidate)?;
        if let Some(pos) = find_gparted_device_dropdown(&gpx, gw, gh) {
            // Extra settle after window appears so initial device scan finishes.
            thread::sleep(Duration::from_secs(if is_tcg { 8 } else { 2 }));
            let settled = capture(&mut qmp, run_dir, "03-gparted", state)?;
            let (gw2, gh2, gpx2) = read_ppm(&settled)?;
            dropdown = find_gparted_device_dropdown(&gpx2, gw2, gh2).or(Some(pos));
            break settled;
        }
        if Instant::now() >= gp_wait_deadline {
            break candidate;
        }
        thread::sleep(Duration::from_secs(2));
    };

    // Open GParted device dropdown at the top-right of the GParted window.
    let (gw, gh, _gpx) = read_ppm(&gp_ppm)?;
    let (dx, dy) = dropdown.unwrap_or(((gw as f32 * 0.73) as u32, (gh as f32 * 0.265) as u32));
    qmp.click_abs(dx, dy, gw, gh)?;
    state
        .qmp_actions
        .push(format!("click_abs({dx}, {dy}) GParted device selector"));
    thread::sleep(Duration::from_secs(if is_tcg { 5 } else { 2 }));
    capture(&mut qmp, run_dir, "04-gparted-devices", state)?;

    // Close GParted dropdown + window cleanly via Escape then Ctrl+Q.
    let _ = qmp.send_key("esc");
    thread::sleep(Duration::from_millis(if is_tcg { 1000 } else { 400 }));
    let _ = qmp.send_keys(&["ctrl", "q"]);
    state
        .qmp_actions
        .push("send-keys: esc, ctrl+q (close GParted)".into());
    thread::sleep(Duration::from_secs(if is_tcg { 5 } else { 2 }));

    // Stage 5: Click Reboot then Confirm on SBM Core UI.
    let pre_reboot = run_dir.join("pre-reboot.ppm");
    qmp.screendump(&pre_reboot)?;
    let (rw, rh, rpx) = read_ppm(&pre_reboot)?;
    let (rx, ry) = find_nth_colored_button(&rpx, rw, rh, ColorKind::Red, 0)
        .unwrap_or(((rw as f32 * 0.23) as u32, (rh as f32 * 0.57) as u32));
    qmp.click_abs(rx, ry, rw, rh)?;
    state
        .qmp_actions
        .push(format!("click_abs({rx}, {ry}) Reboot"));
    thread::sleep(Duration::from_millis(if is_tcg { 3500 } else { 1200 }));

    let confirm_ppm = run_dir.join("confirm-reboot.ppm");
    qmp.screendump(&confirm_ppm)?;
    let (cw, ch, cpx) = read_ppm(&confirm_ppm)?;
    let (cx, cy) =
        find_lowest_colored_button(&cpx, cw, ch, ColorKind::Red, ry + 15).unwrap_or((rx, ry + 64));
    qmp.click_abs(cx, cy, cw, ch)?;
    state
        .qmp_actions
        .push(format!("click_abs({cx}, {cy}) Confirm Reboot"));

    // Stage 6: Wait for second menu_ready after guest reboot + observe QMP RESET event.
    wait_until(child, &mut serial, &mut buf, deadline, |text| {
        if qmp.has_event("RESET") {
            state.saw_reset_event = true;
        }
        let count = parse_markers(text)
            .iter()
            .filter(|m| m.name == "menu_ready")
            .count();
        count >= 2
    })
    .map_err(|e| Error::message(format!("stage6 post-reboot menu_ready: {e}")))?;
    if qmp.has_event("RESET") {
        state.saw_reset_event = true;
    }
    state
        .stages_ms
        .insert("uefi_menu_2".into(), started.elapsed().as_millis() as u64);
    thread::sleep(Duration::from_millis(600));
    capture(&mut qmp, run_dir, "05-post-reboot-menu", state)?;

    state.qmp_events = qmp.events().to_vec();
    let _ = qmp.quit();
    Ok(())
}

fn capture(qmp: &mut Qmp, run_dir: &Path, name: &str, state: &mut FlowState) -> Result<PathBuf> {
    let path = run_dir.join(format!("{name}.ppm"));
    qmp.screendump(&path)?;
    state
        .screenshots
        .insert(name.to_string(), path.display().to_string());
    Ok(path)
}

fn wait_open_child(child: &mut Child, path: &Path, deadline: Instant) -> Result<File> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(Error::message(format!(
                "qemu exited ({status}) before creating {}",
                path.display()
            )));
        }
        if Instant::now() > deadline {
            return Err(Error::message(format!(
                "timed out waiting for {}",
                path.display()
            )));
        }
        if let Ok(file) = File::open(path) {
            return Ok(file);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_open(path: &Path, deadline: Instant) -> Result<File> {
    loop {
        if Instant::now() > deadline {
            return Err(Error::message(format!(
                "timed out waiting for {}",
                path.display()
            )));
        }
        if let Ok(file) = File::open(path) {
            return Ok(file);
        }
        thread::sleep(Duration::from_millis(30));
    }
}

fn wait_qmp(path: &Path, deadline: Instant) -> Result<Qmp> {
    loop {
        if Instant::now() > deadline {
            return Err(Error::message("timed out connecting to qmp"));
        }
        if let Ok(qmp) = Qmp::connect(path) {
            return Ok(qmp);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_until<F>(
    child: &mut Child,
    serial: &mut File,
    buf: &mut String,
    deadline: Instant,
    mut pred: F,
) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let mut tmp = [0u8; 4096];
    loop {
        if Instant::now() > deadline {
            return Err(Error::message("timed out"));
        }
        match serial.read(&mut tmp) {
            Ok(0) => {
                if let Some(status) = child.try_wait()? {
                    return Err(Error::message(format!("qemu exited early: {status}")));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Ok(n) => {
                buf.push_str(&String::from_utf8_lossy(&tmp[..n]));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
        if pred(buf) {
            return Ok(());
        }
    }
}

fn build_decoy_esp(root: &Path, arch: Arch) -> Result<Vec<u8>> {
    let fixture = fs::read(find_fixture(root, arch)?)?;
    let bls_arch = match arch {
        Arch::Aarch64 => "aa64",
        Arch::X86_64 => "x64",
        Arch::Ia32 => "ia32",
    };
    let bls = format!(
        "title Fedora Linux (Decoy Fixture)\nlinux \\EFI\\Linux\\fedora.efi\noptions quiet\narchitecture {bls_arch}\n"
    );
    let marker = b"SBM decoy ESP: must receive zero state writes.\n";
    let files: Vec<(String, &[u8])> = vec![
        ("EFI/Linux/fedora.efi".into(), &fixture),
        ("loader/entries/fedora.conf".into(), bls.as_bytes()),
        ("EFI/decoy-marker.txt".into(), marker),
    ];
    let fat = build_fat32(48 * 1024 * 1024, "DECOYESP", &files)?;
    let disk = build_gpt(
        "sbm-decoy",
        &[PartitionSpec {
            name: "DECOY-ESP".into(),
            type_guid: esp_guid(),
            size_bytes: fat.len() as u64,
            payload: fat,
        }],
        false,
    )?;
    Ok(disk.bytes)
}

fn inspect_overlay_esp(
    base_image: &Path,
    overlay: &Path,
    run_dir: &Path,
) -> Result<(Option<Value>, bool, bool)> {
    let parts = validate_gpt_file(base_image)?;
    let esp = parts
        .iter()
        .find(|p| p.type_guid == esp_guid())
        .ok_or_else(|| Error::message("image missing GPT ESP"))?;
    let sectors = esp.end_lba - esp.start_lba + 1;
    let esp_out = run_dir.join("esp-part.raw");
    let status = Command::new("qemu-img")
        .args([
            "dd",
            "-f",
            "qcow2",
            "-O",
            "raw",
            &format!("if={}", overlay.display()),
            &format!("of={}", esp_out.display()),
            &format!("bs={SECTOR}"),
            &format!("skip={}", esp.start_lba),
            &format!("count={sectors}"),
        ])
        .status()?;
    if !status.success() {
        return Err(Error::message("qemu-img dd failed extracting overlay ESP"));
    }
    let state_dir = run_dir.join("esp-state");
    fs::create_dir_all(&state_dir)?;

    let last_attempt = match read_fat_file_from_path(&esp_out, "EFI/sbm/state/last_attempt.json") {
        Ok(raw) => {
            let _ = fs::write(state_dir.join("last_attempt.json"), &raw);
            serde_json::from_slice::<Value>(&raw).ok()
        }
        Err(_) => None,
    };
    let current_handoff_present =
        match read_fat_file_from_path(&esp_out, "EFI/sbm/handoff/current.json") {
            Ok(raw) => {
                let _ = fs::write(state_dir.join("current.json"), &raw);
                true
            }
            Err(_) => false,
        };
    let boot_success_consumed =
        match read_fat_file_from_path(&esp_out, "EFI/sbm/state/boot-success.json") {
            Ok(raw) => {
                let _ = fs::write(state_dir.join("boot-success.json"), &raw);
                false
            }
            Err(_) => true,
        };
    Ok((last_attempt, current_handoff_present, boot_success_consumed))
}

fn qemu_img_create_overlay(backing: &Path, dest: &Path) -> Result<()> {
    let status = Command::new("qemu-img")
        .args([
            "create",
            "-q",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            &backing.display().to_string(),
            &dest.display().to_string(),
        ])
        .status()?;
    if !status.success() {
        return Err(Error::message("qemu-img overlay create failed"));
    }
    Ok(())
}

fn qemu_img_create_blank(dest: &Path, size: &str) -> Result<()> {
    let status = Command::new("qemu-img")
        .args([
            "create",
            "-q",
            "-f",
            "qcow2",
            &dest.display().to_string(),
            size,
        ])
        .status()?;
    if !status.success() {
        return Err(Error::message("qemu-img blank disk create failed"));
    }
    Ok(())
}

fn query_accels(qemu_bin: &Path) -> Vec<String> {
    let Ok(out) = Command::new(qemu_bin).args(["-accel", "help"]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn parse_menu_ready_us(markers: &[Marker]) -> Vec<u64> {
    markers
        .iter()
        .filter(|m| m.name == "menu_ready")
        .filter_map(|m| m.fields.get("us").and_then(|v| v.parse::<u64>().ok()))
        .collect()
}

pub fn parse_verify_done(markers: &[Marker]) -> (bool, Option<u64>) {
    for m in markers {
        if m.name == "verify_done" {
            let ok = m.fields.get("result").map(String::as_str) == Some("ok");
            let us = m.fields.get("us").and_then(|v| v.parse::<u64>().ok());
            return (ok, us);
        }
    }
    (false, None)
}

/// Compute RGB luminance standard deviation across sampled pixels and return
/// true when the screenshot is demonstrably non-blank.
pub fn ppm_is_non_blank(path: &Path) -> Result<bool> {
    let (w, h, px) = read_ppm(path)?;
    Ok(rgb_luma_stddev(&px, w, h) >= MIN_SCREENSHOT_LUMA_STDDEV)
}

fn rgb_luma_stddev(px: &[u8], w: u32, h: u32) -> f64 {
    let total_pixels = (w as usize).saturating_mul(h as usize);
    if total_pixels == 0 || px.len() < total_pixels * 3 {
        return 0.0;
    }
    let step = (total_pixels / 4096).max(1);
    let mut sum = 0.0f64;
    let mut sum_sq = 0.0f64;
    let mut count = 0u64;
    let mut i = 0usize;
    while i < total_pixels {
        let off = i * 3;
        let luma = 0.299 * px[off] as f64 + 0.587 * px[off + 1] as f64 + 0.114 * px[off + 2] as f64;
        sum += luma;
        sum_sq += luma * luma;
        count += 1;
        i += step;
    }
    if count == 0 {
        return 0.0;
    }
    let mean = sum / count as f64;
    let variance = (sum_sq / count as f64 - mean * mean).max(0.0);
    variance.sqrt()
}

/// Fraction of pixels (`0.0..=1.0`) whose RGB channels differ by > 16 between two PPMs.
pub fn ppm_diff_ratio(a: &Path, b: &Path) -> Result<f64> {
    let (wa, ha, pa) = read_ppm(a)?;
    let (wb, hb, pb) = read_ppm(b)?;
    if wa != wb || ha != hb {
        return Ok(1.0);
    }
    Ok(rgb_diff_ratio(&pa, &pb))
}

fn rgb_diff_ratio(pa: &[u8], pb: &[u8]) -> f64 {
    let n = pa.len().min(pb.len()) / 3;
    if n == 0 {
        return 0.0;
    }
    let step = (n / 8192).max(1);
    let mut diff = 0u64;
    let mut total = 0u64;
    let mut i = 0usize;
    while i < n {
        let off = i * 3;
        let dr = pa[off].abs_diff(pb[off]);
        let dg = pa[off + 1].abs_diff(pb[off + 1]);
        let db = pa[off + 2].abs_diff(pb[off + 2]);
        if dr > 16 || dg > 16 || db > 16 {
            diff += 1;
        }
        total += 1;
        i += step;
    }
    if total == 0 {
        0.0
    } else {
        diff as f64 / total as f64
    }
}

#[derive(Clone, Copy)]
enum ColorKind {
    Blue,
    Red,
}

fn matches_color(r: u8, g: u8, b: u8, kind: ColorKind) -> bool {
    match kind {
        ColorKind::Blue => b > 180 && r < 100,
        ColorKind::Red => r > 180 && g < 130 && b < 130,
    }
}

fn read_ppm(path: &Path) -> Result<(u32, u32, Vec<u8>)> {
    let data = fs::read(path)?;
    if !data.starts_with(b"P6") {
        return Err(Error::message(format!(
            "{} is not a P6 PPM",
            path.display()
        )));
    }
    let mut i = 2usize;
    let mut nums = Vec::new();
    while nums.len() < 3 && i < data.len() {
        while i < data.len() && data[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < data.len() && data[i] == b'#' {
            while i < data.len() && data[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        while i < data.len() && !data[i].is_ascii_whitespace() {
            i += 1;
        }
        let val: u32 = std::str::from_utf8(&data[start..i])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::message("invalid PPM header"))?;
        nums.push(val);
    }
    if nums.len() != 3 || i + 1 >= data.len() {
        return Err(Error::message("truncated PPM header"));
    }
    Ok((nums[0], nums[1], data[i + 1..].to_vec()))
}

fn find_colored_buttons(
    px: &[u8],
    w: u32,
    h: u32,
    kind: ColorKind,
    min_y: u32,
) -> Vec<(u32, u32, u32, u32)> {
    // Scan content pane (x >= 220) to skip left nav bar.
    let x_start = (w / 5).min(220);
    let mut boxes: Vec<(u32, u32, u32, u32)> = Vec::new();
    for y in min_y..h {
        let mut x = x_start;
        while x < w {
            let off = ((y * w + x) * 3) as usize;
            if off + 2 < px.len() && matches_color(px[off], px[off + 1], px[off + 2], kind) {
                let run_start = x;
                while x < w {
                    let o = ((y * w + x) * 3) as usize;
                    if o + 2 >= px.len() || !matches_color(px[o], px[o + 1], px[o + 2], kind) {
                        break;
                    }
                    x += 1;
                }
                let run_end = x - 1;
                if run_end - run_start >= 30 {
                    if let Some(b) = boxes
                        .iter_mut()
                        .find(|b| run_start <= b.2 + 4 && run_end + 4 >= b.0 && y <= b.3 + 16)
                    {
                        b.0 = b.0.min(run_start);
                        b.1 = b.1.min(y);
                        b.2 = b.2.max(run_end);
                        b.3 = b.3.max(y);
                    } else {
                        boxes.push((run_start, y, run_end, y));
                    }
                }
            } else {
                x += 1;
            }
        }
    }
    boxes.retain(|b| b.3 - b.1 >= 14 && b.2 - b.0 >= 40);
    boxes.sort_by_key(|b| (b.1 / 20, b.0));
    boxes
}

fn find_nth_colored_button(
    px: &[u8],
    w: u32,
    h: u32,
    kind: ColorKind,
    index: usize,
) -> Option<(u32, u32)> {
    let boxes = find_colored_buttons(px, w, h, kind, 120);
    boxes.get(index).map(|b| ((b.0 + b.2) / 2, (b.1 + b.3) / 2))
}

fn find_lowest_colored_button(
    px: &[u8],
    w: u32,
    h: u32,
    kind: ColorKind,
    min_y: u32,
) -> Option<(u32, u32)> {
    let boxes = find_colored_buttons(px, w, h, kind, min_y);
    boxes.last().map(|b| ((b.0 + b.2) / 2, (b.1 + b.3) / 2))
}

fn find_gparted_device_dropdown(px: &[u8], w: u32, h: u32) -> Option<(u32, u32)> {
    // GParted renders a bright light-gray/white window (r,g,b > 200) over the dark
    // SBM Core background. Find the first row with a wide contiguous bright span
    // (>= 400 px) to ignore white text in SBM Core, then aim at the top-right
    // toolbar device combobox (~95 px left, ~76 px down from the window top-right).
    for y in 40..h {
        let mut run = 0u32;
        let mut best_len = 0u32;
        let mut best_end = 0u32;
        for x in 180..w {
            let off = ((y * w + x) * 3) as usize;
            if off + 2 < px.len() && px[off] > 200 && px[off + 1] > 200 && px[off + 2] > 200 {
                run += 1;
                if run > best_len {
                    best_len = run;
                    best_end = x;
                }
            } else {
                run = 0;
            }
        }
        if best_len >= 400 {
            return Some((best_end.saturating_sub(95), y.saturating_add(76)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_menu_ready_and_verify_done_markers() {
        let log = "SBM_MARK menu_ready us=15730\n\
                   SBM_MARK verify_done us=362040 bytes=74513752 reads=72 chunk=1048576 result=ok\n\
                   SBM_MARK menu_ready us=18120\n";
        let markers = parse_markers(log);
        assert_eq!(parse_menu_ready_us(&markers), vec![15_730, 18_120]);
        assert_eq!(parse_verify_done(&markers), (true, Some(362_040)));

        let bad = "SBM_MARK verify_done us=12000 result=failed reason=digest\n";
        assert_eq!(
            parse_verify_done(&parse_markers(bad)),
            (false, Some(12_000))
        );
    }

    #[test]
    fn pixel_variance_rejects_flat_frames_and_detects_deltas() {
        let flat_black = vec![0u8; 64 * 64 * 3];
        assert!(rgb_luma_stddev(&flat_black, 64, 64) < MIN_SCREENSHOT_LUMA_STDDEV);

        let mut checkerboard = vec![0u8; 64 * 64 * 3];
        for (idx, chunk) in checkerboard.as_chunks_mut::<3>().0.iter_mut().enumerate() {
            let v = if idx % 2 == 0 { 20 } else { 220 };
            chunk[0] = v;
            chunk[1] = v;
            chunk[2] = v;
        }
        assert!(rgb_luma_stddev(&checkerboard, 64, 64) >= MIN_SCREENSHOT_LUMA_STDDEV);
        assert_eq!(rgb_diff_ratio(&checkerboard, &checkerboard), 0.0);
        assert!(rgb_diff_ratio(&flat_black, &checkerboard) >= 0.4);
    }

    #[test]
    fn negative_scenario_filter_validates_names() {
        assert_eq!(parse_negative_scenarios(None).unwrap().len(), 6);
        assert_eq!(parse_negative_scenarios(Some("all")).unwrap().len(), 6);
        assert_eq!(
            parse_negative_scenarios(Some("tampered-uki")).unwrap(),
            vec!["tampered-uki"]
        );
        assert!(parse_negative_scenarios(Some("unknown-case")).is_err());
    }
}
