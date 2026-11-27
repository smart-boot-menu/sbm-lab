//! End-to-end integration test harness for dual-architecture SBM images.
//!
//! Boots a disposable QCOW2 overlay of a real dual-arch SBM `.raw` image as
//! removable USB storage alongside a decoy ESP (enumerated first) and two
//! blank virtual disks (1 GiB and 2 GiB), with no virtual NIC and no
//! `-no-reboot`. Drives the full user flow via QMP:
//!
//! 1. Firmware -> SBM UEFI graphical menu (`01-uefi-menu.ppm`)
//! 2. QMP `c` -> Manage Computer -> native Core UKI chainload
//! 3. Linux dm-verity EROFS -> `sbm-cored` + `labwc` + Iced `sbm-ui` (`02-core-ui.ppm`)
//! 4. QMP click `Open GParted` -> GParted window (`03-gparted.ppm`) + device selector (`04-gparted-devices.ppm`)
//! 5. QMP close GParted (`Ctrl+Q`) -> click `Reboot` -> click `Confirm` -> QMP `RESET` event
//! 6. Same SBM UEFI menu returns, confirms attempt (`05-post-reboot-menu.ppm`)
//! 7. Inspects overlay ESP state, decoy ESP immutability, and input SHA-256 hashes.

use crate::accel::{Accel, AccelRequest, Arch, HostFacts, effective_timeout, select_accel};
use crate::error::{Error, Result};
use crate::fatimg::{build_fat32, read_fat_file};
use crate::firmware::{copy_vars, select_firmware};
use crate::gpt::{PartitionSpec, SECTOR, build_gpt, esp_guid, validate_gpt};
use crate::host::host_facts;
use crate::launch::{AttachedDisk, LaunchPlan, qemu_args};
use crate::markers::parse_markers;
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
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct IntegrationOptions {
    pub image: PathBuf,
    pub arch: Arch,
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
    pub accel: String,
    pub execution_class: String,
    pub image: String,
    pub image_sha256: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub gates: BTreeMap<String, bool>,
    pub stages_ms: BTreeMap<String, u64>,
    pub duration_ms: u64,
    pub screenshots: BTreeMap<String, String>,
    pub qmp_events: Vec<Value>,
    pub qmp_actions: Vec<String>,
    pub last_attempt: Option<Value>,
    pub current_handoff_present: bool,
    pub boot_success_consumed: bool,
    pub decoy_esp_unchanged: bool,
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

    // Disposable 1 GiB and 2 GiB inspectable virtual disks.
    let disk1g = run_dir.join("disk-1g.qcow2");
    let disk2g = run_dir.join("disk-2g.qcow2");
    qemu_img_create_blank(&disk1g, "1G")?;
    qemu_img_create_blank(&disk2g, "2G")?;

    // Disposable QCOW2 overlay of the real unchanged dual-arch raw image.
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
                path: disk1g,
                format: "qcow2".into(),
                bootindex: 2,
                blkdebug: None,
                serial: Some("SBMTEST1G".into()),
            },
            AttachedDisk {
                id: "disk2g".into(),
                path: disk2g,
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
        gpu: GpuKind::Virtio,
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
    drop(budget);

    // Post-shutdown inspection of ESP state on overlay and decoy immutability.
    let mut failure = flow_res.err().map(|e| e.to_string());
    let decoy_hash_after = sha256_file(&decoy_raw)?;
    let decoy_esp_unchanged = decoy_hash_before == decoy_hash_after;

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
    let menu_ready_count = markers.iter().filter(|m| m.name == "menu_ready").count();

    let mut gates: BTreeMap<String, bool> = BTreeMap::new();
    gates.insert(
        "gate1_uefi_menu".into(),
        menu_ready_count >= 1 && state.screenshots.contains_key("01-uefi-menu"),
    );
    gates.insert(
        "gate2_discovered_targets".into(),
        serial_text.contains("SBM Core") && serial_text.contains("Fedora"),
    );
    gates.insert(
        "gate3_manage_computer_handoff".into(),
        current_handoff_present && serial_text.contains("handoff_verified=true"),
    );
    gates.insert(
        "gate4_real_linux_core".into(),
        serial_text.contains("Linux version")
            && serial_text.contains("SBM_BOOT_METRICS")
            && serial_text.contains("backing=/dev/sd"),
    );
    gates.insert(
        "gate5_management_ui".into(),
        serial_text.contains("SBM_UI_READY")
            && serial_text.contains("SBM_BOOT_SUCCESS_WRITTEN")
            && state.screenshots.contains_key("02-core-ui"),
    );
    gates.insert(
        "gate6_gparted_and_disks".into(),
        serial_text.contains("SBM_GPARTED_LAUNCHED")
            && state.screenshots.contains_key("03-gparted")
            && state.screenshots.contains_key("04-gparted-devices"),
    );
    gates.insert(
        "gate7_reboot_and_confirmation".into(),
        state.saw_reset_event
            && menu_ready_count >= 2
            && serial_text.contains("attempt confirmed")
            && confirmed_in_json
            && boot_success_consumed
            && state.screenshots.contains_key("05-post-reboot-menu"),
    );
    gates.insert("gate8_offline".into(), !argv.iter().any(|a| a == "-netdev"));
    gates.insert(
        "gate9_integrity_and_decoy".into(),
        inputs_unchanged && decoy_esp_unchanged,
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
        schema: "sbm-lab.integration.v1",
        id: id.clone(),
        arch: opts.arch.to_string(),
        accel: choice.accel.to_string(),
        execution_class: choice.execution_class.as_str().into(),
        image: opts.image.display().to_string(),
        image_sha256: image_hash_before,
        success: failure.is_none(),
        failure_reason: failure,
        gates,
        stages_ms: state.stages_ms,
        duration_ms: started.elapsed().as_millis() as u64,
        screenshots: state.screenshots.clone(),
        qmp_events: state.qmp_events,
        qmp_actions: state.qmp_actions,
        last_attempt,
        current_handoff_present,
        boot_success_consumed,
        decoy_esp_unchanged,
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
        let dest = dir.join(format!("{}-{}", opts.arch, id));
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
    // Read GPT header + entries from the first 1 MiB of the base raw image.
    let mut header = vec![0u8; 1024 * 1024];
    {
        let mut f = File::open(base_image)?;
        f.read_exact(&mut header)?;
    }
    let parts = validate_gpt(&header)?;
    let esp = parts
        .iter()
        .find(|p| p.type_guid == esp_guid())
        .ok_or_else(|| Error::message("dual-arch image missing GPT ESP"))?;
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
    let bytes = fs::read(&esp_out)?;
    let state_dir = run_dir.join("esp-state");
    fs::create_dir_all(&state_dir)?;

    let last_attempt = match read_fat_file(&bytes, "EFI/sbm/state/last_attempt.json") {
        Ok(raw) => {
            let _ = fs::write(state_dir.join("last_attempt.json"), &raw);
            serde_json::from_slice::<Value>(&raw).ok()
        }
        Err(_) => None,
    };
    let current_handoff_present = match read_fat_file(&bytes, "EFI/sbm/handoff/current.json") {
        Ok(raw) => {
            let _ = fs::write(state_dir.join("current.json"), &raw);
            true
        }
        Err(_) => false,
    };
    let boot_success_consumed = match read_fat_file(&bytes, "EFI/sbm/state/boot-success.json") {
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
                        .find(|b| run_start <= b.2 + 8 && run_end + 8 >= b.0 && y <= b.3 + 4)
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
