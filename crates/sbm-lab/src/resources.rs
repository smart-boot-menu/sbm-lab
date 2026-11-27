//! Cross-repository QEMU admission.
//!
//! Reservations live in one per-user directory, not in a checkout. Admission
//! holds an exclusive flock on that directory for the check and the write, so
//! two agents cannot reserve the same remaining memory. There is no resident
//! daemon. This process signals only a QEMU pid it started, and only when
//! that pid still has the start time recorded at attach.

use crate::error::{Error, Result};
use crate::profile::{GpuKind, Role};
use crate::util::{FileLock, short_id};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "sbm-lab.resources.v1";
/// An 8192 MiB aarch64 guest on macOS HVF was idle at about 533 MiB inside the
/// guest and still charged about 15 GB of physical footprint. RSS is not the
/// admission number on macOS. Linux KVM demand-pages guest RAM (~1x).
#[cfg(target_os = "macos")]
const FOOTPRINT_PER_GUEST_MIB: u64 = 2;
#[cfg(not(target_os = "macos"))]
const FOOTPRINT_PER_GUEST_MIB: u64 = 1;
/// `hw.memsize` on a 16 GiB Mac is 16384 MiB. Linux `MemTotal` for that
/// class of machine is lower by the kernel reservation, so the same floor
/// starts at 15 GiB.
const SIXTEEN_GIB_CLASS_MIB: u64 = 15 * 1024;
static NOTED_QEMU: AtomicU32 = AtomicU32::new(0);
static CANCEL_HANDLERS: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Workload {
    Efi,
    Linux,
    Graphical,
    Build,
    Ram,
}

impl Workload {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "efi" => Some(Self::Efi),
            "linux" => Some(Self::Linux),
            "graphical" => Some(Self::Graphical),
            "build" => Some(Self::Build),
            "ram" => Some(Self::Ram),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Efi => "efi",
            Self::Linux => "linux",
            Self::Graphical => "graphical",
            Self::Build => "build",
            Self::Ram => "ram",
        }
    }

    pub fn spec(self) -> WorkloadSpec {
        match self {
            // Menu and Secure Boot runs on this machine used 1024 MiB.
            Self::Efi => WorkloadSpec {
                memory_mib: 1024,
                cpus: 1,
                max_memory_mib: 1024,
                heavy: false,
            },
            Self::Linux => WorkloadSpec {
                memory_mib: 2048,
                cpus: 2,
                max_memory_mib: 2048,
                heavy: false,
            },
            Self::Graphical => WorkloadSpec {
                memory_mib: 4096,
                cpus: 2,
                max_memory_mib: 4096,
                heavy: true,
            },
            // linux-dev completed at 4096 MiB and 4 vCPUs. The cap is 6 GiB.
            Self::Build => WorkloadSpec {
                memory_mib: 4096,
                cpus: 4,
                max_memory_mib: 6144,
                heavy: true,
            },
            Self::Ram => WorkloadSpec {
                memory_mib: 6144,
                cpus: 2,
                max_memory_mib: 8192,
                heavy: true,
            },
        }
    }
}

impl std::fmt::Display for Workload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WorkloadSpec {
    pub memory_mib: u32,
    pub cpus: u32,
    pub max_memory_mib: u32,
    pub heavy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Pressure {
    Normal,
    Warn,
    Critical,
    Unknown,
}

impl Pressure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Warn => "warn",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunningQemu {
    pub pid: u32,
    pub guest_mib: u32,
    pub cpus: u32,
    pub memory_known: bool,
    pub command: String,
    pub repo: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostView {
    pub total_mib: u64,
    pub pressure: Pressure,
    pub swap_used_mib: u64,
    pub swap_total_mib: u64,
    pub cpus: u32,
    pub qemu: Vec<RunningQemu>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub max_concurrent: u32,
    pub max_heavy: u32,
}

impl Policy {
    pub fn from_env() -> Self {
        Self {
            max_concurrent: crate::util::env_u32("SBM_VM_MAX_CONCURRENT", 2).max(1),
            max_heavy: crate::util::env_u32("SBM_VM_MAX_HEAVY", 1).max(1),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reservation {
    pub schema: String,
    pub id: String,
    pub owner_pid: u32,
    pub qemu_pid: Option<u32>,
    pub repo: String,
    pub workload: Workload,
    pub memory_mib: u32,
    pub cpus: u32,
    pub heavy: bool,
    pub created_unix: u64,
    /// `ps -o lstart=` at reserve time. A live pid with a different start is
    /// a reuse, not this owner.
    #[serde(default)]
    pub owner_start: Option<String>,
    #[serde(default)]
    pub qemu_start: Option<String>,
    /// True when the reservation intentionally outlives its launching shell
    /// (for example, a persistent builder VM started via `setsid`).
    #[serde(default)]
    pub detached: bool,
}

#[derive(Debug, Clone)]
pub struct AdmitRequest {
    pub owner_pid: u32,
    pub repo: String,
    pub workload: Workload,
    pub memory_mib: u32,
    pub cpus: u32,
    pub detached: bool,
}

#[derive(Debug, Serialize)]
pub struct ResourceReport {
    pub schema: &'static str,
    pub runtime: String,
    pub total_mib: u64,
    pub pressure: String,
    pub swap_used_mib: u64,
    pub swap_total_mib: u64,
    pub host_floor_mib: u64,
    pub guest_budget_mib: u64,
    pub guest_used_mib: u64,
    pub host_cpus: u32,
    pub guest_cpus: u32,
    pub max_concurrent: u32,
    pub max_heavy: u32,
    pub running: u32,
    pub reservations: Vec<Reservation>,
    pub qemu: Vec<QemuRow>,
    pub warnings: Vec<String>,
    pub ok: bool,
}

#[derive(Debug, Serialize)]
pub struct QemuRow {
    pub pid: u32,
    pub guest_mib: u32,
    pub cpus: u32,
    pub memory_known: bool,
    pub repo: Option<String>,
    pub reservation_id: Option<String>,
    pub command: String,
}

/// In-process reservation. Drop releases it. When `kill_on_drop` is set, Drop
/// also SIGKILLs the qemu pid attached here and no other pid.
pub struct ReservationGuard {
    runtime: PathBuf,
    id: String,
    qemu_pid: Option<u32>,
    qemu_start: Option<String>,
    release_on_drop: bool,
    kill_on_drop: bool,
}

impl ReservationGuard {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn attach_qemu(&mut self, pid: u32) -> Result<()> {
        let start = attach_pid(&self.runtime, &self.id, pid)?;
        self.qemu_pid = Some(pid);
        self.qemu_start = start;
        Ok(())
    }

    /// Clear tracked QEMU pid immediately after `child.wait()` reaps it so a
    /// signal handler or `Drop` can never signal a subsequently reused PID.
    pub fn mark_reaped(&mut self) {
        if let Some(pid) = self.qemu_pid.take() {
            clear_noted_qemu_pid(pid);
        }
        self.qemu_start = None;
    }
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        if self.kill_on_drop
            && let Some(pid) = self.qemu_pid
        {
            kill_if_same_process(pid, &self.qemu_start);
            if NOTED_QEMU.load(Ordering::SeqCst) == pid {
                NOTED_QEMU.store(0, Ordering::SeqCst);
            }
        }
        if self.release_on_drop {
            let _ = release_id(&self.runtime, &self.id, false);
        }
    }
}

pub fn workload_for(role: Role, gpu: GpuKind, graphical: bool) -> Workload {
    if role == Role::BuildVm {
        Workload::Build
    } else if graphical || gpu == GpuKind::Virtio {
        Workload::Graphical
    } else {
        Workload::Efi
    }
}

pub fn clamp_launch(
    workload: Workload,
    memory: u32,
    cpus: u32,
    explicit_memory: bool,
    explicit_cpus: bool,
) -> Result<(u32, u32)> {
    let spec = workload.spec();
    if explicit_memory && memory > spec.max_memory_mib {
        return Err(Error::message(format!(
            "{workload} allows at most {} MiB; the request is {memory} MiB",
            spec.max_memory_mib
        )));
    }
    if explicit_cpus && cpus > spec.cpus {
        return Err(Error::message(format!(
            "{workload} allows at most {} vCPU; the request is {cpus}",
            spec.cpus
        )));
    }
    Ok((
        memory.min(spec.max_memory_mib).max(128),
        cpus.clamp(1, spec.cpus),
    ))
}

pub fn runtime_dir() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("SBM_LAB_RUNTIME")
        && !value.is_empty()
    {
        return Ok(PathBuf::from(value));
    }
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| Error::message("HOME is not set; set SBM_LAB_RUNTIME"))?;
    if cfg!(target_os = "macos") {
        Ok(home.join("Library/Application Support/sbm-lab"))
    } else {
        let base = std::env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".local/state"));
        Ok(base.join("sbm-lab"))
    }
}

pub fn host_floor_mib(
    total_mib: u64,
    pressure: Pressure,
    swap_used_mib: u64,
    swap_total_mib: u64,
) -> u64 {
    if pressure == Pressure::Critical {
        return total_mib;
    }
    // 6 GiB is the leftover that still rejected an 8192 MiB guest on the
    // 16 GiB Mac once the 2x footprint was applied. A warning or a half-full
    // swap file raises that floor.
    let mut floor = if total_mib >= SIXTEEN_GIB_CLASS_MIB {
        6144
    } else {
        total_mib / 2
    };
    if pressure == Pressure::Warn {
        floor += 1024;
    }
    if swap_total_mib > 0 && swap_used_mib.saturating_mul(2) > swap_total_mib {
        floor += 2048;
    }
    floor.min(total_mib)
}

pub fn guest_budget_mib_for(
    total_mib: u64,
    pressure: Pressure,
    swap_used_mib: u64,
    swap_total_mib: u64,
    footprint_multiplier: u64,
) -> u64 {
    let floor = host_floor_mib(total_mib, pressure, swap_used_mib, swap_total_mib);
    total_mib.saturating_sub(floor) / footprint_multiplier.max(1)
}

pub fn guest_budget_mib(
    total_mib: u64,
    pressure: Pressure,
    swap_used_mib: u64,
    swap_total_mib: u64,
) -> u64 {
    guest_budget_mib_for(
        total_mib,
        pressure,
        swap_used_mib,
        swap_total_mib,
        FOOTPRINT_PER_GUEST_MIB,
    )
}

pub fn collect_host() -> Result<HostView> {
    let total_mib = read_total_mib()?;
    let pressure = read_pressure();
    let (swap_used_mib, swap_total_mib) = read_swap();
    let cpus = read_cpus();
    let qemu = read_qemu();
    Ok(HostView {
        total_mib,
        pressure,
        swap_used_mib,
        swap_total_mib,
        cpus,
        qemu,
    })
}

pub fn try_admit(
    runtime: &Path,
    view: &HostView,
    policy: &Policy,
    req: &AdmitRequest,
) -> Result<Reservation> {
    admit_inner(runtime, view, policy, req, false)
}

fn try_admit_live(
    runtime: &Path,
    view: &HostView,
    policy: &Policy,
    req: &AdmitRequest,
) -> Result<Reservation> {
    admit_inner(runtime, view, policy, req, true)
}

fn admit_inner(
    runtime: &Path,
    view: &HostView,
    policy: &Policy,
    req: &AdmitRequest,
    refresh_qemu: bool,
) -> Result<Reservation> {
    fs::create_dir_all(runtime)?;
    let _lock = FileLock::exclusive(&runtime.join("admit.lock"))?;
    let live = load_and_reap(runtime)?;
    let view = if refresh_qemu {
        let mut live_view = view.clone();
        live_view.qemu = read_qemu();
        live_view
    } else {
        view.clone()
    };
    decide(&live, &view, policy, req)?;
    let rec = Reservation {
        schema: SCHEMA.into(),
        id: short_id(),
        owner_pid: req.owner_pid,
        owner_start: process_start_token(req.owner_pid),
        qemu_pid: None,
        qemu_start: None,
        repo: req.repo.clone(),
        workload: req.workload,
        memory_mib: req.memory_mib,
        cpus: req.cpus,
        heavy: req.workload.spec().heavy,
        created_unix: unix_now(),
        detached: req.detached,
    };
    store(runtime, &rec)?;
    Ok(rec)
}

pub fn admit_held(
    runtime: &Path,
    view: &HostView,
    policy: &Policy,
    req: &AdmitRequest,
) -> Result<ReservationGuard> {
    let rec = try_admit(runtime, view, policy, req)?;
    Ok(ReservationGuard {
        runtime: runtime.to_path_buf(),
        id: rec.id,
        qemu_pid: None,
        qemu_start: None,
        release_on_drop: true,
        kill_on_drop: true,
    })
}

pub fn admit_retry(req: &AdmitRequest, wait_secs: u64) -> Result<Reservation> {
    let runtime = runtime_dir()?;
    let policy = Policy::from_env();
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    loop {
        let view = collect_host()?;
        match try_admit_live(&runtime, &view, &policy, req) {
            Ok(rec) => return Ok(rec),
            Err(_) if wait_secs > 0 && Instant::now() < deadline => {
                thread::sleep(Duration::from_secs(1));
            }
            Err(err) => return Err(err),
        }
    }
}

pub fn run_reserved(
    req: &AdmitRequest,
    wait_secs: u64,
    timeout_secs: u64,
    command: &[String],
) -> Result<i32> {
    if command.is_empty() {
        return Err(Error::message("resources run needs the command after --"));
    }
    let rec = admit_retry(req, wait_secs)?;
    let mut guard = ReservationGuard {
        runtime: runtime_dir()?,
        id: rec.id,
        qemu_pid: None,
        qemu_start: None,
        release_on_drop: true,
        kill_on_drop: true,
    };
    let mut child_cmd = Command::new(&command[0]);
    tie_to_parent(&mut child_cmd);
    let mut child = child_cmd.args(&command[1..]).spawn()?;
    guard.attach_qemu(child.id())?;
    note_qemu_pid(child.id());
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            guard.mark_reaped();
            return Ok(status.code().unwrap_or(1));
        }
        if timeout_secs > 0 && started.elapsed() >= Duration::from_secs(timeout_secs) {
            let _ = child.kill();
            let _ = child.wait();
            guard.mark_reaped();
            return Ok(124);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

pub fn hold_for_run(root: &Path, req: &AdmitRequest) -> Result<ReservationGuard> {
    let runtime = runtime_dir()?;
    let view = collect_host()?;
    let policy = Policy::from_env();
    let mut req = req.clone();
    if req.repo.is_empty() {
        req.repo = root.display().to_string();
    }
    req.owner_pid = std::process::id();
    let rec = try_admit_live(&runtime, &view, &policy, &req)?;
    Ok(ReservationGuard {
        runtime,
        id: rec.id,
        qemu_pid: None,
        qemu_start: None,
        release_on_drop: true,
        kill_on_drop: true,
    })
}

pub fn release_id(runtime: &Path, id: &str, forget: bool) -> Result<()> {
    check_id(id)?;
    fs::create_dir_all(runtime)?;
    let _lock = FileLock::exclusive(&runtime.join("admit.lock"))?;
    let path = reservation_path(runtime, id);
    let rec = read_reservation(&path).ok_or_else(|| {
        Error::message(format!("no reservation {id} under {}", runtime.display()))
    })?;
    let owner_alive = tracked_alive(rec.owner_pid, &rec.owner_start);
    let qemu_alive = rec
        .qemu_pid
        .is_some_and(|pid| tracked_alive(pid, &rec.qemu_start));
    let ours = caller_owns(rec.owner_pid);
    if ours || forget || (!owner_alive && !qemu_alive) {
        let _ = fs::remove_file(path);
        return Ok(());
    }
    if qemu_alive {
        return Err(Error::message(format!(
            "reservation {id} still has qemu pid {}; this command does not kill it. Stop that process, or pass --forget to drop the record and leave the process running",
            rec.qemu_pid.unwrap_or(0)
        )));
    }
    Err(Error::message(format!(
        "reservation {id} is owned by live pid {}",
        rec.owner_pid
    )))
}

pub fn attach_pid(runtime: &Path, id: &str, qemu_pid: u32) -> Result<Option<String>> {
    check_id(id)?;
    fs::create_dir_all(runtime)?;
    let _lock = FileLock::exclusive(&runtime.join("admit.lock"))?;
    let path = reservation_path(runtime, id);
    let mut rec = read_reservation(&path).ok_or_else(|| {
        Error::message(format!("no reservation {id} under {}", runtime.display()))
    })?;
    if !caller_owns(rec.owner_pid) {
        return Err(Error::message(format!(
            "reservation {id} is owned by pid {}",
            rec.owner_pid
        )));
    }
    let start = process_start_token(qemu_pid);
    rec.qemu_pid = Some(qemu_pid);
    rec.qemu_start = start.clone();
    store(runtime, &rec)?;
    Ok(start)
}

pub fn report(runtime: &Path, view: &HostView, policy: &Policy) -> Result<ResourceReport> {
    fs::create_dir_all(runtime)?;
    let _lock = FileLock::exclusive(&runtime.join("admit.lock"))?;
    let live = load_and_reap(runtime)?;
    Ok(build_report(runtime, view, policy, &live))
}

pub fn status_text(report: &ResourceReport) -> String {
    let mut lines = vec![
        format!(
            "runtime {}  pressure {}  swap {}/{} MiB",
            report.runtime, report.pressure, report.swap_used_mib, report.swap_total_mib
        ),
        format!(
            "host {} MiB  floor {} MiB  guest budget {} MiB  used {} MiB  vCPU {}/{}",
            report.total_mib,
            report.host_floor_mib,
            report.guest_budget_mib,
            report.guest_used_mib,
            report.guest_cpus,
            report.host_cpus
        ),
        format!(
            "running {}/{}  heavy limit {}",
            report.running, report.max_concurrent, report.max_heavy
        ),
    ];
    if report.reservations.is_empty() {
        lines.push("reservations: none".into());
    }
    for rec in &report.reservations {
        let qemu = rec
            .qemu_pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".into());
        lines.push(format!(
            "reservation {} {} {} MiB {} vCPU repo {} owner {} qemu {}",
            rec.id, rec.workload, rec.memory_mib, rec.cpus, rec.repo, rec.owner_pid, qemu
        ));
    }
    if report.qemu.is_empty() {
        lines.push("qemu: none".into());
    }
    for row in &report.qemu {
        let repo = row.repo.clone().unwrap_or_else(|| "unattributed".into());
        let id = row
            .reservation_id
            .clone()
            .unwrap_or_else(|| "unmanaged".into());
        lines.push(format!(
            "qemu pid {} {} MiB {} vCPU {} {}",
            row.pid, row.guest_mib, row.cpus, repo, id
        ));
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines.join("\n")
}

fn build_report(
    runtime: &Path,
    view: &HostView,
    policy: &Policy,
    live: &[Reservation],
) -> ResourceReport {
    let (used, running, guest_cpus) = accounted(live, view);
    let floor = host_floor_mib(
        view.total_mib,
        view.pressure,
        view.swap_used_mib,
        view.swap_total_mib,
    );
    let budget = guest_budget_mib(
        view.total_mib,
        view.pressure,
        view.swap_used_mib,
        view.swap_total_mib,
    );
    let mut warnings = Vec::new();
    if view.pressure == Pressure::Warn {
        warnings.push("memory pressure is warning".into());
    }
    if view.pressure == Pressure::Critical {
        warnings.push("memory pressure is critical; new reservations are refused".into());
    }
    if view.pressure == Pressure::Unknown {
        warnings.push("memory pressure could not be read".into());
    }
    if view.swap_total_mib > 0 && view.swap_used_mib.saturating_mul(2) > view.swap_total_mib {
        warnings.push(format!(
            "swap is {} of {} MiB",
            view.swap_used_mib, view.swap_total_mib
        ));
    }
    if u64::from(used) > budget {
        warnings.push(format!(
            "guest RAM in use ({used} MiB) is above the budget ({budget} MiB)"
        ));
    }
    let mut qemu_rows = Vec::new();
    for qemu in &view.qemu {
        let reservation_id = live.iter().find_map(|rec| {
            rec.qemu_pid
                .filter(|pid| *pid == qemu.pid)
                .map(|_| rec.id.clone())
        });
        if reservation_id.is_none() {
            warnings.push(format!(
                "qemu pid {} is unmanaged ({} MiB guest)",
                qemu.pid, qemu.guest_mib
            ));
        }
        qemu_rows.push(QemuRow {
            pid: qemu.pid,
            guest_mib: qemu.guest_mib,
            cpus: qemu.cpus,
            memory_known: qemu.memory_known,
            repo: qemu.repo.clone(),
            reservation_id,
            command: qemu.command.clone(),
        });
    }
    for rec in live {
        let owner_alive = tracked_alive(rec.owner_pid, &rec.owner_start);
        let qemu_alive = rec
            .qemu_pid
            .is_some_and(|pid| tracked_alive(pid, &rec.qemu_start));
        if !owner_alive && qemu_alive && !rec.detached {
            warnings.push(format!(
                "reservation {} is orphaned; qemu pid {} is still running and will not be killed",
                rec.id,
                rec.qemu_pid.unwrap_or(0)
            ));
        }
        if let Some(pid) = rec.qemu_pid
            && let Some(qemu) = view.qemu.iter().find(|row| row.pid == pid)
            && qemu.guest_mib > rec.memory_mib
        {
            warnings.push(format!(
                "qemu pid {pid} asked for {} MiB, above reservation {} of {} MiB",
                qemu.guest_mib, rec.id, rec.memory_mib
            ));
        }
    }
    let orphan = warnings.iter().any(|w| w.contains("orphaned"));
    let unmanaged = warnings.iter().any(|w| w.contains("unmanaged"));
    let ok =
        view.pressure != Pressure::Critical && u64::from(used) <= budget && !orphan && !unmanaged;
    ResourceReport {
        schema: SCHEMA,
        runtime: runtime.display().to_string(),
        total_mib: view.total_mib,
        pressure: view.pressure.as_str().into(),
        swap_used_mib: view.swap_used_mib,
        swap_total_mib: view.swap_total_mib,
        host_floor_mib: floor,
        guest_budget_mib: budget,
        guest_used_mib: u64::from(used),
        host_cpus: view.cpus,
        guest_cpus,
        max_concurrent: policy.max_concurrent,
        max_heavy: policy.max_heavy,
        running,
        reservations: live.to_vec(),
        qemu: qemu_rows,
        warnings,
        ok,
    }
}

fn decide(
    live: &[Reservation],
    view: &HostView,
    policy: &Policy,
    req: &AdmitRequest,
) -> Result<()> {
    let spec = req.workload.spec();
    if req.memory_mib == 0 || req.memory_mib > spec.max_memory_mib || req.cpus > spec.cpus {
        return Err(Error::message(format!(
            "{} request of {} MiB and {} vCPU exceeds the profile maximum of {} MiB and {} vCPU",
            req.workload, req.memory_mib, req.cpus, spec.max_memory_mib, spec.cpus
        )));
    }
    if view.pressure == Pressure::Critical {
        return Err(Error::message(
            "refusing a virtual machine: host memory pressure is critical",
        ));
    }
    let (used, running, guest_cpus) = accounted(live, view);
    let heavy = live.iter().filter(|rec| rec.heavy).count().saturating_add(
        view.qemu
            .iter()
            .filter(|qemu| !reserved_pid(live, qemu.pid) && qemu.guest_mib > 2048)
            .count(),
    );
    if running >= policy.max_concurrent {
        return Err(Error::message(format!(
            "refusing a virtual machine: {running} already running, limit is {}",
            policy.max_concurrent
        )));
    }
    if spec.heavy && heavy >= policy.max_heavy as usize {
        return Err(Error::message(format!(
            "refusing heavy workload {}: another heavy virtual machine is already reserved",
            req.workload
        )));
    }
    if guest_cpus.saturating_add(req.cpus) > view.cpus {
        return Err(Error::message(format!(
            "refusing {} vCPU: {guest_cpus} already reserved and the host has {}",
            req.cpus, view.cpus
        )));
    }
    let budget = guest_budget_mib(
        view.total_mib,
        view.pressure,
        view.swap_used_mib,
        view.swap_total_mib,
    );
    let next = u64::from(used.saturating_add(req.memory_mib));
    if next > budget {
        return Err(Error::message(format!(
            "refusing {} MiB {}: guest budget is {budget} MiB and {used} MiB is already taken (host footprint counts each guest MiB as {FOOTPRINT_PER_GUEST_MIB})",
            req.memory_mib, req.workload
        )));
    }
    Ok(())
}

fn accounted(live: &[Reservation], view: &HostView) -> (u32, u32, u32) {
    let mut memory = 0u32;
    let mut running = 0u32;
    let mut cpus = 0u32;
    for rec in live {
        let mut charge = rec.memory_mib;
        let mut cpu = rec.cpus;
        if let Some(pid) = rec.qemu_pid
            && let Some(qemu) = view.qemu.iter().find(|row| row.pid == pid)
        {
            charge = charge.max(qemu.guest_mib);
            cpu = cpu.max(qemu.cpus);
        }
        memory = memory.saturating_add(charge);
        cpus = cpus.saturating_add(cpu);
        running += 1;
    }
    for qemu in &view.qemu {
        if reserved_pid(live, qemu.pid) {
            continue;
        }
        memory = memory.saturating_add(qemu.guest_mib);
        cpus = cpus.saturating_add(qemu.cpus);
        running += 1;
    }
    (memory, running, cpus)
}

fn reserved_pid(live: &[Reservation], pid: u32) -> bool {
    live.iter().any(|rec| rec.qemu_pid == Some(pid))
}

fn load_and_reap(runtime: &Path) -> Result<Vec<Reservation>> {
    let dir = runtime.join("reservations");
    fs::create_dir_all(&dir)?;
    let mut live = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(rec) = read_reservation(&path) else {
            continue;
        };
        let owner_alive = tracked_alive(rec.owner_pid, &rec.owner_start);
        let qemu_alive = rec
            .qemu_pid
            .is_some_and(|pid| tracked_alive(pid, &rec.qemu_start));
        if !owner_alive && !qemu_alive {
            let _ = fs::remove_file(path);
            continue;
        }
        live.push(rec);
    }
    live.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(live)
}

fn read_reservation(path: &Path) -> Option<Reservation> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn store(runtime: &Path, rec: &Reservation) -> Result<()> {
    let dir = runtime.join("reservations");
    fs::create_dir_all(&dir)?;
    let dest = reservation_path(runtime, &rec.id);
    let tmp = dir.join(format!(".{}.tmp", rec.id));
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(rec)?)?;
    }
    fs::rename(&tmp, &dest)?;
    Ok(())
}

fn reservation_path(runtime: &Path, id: &str) -> PathBuf {
    runtime.join("reservations").join(format!("{id}.json"))
}

/// `reserve` records the calling shell. `attach` and `release` are separate
/// processes, so the owner may be this process, its parent, or the shell that
/// started a one-line helper such as python.
pub fn shell_owner_pid() -> u32 {
    if let Some(pid) = env_owner_pid() {
        return pid;
    }
    let parent = parent_of(std::process::id());
    if parent > 1 {
        parent
    } else {
        std::process::id()
    }
}

fn env_owner_pid() -> Option<u32> {
    let value = std::env::var("SBM_OWNER_PID").ok()?;
    let pid = value.trim().parse::<u32>().ok()?;
    (pid > 1).then_some(pid)
}

/// `hold=$(sbm_reserve)` runs in a subshell that exits before `attach`.
/// The helper exports `SBM_OWNER_PID=$$`, which stays the script pid.
pub fn owns_reservation(
    owner: u32,
    self_pid: u32,
    ancestors: &[u32],
    env_owner: Option<u32>,
) -> bool {
    if owner == 0 {
        return false;
    }
    if owner == self_pid || env_owner == Some(owner) {
        return true;
    }
    ancestors
        .iter()
        .take(6)
        .any(|pid| *pid > 1 && *pid == owner)
}

fn caller_owns(owner: u32) -> bool {
    let mut ancestors = Vec::with_capacity(6);
    let mut current = parent_of(std::process::id());
    for _ in 0..6 {
        if current <= 1 {
            break;
        }
        ancestors.push(current);
        let next = parent_of(current);
        if next == current {
            break;
        }
        current = next;
    }
    owns_reservation(owner, std::process::id(), &ancestors, env_owner_pid())
}

fn parent_of(pid: u32) -> u32 {
    let Ok(text) = command_stdout("ps", &["-o", "ppid=", "-p", &pid.to_string()]) else {
        return 0;
    };
    text.trim().parse().unwrap_or(0)
}

pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_total_mib() -> Result<u64> {
    if cfg!(target_os = "macos") {
        let text = command_stdout("sysctl", &["-n", "hw.memsize"])?;
        let bytes: u64 = text
            .trim()
            .parse()
            .map_err(|_| Error::message(format!("could not parse hw.memsize {text:?}")))?;
        return Ok(bytes / 1024 / 1024);
    }
    let text = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let info = parse_meminfo(&text)
        .ok_or_else(|| Error::message("could not read host physical memory"))?;
    let total = host_mib_from_stats(info.total_kib, cgroup_memory_bytes());
    if total == 0 {
        return Err(Error::message("could not read host physical memory"));
    }
    Ok(total)
}

fn read_pressure() -> Pressure {
    if cfg!(target_os = "macos") {
        let Ok(text) = command_stdout("sysctl", &["-n", "kern.memorystatus_vm_pressure_level"])
        else {
            return Pressure::Unknown;
        };
        return match text.trim() {
            "0" | "1" => Pressure::Normal,
            "2" => Pressure::Warn,
            "" => Pressure::Unknown,
            _ => Pressure::Critical,
        };
    }
    pressure_from_meminfo(&fs::read_to_string("/proc/meminfo").unwrap_or_default())
}

fn read_swap() -> (u64, u64) {
    if cfg!(target_os = "macos") {
        let Ok(text) = command_stdout("sysctl", &["-n", "vm.swapusage"]) else {
            return (0, 0);
        };
        return parse_swapusage(&text);
    }
    let text = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let Some(info) = parse_meminfo(&text) else {
        return (0, 0);
    };
    let total_mib = info.swap_total_kib / 1024;
    let used_mib = info.swap_total_kib.saturating_sub(info.swap_free_kib) / 1024;
    (used_mib, total_mib)
}

fn read_cpus() -> u32 {
    if cfg!(target_os = "macos")
        && let Ok(text) = command_stdout("sysctl", &["-n", "hw.physicalcpu"])
        && let Ok(n) = text.trim().parse::<u32>()
    {
        return n.max(1);
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

fn read_qemu() -> Vec<RunningQemu> {
    let Ok(text) = command_stdout("ps", &["-axww", "-o", "pid=,command="]) else {
        return Vec::new();
    };
    let self_pid = std::process::id();
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((pid, command)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if !command_is_qemu(command) {
            continue;
        }
        let Ok(pid) = pid.trim().parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let (guest_mib, cpus, memory_known) = parse_guest_spec(command);
        let cwd = process_cwd(pid);
        let repo = repo_hint(command).or_else(|| cwd.as_deref().and_then(repo_hint));
        rows.push(RunningQemu {
            pid,
            guest_mib,
            cpus,
            memory_known,
            command: command.trim().to_string(),
            repo,
        });
    }
    rows
}

fn process_cwd(pid: u32) -> Option<String> {
    let proc = PathBuf::from(format!("/proc/{pid}/cwd"));
    if let Ok(path) = fs::read_link(&proc) {
        return Some(path.to_string_lossy().into_owned());
    }
    let output = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(path) = line.strip_prefix('n') {
            return Some(path.to_string());
        }
    }
    None
}

fn command_stdout(bin: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(bin)
        .args(args)
        .output()
        .map_err(|err| Error::message(format!("{bin}: {err}")))?;
    if !output.status.success() {
        return Err(Error::message(format!("{bin} failed")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub struct MemInfo {
    pub total_kib: u64,
    pub available_kib: Option<u64>,
    pub swap_total_kib: u64,
    pub swap_free_kib: u64,
}

pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut total = None;
    let mut available = None;
    let mut saw_available = false;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = Some(kib_field(rest));
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            saw_available = true;
            available = Some(kib_field(rest));
        } else if let Some(rest) = line.strip_prefix("SwapTotal:") {
            swap_total = kib_field(rest);
        } else if let Some(rest) = line.strip_prefix("SwapFree:") {
            swap_free = kib_field(rest);
        }
    }
    let total = total.filter(|n| *n > 0)?;
    Some(MemInfo {
        total_kib: total,
        available_kib: saw_available.then_some(available.unwrap_or(0)),
        swap_total_kib: swap_total,
        swap_free_kib: swap_free,
    })
}

fn kib_field(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0)
}

pub fn pressure_from_meminfo(text: &str) -> Pressure {
    let Some(info) = parse_meminfo(text) else {
        return Pressure::Unknown;
    };
    let Some(available) = info.available_kib else {
        return Pressure::Unknown;
    };
    let pct = available.saturating_mul(100) / info.total_kib;
    if pct < 10 {
        Pressure::Critical
    } else if pct < 20 {
        Pressure::Warn
    } else {
        Pressure::Normal
    }
}

pub fn parse_cgroup_memory(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() || text == "max" {
        return None;
    }
    let bytes: u64 = text.parse().ok()?;
    if bytes == 0 || bytes >= (1_u64 << 60) {
        None
    } else {
        Some(bytes)
    }
}

pub fn host_mib_from_stats(total_kib: u64, cgroup_bytes: Option<u64>) -> u64 {
    let mut total = total_kib / 1024;
    if let Some(bytes) = cgroup_bytes {
        let cap = bytes / 1024 / 1024;
        if cap > 0 && cap < total {
            total = cap;
        }
    }
    total
}

fn cgroup_memory_bytes() -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut tighten = |bytes: u64| {
        if bytes == 0 || bytes >= (1_u64 << 60) {
            return;
        }
        best = Some(best.map(|current| current.min(bytes)).unwrap_or(bytes));
    };
    if let Ok(text) = fs::read_to_string("/proc/self/cgroup") {
        for line in text.lines() {
            if let Some(path) = line.strip_prefix("0::") {
                let file = cgroup_file(path, "memory.max");
                if let Some(bytes) = fs::read_to_string(file)
                    .ok()
                    .and_then(|body| parse_cgroup_memory(&body))
                {
                    tighten(bytes);
                }
            }
            let mut parts = line.splitn(3, ':');
            let _id = parts.next();
            let controllers = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");
            if controllers.split(',').any(|item| item == "memory") {
                let file = PathBuf::from("/sys/fs/cgroup/memory")
                    .join(path.trim_start_matches('/'))
                    .join("memory.limit_in_bytes");
                if let Some(bytes) = fs::read_to_string(file)
                    .ok()
                    .and_then(|body| parse_cgroup_memory(&body))
                {
                    tighten(bytes);
                }
            }
        }
    }
    if let Some(bytes) = fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|body| parse_cgroup_memory(&body))
    {
        tighten(bytes);
    }
    best
}

fn cgroup_file(path: &str, name: &str) -> PathBuf {
    if path.is_empty() || path == "/" {
        PathBuf::from("/sys/fs/cgroup").join(name)
    } else {
        PathBuf::from("/sys/fs/cgroup")
            .join(path.trim_start_matches('/'))
            .join(name)
    }
}

pub fn command_is_qemu(command: &str) -> bool {
    let exe = command.split_whitespace().next().unwrap_or("");
    let base = exe.rsplit('/').next().unwrap_or(exe);
    base.starts_with("qemu-system-")
}

fn check_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 80
        && !id.contains("..")
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(Error::message(format!("invalid reservation id {id:?}")))
    }
}

fn tracked_alive(pid: u32, started: &Option<String>) -> bool {
    if !pid_alive(pid) {
        return false;
    }
    match started {
        None => true,
        Some(expected) => match process_start_token(pid) {
            Some(got) => got == *expected,
            None => true,
        },
    }
}

fn process_start_token(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let output = Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn kill_if_same_process(pid: u32, started: &Option<String>) {
    if pid <= 1 || pid == std::process::id() || !pid_alive(pid) {
        return;
    }
    let same = match started {
        Some(expected) => process_start_token(pid).as_ref() == Some(expected),
        None => parent_of(pid) == std::process::id(),
    };
    if same {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
}

extern "C" fn cancel_qemu(sig: libc::c_int) {
    let pid = NOTED_QEMU.load(Ordering::SeqCst);
    if pid > 1 {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

pub fn install_cancel_handlers() {
    CANCEL_HANDLERS.call_once(|| unsafe {
        libc::signal(libc::SIGINT, cancel_qemu as *const () as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            cancel_qemu as *const () as libc::sighandler_t,
        );
    });
}

pub fn note_qemu_pid(pid: u32) {
    NOTED_QEMU.store(pid, Ordering::SeqCst);
}

pub fn clear_noted_qemu_pid(pid: u32) {
    let _ = NOTED_QEMU.compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst);
}

pub fn tie_to_parent(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                let rc = libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                );
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() == 1 {
                    libc::raise(libc::SIGKILL);
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
    }
}

pub fn parse_swapusage(text: &str) -> (u64, u64) {
    let mut total = 0u64;
    let mut used = 0u64;
    if let Some(token) = field_after(text, "total =") {
        total = parse_size_mib(token);
    }
    if let Some(token) = field_after(text, "used =") {
        used = parse_size_mib(token);
    }
    (used, total)
}

fn field_after<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let rest = text.split(key).nth(1)?;
    rest.split_whitespace().next()
}

pub fn parse_size_mib(token: &str) -> u64 {
    let token = token.trim().trim_matches(',');
    let (number, factor) = if token.ends_with(['G', 'g']) {
        (&token[..token.len() - 1], 1024.0)
    } else if token.ends_with(['M', 'm']) {
        (&token[..token.len() - 1], 1.0)
    } else if token.ends_with(['K', 'k']) {
        (&token[..token.len() - 1], 1.0 / 1024.0)
    } else {
        (token, 1.0)
    };
    let value: f64 = number.parse().unwrap_or(0.0);
    (value * factor).round() as u64
}

pub fn parse_guest_spec(command: &str) -> (u32, u32, bool) {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let mut memory = None;
    let mut cpus = None;
    for (index, part) in parts.iter().enumerate() {
        if *part == "-m" || *part == "-memory" {
            memory = parts.get(index + 1).map(|token| parse_memory_mib(token));
        } else if let Some(token) = part.strip_prefix("-m=") {
            memory = Some(parse_memory_mib(token));
        }
        if *part == "-smp" {
            cpus = parts.get(index + 1).and_then(|token| parse_smp(token));
        }
    }
    match memory {
        Some(memory) => (memory.max(1), cpus.unwrap_or(1), true),
        None => (1024, cpus.unwrap_or(1), false),
    }
}

fn parse_memory_mib(token: &str) -> u32 {
    let token = token.split(',').next().unwrap_or(token).trim();
    let token = token.strip_prefix("size=").unwrap_or(token);
    if token.ends_with(['G', 'g']) {
        let number = &token[..token.len() - 1];
        return number.parse::<u32>().unwrap_or(0).saturating_mul(1024);
    }
    if token.ends_with(['M', 'm']) {
        let number = &token[..token.len() - 1];
        return number.parse().unwrap_or(0);
    }
    token.parse().unwrap_or(0)
}

fn parse_smp(token: &str) -> Option<u32> {
    if let Some(rest) = token.split(',').next()
        && let Ok(n) = rest.parse::<u32>()
    {
        return Some(n.max(1));
    }
    let mut cpus = None;
    let mut cores = None;
    let mut threads = None;
    let mut sockets = None;
    for piece in token.split(',') {
        let Some((key, value)) = piece.split_once('=') else {
            continue;
        };
        let Ok(n) = value.parse::<u32>() else {
            continue;
        };
        match key {
            "cpus" => cpus = Some(n),
            "cores" => cores = Some(n),
            "threads" => threads = Some(n),
            "sockets" => sockets = Some(n),
            _ => {}
        }
    }
    if let Some(n) = cpus {
        return Some(n.max(1));
    }
    if cores.is_some() || threads.is_some() || sockets.is_some() {
        return Some(
            cores
                .unwrap_or(1)
                .saturating_mul(threads.unwrap_or(1))
                .saturating_mul(sockets.unwrap_or(1))
                .max(1),
        );
    }
    None
}

pub fn repo_hint(text: &str) -> Option<String> {
    let names = [
        "sbm-lab",
        "sbm-uefi",
        "sbm-core",
        "sbm-catalog",
        "sbm-as",
        "install",
    ];
    let mut best: Option<(usize, bool, &str)> = None;
    for name in names {
        let needle = format!("/{name}");
        let mut from = 0;
        while let Some(rel) = text[from..].find(&needle) {
            let idx = from + rel;
            let after = idx + needle.len();
            let boundary = text[after..].chars().next();
            let segment = matches!(boundary, None | Some('/' | ',' | '"' | '\''))
                || boundary.is_some_and(char::is_whitespace);
            let launched_here = text[after..].starts_with("/var/runs");
            let replace = match best {
                None => true,
                Some((at, runs, _)) => launched_here && !runs || idx >= at && launched_here == runs,
            };
            if segment && replace {
                best = Some((idx, launched_here, name));
            }
            from = after;
        }
    }
    best.map(|(_, _, name)| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_scratch;
    use std::process::{Command, Stdio};

    fn quiet(total: u64) -> HostView {
        HostView {
            total_mib: total,
            pressure: Pressure::Normal,
            swap_used_mib: 0,
            swap_total_mib: 0,
            cpus: 8,
            qemu: Vec::new(),
        }
    }

    fn policy() -> Policy {
        Policy {
            max_concurrent: 2,
            max_heavy: 1,
        }
    }

    fn request(workload: Workload, memory: u32) -> AdmitRequest {
        AdmitRequest {
            owner_pid: std::process::id(),
            repo: "/tmp/sbm-lab".into(),
            workload,
            memory_mib: memory,
            cpus: workload.spec().cpus,
            detached: false,
        }
    }

    #[test]
    fn parent_of_this_process_matches_getppid() {
        let parent = parent_of(std::process::id());
        let ppid = unsafe { libc::getppid() } as u32;
        assert_eq!(parent, ppid);
        assert!(caller_owns(std::process::id()));
        assert!(caller_owns(parent));
    }

    #[test]
    fn budget_matches_the_16_gib_mac() {
        assert_eq!(guest_budget_mib_for(16384, Pressure::Normal, 0, 0, 2), 5120);
        assert_eq!(
            guest_budget_mib_for(16384, Pressure::Warn, 1968, 3072, 2),
            3584
        );
        assert_eq!(guest_budget_mib_for(16384, Pressure::Critical, 0, 0, 2), 0);
        assert_eq!(
            guest_budget_mib_for(16384, Pressure::Normal, 0, 0, 1),
            10240
        );
        assert_eq!(host_floor_mib(15999, Pressure::Normal, 0, 0), 6144);
        assert!(guest_budget_mib_for(15999, Pressure::Normal, 0, 0, 2) >= 4096);
        let (used, total) =
            parse_swapusage("total = 3072.00M  used = 1967.75M  free = 1104.25M  (encrypted)");
        assert_eq!(total, 3072);
        assert_eq!(used, 1968);
    }

    #[test]
    fn parses_guest_size_and_repo() {
        let cmd = "qemu-system-aarch64 -name sbm-builder -smp 4 -m 8192 -drive file=/Users/felg/gh/smart-boot-menu/sbm-core/build/builder/disk.qcow2";
        let (memory, cpus, known) = parse_guest_spec(cmd);
        assert_eq!((memory, cpus, known), (8192, 4, true));
        assert_eq!(repo_hint(cmd).as_deref(), Some("sbm-core"));
        assert_eq!(
            repo_hint(
                "file=/Users/x/smart-boot-menu/install/../sbm-lab/var/runs/id -drive file=/Users/x/smart-boot-menu/install/build/disk.qcow2"
            )
            .as_deref(),
            Some("sbm-lab")
        );
        assert_eq!(
            parse_guest_spec("qemu-system-x86_64 -m 4G -smp cpus=2").0,
            4096
        );
        assert_eq!(
            parse_guest_spec("qemu-system-x86_64 -m 4G,slots=2 -smp cores=4"),
            (4096, 4, true)
        );
        assert_eq!(
            parse_guest_spec("qemu-system-aarch64 -m size=4G,slots=2 -smp cores=2,threads=2"),
            (4096, 4, true)
        );
        assert!(command_is_qemu("/usr/bin/qemu-system-aarch64 -m 1024"));
        assert!(!command_is_qemu(
            "/usr/local/bin/sbm-lab resources run -- qemu-system-aarch64 -m 8192"
        ));
    }

    #[test]
    fn clamps_efi_and_keeps_the_measured_build_size() {
        assert_eq!(
            clamp_launch(Workload::Efi, 2048, 2, false, false).unwrap(),
            (1024, 1)
        );
        assert!(clamp_launch(Workload::Efi, 2048, 1, true, false).is_err());
        assert_eq!(
            clamp_launch(Workload::Build, 4096, 4, false, false).unwrap(),
            (4096, 4)
        );
        assert!(clamp_launch(Workload::Build, 8192, 4, true, false).is_err());
    }

    #[test]
    fn refuses_the_second_slice_of_the_same_budget() {
        let dir = test_scratch("budget");
        let (view, first_mib) = if cfg!(target_os = "macos") {
            // 16 GiB Mac: guest budget 5120 MiB -> 4096 + 2048 exceeds budget.
            (quiet(16384), 4096)
        } else {
            // 14 GiB Linux: guest budget 7168 MiB -> 6144 + 2048 exceeds budget.
            (quiet(14336), 6144)
        };
        let rules = policy();
        let first_wl = Workload::Build;
        try_admit(&dir, &view, &rules, &request(first_wl, first_mib)).unwrap();
        let err = try_admit(&dir, &view, &rules, &request(Workload::Linux, 2048)).unwrap_err();
        assert!(err.to_string().contains("budget"), "{err}");
    }

    #[test]
    fn heavy_workloads_are_sequential_when_memory_would_allow_both() {
        let dir = test_scratch("heavy");
        let view = quiet(65536);
        let rules = policy();
        try_admit(&dir, &view, &rules, &request(Workload::Build, 4096)).unwrap();
        let err = try_admit(&dir, &view, &rules, &request(Workload::Graphical, 4096)).unwrap_err();
        assert!(err.to_string().contains("heavy"), "{err}");
        try_admit(&dir, &view, &rules, &request(Workload::Efi, 1024)).unwrap();
    }

    #[test]
    fn unmanaged_qemu_consumes_budget_and_is_not_killed() {
        let dir = test_scratch("unmanaged");
        let mut sleeper = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = sleeper.id();
        let view = HostView {
            qemu: vec![RunningQemu {
                pid,
                guest_mib: 9216,
                cpus: 4,
                memory_known: true,
                command: "qemu-system-aarch64 -m 8192".into(),
                repo: Some("/work/sbm-core".into()),
            }],
            ..quiet(16384)
        };
        let err = try_admit(&dir, &view, &policy(), &request(Workload::Linux, 2048)).unwrap_err();
        assert!(err.to_string().contains("budget"), "{err}");
        assert!(pid_alive(pid));
        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    #[test]
    fn stale_reservation_is_reaped_and_a_live_one_is_kept() {
        let dir = test_scratch("stale");
        let mut sleeper = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let dead = sleeper.id();
        sleeper.kill().unwrap();
        sleeper.wait().unwrap();
        let stale = Reservation {
            schema: SCHEMA.into(),
            id: "stale-one".into(),
            owner_pid: dead,
            qemu_pid: None,
            repo: "old".into(),
            workload: Workload::Efi,
            memory_mib: 1024,
            cpus: 1,
            heavy: false,
            created_unix: 1,
            owner_start: None,
            qemu_start: None,
            detached: false,
        };
        store(&dir, &stale).unwrap();
        try_admit(
            &dir,
            &quiet(16384),
            &policy(),
            &request(Workload::Efi, 1024),
        )
        .unwrap();
        assert!(!reservation_path(&dir, "stale-one").exists());
    }

    #[test]
    fn release_does_not_kill_another_agents_process() {
        let dir = test_scratch("foreign");
        let mut sleeper = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = sleeper.id();
        let rec = Reservation {
            schema: SCHEMA.into(),
            id: "foreign-vm".into(),
            owner_pid: pid,
            qemu_pid: Some(pid),
            repo: "other".into(),
            workload: Workload::Build,
            memory_mib: 4096,
            cpus: 4,
            heavy: true,
            created_unix: 1,
            owner_start: None,
            qemu_start: None,
            detached: false,
        };
        store(&dir, &rec).unwrap();
        let err = release_id(&dir, "foreign-vm", false).unwrap_err();
        assert!(err.to_string().contains("does not kill"), "{err}");
        assert!(pid_alive(pid));
        release_id(&dir, "foreign-vm", true).unwrap();
        assert!(pid_alive(pid));
        assert!(!reservation_path(&dir, "foreign-vm").exists());
        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    #[test]
    fn drop_kills_only_the_attached_pid() {
        let dir = test_scratch("owned");
        let mut owned = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut other = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let owned_pid = owned.id();
        let other_pid = other.id();
        let mut guard = admit_held(
            &dir,
            &quiet(16384),
            &policy(),
            &request(Workload::Efi, 1024),
        )
        .unwrap();
        guard.attach_qemu(owned_pid).unwrap();
        drop(guard);
        let _ = owned.wait();
        assert!(!pid_alive(owned_pid));
        assert!(pid_alive(other_pid));
        let _ = other.kill();
        let _ = other.wait();
    }

    #[test]
    fn two_processes_cannot_reserve_the_same_remainder() {
        let dir = test_scratch("race");
        let exe = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for _ in 0..2 {
            children.push(
                Command::new(&exe)
                    .args(["--exact", "resources::tests::concurrent_admit_child"])
                    .env("SBM_LAB_ADMIT_CHILD_DIR", &dir)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
        }
        let mut codes = Vec::new();
        for mut child in children {
            codes.push(child.wait().unwrap().code().unwrap_or(99));
        }
        codes.sort_unstable();
        assert_eq!(
            codes,
            vec![0, 2],
            "one admit must win and the other must lose"
        );
    }

    #[test]
    fn concurrent_admit_child() {
        let Ok(dir) = std::env::var("SBM_LAB_ADMIT_CHILD_DIR") else {
            return;
        };
        let req = request(Workload::Build, 4096);
        match try_admit(Path::new(&dir), &quiet(16384), &policy(), &req) {
            Ok(_) => {
                // Stay alive so the reservation is not reaped as stale before
                // the other process takes the lock.
                thread::sleep(Duration::from_secs(2));
                std::process::exit(0);
            }
            Err(_) => std::process::exit(2),
        }
    }

    #[test]
    fn shell_owner_env_counts_as_the_caller() {
        assert!(owns_reservation(40, 10, &[20, 30], Some(40)));
        assert!(owns_reservation(20, 10, &[20, 30], None));
        assert!(owns_reservation(30, 10, &[20, 30], None));
        assert!(!owns_reservation(99, 10, &[20, 30], None));
        assert!(!owns_reservation(0, 10, &[20, 30], None));
    }

    #[test]
    fn linux_meminfo_does_not_treat_a_missing_available_as_critical() {
        let quiet =
            "MemTotal: 16384532 kB\nMemAvailable: 14000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n";
        assert_eq!(pressure_from_meminfo(quiet), Pressure::Normal);
        assert_eq!(
            pressure_from_meminfo("MemTotal: 8000000 kB\n"),
            Pressure::Unknown
        );
        assert_eq!(
            pressure_from_meminfo("MemTotal: 8000000 kB\nMemAvailable: 400000 kB\n"),
            Pressure::Critical
        );
        assert_eq!(
            pressure_from_meminfo("MemTotal: 10000 kB\nMemAvailable: 1500 kB\n"),
            Pressure::Warn
        );
        assert_eq!(host_mib_from_stats(16_382_976, None), 15999);
        assert_eq!(
            host_mib_from_stats(16_382_976, Some(2 * 1024 * 1024 * 1024)),
            2048
        );
        assert_eq!(parse_cgroup_memory("max"), None);
        assert_eq!(parse_cgroup_memory("2147483648"), Some(2_147_483_648));
    }

    #[test]
    fn two_admits_in_one_process_keep_distinct_files() {
        let dir = test_scratch("ids");
        let view = quiet(65536);
        let rules = Policy {
            max_concurrent: 4,
            max_heavy: 1,
        };
        let first = try_admit(&dir, &view, &rules, &request(Workload::Efi, 1024)).unwrap();
        let second = try_admit(&dir, &view, &rules, &request(Workload::Efi, 1024)).unwrap();
        assert_ne!(first.id, second.id);
        assert!(reservation_path(&dir, &first.id).exists());
        assert!(reservation_path(&dir, &second.id).exists());
    }

    #[test]
    fn a_reused_pid_is_not_the_recorded_owner() {
        let dir = test_scratch("reused");
        let mut sleeper = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = sleeper.id();
        let rec = Reservation {
            schema: SCHEMA.into(),
            id: "reused-owner".into(),
            owner_pid: pid,
            qemu_pid: Some(pid),
            repo: "old".into(),
            workload: Workload::Efi,
            memory_mib: 1024,
            cpus: 1,
            heavy: false,
            created_unix: 1,
            owner_start: Some("Thu Jan 1 00:00:00 1970".into()),
            qemu_start: Some("Thu Jan 1 00:00:00 1970".into()),
            detached: false,
        };
        store(&dir, &rec).unwrap();
        let live = load_and_reap(&dir).unwrap();
        assert!(live.is_empty(), "{live:?}");
        assert!(!reservation_path(&dir, "reused-owner").exists());
        assert!(pid_alive(pid));
        kill_if_same_process(pid, &Some("Thu Jan 1 00:00:00 1970".into()));
        assert!(pid_alive(pid));
        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    #[test]
    fn reservation_ids_cannot_escape_the_ledger() {
        let dir = test_scratch("id");
        let err = release_id(&dir, "../secret", false).unwrap_err();
        assert!(err.to_string().contains("invalid"), "{err}");
    }

    #[test]
    fn unknown_pressure_admits_and_critical_pressure_does_not() {
        let dir = test_scratch("pressure");
        let mut unknown = quiet(16384);
        unknown.pressure = Pressure::Unknown;
        try_admit(&dir, &unknown, &policy(), &request(Workload::Efi, 1024)).unwrap();
        let mut critical = quiet(16384);
        critical.pressure = Pressure::Critical;
        let err =
            try_admit(&dir, &critical, &policy(), &request(Workload::Linux, 2048)).unwrap_err();
        assert!(err.to_string().contains("critical"), "{err}");
    }

    #[test]
    fn detached_reservation_with_live_qemu_is_not_reported_as_orphaned() {
        let dir = test_scratch("detached");
        let mut dead_owner = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let owner_pid = dead_owner.id();
        let _ = dead_owner.kill();
        let _ = dead_owner.wait();

        let mut live_qemu = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let qemu_pid = live_qemu.id();

        let rec = Reservation {
            schema: SCHEMA.into(),
            id: "detached-builder".into(),
            owner_pid,
            qemu_pid: Some(qemu_pid),
            repo: "sbm-core".into(),
            workload: Workload::Build,
            memory_mib: 4096,
            cpus: 2,
            heavy: true,
            created_unix: 1,
            owner_start: None,
            qemu_start: process_start_token(qemu_pid),
            detached: true,
        };
        store(&dir, &rec).unwrap();
        let view = HostView {
            qemu: vec![RunningQemu {
                pid: qemu_pid,
                guest_mib: 4096,
                cpus: 2,
                memory_known: true,
                command: "qemu-system-aarch64 -m 4096".into(),
                repo: Some("sbm-core".into()),
            }],
            ..quiet(16384)
        };
        let snap = report(&dir, &view, &policy()).unwrap();
        assert!(
            snap.ok,
            "detached builder must pass doctor: {:?}",
            snap.warnings
        );
        let _ = live_qemu.kill();
        let _ = live_qemu.wait();
    }

    #[test]
    fn owns_reservation_accepts_depth_three_ancestor() {
        assert!(owns_reservation(40, 10, &[20, 30, 40], None));
        assert!(!owns_reservation(99, 10, &[20, 30, 40], None));
    }

    #[test]
    fn clear_noted_qemu_pid_resets_only_matching_pid() {
        note_qemu_pid(424242);
        clear_noted_qemu_pid(111111);
        assert_eq!(NOTED_QEMU.load(Ordering::SeqCst), 424242);
        clear_noted_qemu_pid(424242);
        assert_eq!(NOTED_QEMU.load(Ordering::SeqCst), 0);
    }
}
