use crate::accel::AccelRequest;
use crate::accel::Arch;
use crate::artifacts::{fetch_release, scan};
use crate::bench::{class_note, methodology_complete, summarize};
use crate::error::{Error, Result};
use crate::fixtures::fixture_ids;
use crate::host::doctor;
use crate::integration::{IntegrationOptions, run_integration};
use crate::product::{find_core_uki, find_menu};
use crate::profile::{
    BootKind, NetworkMode, ScenarioMode, Tier, find_profile, load_profiles, load_scenarios,
};
use crate::resources::{
    AdmitRequest, Policy, Workload, admit_retry, attach_pid, clamp_launch, collect_host,
    release_id, report, run_reserved, runtime_dir, shell_owner_pid, status_text,
};
use crate::run::{RunOptions, ScenarioCheck, apply_scenario, execute_run, probe_efi};
use crate::secureboot::enroll;
use crate::util::{lab_root, sha256_file, which};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "sbm-lab",
    version,
    about = "Smart Boot Menu virtual hardware laboratory"
)]
struct Cli {
    /// Laboratory root. Defaults to SBM_LAB_ROOT or the repo that contains profiles/.
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    /// Write machine-readable JSON to stdout.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Report host virtualization, firmware, and tool availability.
    Doctor,
    /// Build the UEFI probe, disk fixtures, and optional U-Boot or build VM.
    Setup {
        #[arg(long)]
        probe: bool,
        #[arg(long)]
        fixtures: bool,
        #[arg(long)]
        uboot: bool,
        #[arg(long)]
        build_vm: bool,
        /// Enroll development Secure Boot keys and sign the lab probe.
        #[arg(long)]
        secure_boot: bool,
    },
    /// List profiles, fixtures, scenarios, artifacts, or runs.
    List {
        #[arg(long)]
        profiles: bool,
        #[arg(long)]
        fixtures: bool,
        #[arg(long)]
        scenarios: bool,
        #[arg(long)]
        artifacts: bool,
        #[arg(long)]
        runs: bool,
    },
    /// Boot a virtual machine profile.
    Run {
        profile: String,
        #[arg(long)]
        efi: Option<PathBuf>,
        #[arg(long)]
        core: Option<PathBuf>,
        #[arg(long)]
        fixture: Option<String>,
        #[arg(long)]
        disk: Vec<PathBuf>,
        #[arg(long)]
        secure_boot: bool,
        #[arg(long)]
        tpm: bool,
        #[arg(long)]
        graphical: bool,
        #[arg(long, value_parser = ["user", "none", "slow"])]
        network: Option<String>,
        #[arg(long, default_value_t = 180)]
        timeout: u64,
        #[arg(long)]
        keep: bool,
        #[arg(long)]
        keep_failed: bool,
        #[arg(long)]
        memory: Option<u32>,
        #[arg(long)]
        cpus: Option<u32>,
        #[arg(long)]
        screenshot: Option<PathBuf>,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        chainload: bool,
        #[arg(long)]
        no_probe: bool,
    },
    /// Run scenario tiers. smoke is the default.
    Test {
        #[arg(long, default_value = "smoke")]
        tier: String,
        /// Run one scenario id. The tier filter is not applied.
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        efi: Option<PathBuf>,
        /// Dual-architecture SBM raw image for `--tier integration`.
        #[arg(long)]
        image: Option<PathBuf>,
        /// Architecture(s) for `--tier integration`: aarch64, x86_64, or both.
        #[arg(long, default_value = "both")]
        arch: String,
        /// Guest memory in MiB for `--tier integration`.
        #[arg(long, default_value_t = 4096)]
        memory: u32,
        /// Copy integration evidence (screenshots, serial, result.json) into this directory.
        #[arg(long)]
        artifacts_dir: Option<PathBuf>,
        /// Keep disposable overlays after a passing integration run.
        #[arg(long)]
        keep: bool,
        #[arg(long, default_value_t = 180)]
        timeout: u64,
    },
    /// Repeat a boot and write sbm-lab.benchmark.v1 JSON.
    Benchmark {
        #[arg(long, default_value = "aarch64-uefi")]
        profile: String,
        #[arg(long, default_value_t = 3)]
        runs: u32,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Boot until a frame is available and write a PPM screenshot.
    Screenshot {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        efi: Option<PathBuf>,
        #[arg(long, default_value_t = 180)]
        timeout: u64,
    },
    /// Delete run state. Does not touch host disks or QEMU's firmware files.
    Clean {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        fixtures: bool,
        /// Remove var/firmware only. Does not touch QEMU's own firmware files.
        #[arg(long)]
        firmware: bool,
        #[arg(long)]
        stop: bool,
    },
    /// Run one fault scenario against disposable overlays.
    Fault { name: String },
    /// Discover local build artifacts or download a pinned GitHub release asset.
    Artifacts {
        #[command(subcommand)]
        action: ArtifactCmd,
    },
    /// Share one memory budget across SBM checkouts.
    Resources {
        #[command(subcommand)]
        action: ResourceCmd,
    },
}

#[derive(Subcommand)]
enum ResourceCmd {
    /// Show host memory, reservations, and QEMU processes.
    Status,
    /// Exit 1 when the host cannot safely admit another managed VM.
    Doctor,
    /// Reserve guest RAM. Prints the reservation id.
    Reserve {
        #[arg(long)]
        workload: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        memory: Option<u32>,
        #[arg(long)]
        cpus: Option<u32>,
        /// Process that owns the reservation. Shell helpers pass `$$`.
        #[arg(long)]
        owner: Option<u32>,
        /// Retry for this many seconds instead of refusing immediately.
        #[arg(long, default_value_t = 0)]
        wait: u64,
    },
    /// Drop a reservation. Does not signal QEMU.
    Release {
        #[arg(long)]
        id: String,
        /// Remove the record even if its QEMU process is still running.
        #[arg(long)]
        forget: bool,
    },
    /// Record the QEMU pid for a reservation this process owns.
    Attach {
        #[arg(long)]
        id: String,
        #[arg(long)]
        pid: u32,
    },
    /// Reserve, run a command, then release. The command's pid is the one that gets killed if this process is cancelled.
    #[command(trailing_var_arg = true)]
    Run {
        #[arg(long)]
        workload: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        memory: Option<u32>,
        #[arg(long)]
        cpus: Option<u32>,
        #[arg(long, default_value_t = 0)]
        wait: u64,
        /// Kill the command after this many seconds. 0 waits until it exits.
        #[arg(long, default_value_t = 0)]
        timeout: u64,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ArtifactCmd {
    Scan,
    Fetch {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        tag: String,
        #[arg(long)]
        asset: String,
    },
}

pub fn execute() -> Result<i32> {
    let cli = Cli::parse();
    if let CommandKind::Resources { action } = &cli.command {
        return resources_main(cli.json, action);
    }
    let root = lab_root(cli.root.as_deref())?;
    match cli.command {
        CommandKind::Doctor => {
            let report = doctor(&root)?;
            emit(cli.json, &report, &doctor_text(&report))?;
            Ok(if report.ok { 0 } else { 1 })
        }
        CommandKind::Setup {
            probe,
            fixtures,
            uboot,
            build_vm,
            secure_boot,
        } => {
            let all = !probe && !fixtures && !uboot && !build_vm && !secure_boot;
            if all || probe {
                build_probe(&root)?;
            }
            if all || fixtures {
                build_all_fixtures(&root)?;
            }
            if all || uboot {
                build_uboot(&root)?;
            }
            if build_vm {
                setup_build_vm(&root)?;
            }
            if secure_boot {
                enroll(&root)?;
            }
            Ok(0)
        }
        CommandKind::List {
            profiles,
            fixtures,
            scenarios,
            artifacts,
            runs,
        } => {
            let all = !profiles && !fixtures && !scenarios && !artifacts && !runs;
            let mut body = json!({});
            if all || profiles {
                let items: Vec<_> = load_profiles(&root)?.into_iter().map(|p| p.id).collect();
                body["profiles"] = json!(items);
            }
            if all || fixtures {
                body["fixtures"] = json!(fixture_ids());
            }
            if all || scenarios {
                let items: Vec<_> = load_scenarios(&root)?.into_iter().map(|s| s.id).collect();
                body["scenarios"] = json!(items);
            }
            if all || artifacts {
                body["artifacts"] = json!(scan(&root));
            }
            if all || runs {
                let dir = root.join("var/runs");
                let mut ids = Vec::new();
                if dir.is_dir() {
                    for entry in fs::read_dir(dir)?.flatten() {
                        if entry.path().is_dir() {
                            ids.push(entry.file_name().to_string_lossy().to_string());
                        }
                    }
                }
                body["runs"] = json!(ids);
            }
            emit(cli.json, &body, &serde_json::to_string_pretty(&body)?)?;
            Ok(0)
        }
        CommandKind::Run {
            profile,
            efi,
            core,
            fixture,
            disk,
            secure_boot,
            tpm,
            graphical,
            network,
            timeout,
            keep,
            keep_failed,
            memory,
            cpus,
            screenshot,
            key,
            chainload,
            no_probe,
        } => {
            let profiles = load_profiles(&root)?;
            let profile = find_profile(&profiles, &profile)?.clone();
            let send_key_after = if profile.boot == BootKind::SbmMenu {
                "menu_ready".into()
            } else {
                "waiting-for-key".into()
            };
            let opts = RunOptions {
                profile,
                fixture,
                efi,
                core,
                extra_disks: disk,
                secure_boot: secure_boot.then_some(true),
                tpm: tpm.then_some(true),
                graphical,
                network: network.as_deref().map(parse_net).transpose()?,
                timeout_secs: timeout,
                keep,
                keep_failed,
                memory_mib: memory,
                cpus,
                screenshot,
                send_key: key,
                chainload,
                journal: false,
                corrupt_vars: false,
                io_error: false,
                drop_link: false,
                inject_probe: !no_probe,
                artifacts_dir: None,
                accel: AccelRequest::Auto,
                boot: BootKind::Probe,
                send_key_after,
                stop_on_expect: false,
                expect: Vec::new(),
                stop_on_serial: Vec::new(),
                require_files: Vec::new(),
                reset_after: None,
            };
            let report = execute_run(&root, &opts)?;
            let code = if report.success { 0 } else { 1 };
            emit(
                cli.json,
                &report,
                &format!("{} {}", report.id, report.success),
            )?;
            Ok(code)
        }
        CommandKind::Test {
            tier,
            id,
            efi,
            image,
            arch,
            memory,
            artifacts_dir,
            keep,
            timeout,
        } => {
            if tier == "integration" {
                let img = image
                    .ok_or_else(|| Error::message("--tier integration requires --image PATH"))?;
                run_integration_tier(
                    &root,
                    &img,
                    &arch,
                    memory,
                    timeout.max(300),
                    artifacts_dir,
                    keep,
                    cli.json,
                )
            } else {
                run_tier(&root, &tier, id.as_deref(), efi, timeout, cli.json)
            }
        }
        CommandKind::Benchmark {
            profile,
            runs,
            output,
        } => benchmark(&root, &profile, runs, output, cli.json),
        CommandKind::Screenshot {
            profile,
            output,
            efi,
            timeout,
        } => {
            let profiles = load_profiles(&root)?;
            let profile = find_profile(&profiles, &profile)?.clone();
            let opts = base_opts(profile, timeout);
            let mut opts = opts;
            opts.efi = efi;
            opts.screenshot = Some(output.clone());
            opts.send_key = None;
            let report = execute_run(&root, &opts)?;
            emit(cli.json, &report, &format!("{:?}", report.screenshot))?;
            Ok(if report.screenshot.is_some() { 0 } else { 1 })
        }
        CommandKind::Clean {
            all,
            fixtures,
            firmware,
            stop,
        } => {
            if stop {
                stop_lab_processes(&root)?;
            }
            let runs = root.join("var/runs");
            if runs.exists() {
                fs::remove_dir_all(&runs)?;
            }
            if all || fixtures {
                let dir = root.join("var/fixtures");
                if dir.exists() {
                    fs::remove_dir_all(dir)?;
                }
            }
            if all || firmware {
                let dir = root.join("var/firmware");
                if dir.exists() {
                    fs::remove_dir_all(dir)?;
                }
            }
            println!("cleaned {}", root.join("var").display());
            Ok(0)
        }
        CommandKind::Fault { name } => {
            let id = match name.as_str() {
                "power-loss" => "fault-power-loss",
                "io-error" => "fault-io-error",
                "net-down" => "fault-net-down",
                "slow-net" => "fault-slow-net",
                "corrupt-config" => "fault-corrupt-config",
                "missing-boot" => "fault-missing-boot",
                "broken-vars" => "fault-broken-vars",
                "low-memory" => "fault-low-memory",
                other => {
                    return Err(Error::message(format!("unknown fault {other}")));
                }
            };
            run_one(&root, id, None, 180, cli.json)
        }
        CommandKind::Resources { .. } => {
            unreachable!("resources is handled before lab root lookup")
        }
        CommandKind::Artifacts { action } => match action {
            ArtifactCmd::Scan => {
                let found = scan(&root);
                emit(cli.json, &found, &serde_json::to_string_pretty(&found)?)?;
                Ok(0)
            }
            ArtifactCmd::Fetch { repo, tag, asset } => {
                let path = fetch_release(&root, &repo, &tag, &asset)?;
                println!("{}", path.display());
                Ok(0)
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn run_integration_tier(
    root: &Path,
    image: &Path,
    arch_arg: &str,
    memory_mib: u32,
    timeout_secs: u64,
    artifacts_dir: Option<PathBuf>,
    keep: bool,
    json_out: bool,
) -> Result<i32> {
    let arches = match arch_arg {
        "aarch64" | "arm64" => vec![Arch::Aarch64],
        "x86_64" | "x86-64" => vec![Arch::X86_64],
        "both" => vec![Arch::Aarch64, Arch::X86_64],
        other => {
            return Err(Error::message(format!(
                "unknown integration arch {other}; use aarch64, x86_64, or both"
            )));
        }
    };
    let mut reports = Vec::new();
    let mut failed = 0;
    for arch in arches {
        let report = run_integration(
            root,
            &IntegrationOptions {
                image: image.to_path_buf(),
                arch,
                memory_mib,
                cpus: 2,
                timeout_secs,
                artifacts_dir: artifacts_dir.clone(),
                keep,
            },
        )?;
        if !report.success {
            failed += 1;
        }
        reports.push(report);
    }
    emit(json_out, &reports, &serde_json::to_string_pretty(&reports)?)?;
    Ok(if failed == 0 { 0 } else { 1 })
}

fn run_tier(
    root: &Path,
    tier: &str,
    only: Option<&str>,
    efi: Option<PathBuf>,
    timeout: u64,
    json_out: bool,
) -> Result<i32> {
    let want = match tier {
        "smoke" => vec![Tier::Smoke],
        "full" => vec![Tier::Full],
        "fault" => vec![Tier::Fault],
        "product" => vec![Tier::Product],
        "secure" => vec![Tier::Secure],
        "builder" => vec![Tier::Builder],
        "all" => vec![Tier::Smoke, Tier::Full, Tier::Fault],
        other => return Err(Error::message(format!("unknown tier {other}"))),
    };
    let scenarios = load_scenarios(root)?;
    let profiles = load_profiles(root)?;
    let mut failed = 0;
    let mut results = Vec::new();
    let mut ran = false;
    for scenario in scenarios.into_iter().filter(|scenario| {
        if let Some(id) = only {
            scenario.id == id
        } else {
            want.contains(&scenario.tier)
        }
    }) {
        ran = true;
        if scenario.profile == "uboot-efi" && crate::firmware::uboot_binary(root).is_none() {
            results.push(json!({"id": scenario.id, "skipped": "u-boot binary missing"}));
            continue;
        }
        if scenario.profile.contains("tpm") && which("swtpm").is_none() {
            results.push(json!({"id": scenario.id, "skipped": "swtpm missing"}));
            continue;
        }
        let profile = find_profile(&profiles, &scenario.profile)?.clone();
        if scenario.use_core && find_core_uki(root, profile.arch).is_none() {
            results.push(json!({"id": scenario.id, "skipped": "sbm-core UKI is not built"}));
            continue;
        }
        if (scenario.boot == BootKind::SbmMenu || profile.boot == BootKind::SbmMenu)
            && find_menu(root, profile.arch).is_err()
        {
            failed += 1;
            results.push(json!({"id": scenario.id, "success": false, "reason": "SBM UEFI menu binary is missing"}));
            continue;
        }
        if scenario.profile == "linux-dev" && crate::builder::find_build_image(root).is_err() {
            results.push(json!({"id": scenario.id, "skipped": "build VM image is missing"}));
            continue;
        }
        match run_scenario(root, &scenario, efi.clone(), timeout) {
            Ok(report) => {
                let pass = report.success;
                if !pass {
                    failed += 1;
                }
                results.push(json!({"id": scenario.id, "success": pass, "run": report.id, "reason": report.failure_reason}));
            }
            Err(err) => {
                failed += 1;
                results
                    .push(json!({"id": scenario.id, "success": false, "reason": err.to_string()}));
            }
        }
    }
    if !ran {
        return Err(Error::message(match only {
            Some(id) => format!("unknown scenario {id}"),
            None => format!("no scenarios in tier {tier}"),
        }));
    }
    emit(json_out, &results, &serde_json::to_string_pretty(&results)?)?;
    Ok(if failed == 0 { 0 } else { 1 })
}

fn run_one(
    root: &Path,
    id: &str,
    efi: Option<PathBuf>,
    timeout: u64,
    json_out: bool,
) -> Result<i32> {
    let scenarios = load_scenarios(root)?;
    let scenario = scenarios
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| Error::message(format!("unknown scenario {id}")))?;
    match run_scenario(root, &scenario, efi, timeout) {
        Ok(report) => {
            let code = if report.success { 0 } else { 1 };
            emit(
                json_out,
                &report,
                &format!("{} {}", report.id, report.success),
            )?;
            Ok(code)
        }
        Err(err) => Err(err),
    }
}

fn run_scenario(
    root: &Path,
    scenario: &crate::profile::Scenario,
    efi: Option<PathBuf>,
    timeout: u64,
) -> Result<crate::run::RunReport> {
    let profiles = load_profiles(root)?;
    let profile = find_profile(&profiles, &scenario.profile)?.clone();
    let mut opts = base_opts(profile, scenario.timeout_secs.max(timeout));
    opts.fixture = scenario.fixture.clone();
    opts.efi = efi;
    opts.chainload = scenario.chainload;
    opts.send_key = scenario.send_key.clone();
    opts.journal = scenario.journal;
    opts.corrupt_vars = scenario.corrupt_vars;
    opts.io_error = scenario.io_error;
    opts.drop_link = scenario.drop_link;
    opts.inject_probe = scenario.inject_probe;
    opts.memory_mib = scenario.memory_mib;
    opts.network = scenario.network;
    opts.boot = scenario.boot;
    opts.send_key_after = scenario
        .send_key_after
        .clone()
        .unwrap_or_else(|| "waiting-for-key".into());
    opts.stop_on_expect = scenario.stop_on_expect;
    opts.expect = scenario.expect.clone();
    opts.stop_on_serial = scenario.stop_on_serial.clone();
    opts.require_files = scenario.require_files.clone();
    opts.reset_after = scenario.reset_after.clone();
    if scenario.use_core {
        opts.core = find_core_uki(root, opts.profile.arch);
    }
    if let Some(variant) = &scenario.efi_variant {
        opts.efi = Some(secure_efi(root, variant)?);
    }
    opts.keep_failed = true;
    let report = execute_run(root, &opts)?;
    let mode = match scenario.mode {
        ScenarioMode::Markers => "markers",
        ScenarioMode::Observe => "observe",
        ScenarioMode::Serial => "serial",
        ScenarioMode::PowerLoss => "power-loss",
    };
    let shot = match scenario.screenshot {
        crate::profile::ScreenshotMode::Off => "off",
        crate::profile::ScreenshotMode::Qmp => "qmp",
        crate::profile::ScreenshotMode::Any => "any",
    };
    Ok(apply_scenario(
        report,
        &ScenarioCheck {
            expect: &scenario.expect,
            require: &scenario.require_paths,
            forbid: &scenario.forbid_paths,
            serial_contains: &scenario.serial_contains,
            mode,
            screenshot: shot,
            forbid_markers: &scenario.forbid_markers,
            serial_contains_any: &scenario.serial_contains_any,
            reset_after: scenario.reset_after.as_deref(),
        },
    ))
}

fn base_opts(profile: crate::profile::Profile, timeout: u64) -> RunOptions {
    RunOptions {
        profile,
        fixture: None,
        efi: None,
        core: None,
        extra_disks: vec![],
        secure_boot: None,
        tpm: None,
        graphical: false,
        network: None,
        timeout_secs: timeout,
        keep: false,
        keep_failed: true,
        memory_mib: None,
        cpus: None,
        screenshot: None,
        send_key: None,
        chainload: false,
        journal: false,
        corrupt_vars: false,
        io_error: false,
        drop_link: false,
        inject_probe: true,
        artifacts_dir: None,
        accel: AccelRequest::Auto,
        boot: BootKind::Probe,
        send_key_after: "waiting-for-key".into(),
        stop_on_expect: false,
        expect: Vec::new(),
        stop_on_serial: Vec::new(),
        require_files: Vec::new(),
        reset_after: None,
    }
}

fn secure_efi(root: &Path, variant: &str) -> Result<PathBuf> {
    let path = match variant {
        "signed" => root.join("var/secure-boot/probe-signed.efi"),
        "tampered" => root.join("var/secure-boot/probe-tampered.efi"),
        "unsigned" => probe_efi(root, Arch::X86_64).ok_or_else(|| {
            Error::message("x86_64 probe EFI is missing; run sbm-lab setup --probe")
        })?,
        other => return Err(Error::message(format!("unknown efi variant {other}"))),
    };
    if !path.is_file() {
        return Err(Error::message(format!(
            "{} is missing; run sbm-lab setup --secure-boot",
            path.display()
        )));
    }
    Ok(path)
}

fn benchmark(
    root: &Path,
    profile_id: &str,
    runs: u32,
    output: Option<PathBuf>,
    json_out: bool,
) -> Result<i32> {
    let profiles = load_profiles(root)?;
    let profile = find_profile(&profiles, profile_id)?.clone();
    let mut samples = Vec::new();
    let mut class = String::new();
    let mut note = String::new();
    let mut accel = String::new();
    let mut guest_arch = String::new();
    for _ in 0..runs.max(1) {
        let opts = base_opts(profile.clone(), 180);
        let report = execute_run(root, &opts)?;
        if !report.success {
            return Err(Error::message(
                report
                    .failure_reason
                    .unwrap_or_else(|| "benchmark run failed".into()),
            ));
        }
        let ms = report
            .stages_ms
            .get("efi-launched")
            .copied()
            .unwrap_or(report.duration_ms);
        samples.push(ms);
        class = report.execution_class;
        note = report.execution_note;
        accel = report.accel;
        guest_arch = report.arch;
    }
    let host_arch = std::env::consts::ARCH;
    let cross = guest_arch != host_arch && !(guest_arch == "ia32" && host_arch == "x86_64");
    let summary = summarize(samples.clone());
    let body = json!({
        "schema": "sbm-lab.benchmark.v1",
        "profile": profile_id,
        "accel": accel,
        "execution_class": class,
        "representative_of_physical_hardware": false,
        "note": note,
        "class_note": class_note(
            if class == "emulation" {
                crate::accel::ExecutionClass::Emulation
            } else {
                crate::accel::ExecutionClass::AcceleratedVirtualization
            },
            cross
        ),
        "metric": "host_ms_until_efi_launched",
        "samples_ms": samples,
        "summary": summary,
        "methodology_complete": methodology_complete(runs),
    });
    if let Some(path) = output {
        fs::write(&path, serde_json::to_string_pretty(&body)?)?;
    }
    emit(json_out, &body, &serde_json::to_string_pretty(&body)?)?;
    Ok(0)
}

fn build_probe(root: &Path) -> Result<()> {
    let manifest = root.join("fixtures/efi-probe/Cargo.toml");
    for target in ["x86_64-unknown-uefi", "aarch64-unknown-uefi"] {
        let status = Command::new("cargo")
            .args(["build", "--manifest-path"])
            .arg(&manifest)
            .args(["--release", "--target", target])
            .status()?;
        if !status.success() {
            return Err(Error::message(format!("probe build failed for {target}")));
        }
    }
    println!("built efi-probe for x86_64 and aarch64");
    Ok(())
}

fn build_all_fixtures(root: &Path) -> Result<()> {
    let dir = root.join("var/fixtures");
    fs::create_dir_all(&dir)?;
    for id in fixture_ids() {
        println!("fixture {id}");
        crate::run::ensure_fixture(root, id)?;
    }
    Ok(())
}

fn build_uboot(root: &Path) -> Result<()> {
    let dest = root.join("var/firmware/u-boot-qemu-arm64.bin");
    if dest.is_file() {
        println!("u-boot already at {}", dest.display());
        return Ok(());
    }
    let src = root.join("var/src/u-boot-2026.10");
    if !src.join("Makefile").is_file() {
        download_uboot(root)?;
    }
    let gmake = which("gmake").unwrap_or_else(|| PathBuf::from("make"));
    let openssl = PathBuf::from("/opt/homebrew/opt/openssl@3");
    let mut cmd = Command::new(&gmake);
    cmd.current_dir(&src)
        .env("CROSS_COMPILE", "aarch64-elf-")
        .env(
            "PKG_CONFIG_PATH",
            openssl.join("lib/pkgconfig").to_string_lossy().as_ref(),
        );
    let mut make_args = vec![format!("-j{}", threads())];
    if openssl.join("include/openssl/evp.h").is_file() {
        make_args.push(format!(
            "HOSTCC=clang -I{}",
            openssl.join("include").display()
        ));
        make_args.push(format!("HOSTLDFLAGS=-L{}", openssl.join("lib").display()));
    }
    let status = cmd.args(&make_args).status()?;
    if !status.success() {
        return Err(Error::message(
            "U-Boot build failed. On macOS use GNU make and aarch64-elf-gcc. OpenSSL headers are required.",
        ));
    }
    fs::create_dir_all(root.join("var/firmware"))?;
    fs::copy(src.join("u-boot.bin"), &dest)?;
    println!("installed {}", dest.display());
    Ok(())
}

fn download_uboot(root: &Path) -> Result<()> {
    let text = fs::read_to_string(root.join("firmware/sources.toml"))?;
    let value: toml::Value = toml::from_str(&text)?;
    let url = value["uboot"]["url"]
        .as_str()
        .ok_or_else(|| Error::message("firmware/sources.toml is missing uboot.url"))?;
    let expect = value["uboot"]["sha256"]
        .as_str()
        .ok_or_else(|| Error::message("firmware/sources.toml is missing uboot.sha256"))?;
    let dir = root.join("var/src");
    fs::create_dir_all(&dir)?;
    let tar = dir.join("u-boot-v2026.10.tar.gz");
    if !tar.is_file() {
        let status = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&tar)
            .arg(url)
            .status()?;
        if !status.success() {
            return Err(Error::message("failed to download U-Boot"));
        }
    }
    let got = sha256_file(&tar)?;
    if got != expect {
        return Err(Error::message(format!(
            "U-Boot tarball sha256 {got} != {expect}"
        )));
    }
    let status = Command::new("tar")
        .args(["-xzf"])
        .arg(&tar)
        .current_dir(&dir)
        .status()?;
    if !status.success() {
        return Err(Error::message("failed to extract U-Boot"));
    }
    Ok(())
}

fn setup_build_vm(root: &Path) -> Result<()> {
    let text = fs::read_to_string(root.join("firmware/sources.toml"))?;
    let value: toml::Value = toml::from_str(&text)?;
    let sums_url = value["build_vm"]["sha256sums_url"]
        .as_str()
        .ok_or_else(|| Error::message("missing build_vm.sha256sums_url"))?;
    let dir = root.join("var/build-vm");
    fs::create_dir_all(&dir)?;
    let sums = dir.join("SHA256SUMS");
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&sums)
        .arg(sums_url)
        .status()?;
    if !status.success() {
        return Err(Error::message(
            "could not download Ubuntu SHA256SUMS; the build VM was not created",
        ));
    }
    let body = fs::read_to_string(&sums)?;
    let needle = if std::env::consts::ARCH == "aarch64" {
        "server-cloudimg-arm64.img"
    } else {
        "server-cloudimg-amd64.img"
    };
    let Some(line) = body
        .lines()
        .find(|l| l.contains(needle) && !l.contains("azure") && !l.contains("lxd"))
    else {
        return Err(Error::message(format!("SHA256SUMS has no {needle}")));
    };
    let mut parts = line.split_whitespace();
    let hash = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    let base = sums_url.trim_end_matches("SHA256SUMS");
    let url = format!("{base}{name}");
    let image = dir.join(name);
    if !image.is_file() {
        println!("downloading {url}");
        let status = Command::new("curl")
            .args(["-fL", "-o"])
            .arg(&image)
            .arg(&url)
            .status()?;
        if !status.success() {
            return Err(Error::message("cloud image download failed"));
        }
    }
    let got = sha256_file(&image)?;
    if got != hash {
        return Err(Error::message(format!(
            "cloud image sha256 {got} != {hash}"
        )));
    }
    fs::write(
        dir.join("image.lock"),
        format!("url = {url:?}\nsha256 = {got:?}\nfile = {name:?}\n"),
    )?;
    println!("build VM image ready at {}", image.display());
    println!("boot it later with the cloud-init seed documented in docs/CLI.md");
    Ok(())
}

fn stop_lab_processes(root: &Path) -> Result<()> {
    let marker = root.join("var/runs");
    let marker = marker.display().to_string();
    let self_pid = std::process::id();
    let output = Command::new("ps")
        .args(["-axww", "-o", "pid=,command="])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if !line.contains(&marker) {
            continue;
        }
        let Some((pid_text, command)) = line.trim().split_once(char::is_whitespace) else {
            continue;
        };
        let Some(pid) = pid_text.trim().parse::<i32>().ok() else {
            continue;
        };
        if pid as u32 == self_pid {
            continue;
        }
        let exe = command.split_whitespace().next().unwrap_or("");
        let base = exe.rsplit('/').next().unwrap_or(exe);
        if !base.starts_with("qemu-system-") {
            continue;
        }
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    Ok(())
}

fn parse_net(value: &str) -> Result<NetworkMode> {
    match value {
        "user" => Ok(NetworkMode::User),
        "none" => Ok(NetworkMode::None),
        "slow" => Ok(NetworkMode::Slow),
        other => Err(Error::message(format!("unknown network {other}"))),
    }
}

fn threads() -> String {
    std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|_| "2".into())
}

fn resources_main(json_out: bool, action: &ResourceCmd) -> Result<i32> {
    match action {
        ResourceCmd::Status | ResourceCmd::Doctor => {
            let runtime = runtime_dir()?;
            let view = collect_host()?;
            let snapshot = report(&runtime, &view, &Policy::from_env())?;
            let text = status_text(&snapshot);
            emit(json_out, &snapshot, &text)?;
            let failing = matches!(action, ResourceCmd::Doctor) && !snapshot.ok;
            Ok(if failing { 1 } else { 0 })
        }
        ResourceCmd::Reserve {
            workload,
            repo,
            memory,
            cpus,
            owner,
            wait,
        } => {
            let mut req = admit_request(workload, repo, *memory, *cpus)?;
            req.owner_pid = owner.unwrap_or_else(shell_owner_pid);
            let rec = admit_retry(&req, *wait)?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&rec)?);
            } else {
                println!("{}", rec.id);
            }
            Ok(0)
        }
        ResourceCmd::Release { id, forget } => {
            release_id(&runtime_dir()?, id, *forget)?;
            Ok(0)
        }
        ResourceCmd::Attach { id, pid } => {
            attach_pid(&runtime_dir()?, id, *pid)?;
            Ok(0)
        }
        ResourceCmd::Run {
            workload,
            repo,
            memory,
            cpus,
            wait,
            timeout,
            command,
        } => {
            let req = admit_request(workload, repo, *memory, *cpus)?;
            run_reserved(&req, *wait, *timeout, command)
        }
    }
}

fn admit_request(
    workload: &str,
    repo: &Option<PathBuf>,
    memory: Option<u32>,
    cpus: Option<u32>,
) -> Result<AdmitRequest> {
    let workload = Workload::parse(workload)
        .ok_or_else(|| Error::message(format!("unknown workload {workload}")))?;
    let spec = workload.spec();
    let (memory, cpus) = clamp_launch(
        workload,
        memory.unwrap_or(spec.memory_mib),
        cpus.unwrap_or(spec.cpus),
        memory.is_some(),
        cpus.is_some(),
    )?;
    let repo = match repo {
        Some(path) => path.display().to_string(),
        None => std::env::current_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    };
    Ok(AdmitRequest {
        owner_pid: std::process::id(),
        repo,
        workload,
        memory_mib: memory,
        cpus,
    })
}

fn emit(json_out: bool, value: &impl serde::Serialize, text: &str) -> Result<()> {
    if json_out {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{text}");
    }
    Ok(())
}

fn doctor_text(report: &crate::host::DoctorReport) -> String {
    let mut lines = vec![
        format!("host {} {}", report.arch, report.os),
        format!("hv_support {}", report.hv_support),
        format!(
            "x86_64 accel {} — {}",
            report.x86_64_accel, report.x86_64_note
        ),
        format!(
            "aarch64 accel {} — {}",
            report.aarch64_accel, report.aarch64_note
        ),
    ];
    for tool in &report.tools {
        lines.push(format!(
            "{} {} {}",
            tool.name,
            tool.version.as_deref().unwrap_or("missing"),
            tool.accels.join(",")
        ));
    }
    for item in &report.firmware {
        lines.push(item.clone());
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines.join("\n")
}
