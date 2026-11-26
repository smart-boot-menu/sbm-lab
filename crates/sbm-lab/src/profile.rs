use crate::accel::{AccelRequest, Arch};
use crate::error::{Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    #[default]
    Guest,
    BuildVm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootKind {
    #[default]
    Probe,
    SbmMenu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuKind {
    #[default]
    Software,
    Virtio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    User,
    #[default]
    None,
    Slow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub description: String,
    pub arch: Arch,
    #[serde(default = "default_machine")]
    pub machine: String,
    #[serde(default = "default_mem")]
    pub memory_mib: u32,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default)]
    pub gpu: GpuKind,
    #[serde(default)]
    pub secure_boot: bool,
    #[serde(default)]
    pub tpm: bool,
    #[serde(default)]
    pub network: NetworkMode,
    #[serde(default)]
    pub guest_agent: bool,
    #[serde(default)]
    pub usb: bool,
    #[serde(default)]
    pub disks: Vec<String>,
    #[serde(default)]
    pub accel: AccelRequest,
    #[serde(default)]
    pub role: Role,
    #[serde(default)]
    pub boot: BootKind,
    /// Path relative to the lab root. Replaces the firmware variable template.
    #[serde(default)]
    pub vars_template: Option<String>,
    #[serde(default)]
    pub notes: String,
}

fn default_machine() -> String {
    "q35".into()
}
fn default_mem() -> u32 {
    2048
}
fn default_cpus() -> u32 {
    2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    Smoke,
    Full,
    Fault,
    Product,
    Secure,
    Builder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioMode {
    #[default]
    Markers,
    Observe,
    Serial,
    PowerLoss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotMode {
    #[default]
    Off,
    Qmp,
    Any,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub description: String,
    pub tier: Tier,
    pub profile: String,
    #[serde(default)]
    pub fixture: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub mode: ScenarioMode,
    #[serde(default)]
    pub expect: Vec<String>,
    #[serde(default)]
    pub require_paths: Vec<String>,
    #[serde(default)]
    pub forbid_paths: Vec<String>,
    #[serde(default)]
    pub screenshot: ScreenshotMode,
    #[serde(default)]
    pub chainload: bool,
    #[serde(default)]
    pub send_key: Option<String>,
    #[serde(default)]
    pub journal: bool,
    #[serde(default)]
    pub corrupt_vars: bool,
    #[serde(default)]
    pub io_error: bool,
    #[serde(default)]
    pub drop_link: bool,
    #[serde(default = "yes")]
    pub inject_probe: bool,
    #[serde(default)]
    pub serial_contains: Vec<String>,
    #[serde(default)]
    pub memory_mib: Option<u32>,
    #[serde(default)]
    pub network: Option<NetworkMode>,
    #[serde(default)]
    pub boot: BootKind,
    #[serde(default)]
    pub send_key_after: Option<String>,
    #[serde(default)]
    pub stop_on_expect: bool,
    #[serde(default)]
    pub stop_on_serial: Vec<String>,
    #[serde(default)]
    pub forbid_markers: Vec<String>,
    #[serde(default)]
    pub serial_contains_any: Vec<String>,
    #[serde(default)]
    pub require_files: Vec<String>,
    #[serde(default)]
    pub reset_after: Option<String>,
    /// `signed`, `unsigned`, or `tampered` for the Secure Boot tier.
    #[serde(default)]
    pub efi_variant: Option<String>,
    #[serde(default)]
    pub use_core: bool,
}

fn default_timeout() -> u64 {
    180
}
fn yes() -> bool {
    true
}

pub fn load_profiles(root: &Path) -> Result<Vec<Profile>> {
    load_toml_dir(&root.join("profiles"))
}

pub fn load_scenarios(root: &Path) -> Result<Vec<Scenario>> {
    let dir = root.join("scenarios");
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            names.push(path);
        }
    }
    names.sort();
    let mut out = Vec::new();
    for path in names {
        let text = fs::read_to_string(&path)?;
        let value: toml::Value = toml::from_str(&text)
            .map_err(|err| Error::message(format!("parse {}: {err}", path.display())))?;
        if let Some(list) = value.get("scenario").and_then(|item| item.as_array()) {
            for item in list {
                out.push(
                    item.clone().try_into().map_err(|err| {
                        Error::message(format!("parse {}: {err}", path.display()))
                    })?,
                );
            }
        } else {
            out.push(
                Scenario::deserialize(value)
                    .map_err(|err| Error::message(format!("parse {}: {err}", path.display())))?,
            );
        }
    }
    Ok(out)
}

fn load_toml_dir<T: serde::de::DeserializeOwned>(dir: &Path) -> Result<Vec<T>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            names.push(path);
        }
    }
    names.sort();
    let mut out = Vec::new();
    for path in names {
        let text = fs::read_to_string(&path)?;
        let value = toml::from_str(&text)
            .map_err(|err| Error::message(format!("parse {}: {err}", path.display())))?;
        out.push(value);
    }
    Ok(out)
}

pub fn find_profile<'a>(profiles: &'a [Profile], id: &str) -> Result<&'a Profile> {
    profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| Error::message(format!("unknown profile {id}")))
}

pub fn profile_path_hint(root: &Path, id: &str) -> PathBuf {
    root.join("profiles").join(format!("{id}.toml"))
}
