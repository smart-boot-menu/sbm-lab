use crate::error::{Error, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub kind: String,
    pub path: String,
}

pub fn scan(root: &Path) -> Vec<Artifact> {
    let mut found = Vec::new();
    let mut dirs = vec![
        root.join("var/artifacts"),
        root.join("var/artifacts/pinned"),
        root.join("../sbm-uefi/artifacts"),
        root.join("sbm-uefi-src/artifacts"),
        root.join("../sbm-uefi/target/x86_64-unknown-uefi/release"),
        root.join("../sbm-uefi/target/aarch64-unknown-uefi/release"),
        root.join("../sbm-uefi/target/x86_64-unknown-uefi/debug"),
        root.join("../sbm-uefi/target/aarch64-unknown-uefi/debug"),
        root.join("../sbm-core/image"),
        root.join("../sbm-core/build"),
        root.join("../install/out"),
    ];
    if let Ok(extra) = std::env::var("SBM_LAB_ARTIFACTS") {
        dirs.insert(0, PathBuf::from(extra));
    }
    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            if matches!(ext, "efi" | "uki" | "qcow2" | "img" | "raw" | "iso") {
                found.push(Artifact {
                    kind: ext.to_string(),
                    path: path.display().to_string(),
                });
            }
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

pub fn fetch_release(root: &Path, repo: &str, tag: &str, asset: &str) -> Result<PathBuf> {
    let dest = root
        .join("var/artifacts/pinned")
        .join(repo.replace('/', "__"))
        .join(tag);
    fs::create_dir_all(&dest)?;
    let gh = crate::util::which("gh").ok_or_else(|| {
        Error::message("gh is not installed; cannot fetch a GitHub release asset")
    })?;
    let status = Command::new(gh)
        .args([
            "release",
            "download",
            tag,
            "--repo",
            repo,
            "--pattern",
            asset,
            "--dir",
        ])
        .arg(&dest)
        .status()?;
    if !status.success() {
        return Err(Error::message(format!(
            "gh release download failed for {repo} {tag} {asset}"
        )));
    }
    let path = dest.join(asset);
    if !path.is_file() {
        return Err(Error::message(format!(
            "download finished but {} is missing",
            path.display()
        )));
    }
    let hash = crate::util::sha256_file(&path)?;
    fs::write(
        dest.join(format!("{asset}.sha256")),
        format!("{hash}  {asset}\n"),
    )?;
    Ok(path)
}
