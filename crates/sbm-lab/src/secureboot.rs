//! Development Secure Boot keys for the lab. They are not production keys.
//!
//! Private keys stay in `var/secure-boot`, which is gitignored. The enrolled
//! variable store is a copy. The firmware code file is never written.

use crate::accel::Arch;
use crate::error::{Error, Result};
use crate::firmware::select_firmware;
use crate::run::probe_efi;
use crate::util::{FileLock, which};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const OWNER: &str = "11111111-2222-3333-4444-555555555555";

pub fn enroll(root: &Path) -> Result<()> {
    let _lock = FileLock::exclusive(&root.join("var/secure-boot/.lock"))?;
    let dir = root.join("var/secure-boot");
    fs::create_dir_all(&dir)?;
    let openssl = which("openssl").ok_or_else(|| Error::message("openssl is not installed"))?;
    for name in ["PK", "KEK", "DB"] {
        cert_pair(&openssl, &dir, name)?;
    }
    let fw = select_firmware(
        which("qemu-system-x86_64").as_deref(),
        Arch::X86_64,
        true,
        "q35",
    )?;
    let enrolled = dir.join("enrolled.fd");
    fs::copy(&fw.vars_template, &enrolled)?;
    let virt = virt_fw_vars(root)?;
    let mut enroll_cmd = Command::new(&virt);
    if let Some(py) = virt.parent().and_then(|bin| bin.parent())
        && py.join("virt").is_dir()
    {
        enroll_cmd.env("PYTHONPATH", py);
    }
    let status = enroll_cmd
        .arg("--inplace")
        .arg(&enrolled)
        .args(["--set-pk", OWNER])
        .arg(dir.join("PK.pem"))
        .args(["--add-kek", OWNER])
        .arg(dir.join("KEK.pem"))
        .args(["--add-db", OWNER])
        .arg(dir.join("DB.pem"))
        .arg("--secure-boot")
        .status()?;
    if !status.success() {
        let _ = fs::remove_file(&enrolled);
        return Err(Error::message(
            "virt-fw-vars could not enroll the development keys",
        ));
    }
    let probe = probe_efi(root, Arch::X86_64)
        .ok_or_else(|| Error::message("x86_64 probe EFI is missing; run sbm-lab setup --probe"))?;
    let signed = dir.join("probe-signed.efi");
    sign(&dir, &probe, &signed)?;
    let mut tampered = fs::read(&signed)?;
    tamper(&mut tampered);
    fs::write(dir.join("probe-tampered.efi"), &tampered)?;
    println!(
        "enrolled development Secure Boot keys at {}",
        enrolled.display()
    );
    Ok(())
}

pub fn tamper(bytes: &mut [u8]) {
    if bytes.len() > 0x200 {
        let index = bytes.len() / 2;
        bytes[index] ^= 0xff;
    }
}

fn cert_pair(openssl: &Path, dir: &Path, name: &str) -> Result<()> {
    let key = dir.join(format!("{name}.key"));
    let cert = dir.join(format!("{name}.pem"));
    if key.is_file() && cert.is_file() {
        return Ok(());
    }
    let status = Command::new(openssl)
        .args(["req", "-new", "-x509", "-newkey", "rsa:2048", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "3650",
            "-nodes",
            "-subj",
            &format!("/CN=SBM Lab Development {name}/"),
        ])
        .status()?;
    if !status.success() {
        return Err(Error::message(format!("openssl failed for {name}")));
    }
    Ok(())
}

fn sign(dir: &Path, input: &Path, output: &Path) -> Result<()> {
    let signer = which("osslsigncode").ok_or_else(|| {
        Error::message("osslsigncode is not installed; install it and rerun setup --secure-boot")
    })?;
    let status = Command::new(signer)
        .arg("sign")
        .arg("-certs")
        .arg(dir.join("DB.pem"))
        .arg("-key")
        .arg(dir.join("DB.key"))
        .arg("-h")
        .arg("sha256")
        .arg("-in")
        .arg(input)
        .arg("-out")
        .arg(output)
        .status()?;
    if !status.success() {
        return Err(Error::message("osslsigncode failed"));
    }
    Ok(())
}

fn virt_fw_vars(root: &Path) -> Result<PathBuf> {
    if let Some(path) = which("virt-fw-vars") {
        return Ok(path);
    }
    let local = root.join("var/py/bin/virt-fw-vars");
    if local.is_file() {
        return Ok(local);
    }
    let python = which("python3").ok_or_else(|| Error::message("python3 is not installed"))?;
    let dest = root.join("var/py");
    fs::create_dir_all(&dest)?;
    let mut install = Command::new(python);
    let include = Path::new("/opt/homebrew/opt/libxcrypt/include");
    let lib = Path::new("/opt/homebrew/opt/libxcrypt/lib");
    if include.is_dir() {
        install.env("CPATH", include);
        install.env("LIBRARY_PATH", lib);
    }
    let status = install
        .args([
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--target",
        ])
        .arg(&dest)
        .arg("virt-firmware")
        .status()?;
    if !status.success() || !local.is_file() {
        return Err(Error::message(
            "could not install virt-firmware into var/py; virt-fw-vars is required to enroll keys",
        ));
    }
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tamper_flips_one_byte_past_the_header() {
        let mut bytes = vec![0u8; 1024];
        bytes[512] = 0x10;
        tamper(&mut bytes);
        assert_eq!(bytes[512], 0xef);
        assert_eq!(bytes[0], 0);
    }
}
