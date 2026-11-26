use crate::error::{Error, Result};
use crate::fatimg::build_fat32;
use crate::gpt::{
    BuiltDisk, PartitionSpec, apple_apfs_guid, build_gpt, empty_mbr, esp_guid, linux_guid,
    microsoft_basic_guid,
};
use crate::util::{sha256_bytes, which};
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub const NOT_WINDOWS: &str = "\
THIS IS NOT WINDOWS.\n\
This fixture is a synthetic UEFI directory layout for Smart Boot Menu tests.\n\
It does not contain Microsoft Windows, a real BCD hive, or BitLocker user data.\n";

pub const NOT_APPLE: &str = "\
THIS IS NOT AN APPLE DISK.\n\
Partition names iSCPreboot and Recovery are synthetic guard-test labels.\n\
There is no Apple firmware, APFS container, or RecoveryOS image here.\n";

pub const NOT_UKI: &str = "\
SBM-LAB-SYNTHETIC-UKI\n\
This file is not a Unified Kernel Image and does not contain a Linux kernel.\n";

#[derive(Debug, Clone, Serialize)]
pub struct FixtureManifest {
    pub schema: &'static str,
    pub id: String,
    pub synthetic: bool,
    pub proprietary_os: bool,
    pub warning: String,
    pub sha256: String,
    pub partitions: Vec<ManifestPartition>,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestPartition {
    pub name: String,
    pub start_lba: u64,
    pub end_lba: u64,
    pub creator: String,
}

#[derive(Debug, Clone)]
pub struct Fixture {
    pub manifest: FixtureManifest,
    pub disk: BuiltDisk,
}

pub fn fixture_ids() -> &'static [&'static str] {
    &[
        "empty-gpt",
        "empty-mbr",
        "one-esp",
        "multi-esp",
        "multi-efi",
        "linux-bls",
        "windows-like",
        "uki",
        "filesystems",
        "missing-boot",
        "corrupt-gpt",
        "corrupt-config",
        "duplicate-entries",
        "apple-protected",
    ]
}

pub fn build_fixture(id: &str, work: &Path) -> Result<Fixture> {
    let efi = b"SBM-LAB-SYNTHETIC-EFI\n".to_vec();
    match id {
        "empty-gpt" => finish(id, "Empty GPT disk.", build_gpt(id, &[], false)?, vec![]),
        "empty-mbr" => {
            let bytes = empty_mbr(8 * 1024 * 1024);
            let disk = BuiltDisk {
                bytes,
                partitions: vec![],
            };
            finish(
                id,
                "Empty MBR disk with no partition entries.",
                disk,
                vec![],
            )
        }
        "one-esp" => fat_disk(
            id,
            "One EFI System Partition.",
            vec![fat_part(
                "ESP",
                48,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"one-esp\n"),
                    ("EFI/sbm-lab/only.efi", efi.as_slice()),
                    ("EFI/sbm-lab/manifest.txt", b"EFI/sbm-lab/only.efi\n"),
                ],
            )?],
        ),
        "multi-esp" => fat_disk(
            id,
            "Two EFI System Partitions.",
            vec![
                fat_part(
                    "ESP-A",
                    48,
                    &[
                        ("EFI/sbm-lab/disk-id.txt", b"esp-a\n"),
                        ("EFI/BOOT/BOOTX64.EFI", efi.as_slice()),
                        ("EFI/sbm-lab/manifest.txt", b"EFI/BOOT/BOOTX64.EFI\n"),
                    ],
                )?,
                fat_part(
                    "ESP-B",
                    48,
                    &[
                        ("EFI/sbm-lab/disk-id.txt", b"esp-b\n"),
                        ("EFI/BOOT/BOOTAA64.EFI", efi.as_slice()),
                        ("EFI/sbm-lab/manifest.txt", b"EFI/BOOT/BOOTAA64.EFI\n"),
                    ],
                )?,
            ],
        ),
        "multi-efi" => fat_disk(
            id,
            "Several synthetic EFI executables on one ESP.",
            vec![fat_part(
                "ESP",
                48,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"multi-efi\n"),
                    ("EFI/sbm-lab/alpha.efi", efi.as_slice()),
                    ("EFI/sbm-lab/beta.efi", efi.as_slice()),
                    ("EFI/sbm-lab/gamma.efi", efi.as_slice()),
                    (
                        "EFI/sbm-lab/manifest.txt",
                        b"EFI/sbm-lab/alpha.efi\nEFI/sbm-lab/beta.efi\nEFI/sbm-lab/gamma.efi\n",
                    ),
                ],
            )?],
        ),
        "linux-bls" => {
            let files = linux_files();
            fat_disk(
                id,
                "Synthetic BLS type 1 entries plus a synthetic UKI note. Not a Linux install.",
                vec![fat_part("ESP", 48, &files)?],
            )
        }
        "uki" => fat_disk(
            id,
            "Synthetic UKI path. The EFI file is not a Linux UKI.",
            vec![fat_part(
                "ESP",
                48,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"uki\n"),
                    ("EFI/Linux/synthetic.efi", efi.as_slice()),
                    ("EFI/Linux/synthetic.uki-note", NOT_UKI.as_bytes()),
                    (
                        "EFI/sbm-lab/manifest.txt",
                        b"EFI/Linux/synthetic.efi\nEFI/Linux/synthetic.uki-note\n",
                    ),
                ],
            )?],
        ),
        "windows-like" => {
            let mut parts = vec![fat_part(
                "ESP",
                48,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"windows-like\n"),
                    ("EFI/sbm-lab/README.txt", NOT_WINDOWS.as_bytes()),
                    ("EFI/Microsoft/Boot/bootmgfw.efi", efi.as_slice()),
                    (
                        "EFI/Microsoft/Boot/BCD",
                        b"SBM-LAB-SYNTHETIC-BCD-NOT-A-WINDOWS-INSTALL\n",
                    ),
                    (
                        "EFI/sbm-lab/manifest.txt",
                        b"EFI/Microsoft/Boot/bootmgfw.efi\nEFI/Microsoft/Boot/BCD\n",
                    ),
                ],
            )?];
            parts.push(PartitionSpec {
                name: "SYNTHETIC-BITLOCKER".into(),
                type_guid: microsoft_basic_guid(),
                size_bytes: 8 * 1024 * 1024,
                payload: bitlocker_header(),
            });
            fat_disk(
                id,
                "Synthetic Windows-like ESP and BitLocker marker. Not Windows.",
                parts,
            )
        }
        "missing-boot" => fat_disk(
            id,
            "ESP with no EFI executables.",
            vec![fat_part(
                "ESP",
                48,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"missing-boot\n"),
                    ("EFI/sbm-lab/note-missing-boot.txt", b"missing-boot\n"),
                    (
                        "EFI/sbm-lab/manifest.txt",
                        b"EFI/sbm-lab/note-missing-boot.txt\n",
                    ),
                ],
            )?],
        ),
        "corrupt-gpt" => {
            let disk = build_gpt(
                id,
                &[fat_part(
                    "ESP",
                    48,
                    &[("EFI/sbm-lab/disk-id.txt", b"corrupt-gpt\n")],
                )?],
                true,
            )?;
            finish(
                id,
                "GPT with both signatures destroyed.",
                disk,
                vec!["EFI/sbm-lab/disk-id.txt".into()],
            )
        }
        "corrupt-config" => fat_disk(
            id,
            "ESP with a policy file that is not valid JSON.",
            vec![fat_part(
                "ESP",
                48,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"corrupt-config\n"),
                    ("EFI/sbm/policy.json", b"{broken"),
                    ("EFI/sbm-lab/manifest.txt", b"EFI/sbm/policy.json\n"),
                ],
            )?],
        ),
        "duplicate-entries" => {
            fat_disk(
                id,
                "Two BLS entries and a catalog that repeat the same id.",
                vec![fat_part(
                "ESP",
                48,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"duplicate-entries\n"),
                    (
                        "loader/entries/a.conf",
                        b"title Synthetic Linux\nlinux /EFI/Linux/a.efi\n",
                    ),
                    (
                        "loader/entries/b.conf",
                        b"title Synthetic Linux\nlinux /EFI/Linux/b.efi\n",
                    ),
                    ("EFI/sbm-lab/catalog.txt", b"id=synth-linux\nid=synth-linux\n"),
                    (
                        "EFI/sbm-lab/manifest.txt",
                        b"loader/entries/a.conf\nloader/entries/b.conf\nEFI/sbm-lab/catalog.txt\n",
                    ),
                ],
            )?],
            )
        }
        "apple-protected" => {
            let mut parts = vec![fat_part(
                "ESP",
                32,
                &[
                    ("EFI/sbm-lab/disk-id.txt", b"apple-protected\n"),
                    ("EFI/sbm-lab/README.txt", NOT_APPLE.as_bytes()),
                    ("EFI/sbm-lab/manifest.txt", b"EFI/sbm-lab/README.txt\n"),
                ],
            )?];
            parts.push(PartitionSpec {
                name: "iSCPreboot".into(),
                type_guid: apple_apfs_guid(),
                size_bytes: 8 * 1024 * 1024,
                payload: NOT_APPLE.as_bytes().to_vec(),
            });
            parts.push(PartitionSpec {
                name: "Recovery".into(),
                type_guid: apple_apfs_guid(),
                size_bytes: 8 * 1024 * 1024,
                payload: NOT_APPLE.as_bytes().to_vec(),
            });
            fat_disk(
                id,
                "Synthetic Apple-style partition names. Not an Apple disk.",
                parts,
            )
        }
        "filesystems" => build_filesystems(work),
        other => Err(Error::message(format!("unknown fixture {other}"))),
    }
}

fn finish(id: &str, warning: &str, disk: BuiltDisk, files: Vec<String>) -> Result<Fixture> {
    let sha256 = sha256_bytes(&disk.bytes);
    let partitions = disk
        .partitions
        .iter()
        .map(|p| ManifestPartition {
            name: p.name.clone(),
            start_lba: p.start_lba,
            end_lba: p.end_lba,
            creator: "gpt".into(),
        })
        .collect();
    Ok(Fixture {
        manifest: FixtureManifest {
            schema: "sbm-lab.fixture.v1",
            id: id.to_string(),
            synthetic: true,
            proprietary_os: false,
            warning: warning.to_string(),
            sha256,
            partitions,
            files,
        },
        disk,
    })
}

fn fat_disk(id: &str, warning: &str, parts: Vec<PartitionSpec>) -> Result<Fixture> {
    let files = Vec::new();
    let disk = build_gpt(id, &parts, false)?;
    finish(id, warning, disk, files)
}

fn fat_part(name: &str, mib: u64, files: &[(&str, &[u8])]) -> Result<PartitionSpec> {
    let owned: Vec<(String, &[u8])> = files.iter().map(|(p, b)| ((*p).to_string(), *b)).collect();
    let size = mib * 1024 * 1024;
    let payload = build_fat32(size, "SBMLAB", &owned)?;
    Ok(PartitionSpec {
        name: name.to_string(),
        type_guid: esp_guid(),
        size_bytes: size,
        payload,
    })
}

fn linux_files() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("EFI/sbm-lab/disk-id.txt", b"linux-bls\n"),
        (
            "loader/entries/a.conf",
            b"title Synthetic Linux A\nlinux /EFI/Linux/vmlinuz-synthetic\noptions console=ttyS0\n",
        ),
        (
            "loader/entries/b.conf",
            b"title Synthetic Linux B\nlinux /EFI/Linux/vmlinuz-synthetic\noptions console=ttyS0\n",
        ),
        ("EFI/Linux/synthetic.efi", b"SBM-LAB-SYNTHETIC-EFI\n"),
        ("EFI/Linux/synthetic.uki-note", NOT_UKI.as_bytes()),
        (
            "EFI/sbm-lab/manifest.txt",
            b"loader/entries/a.conf\nloader/entries/b.conf\nEFI/Linux/synthetic.efi\nEFI/Linux/synthetic.uki-note\n",
        ),
    ]
}

fn bitlocker_header() -> Vec<u8> {
    let mut raw = vec![0u8; 4096];
    raw[0] = 0xEB;
    raw[1] = 0x58;
    raw[2] = 0x90;
    raw[3..11].copy_from_slice(b"-FVE-FS-");
    raw.extend_from_slice(b"\nSBM-LAB-SYNTHETIC-BITLOCKER-NOT-WINDOWS\n");
    raw
}

fn build_filesystems(work: &Path) -> Result<Fixture> {
    let esp = fat_part(
        "ESP",
        48,
        &[
            ("EFI/sbm-lab/disk-id.txt", b"filesystems\n"),
            (
                "EFI/sbm-lab/README.txt",
                b"FAT32 ESP plus synthetic ext4, NTFS, Btrfs, and LUKS1 volumes.\n",
            ),
        ],
    )?;
    let ext4 = special_part(work, "ext4", linux_guid(), "ext4")?;
    let ntfs = special_part(work, "ntfs", microsoft_basic_guid(), "ntfs")?;
    let btrfs = special_part(work, "btrfs", linux_guid(), "btrfs")?;
    let luks = PartitionSpec {
        name: "SYNTHETIC-LUKS1".into(),
        type_guid: linux_guid(),
        size_bytes: 8 * 1024 * 1024,
        payload: luks1_header(),
    };
    fat_disk(
        "filesystems",
        "FAT32 plus ext4 (mkfs when available), identifiable NTFS and Btrfs headers, and a synthetic LUKS1 header with disabled key slots.",
        vec![esp, ext4, ntfs, btrfs, luks],
    )
}

fn special_part(work: &Path, name: &str, type_guid: [u8; 16], kind: &str) -> Result<PartitionSpec> {
    let size = 8 * 1024 * 1024;
    let payload = match kind {
        "ext4" => ext4_payload(work, size)?,
        "ntfs" => ntfs_payload(size),
        "btrfs" => btrfs_payload(size),
        _ => Vec::new(),
    };
    Ok(PartitionSpec {
        name: name.to_string(),
        type_guid,
        size_bytes: size,
        payload,
    })
}

fn ext4_payload(work: &Path, size: u64) -> Result<Vec<u8>> {
    if let Some(mkfs) = which("mkfs.ext4").or_else(|| {
        which("mkfs.ext4")
            .or(Some(std::path::PathBuf::from(
                "/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4",
            )))
            .filter(|p| p.is_file())
    }) {
        let path = work.join("ext4.img");
        let mut file = File::create(&path)?;
        file.set_len(size)?;
        file.flush()?;
        drop(file);
        let status = Command::new(&mkfs)
            .args(["-F", "-L", "SBMLAB", "-q"])
            .arg(&path)
            .status();
        if matches!(status, Ok(code) if code.success()) {
            return Ok(std::fs::read(path)?);
        }
    }
    let mut raw = vec![0u8; size as usize];
    raw[1080] = 0x53;
    raw[1081] = 0xEF;
    raw[1024 + 0x78..1024 + 0x78 + 6].copy_from_slice(b"SBMLAB");
    Ok(raw)
}

fn ntfs_payload(size: u64) -> Vec<u8> {
    let mut raw = vec![0u8; size as usize];
    raw[0] = 0xEB;
    raw[1] = 0x52;
    raw[2] = 0x90;
    raw[3..11].copy_from_slice(b"NTFS    ");
    raw[0x0B] = 0x00;
    raw[0x0C] = 0x02;
    raw[0x0D] = 8;
    raw[0x15] = 0xF8;
    let sectors = size / 512;
    raw[0x28..0x30].copy_from_slice(&sectors.to_le_bytes());
    raw[510] = 0x55;
    raw[511] = 0xAA;
    raw
}

fn btrfs_payload(size: u64) -> Vec<u8> {
    let mut raw = vec![0u8; size as usize];
    let off = 0x10040;
    if off + 8 <= raw.len() {
        raw[off..off + 8].copy_from_slice(b"_BHRfS_M");
    }
    raw
}

pub fn luks1_header() -> Vec<u8> {
    let mut hdr = vec![0u8; 1024];
    hdr[0..6].copy_from_slice(b"LUKS\xba\xbe");
    hdr[6..8].copy_from_slice(&1u16.to_be_bytes());
    put_cstr(&mut hdr[8..40], b"aes");
    put_cstr(&mut hdr[40..72], b"xts-plain64");
    put_cstr(&mut hdr[72..104], b"sha256");
    hdr[104..108].copy_from_slice(&4096u32.to_be_bytes());
    hdr[108..112].copy_from_slice(&64u32.to_be_bytes());
    let digest = Sha1::digest(b"sbm-lab-synthetic-luks");
    hdr[112..132].copy_from_slice(&digest);
    hdr[164..168].copy_from_slice(&1u32.to_be_bytes());
    put_cstr(&mut hdr[168..208], b"00000000-0000-4000-8000-000000000001");
    for slot in 0..8 {
        let off = 208 + slot * 48;
        hdr[off..off + 4].copy_from_slice(&0x0000_DEADu32.to_be_bytes());
    }
    let sum = Sha1::digest(&hdr[..592]);
    hdr[592..612].copy_from_slice(&sum);
    hdr
}

fn put_cstr(dst: &mut [u8], text: &[u8]) {
    let n = text.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&text[..n]);
}

pub fn command_envelope_obviously_invalid(value: &serde_json::Value) -> bool {
    const REQUIRED: &[&str] = &[
        "schema_version",
        "command_id",
        "device_id",
        "sequence",
        "issued_at_unix",
        "expires_at_unix",
        "required_scope",
        "issuer_key_id",
        "payload",
        "signature_ed25519_hex",
    ];
    let Some(obj) = value.as_object() else {
        return true;
    };
    REQUIRED.iter().any(|key| match obj.get(*key) {
        None => true,
        Some(serde_json::Value::String(text)) if text.is_empty() => true,
        Some(serde_json::Value::Null) => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fatimg::read_fat_file;
    use crate::gpt::{SECTOR, validate_gpt};

    #[test]
    fn multi_efi_lists_three_executables() {
        let dir = crate::util::test_scratch("fix");
        let fx = build_fixture("multi-efi", &dir).unwrap();
        assert!(!fx.manifest.proprietary_os);
        let part = &fx.disk.partitions[0];
        let off = (part.start_lba * SECTOR) as usize;
        let end = ((part.end_lba + 1) * SECTOR) as usize;
        let alpha = read_fat_file(&fx.disk.bytes[off..end], "EFI/sbm-lab/alpha.efi").unwrap();
        assert!(alpha.starts_with(b"SBM-LAB-SYNTHETIC-EFI"));
    }

    #[test]
    fn windows_fixture_is_labeled_synthetic() {
        let dir = crate::util::test_scratch("win");
        let fx = build_fixture("windows-like", &dir).unwrap();
        let esp = &fx.disk.partitions[0];
        let off = (esp.start_lba * SECTOR) as usize;
        let end = ((esp.end_lba + 1) * SECTOR) as usize;
        let text = read_fat_file(&fx.disk.bytes[off..end], "EFI/sbm-lab/README.txt").unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("THIS IS NOT WINDOWS"));
        assert_eq!(fx.disk.partitions[1].name, "SYNTHETIC-BITLOCKER");
    }

    #[test]
    fn apple_names_are_present_and_labeled() {
        let dir = crate::util::test_scratch("apple");
        let fx = build_fixture("apple-protected", &dir).unwrap();
        let names: Vec<_> = fx.disk.partitions.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"iSCPreboot"));
        assert!(names.contains(&"Recovery"));
    }

    #[test]
    fn corrupt_gpt_fails_validation() {
        let dir = crate::util::test_scratch("bad");
        let fx = build_fixture("corrupt-gpt", &dir).unwrap();
        assert!(validate_gpt(&fx.disk.bytes).is_err());
    }

    #[test]
    fn luks_header_checksum_matches() {
        let hdr = luks1_header();
        assert_eq!(&hdr[0..6], b"LUKS\xba\xbe");
        assert_eq!(u16::from_be_bytes(hdr[6..8].try_into().unwrap()), 1);
        let sum = Sha1::digest(&hdr[..592]);
        assert_eq!(&hdr[592..612], sum.as_slice());
        assert_eq!(&hdr[208..212], &0x0000_DEADu32.to_be_bytes());
    }

    #[test]
    fn invalid_command_corpus_is_rejected() {
        let raw = include_str!("../../../fixtures/corpus/invalid-command-envelope.json");
        let value: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert!(command_envelope_obviously_invalid(&value));
    }

    #[test]
    fn filesystems_have_identifiable_headers() {
        let dir = crate::util::test_scratch("fs");
        let fx = build_fixture("filesystems", &dir).unwrap();
        let ntfs = fx
            .disk
            .partitions
            .iter()
            .find(|p| p.name == "ntfs")
            .unwrap();
        let off = (ntfs.start_lba * SECTOR) as usize;
        assert_eq!(&fx.disk.bytes[off + 3..off + 11], b"NTFS    ");
        let btrfs = fx
            .disk
            .partitions
            .iter()
            .find(|p| p.name == "btrfs")
            .unwrap();
        let boff = (btrfs.start_lba * SECTOR) as usize + 0x10040;
        assert_eq!(&fx.disk.bytes[boff..boff + 8], b"_BHRfS_M");
    }
}
