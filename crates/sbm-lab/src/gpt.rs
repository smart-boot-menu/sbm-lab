//! Thin GPT fixture adapter delegating to `sbm-media::gpt`.

use crate::error::{Error, Result};
use sbm_media::gpt::{self, GptPartition, Guid};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const SECTOR: u64 = gpt::SECTOR;

#[derive(Debug, Clone)]
pub struct PartitionSpec {
    pub name: String,
    pub type_guid: [u8; 16],
    pub size_bytes: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedPartition {
    pub name: String,
    pub type_guid: [u8; 16],
    pub start_lba: u64,
    pub end_lba: u64,
}

#[derive(Debug, Clone)]
pub struct BuiltDisk {
    pub bytes: Vec<u8>,
    pub partitions: Vec<PlacedPartition>,
}

pub fn parse_guid(text: &str) -> Result<[u8; 16]> {
    text.parse::<Guid>()
        .map(|g| g.0)
        .map_err(|e| Error::message(format!("invalid guid {text}: {e}")))
}

pub fn guid_from_name(name: &str) -> [u8; 16] {
    Guid::derive("sbm-lab-v1", &[name.as_bytes()]).0
}

pub fn esp_guid() -> [u8; 16] {
    gpt::types::esp().0
}

pub fn linux_guid() -> [u8; 16] {
    gpt::types::linux_generic().0
}

pub fn microsoft_basic_guid() -> [u8; 16] {
    gpt::types::microsoft_basic_data().0
}

pub fn apple_apfs_guid() -> [u8; 16] {
    gpt::types::apple_apfs().0
}

pub fn empty_mbr(total_bytes: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; total_bytes as usize];
    if bytes.len() > 511 {
        bytes[510] = 0x55;
        bytes[511] = 0xAA;
    }
    bytes
}

pub fn build_gpt(disk_name: &str, parts: &[PartitionSpec], corrupt: bool) -> Result<BuiltDisk> {
    let mut cursor = 2048u64;
    let mut placed = Vec::with_capacity(parts.len());
    let mut entries = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        let sectors = part.size_bytes.div_ceil(SECTOR).max(1);
        let aligned = sectors.div_ceil(2048) * 2048;
        let start = cursor;
        let end = start + aligned - 1;
        cursor = end + 1;
        placed.push(PlacedPartition {
            name: part.name.clone(),
            type_guid: part.type_guid,
            start_lba: start,
            end_lba: end,
        });
        let idx = (index as u32 + 1).to_le_bytes();
        entries.push(GptPartition {
            number: index as u32 + 1,
            type_guid: Guid(part.type_guid),
            unique_guid: Guid::derive(
                "sbm-lab-v1-part",
                &[disk_name.as_bytes(), &idx, part.name.as_bytes()],
            ),
            first_lba: start,
            last_lba: end,
            attributes: 0,
            name: part.name.clone(),
        });
    }
    let backup_entries = cursor.max(2048);
    let backup_header = backup_entries + gpt::ENTRY_SECTORS;
    let total = backup_header + 1;

    let mut file = tempfile::tempfile()?;
    file.set_len(total * SECTOR)?;
    let disk_guid = Guid(guid_from_name(disk_name));
    gpt::write_gpt(&file, total, disk_guid, &entries)
        .map_err(|e| Error::message(format!("write_gpt: {e}")))?;

    for (spec, place) in parts.iter().zip(placed.iter()) {
        let room = ((place.end_lba - place.start_lba + 1) * SECTOR) as usize;
        let n = spec.payload.len().min(room);
        if n > 0 {
            file.seek(SeekFrom::Start(place.start_lba * SECTOR))?;
            file.write_all(&spec.payload[..n])?;
        }
    }
    if corrupt {
        file.seek(SeekFrom::Start(SECTOR))?;
        file.write_all(b"X")?;
        file.seek(SeekFrom::Start(backup_header * SECTOR))?;
        file.write_all(b"X")?;
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity((total * SECTOR) as usize);
    file.read_to_end(&mut bytes)?;
    Ok(BuiltDisk {
        bytes,
        partitions: placed,
    })
}

pub fn validate_gpt(disk: &[u8]) -> Result<Vec<PlacedPartition>> {
    let mut file = tempfile::tempfile()?;
    file.write_all(disk)?;
    read_placed(&file, disk.len() as u64, "sbm-lab")
}

pub fn validate_gpt_file(path: &Path) -> Result<Vec<PlacedPartition>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    read_placed(&file, size, &path.display().to_string())
}

fn read_placed(file: &File, size: u64, what: &str) -> Result<Vec<PlacedPartition>> {
    let table =
        gpt::read_gpt_strict(file, size, what).map_err(|e| Error::message(format!("gpt: {e}")))?;
    Ok(table
        .partitions
        .into_iter()
        .map(|p| PlacedPartition {
            name: p.name,
            type_guid: p.type_guid.0,
            start_lba: p.first_lba,
            end_lba: p.last_lba,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn esp_guid_matches_uefi_layout() {
        let guid = parse_guid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").unwrap();
        assert_eq!(&guid[0..4], &[0x28, 0x73, 0x2A, 0xC1]);
    }

    #[test]
    fn empty_gpt_roundtrip_and_corrupt() {
        let disk = build_gpt("empty", &[], false).unwrap();
        assert!(validate_gpt(&disk.bytes).unwrap().is_empty());
        let bad = build_gpt("empty", &[], true).unwrap();
        assert!(validate_gpt(&bad.bytes).is_err());
    }

    #[test]
    fn empty_mbr_has_signature_and_no_partitions() {
        let disk = empty_mbr(8 * 1024 * 1024);
        assert_eq!(disk[510], 0x55);
        assert_eq!(disk[511], 0xAA);
        assert!(disk[446..510].iter().all(|b| *b == 0));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn random_empty_partitions_validate(a in 1u64..4, b in 1u64..4) {
            let parts = vec![
                PartitionSpec { name: "a".into(), type_guid: linux_guid(), size_bytes: a * 1024 * 1024, payload: Vec::new() },
                PartitionSpec { name: "b".into(), type_guid: linux_guid(), size_bytes: b * 1024 * 1024, payload: Vec::new() },
            ];
            let disk = build_gpt("prop", &parts, false).unwrap();
            let got = validate_gpt(&disk.bytes).unwrap();
            prop_assert_eq!(got.len(), 2);
            prop_assert!(got[0].end_lba < got[1].start_lba);
        }
    }
}
