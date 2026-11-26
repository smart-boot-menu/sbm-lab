use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

pub const SECTOR: u64 = 512;
const ENTRY_SIZE: usize = 128;
const ENTRY_COUNT: usize = 128;

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
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(Error::message(format!("invalid guid {text}")));
    }
    let mut raw = [0u8; 16];
    for i in 0..16 {
        raw[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::message(format!("invalid guid {text}")))?;
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&raw[0..4]);
    out[0..4].reverse();
    out[4..6].copy_from_slice(&raw[4..6]);
    out[4..6].reverse();
    out[6..8].copy_from_slice(&raw[6..8]);
    out[6..8].reverse();
    out[8..16].copy_from_slice(&raw[8..16]);
    Ok(out)
}

pub fn guid_from_name(name: &str) -> [u8; 16] {
    let digest = Sha256::digest(format!("sbm-lab-v1:{name}").as_bytes());
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&digest[..16]);
    guid[6] = (guid[6] & 0x0f) | 0x50;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    guid
}

pub fn esp_guid() -> [u8; 16] {
    parse_guid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").expect("esp guid")
}

pub fn linux_guid() -> [u8; 16] {
    parse_guid("0FC63DAF-8483-4772-8E79-3D69D8477DE4").expect("linux guid")
}

pub fn microsoft_basic_guid() -> [u8; 16] {
    parse_guid("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").expect("ms guid")
}

pub fn apple_apfs_guid() -> [u8; 16] {
    parse_guid("7C3457EF-0000-11AA-AA11-00306543ECAC").expect("apfs guid")
}

pub fn empty_mbr(total_bytes: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; total_bytes as usize];
    let n = bytes.len();
    bytes[n.min(510).saturating_sub(0)] = 0x55;
    if n > 511 {
        bytes[510] = 0x55;
        bytes[511] = 0xAA;
    }
    bytes
}

pub fn build_gpt(disk_name: &str, parts: &[PartitionSpec], corrupt: bool) -> Result<BuiltDisk> {
    let mut cursor = 2048u64;
    let mut placed = Vec::new();
    for part in parts {
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
    }
    let backup_entries = cursor.max(2048);
    let backup_header = backup_entries + 32;
    let total = backup_header + 1;
    let mut bytes = vec![0u8; (total * SECTOR) as usize];
    write_protective_mbr(&mut bytes, total);
    let entries = entry_bytes(&placed, disk_name)?;
    write_header(
        &mut bytes,
        HeaderLoc {
            current: 1,
            backup: backup_header,
            first_usable: 2048,
            last_usable: backup_entries - 1,
            entries_lba: 2,
            disk_guid: guid_from_name(disk_name),
        },
        &entries,
    )?;
    bytes[2 * SECTOR as usize..2 * SECTOR as usize + entries.len()].copy_from_slice(&entries);
    write_header(
        &mut bytes,
        HeaderLoc {
            current: backup_header,
            backup: 1,
            first_usable: 2048,
            last_usable: backup_entries - 1,
            entries_lba: backup_entries,
            disk_guid: guid_from_name(disk_name),
        },
        &entries,
    )?;
    let backup_off = (backup_entries * SECTOR) as usize;
    bytes[backup_off..backup_off + entries.len()].copy_from_slice(&entries);
    for (spec, place) in parts.iter().zip(placed.iter()) {
        let off = (place.start_lba * SECTOR) as usize;
        let room = ((place.end_lba - place.start_lba + 1) * SECTOR) as usize;
        let n = spec.payload.len().min(room);
        if n > 0 {
            bytes[off..off + n].copy_from_slice(&spec.payload[..n]);
        }
    }
    if corrupt {
        bytes[SECTOR as usize] = b'X';
        let backup_header_off = (backup_header * SECTOR) as usize;
        bytes[backup_header_off] = b'X';
    }
    Ok(BuiltDisk {
        bytes,
        partitions: placed,
    })
}

struct HeaderLoc {
    current: u64,
    backup: u64,
    first_usable: u64,
    last_usable: u64,
    entries_lba: u64,
    disk_guid: [u8; 16],
}

fn write_header(disk: &mut [u8], loc: HeaderLoc, entries: &[u8]) -> Result<()> {
    let mut header = [0u8; 92];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[24..32].copy_from_slice(&loc.current.to_le_bytes());
    header[32..40].copy_from_slice(&loc.backup.to_le_bytes());
    header[40..48].copy_from_slice(&loc.first_usable.to_le_bytes());
    header[48..56].copy_from_slice(&loc.last_usable.to_le_bytes());
    header[56..72].copy_from_slice(&loc.disk_guid);
    header[72..80].copy_from_slice(&loc.entries_lba.to_le_bytes());
    header[80..84].copy_from_slice(&(ENTRY_COUNT as u32).to_le_bytes());
    header[84..88].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
    let crc = crc32fast::hash(entries);
    header[88..92].copy_from_slice(&crc.to_le_bytes());
    let header_crc = crc32fast::hash(&header);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());
    let off = (loc.current * SECTOR) as usize;
    if off + header.len() > disk.len() {
        return Err(Error::message("gpt header does not fit"));
    }
    disk[off..off + header.len()].copy_from_slice(&header);
    Ok(())
}

fn entry_bytes(parts: &[PlacedPartition], disk_name: &str) -> Result<Vec<u8>> {
    let mut entries = vec![0u8; ENTRY_COUNT * ENTRY_SIZE];
    for (index, part) in parts.iter().enumerate() {
        if index >= ENTRY_COUNT {
            return Err(Error::message("too many partitions"));
        }
        let off = index * ENTRY_SIZE;
        entries[off..off + 16].copy_from_slice(&part.type_guid);
        let unique = guid_from_name(&format!("{disk_name}:{}", part.name));
        entries[off + 16..off + 32].copy_from_slice(&unique);
        entries[off + 32..off + 40].copy_from_slice(&part.start_lba.to_le_bytes());
        entries[off + 40..off + 48].copy_from_slice(&part.end_lba.to_le_bytes());
        let mut name = [0u8; 72];
        for (i, ch) in part.name.encode_utf16().take(35).enumerate() {
            name[i * 2..i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }
        entries[off + 56..off + 128].copy_from_slice(&name);
    }
    Ok(entries)
}

fn write_protective_mbr(disk: &mut [u8], total_sectors: u64) {
    let size =
        u32::try_from(total_sectors.saturating_sub(1).min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    disk[446] = 0x00;
    disk[450] = 0xEE;
    disk[454..458].copy_from_slice(&1u32.to_le_bytes());
    disk[458..462].copy_from_slice(&size.to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
}

pub fn validate_gpt(disk: &[u8]) -> Result<Vec<PlacedPartition>> {
    if disk.len() < 2 * SECTOR as usize {
        return Err(Error::message("disk is smaller than a GPT header"));
    }
    let header = &disk[SECTOR as usize..SECTOR as usize + 92];
    if &header[0..8] != b"EFI PART" {
        return Err(Error::message("gpt signature is invalid"));
    }
    let mut zeroed = [0u8; 92];
    zeroed.copy_from_slice(header);
    zeroed[16..20].fill(0);
    let expect = u32::from_le_bytes(header[16..20].try_into().unwrap());
    if crc32fast::hash(&zeroed) != expect {
        return Err(Error::message("gpt header crc mismatch"));
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(header[80..84].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(header[84..88].try_into().unwrap()) as usize;
    let off = (entries_lba * SECTOR) as usize;
    let bytes = count.saturating_mul(size);
    if off + bytes > disk.len() {
        return Err(Error::message("gpt entries do not fit"));
    }
    let entries = &disk[off..off + bytes];
    let expect_entries = u32::from_le_bytes(header[88..92].try_into().unwrap());
    if crc32fast::hash(entries) != expect_entries {
        return Err(Error::message("gpt entry crc mismatch"));
    }
    let mut out = Vec::new();
    for index in 0..count {
        let e = &entries[index * size..(index + 1) * size];
        if e[0..16].iter().all(|b| *b == 0) {
            continue;
        }
        let start = u64::from_le_bytes(e[32..40].try_into().unwrap());
        let end = u64::from_le_bytes(e[40..48].try_into().unwrap());
        let name = decode_name(&e[56..128]);
        out.push(PlacedPartition {
            name,
            type_guid: e[0..16].try_into().unwrap(),
            start_lba: start,
            end_lba: end,
        });
    }
    Ok(out)
}

fn decode_name(raw: &[u8]) -> String {
    let mut units = Vec::new();
    for chunk in raw.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
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
