//! Thin FAT32 fixture adapter delegating to `sbm-media::esp`.

use crate::error::{Error, Result};
use sbm_media::esp::{self, EspContents, FatType};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const FIXED_EPOCH: i64 = 1_700_000_000;
const LAB_VOLUME_ID: u32 = 0x5342_4D31;

pub fn build_fat32(size: u64, label: &str, files: &[(String, &[u8])]) -> Result<Vec<u8>> {
    let mut contents = EspContents::default();
    for (raw_path, data) in files {
        let normalized = raw_path.replace('\\', "/");
        let trimmed = normalized.trim_matches('/');
        if trimmed.is_empty() {
            return Err(Error::message("empty fat path"));
        }
        contents.add_file(trimmed, data.to_vec());
    }
    let mut file = tempfile::tempfile()?;
    file.set_len(size)?;
    esp::format_with(
        &file,
        0,
        size,
        FatType::Fat32,
        512,
        LAB_VOLUME_ID,
        label,
        FIXED_EPOCH,
        &contents,
    )
    .map_err(|e| Error::message(format!("fat format: {e}")))?;
    file.seek(SeekFrom::Start(0))?;
    let mut out = Vec::with_capacity(size as usize);
    file.read_to_end(&mut out)?;
    Ok(out)
}

pub fn read_fat_file(volume: &[u8], path: &str) -> Result<Vec<u8>> {
    let mut file = tempfile::tempfile()?;
    file.write_all(volume)?;
    read_from_file(&file, volume.len() as u64, path)
}

pub fn read_fat_file_from_path(image_path: &Path, path: &str) -> Result<Vec<u8>> {
    let file = File::open(image_path)?;
    let len = file.metadata()?.len();
    read_from_file(&file, len, path)
}

fn read_from_file(file: &File, len: u64, path: &str) -> Result<Vec<u8>> {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_matches('/');
    esp::read_file(file, 0, len, trimmed, len, "sbm-lab")
        .map_err(|e| Error::message(format!("fat read {trimmed}: {e}")))?
        .ok_or_else(|| Error::message(format!("open {trimmed}: not found")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat32_roundtrip() {
        let hello = b"hello-lab".to_vec();
        let files = [("EFI/sbm-lab/hello.txt".to_string(), hello.as_slice())];
        let image = build_fat32(48 * 1024 * 1024, "SBMLAB", &files).unwrap();
        let got = read_fat_file(&image, "EFI/sbm-lab/hello.txt").unwrap();
        assert_eq!(got, b"hello-lab");
    }
}
