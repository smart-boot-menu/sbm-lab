use crate::error::{Error, Result};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

pub fn build_fat32(size: u64, label: &str, files: &[(String, &[u8])]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(vec![0u8; size as usize]);
    let mut label_bytes = [b' '; 11];
    for (i, b) in label.bytes().take(11).enumerate() {
        label_bytes[i] = b;
    }
    let opts = fatfs::FormatVolumeOptions::new()
        .fat_type(fatfs::FatType::Fat32)
        .bytes_per_sector(512)
        .bytes_per_cluster(512)
        .volume_label(label_bytes);
    fatfs::format_volume(&mut cursor, opts)
        .map_err(|e| Error::message(format!("fat format: {e}")))?;
    cursor.seek(SeekFrom::Start(0))?;
    {
        let fs = fatfs::FileSystem::new(&mut cursor, fatfs::FsOptions::new())
            .map_err(|e| Error::message(format!("fat open: {e}")))?;
        for (path, data) in files {
            place_file(&fs, path, data)?;
        }
    }
    Ok(cursor.into_inner())
}

fn place_file(fs: &fatfs::FileSystem<&mut Cursor<Vec<u8>>>, path: &str, data: &[u8]) -> Result<()> {
    let path = path.replace('\\', "/");
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return Err(Error::message("empty fat path"));
    }
    let mut prefix = String::new();
    for part in &parts[..parts.len() - 1] {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        fs.root_dir()
            .create_dir(&prefix)
            .map_err(|e| Error::message(format!("mkdir {prefix} in {path}: {e}")))?;
    }
    let mut file = fs
        .root_dir()
        .create_file(&path)
        .map_err(|e| Error::message(format!("create {path}: {e}")))?;
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

pub fn read_fat_file(volume: &[u8], path: &str) -> Result<Vec<u8>> {
    let mut owned = volume.to_vec();
    let cursor = Cursor::new(&mut owned);
    let fs = fatfs::FileSystem::new(cursor, fatfs::FsOptions::new())
        .map_err(|e| Error::message(format!("fat read open: {e}")))?;
    let path = path.replace('\\', "/");
    let mut file = fs
        .root_dir()
        .open_file(&path)
        .map_err(|e| Error::message(format!("open {path}: {e}")))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
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
