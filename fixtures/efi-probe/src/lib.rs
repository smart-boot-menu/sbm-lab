#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use uefi::boot::{self, LoadImageSource};
use uefi::fs::FileSystem;
use uefi::proto::console::gop::{BltOp, BltPixel, GraphicsOutput};
use uefi::proto::media::fs::SimpleFileSystem;

pub fn emit(text: &str) {
    let mut line = String::from(text);
    if !line.ends_with('\n') {
        line.push_str("\r\n");
    }
    write_console(line.as_bytes());
    if let Ok(cstr) = uefi::CString16::try_from(line.as_str()) {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.output_string(&cstr);
        });
    }
}

pub fn marker(text: &str) {
    emit(&format!("SBM-LAB-MARKER:{text}"));
}

pub fn run() {
    let mut log = String::new();
    note(&mut log, "uefi-entry");
    note(&mut log, "efi-launched");
    draw(&mut log);
    discover(&mut log);
    if file_exists("\\EFI\\sbm-lab\\auto-chainload") {
        note(&mut log, "chainload-start");
        if chainload("\\EFI\\sbm-lab\\payload.efi") {
            note(&mut log, "chainload-ok");
        }
    }
    if file_exists("\\EFI\\sbm-lab\\journal-loop") {
        note(&mut log, "journal-begin");
        journal();
    }
    if file_exists("\\EFI\\sbm-lab\\wait-key") {
        note(&mut log, "waiting-for-key");
        boot::stall(Duration::from_millis(500));
        poll_key(&mut log);
    }
    note(&mut log, "halt");
    let _ = write_boot("\\EFI\\sbm-lab\\result.txt", log.as_bytes());
    boot::stall(Duration::from_millis(300));
}

fn note(log: &mut String, text: &str) {
    marker(text);
    log.push_str("SBM-LAB-MARKER:");
    log.push_str(text);
    log.push_str("\r\n");
}

fn draw(log: &mut String) {
    let Ok(handle) = boot::get_handle_for_protocol::<GraphicsOutput>() else {
        note(log, "gop-missing");
        return;
    };
    let Ok(mut gop) = boot::open_protocol_exclusive::<GraphicsOutput>(handle) else {
        note(log, "gop-missing");
        return;
    };
    let (width, height) = gop.current_mode_info().resolution();
    let band = height.min(64).max(1);
    let _ = gop.blt(BltOp::VideoFill {
        color: BltPixel::new(20, 90, 220),
        dest: (0, 0),
        dims: (width.max(1), band),
    });
    note(log, &format!("gop-ready width={width} height={height}"));
    let ppm = tiny_ppm();
    let _ = write_boot("\\EFI\\sbm-lab\\gop.ppm", &ppm);
}

fn tiny_ppm() -> Vec<u8> {
    let mut ppm = b"P6\n8 8\n255\n".to_vec();
    for _ in 0..(8 * 8) {
        ppm.extend_from_slice(&[20, 90, 220]);
    }
    ppm
}

fn discover(log: &mut String) {
    let Ok(handles) = boot::find_handles::<SimpleFileSystem>() else {
        note(log, "discovery-done count=0");
        return;
    };
    let mut count = 0u32;
    let mut titles = Vec::new();
    for handle in handles {
        let Ok(proto) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let mut fs = FileSystem::new(proto);
        if let Some(id) = read_text(&mut fs, "\\EFI\\sbm-lab\\disk-id.txt") {
            let id = id.trim();
            note(log, &format!("disk-id id={id}"));
            if id.contains("missing-boot") {
                note(log, "note id=missing-boot");
            }
        }
        if let Some(policy) = read_text(&mut fs, "\\EFI\\sbm\\policy.json") {
            let trimmed = policy.trim_start();
            if !trimmed.starts_with('{') || !policy.contains("\"version\"") {
                note(log, "config-invalid");
            }
        }
        if let Some(catalog) = read_text(&mut fs, "\\EFI\\sbm-lab\\catalog.txt") {
            let mut seen = Vec::new();
            for line in catalog.lines() {
                let line = line.trim();
                if seen.contains(&line) && !line.is_empty() {
                    note(log, &format!("duplicate-boot-entry id={line}"));
                }
                seen.push(line);
            }
        }
        for name in ["\\loader\\entries\\a.conf", "\\loader\\entries\\b.conf"] {
            if let Some(text) = read_text(&mut fs, name) {
                for line in text.lines() {
                    if let Some(title) = line.strip_prefix("title ") {
                        if titles.iter().any(|existing: &String| existing == title) {
                            note(log, &format!("duplicate-boot-entry id={title}"));
                        }
                        titles.push(String::from(title));
                    }
                }
            }
        }
        if let Some(manifest) = read_text(&mut fs, "\\EFI\\sbm-lab\\manifest.txt") {
            for line in manifest.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let path = format!("\\{}", line.replace('/', "\\"));
                if path.ends_with(".efi") && exists(&mut fs, &path) {
                    note(log, &format!("boot-target path={path}"));
                    count += 1;
                }
            }
        }
    }
    note(log, &format!("discovery-done count={count}"));
}

fn read_text(fs: &mut FileSystem, path: &str) -> Option<String> {
    let path = uefi_path(path)?;
    fs.read_to_string(&*path).ok()
}

fn exists(fs: &mut FileSystem, path: &str) -> bool {
    uefi_path(path)
        .and_then(|path| fs.try_exists(&*path).ok())
        .unwrap_or(false)
}

fn uefi_path(path: &str) -> Option<uefi::CString16> {
    uefi::CString16::try_from(path).ok()
}

fn file_exists(path: &str) -> bool {
    with_boot_fs(|fs| exists(fs, path)).unwrap_or(false)
}

fn write_boot(path: &str, bytes: &[u8]) -> bool {
    let Some(uefi) = uefi_path(path) else {
        return false;
    };
    with_boot_fs(|fs| fs.write(&*uefi, bytes).is_ok()).unwrap_or(false)
}

pub fn write_payload_result() -> bool {
    write_boot(
        "\\EFI\\sbm-lab\\payload-result.txt",
        b"SBM-LAB-MARKER:chainload-ok\r\n",
    )
}

fn with_boot_fs<T>(body: impl FnOnce(&mut FileSystem) -> T) -> Option<T> {
    let handles = boot::find_handles::<SimpleFileSystem>().ok()?;
    for handle in handles {
        let Ok(proto) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let mut fs = FileSystem::new(proto);
        if read_text(&mut fs, "\\EFI\\sbm-lab\\role.txt").is_some_and(|role| role.contains("probe"))
        {
            return Some(body(&mut fs));
        }
    }
    None
}

fn chainload(path: &str) -> bool {
    let Some(uefi) = uefi_path(path) else {
        return false;
    };
    let Some(bytes) = with_boot_fs(|fs| fs.read(&*uefi).ok()) else {
        return false;
    };
    let Some(bytes) = bytes else {
        return false;
    };
    let Ok(image) = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromBuffer {
            buffer: &bytes,
            file_path: None,
        },
    ) else {
        return false;
    };
    boot::start_image(image).is_ok()
}

fn journal() {
    for n in 0..80 {
        let name = format!("\\EFI\\sbm-lab\\journal-{n}.bin");
        let _ = write_boot(&name, &[b'J'; 1024]);
        boot::stall(Duration::from_millis(100));
    }
}

fn poll_key(log: &mut String) {
    for _ in 0..80 {
        boot::stall(Duration::from_millis(50));
        let key = uefi::system::with_stdin(|stdin| stdin.read_key());
        if let Ok(Some(key)) = key {
            note(log, &format!("key-received key={key:?}"));
            return;
        }
    }
}

fn write_console(bytes: &[u8]) {
    for &byte in bytes {
        unsafe { write_console_byte(byte) }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_console_byte(byte: u8) {
    // SAFETY: the lab attaches QEMU isa-debugcon at I/O port 0x402 for x86
    // guests. `out` writes one byte to that device and does not touch memory.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x402u16,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn write_console_byte(byte: u8) {
    // SAFETY: QEMU's virt machine maps a PL011 UART at 0x0900_0000. The lab
    // captures that UART as the serial socket. The flag register is checked
    // so a full FIFO does not spin forever.
    unsafe {
        let uart = 0x0900_0000 as *mut u32;
        let mut spins = 0;
        while core::ptr::read_volatile(uart.add(6)) & (1 << 5) != 0 && spins < 10_000 {
            spins += 1;
            core::hint::spin_loop();
        }
        if spins < 10_000 {
            core::ptr::write_volatile(uart, u32::from(byte));
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn write_console_byte(_byte: u8) {}
