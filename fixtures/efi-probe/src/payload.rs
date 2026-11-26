#![no_std]
#![no_main]

use uefi::prelude::*;

#[entry]
fn main() -> Status {
    let _ = uefi::helpers::init();
    efi_probe::marker("chainload-ok");
    let _ = efi_probe::write_payload_result();
    Status::SUCCESS
}
