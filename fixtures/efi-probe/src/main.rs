#![no_std]
#![no_main]

use uefi::prelude::*;

#[entry]
fn main() -> Status {
    let _ = uefi::helpers::init();
    efi_probe::run();
    Status::SUCCESS
}
