# Limitations

Verified on the Apple M5 dev Mac with QEMU 11.1.3 on 2026-11-26:

- `qemu-system-aarch64 -accel help` lists `hvf` and `tcg`. `qemu-system-x86_64 -accel help` lists only `tcg`. The lab refuses to treat HVF as an x86 accelerator on this host.
- The firmware banner that actually boots is `edk2-stable202408-prebuilt.qemu.org`. ADR-008 names `edk2-stable202611`. The lab records the banner it observed. A newer firmware can be dropped in through `SBM_LAB_FIRMWARE` or `var/firmware`.
- x86 OVMF code is 3,653,632 bytes and the variable template is 540,672 bytes. They are used as a split pflash pair and are not padded.
- Headless screenshots are QMP `screendump` PPM files. This QEMU has no VNC display. `--graphical` is `cocoa`.
- U-Boot `v2026.10` `qemu_arm64` builds with `CONFIG_EFI_LOADER=y` when GNU make and `aarch64-elf-gcc` are installed. The binary is gitignored under `var/firmware`. On this host QEMU 11.1.3 HVF aborts inside `hvf_handle_exception` before U-Boot prints a banner, so the `uboot-efi` profile uses TCG.
- swtpm is 0.10.2. The TPM scenario attaches it and does not check PCRs.

Partial, and labeled that way in the scenarios:

- Secure Boot firmware comes up without enrolled keys. An unsigned probe can still launch. The lab does not claim enforcement.
- There is no `i686-unknown-uefi` probe. IA32 tests stop at the firmware shell unless the caller passes a PE whose machine is `0x14C`.
- Legacy BIOS expects a SeaBIOS banner and does not run the UEFI probe.
- NTFS, Btrfs, and LUKS1 fixtures are synthetic headers. LUKS is not unlockable. There is no Windows image and no Apple disk image.
- `setup --build-vm` downloads and hashes the Ubuntu noble cloud image. `run linux-dev` does not boot that image yet.
- SBM UEFI and SBM Core images are picked up with `--efi`, `--core`, or `artifacts scan` when those builds exist. The smoke tier uses the lab probe when they do not.
- Recovery of a full Linux guest is not part of this harness. The chainload check starts the lab payload.
