# Limitations

Verified on the Apple M5 dev Mac with QEMU 11.1.3 on 2026-11-26:

- `qemu-system-aarch64 -accel help` lists `hvf` and `tcg`. `qemu-system-x86_64 -accel help` lists only `tcg`. The lab refuses to treat HVF as an x86 accelerator on this host.
- The firmware banner that actually boots is `edk2-stable202408-prebuilt.qemu.org`. ADR-008 names `edk2-stable202611`. The lab records the banner it observed. A newer firmware can be dropped in through `SBM_LAB_FIRMWARE` or `var/firmware`.
- x86 OVMF code is 3,653,632 bytes and the variable template is 540,672 bytes. They are used as a split pflash pair and are not padded.
- Headless screenshots are QMP `screendump` PPM files. This QEMU has no VNC display. `--graphical` is `cocoa`.
- U-Boot `v2026.10` `qemu_arm64` builds with `CONFIG_EFI_LOADER=y` when GNU make and `aarch64-elf-gcc` are installed. The binary is gitignored under `var/firmware`. On this host QEMU 11.1.3 HVF aborts inside `hvf_handle_exception` before U-Boot prints a banner, so the `uboot-efi` profile uses TCG.
- swtpm is 0.10.2. The TPM scenario attaches it and does not check PCRs.

Partial, and labeled that way in the scenarios:

- `x86_64-uefi-secure-boot` still boots the firmware's own variable template, which is not key-enrolled. Enforcement is the separate `x86_64-secure-enrolled` profile, created by `sbm-lab setup --secure-boot`. Those keys are development keys.
- There is no `i686-unknown-uefi` probe. IA32 tests stop at the firmware shell unless the caller passes a PE whose machine is `0x14C`.
- Legacy BIOS expects a SeaBIOS banner and does not run the UEFI probe.
- NTFS, Btrfs, and LUKS1 fixtures are synthetic headers. LUKS is not unlockable. There is no Windows image and no Apple disk image.
- `setup --build-vm` downloads and hashes the Ubuntu noble cloud image. `run linux-dev` and `test --id linux-dev-ready` boot an overlay of that image, or of the Fedora cloud qcow2 already built under `sbm-core`, and wait for `build-vm-ready`. The lab does not run mkosi.
- The smoke tier uses the lab probe. `test --tier product` boots `../sbm-uefi/artifacts/sbm-*.efi`. Without an SBM Core UKI the recovery payload is the SBM fixture EFI, and the Core scenarios are skipped. A skip is not a boot of Linux, the management shell, or GParted.
- Guest RAM is admitted through one per-user ledger. On this 16 GiB Mac an 8192 MiB guest does not fit. A typed `qemu-system-*` command still starts, and `sbm-lab resources doctor` reports it as unmanaged. The ledger does not kill that process. See [RESOURCES.md](RESOURCES.md).
