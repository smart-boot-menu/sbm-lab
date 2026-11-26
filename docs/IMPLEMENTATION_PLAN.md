# sbm-lab implementation plan

Status: implemented for SBM 0.1. The plan below is the record of the decisions made before the harness code. Current commands and limits are in [CLI.md](CLI.md) and [LIMITATIONS.md](LIMITATIONS.md).

## What this repository owns

A Rust CLI, `sbm-lab`, that builds disposable QEMU machines, golden QCOW2 fixtures, and machine-readable run reports. Production boot-manager code stays in `sbm-uefi` and `sbm-core`.

## Host facts the plan is built on

Verified on the Apple M5 dev Mac (2026-11-26), not assumed:

- `qemu-system-aarch64` 11.1.3 advertises `hvf` and `tcg`. `kern.hv_support` is 1. Same-architecture ARM64 guests use HVF.
- `qemu-system-x86_64` 11.1.3 advertises only `tcg`. HVF is not used for x86 guests. TCG results are labeled emulation and are not treated as physical-hardware performance.
- Homebrew QEMU's OVMF banner is `edk2-stable202408-prebuilt.qemu.org`. ADR-008 names `edk2-stable202611` as the project pin. The lab boots the firmware it actually finds, records the banner, and accepts a drop-in newer tree under `var/firmware/`. It does not claim the ADR pin until that banner is observed.
- x86 code and variable-store images are different sizes (3,653,632 and 540,672 bytes) and boot as a split pflash pair. The lab copies the variable template per run and does not resize it.
- `-display none` plus the default VGA device accepts QMP `screendump` (PPM). This QEMU build has no VNC display backend. Graphical mode uses `cocoa` on macOS.
- `swtpm` 0.10.2 is installed. U-Boot `v2026.10` is built with GNU make and `aarch64-elf-gcc`. BSD `make` cannot build U-Boot.

## Layout

- `crates/sbm-lab` — CLI and library.
- `fixtures/efi-probe` — tiny UEFI probe and chainload payload (`uefi` 0.41), not part of the default Cargo workspace, so host `cargo test` does not try to link it for macOS.
- `profiles/*.toml`, `scenarios/*.toml` — machine and test definitions other agents can read.
- `var/` — gitignored firmware cache, fixture images, and per-run state. Run directories include a short id, a copied variable store, and a QCOW2 overlay. Golden images are never opened writable.
- `firmware/sources.toml` — pinned U-Boot source URL and SHA-256.

## Acceleration

`auto` selects HVF or KVM only when the guest architecture equals the host and the accelerator is listed by that QEMU binary. Otherwise it selects TCG. Explicit `--accel hvf` on an x86 guest on this Mac is an error, not a silent fallback.

## Fixtures

Pure-Rust GPT + FAT32 for ESP layouts. ext4 uses `mkfs.ext4` when present. NTFS, Btrfs, and LUKS1 fixtures are identifiable synthetic volumes; the manifest says whether they were made by a real mkfs or by a header writer. Windows-like and Apple-style disks carry an in-image banner that they are not those operating systems. No proprietary OS image is downloaded.

## Tests and benchmarks

Smoke tests boot the probe, require serial markers, and on x86 require a QMP screenshot. Fault tests run only against overlays. Benchmark JSON records `execution_class` and sets `representative_of_physical_hardware` to false for every virtual run. `methodology_complete` is true only when `N >= 10`.

## CI

GitHub-hosted `ubuntu-latest` runs unit tests and a TCG/KVM smoke test. Missing `/dev/kvm` is not a failure. The lab does not pass through host disks.

## Out of scope for this pass

Rewriting EDK2, enrolling production Secure Boot keys, booting a full Fedora `sbm-core` image (the hook exists; the image is Agent 02's), and any change to the physical Mac boot configuration.
