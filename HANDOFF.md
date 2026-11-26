# sbm-lab handoff

The CLI boots disposable QEMU machines, injects the lab UEFI probe, and checks QCOW2 overlays and firmware variable templates. It does not pass through host disks and it does not change the Mac boot configuration.

## Use these commands

```bash
cargo run -p sbm-lab -- doctor
cargo run -p sbm-lab -- setup
cargo run -p sbm-lab -- test --tier smoke
cargo run -p sbm-lab -- run aarch64-uefi --efi path/to/app.efi
cargo run -p sbm-lab -- benchmark --profile aarch64-uefi --runs 10 --output bench.json
```

The contract for Agents 01 and 02 is [docs/CLI.md](docs/CLI.md). Profiles, fixtures, and the limits of what a pass means are in [docs/PROFILES.md](docs/PROFILES.md), [docs/FIXTURES.md](docs/FIXTURES.md), and [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## What was measured

Host: Apple Silicon, QEMU 11.1.3, swtpm 0.10.2. `qemu-system-aarch64 -accel help` lists `hvf` and `tcg`. `qemu-system-x86_64 -accel help` lists only `tcg`. The firmware banner observed on both arches is `edk2-stable202408-prebuilt.qemu.org`. ADR-008 names `edk2-stable202611`. That newer banner was not observed. Numbers and run ids are in `research/validation/evidence/sbm-lab-2026-11-26.md`.

On 2026-11-26 the smoke tier passed: x86_64 TCG launch with a key and a QMP screenshot, aarch64 HVF discovery of two fixture disks, and an aarch64 chainload. `fault power-loss` and `fault corrupt-config` also passed. Every one of those runs left the fixture backing hash and the variable-store template unchanged.

A 10-run aarch64 HVF sample of host milliseconds until `efi-launched` is methodology-complete. p50 is 5525 ms, p95 is 5812 ms, min is 5508 ms, max is 5812 ms. `representative_of_physical_hardware` is false.

## Left for a later pass

- `setup --build-vm` downloads and hashes the Ubuntu noble cloud image. `run linux-dev` does not boot it.
- Secure Boot firmware is not key-enrolled. An unsigned probe can still launch.
- There is no IA32 build of the probe. The IA32 profile stops at the firmware shell.
- NTFS, Btrfs, and LUKS1 fixtures are synthetic headers.
- SBM UEFI and SBM Core images are accepted with `--efi` and `--core` when those builds exist. The smoke tier uses the lab probe.
- U-Boot `v2026.10` with `CONFIG_EFI_LOADER=y` builds into `var/firmware/u-boot-qemu-arm64.bin`. The separate Apple Silicon probe script is [scripts/run-uboot-efi-probe.sh](scripts/run-uboot-efi-probe.sh). QEMU `virt` is not an Apple Silicon Mac, and that probe's passing accelerator on this host was TCG after HVF aborted.
