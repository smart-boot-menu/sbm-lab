# sbm-lab handoff

The CLI boots disposable QEMU machines. Smoke tests inject the lab UEFI probe. Product tests boot the real SBM UEFI menu from `../sbm-uefi/artifacts`. Nothing here passes through a host disk or changes the Mac boot configuration.

## Reproduce

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo build --release
./target/release/sbm-lab test --tier smoke
./target/release/sbm-lab test --tier product
./target/release/sbm-lab setup --secure-boot
./target/release/sbm-lab test --tier secure
./target/release/sbm-lab test --id linux-dev-ready
```

`--id` runs one scenario and ignores the tier. `product` skips a scenario whose SBM Core UKI is not built. That skip is not a pass of the kernel, the management shell, or GParted.

The contract for the other agents is [docs/CLI.md](docs/CLI.md). Profiles and the limits of a pass are in [docs/PROFILES.md](docs/PROFILES.md), [docs/TESTING.md](docs/TESTING.md), and [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## What was measured on 2026-11-26

Host: Apple Silicon, QEMU 11.1.3. `qemu-system-aarch64 -accel help` lists `hvf` and `tcg`. `qemu-system-x86_64 -accel help` lists only `tcg`. The firmware banner on these runs is `edk2-stable202408-prebuilt.qemu.org`. ADR-008 names `edk2-stable202611`. That newer banner was not observed.

Smoke, after the `startup.nsh` change, still passed: `6b0897f0-42809-42264c9e63a9` (x86_64 TCG), `6b0897f5-42809-42264ca17c9a` (aarch64 HVF), `6b0897fc-42809-42264ca6881d` (aarch64 chainload).

Product menu, payload class `synthetic-fixture` (the SBM fixture EFI, not Linux):

| Run | Arch | Accel | Duration | menu_ready |
| --- | --- | --- | --- | --- |
| `6b0897a4-41995-42264c6f6837` | x86_64 | tcg | 8888 ms | 3778 ms |
| `6b0897eb-42773-42264c9b0a68` | x86_64, user NIC | tcg | 4786 ms | 4152 ms |
| `6b0897cd-42477-42264c8986e6` | aarch64 | hvf | 12294 ms | 5668 ms |

The x86 and aarch64 offline runs pressed `c`, saw `fixture_started` and `chainload_returned`, read `EFI/sbm/handoff/current.json` and `EFI/sbm/test/chainload-ok.txt` back off the disposable disk, then issued QMP `system_reset` and saw `menu_ready` a second time. The online run printed `remote disabled`. GOP on the x86 run was 1280x800. `representative_of_physical_hardware` is false.

Secure Boot, development keys only, separate from the menu test. All three are x86_64 TCG:

| Run | Result | Duration |
| --- | --- | --- |
| `6b0897cd-42472-42264c8986e3` | signed probe reached `efi-launched` | 5175 ms |
| `6b0897d2-42472-42264c8c9ff6` | unsigned probe, `Access Denied`, no `efi-launched` | 5197 ms |
| `6b0897d8-42472-42264c8f4a80` | signed probe with one byte flipped, `Access Denied`, no `efi-launched` | 5342 ms |

The profile `x86_64-uefi-secure-boot` is still the observe-only firmware. It is not the enrolled profile.

Build VM `6b0897eb-42774-42264c9b0a6b`: aarch64 HVF, 16401 ms, marker `build-vm-ready` at 13611 ms. The guest banner was `Fedora Linux (7.2.11-300.fc45.aarch64) 45 (Cloud Edition)`. The backing qcow2 hash was unchanged. This checkout had no `var/build-vm` image, so the lab used `../sbm-core/build/builder/Fedora-Cloud-Base-*.qcow2` through a per-run overlay and a NoCloud seed. `sbm-core/scripts/provision-builder.sh` is what runs inside that guest. The lab did not run mkosi.

## CI smoke

GitHub Actions run 45879871319 failed in the smoke job. x86_64 passed. `aarch64-efi-launch` and `aarch64-chainload` each ran to the 240 s timeout and reported `missing marker efi-launched`. On an x86 runner that guest is TCG. A cross-architecture boot now uses at least 720 s. The probe disk also contains `startup.nsh`, so a drop to the UEFI shell still starts the boot file. A failed smoke job uploads `serial.log`, `debugcon.log`, `qemu.stderr`, and `result.json`.

## Host resources

`sbm-lab resources` is the shared admission check for QEMU. The ledger is `~/Library/Application Support/sbm-lab` (`SBM_LAB_RUNTIME` overrides it), with an exclusive flock around each reserve. It is not a daemon. `resources release` does not signal QEMU. A guard inside `sbm-lab run` kills only the QEMU pid that run started.

On 2026-11-26 this Mac had 16384 MiB of physical RAM. While an 8192 MiB `qemu-system-aarch64 -name sbm-builder` was up, `kern.memorystatus_vm_pressure_level` was 2 and swap was 1968 of 3072 MiB. `sbm-core/scripts/host-resources.sh` records that the guest was idle near 533 MiB and the process still charged about 15 GB of physical footprint. The budget therefore counts each guest MiB twice and keeps at least 6 GiB for macOS. On a quiet 16 GiB host that leaves 5120 MiB of guest RAM. Warning pressure plus a half-full swap file leaves 3584 MiB. An 8192 MiB guest does not fit. EFI reservations are capped at 1024 MiB and 1 vCPU. The build workload stays at the 4096 MiB / 4 vCPU size that `linux-dev` already booted, with a 6144 MiB cap. Heavy workloads (graphical, build, ram) admit one at a time.

`sbm-lab run` reserves before it spawns QEMU. These launchers did not, and now call the same ledger: `sbm-uefi/crates/xtask/src/qemu.rs` (1024 MiB, 1 vCPU), `sbm-core/scripts/boot-smoke.sh`, `sbm-core/scripts/start-builder.sh`, `sbm-catalog/tools/boot-installer.sh` (2048 MiB, 2 vCPU), and `sbm-as/scripts/uboot-efi-poc.sh` (1024 MiB, 1 vCPU). `install` has no QEMU launcher. A QEMU command typed by hand is still invisible until `resources status` sees the process; it counts against the budget and is not killed.

## Isolation

Each run has its own directory under `var/runs/<id>`, its own variable-store copy, and its own qcow2 overlays. `var/fixtures/.lock` is an exclusive flock around fixture creation. Paths under `/dev`, block devices, and paths that contain a comma are rejected. Two agents should still use separate checkouts or `SBM_LAB_ROOT` if they need separate firmware and key directories. The enrolled Secure Boot keys live only in `var/secure-boot`.

## Catalog installer ISOs

`docs/installer-boot.md` points at `sbm-catalog/tools/boot-installer.sh`. That script is the path for Debian, openSUSE, and Fedora aarch64 installer logs. The lab launch plan still has no CD-ROM argument and still rejects `/dev` paths. Those installer runs are not lab scenario passes.

## Still open

- No SBM Core UKI was present. `sbm-core-x86_64`, `sbm-core-x86_64-offline`, and `sbm-core-aarch64-offline` skip. They expect `Linux version`, `SBM_UI_READY`, and `SBM_SMOKE_DONE` on serial, and they attach a 64 MiB scratch disk that is not a host disk. Those scenarios have not booted a kernel, a management shell, or GParted.
- The menu recovery payload in the measured product runs is the SBM fixture EFI. The files under `EFI/Microsoft`, `EFI/ubuntu`, `EFI/systemd`, and `EFI/Linux` are copies of that fixture. They are not Windows, Ubuntu, or Fedora.
- There is no IA32 build of the probe. NTFS, Btrfs, and LUKS1 fixtures are synthetic headers.
- U-Boot `v2026.10` with `CONFIG_EFI_LOADER=y` is `var/firmware/u-boot-qemu-arm64.bin`. `uboot-efi` forces TCG because QEMU 11.1.3 HVF aborts in `hvf_handle_exception` before U-Boot prints a banner.
