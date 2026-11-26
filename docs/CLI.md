# sbm-lab CLI

`sbm-lab` is the command other agents use to boot a virtual machine, inject an EFI binary, and read a JSON report. `--json` prints the report on stdout. Human text and QEMU errors go to stderr. Exit status is 0 for success and 1 for a failed check.

```bash
sbm-lab [--root PATH] [--json] <command>
```

`--root` overrides discovery. Without it, the tool uses `SBM_LAB_ROOT` or walks upward until it finds `profiles/` next to a `Cargo.toml` that names `sbm-lab`.

## doctor

Reports QEMU, qemu-img, swtpm, advertised accelerators, and the firmware pair that would boot. Exit 1 when either QEMU system binary, qemu-img, or a firmware image is missing. A missing swtpm or U-Boot binary is a warning.

## setup

```bash
sbm-lab setup                  # probe, fixtures, and U-Boot
sbm-lab setup --probe
sbm-lab setup --fixtures
sbm-lab setup --uboot
sbm-lab setup --build-vm
sbm-lab setup --secure-boot
```

`--probe` cross-compiles `fixtures/efi-probe` for `x86_64-unknown-uefi` and `aarch64-unknown-uefi`. `--fixtures` writes `var/fixtures/<id>.qcow2`. `--uboot` downloads the tarball pinned in `firmware/sources.toml`, checks its SHA-256, and builds `var/firmware/u-boot-qemu-arm64.bin` with GNU make. On macOS the host compiler is passed as `HOSTCC=clang -I<openssl>/include` because the U-Boot makefile overrides an environment `HOSTCC`. `--build-vm` downloads the Ubuntu noble cloud image named in `firmware/sources.toml` and checks it against `SHA256SUMS`. The image stays in `var/build-vm`. `--secure-boot` writes development PK, KEK, and db keys under `var/secure-boot`, enrolls them into a copy of the OVMF variable template, and signs the x86_64 probe with `osslsigncode`. Those keys are not production keys.

## list

```bash
sbm-lab list
sbm-lab list --profiles --fixtures --scenarios --artifacts --runs
```

## run

```bash
sbm-lab run <profile> [options]
```

| Option | Meaning |
| --- | --- |
| `--efi PATH` | Boot this PE image instead of the lab probe. The PE machine must match the profile. |
| `--core PATH` | Copy an SBM Core image to `EFI/Linux/sbm-core.efi` on the probe disk. |
| `--fixture ID` | Use this fixture instead of the profile's disk list. |
| `--disk PATH` | Attach an extra raw or qcow2 file. Paths under `/dev` and paths containing a comma are rejected. |
| `--secure-boot` | Select the Secure Boot firmware pair. |
| `--tpm` | Start swtpm and attach it. |
| `--graphical` / headless is the default | `--graphical` uses the `cocoa` display on macOS. |
| `--network user\|none\|slow` | Default comes from the profile. `slow` inserts a local delaying proxy. |
| `--timeout SECS` | Default 180. |
| `--keep` | Keep the probe disk, overlays, and variable copy after success. |
| `--keep-failed` | Keep them after failure. |
| `--memory MIB` / `--cpus N` | Clamped by `SBM_LAB_MAX_MEMORY_MIB` (8192) and `SBM_LAB_MAX_CPUS` (4). |
| `--screenshot PATH` | Copy the QMP PPM here. |
| `--key QCODE` | Inject this QEMU key. The probe waits for `waiting-for-key`. An SBM menu profile waits for `menu_ready`. `ret` is Return and `c` is the recovery key. |
| `--chainload` | Place the lab payload on the probe disk and ask the probe to start it. |
| `--no-probe` | Do not build the probe disk. |

A run exits 0 when the guest emits `efi-launched` or a firmware banner, the safety hashes match, and QEMU did not fail first. Scenario assertions are `sbm-lab test`.

The report schema is `sbm-lab.run.v1`. Fields agents can rely on:

- `accel`, `execution_class` (`accelerated_virtualization` or `emulation`)
- `representative_of_physical_hardware` (always false)
- `firmware_banner`
- `markers` (text after `SBM-LAB-MARKER:`)
- `boot_targets`
- `screenshot`, `guest_screenshot`
- `stages_ms` (host milliseconds until each marker was first seen)
- `safety.backing_hashes_unchanged`, `safety.firmware_template_unchanged`

## test

```bash
sbm-lab test --tier smoke
sbm-lab test --tier full
sbm-lab test --tier fault
sbm-lab test --tier product
sbm-lab test --tier secure
sbm-lab test --tier builder
sbm-lab test --tier all
sbm-lab test --id sbm-uefi-menu-x86_64
sbm-lab test --tier smoke --efi path/to/app.efi
```

`smoke` is the default. `--id` runs that scenario and does not apply the tier filter. A scenario that needs U-Boot, swtpm, a build-VM image, or an SBM Core UKI is skipped, not failed, when that input is absent. A missing SBM UEFI menu binary fails the product scenario. See [TESTING.md](TESTING.md).

## benchmark

```bash
sbm-lab benchmark --profile aarch64-uefi --runs 3 --output bench.json
```

Each sample is host milliseconds until `efi-launched`. The schema is `sbm-lab.benchmark.v1`. `methodology_complete` is true only when `--runs` is at least 10. The default of 3 is a smoke sample, not a benchmark. Every virtual sample sets `representative_of_physical_hardware` to false. TCG numbers are not physical x86 performance.

## screenshot

```bash
sbm-lab screenshot --profile aarch64-uefi --output frame.ppm
```

## clean

```bash
sbm-lab clean                 # var/runs
sbm-lab clean --fixtures      # also var/fixtures
sbm-lab clean --firmware      # also var/firmware, not the system QEMU firmware
sbm-lab clean --all
sbm-lab clean --stop          # SIGKILL processes whose command line contains this repo's var/runs
```

## fault

```bash
sbm-lab fault power-loss
sbm-lab fault io-error
sbm-lab fault net-down
sbm-lab fault slow-net
sbm-lab fault corrupt-config
sbm-lab fault missing-boot
sbm-lab fault broken-vars
sbm-lab fault low-memory
```

Faults apply to the overlay or to the per-run variable copy. The backing image and the variable template are checked afterward.

## artifacts

```bash
sbm-lab artifacts scan
sbm-lab artifacts fetch --repo smart-boot-menu/sbm-uefi --tag vX.Y.Z --asset NAME.efi
```

`scan` looks in `$SBM_LAB_ARTIFACTS`, `var/artifacts`, `var/artifacts/pinned`, and the sibling `sbm-uefi`, `sbm-core`, and `install` build directories. `fetch` runs `gh release download` into `var/artifacts/pinned/<repo>/<tag>/` and writes a `.sha256` file beside the asset. Tests do not download artifacts.

## Marker contract

The probe, and any EFI an agent wants the harness to assert on, prints lines of the form:

```text
SBM-LAB-MARKER:efi-launched
SBM-LAB-MARKER:gop-ready width=800 height=600
SBM-LAB-MARKER:boot-target path=\EFI\sbm-lab\alpha.efi
SBM-LAB-MARKER:discovery-done count=4
SBM-LAB-MARKER:disk-id id=multi-efi
SBM-LAB-MARKER:config-invalid
SBM-LAB-MARKER:duplicate-boot-entry id=Synthetic Linux A
SBM-LAB-MARKER:note id=missing-boot
SBM-LAB-MARKER:waiting-for-key
SBM-LAB-MARKER:key-received key=Printable(...)
SBM-LAB-MARKER:chainload-start
SBM-LAB-MARKER:chainload-ok
SBM-LAB-MARKER:journal-begin
SBM-LAB-MARKER:halt
```

The same text is written to `EFI/sbm-lab/result.txt` on the probe disk. The harness reads that file back from the raw image. A guest GOP image may also be written to `EFI/sbm-lab/gop.ppm`.

## Resource limits

`sbm-lab run` and `sbm-lab test` take a reservation from the shared ledger before QEMU starts. The per-checkout slot files under `var/runs/.slot-N` still cap how many runs one checkout starts (`SBM_LAB_MAX_CONCURRENT`, default 2). They do not see another repo. The shared ledger does. `SBM_LAB_FIRMWARE` adds a firmware directory searched before the system QEMU paths.

```bash
sbm-lab resources status
sbm-lab resources doctor
sbm-lab resources reserve --workload efi --memory 1024 --cpus 1 --repo "$PWD"
sbm-lab resources attach --id ID --pid PID
sbm-lab resources release --id ID
sbm-lab resources run --workload linux --memory 2048 --cpus 2 --timeout 75 -- qemu-system-aarch64 ...
```

`doctor` exits 1 when memory pressure is critical, guest RAM is over the budget, a reservation is orphaned, or a QEMU process has no reservation. `status` always exits 0. `reserve` prints the id. `--owner` records the shell pid; helpers also export `SBM_OWNER_PID`. `release` deletes that record and does not signal QEMU. `--forget` deletes it while the process is still running. `run` kills only the command it started, and only while that pid still has the start time recorded at attach. SIGINT and SIGTERM kill that same pid.

The ledger is `~/Library/Application Support/sbm-lab` on macOS and `$XDG_STATE_HOME/sbm-lab` elsewhere. `SBM_LAB_RUNTIME` overrides it. Details, the measured budget, and the launchers that used to skip the lab are in [RESOURCES.md](RESOURCES.md).
