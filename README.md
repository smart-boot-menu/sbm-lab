# Virtual Hardware, Benchmarks & Integration Testing (`sbm-lab`)

`sbm-lab` boots disposable QEMU machines so other Smart Boot Menu agents can test UEFI and SBM Core artifacts without touching the host disk or the Mac boot configuration. Destructive storage tests use QCOW2 overlays. Golden images and firmware variable templates are hashed before and after every run.

The Apple Silicon U-Boot EFI probe is a separate script, not this harness. QEMU `virt` is not an Apple Silicon Mac. See [scenarios/exp-as-ext01-phase1.md](scenarios/exp-as-ext01-phase1.md).

Installer ISO boots stay in `sbm-catalog/tools/boot-installer.sh`. This harness does not grow a host-disk path for them. See [docs/installer-boot.md](docs/installer-boot.md).

## Commands other agents should use

```bash
cargo run -p sbm-lab -- doctor
cargo run -p sbm-lab -- setup
cargo run -p sbm-lab -- list
cargo run -p sbm-lab -- run aarch64-uefi --efi path/to/app.efi
cargo run -p sbm-lab -- test --tier smoke
cargo run -p sbm-lab -- benchmark --profile aarch64-uefi --runs 10 --output bench.json
```

The full contract is [docs/CLI.md](docs/CLI.md). Profiles are [docs/PROFILES.md](docs/PROFILES.md). Disk fixtures are [docs/FIXTURES.md](docs/FIXTURES.md). What is verified, and what is still partial, is [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## What a run does

1. Selects HVF or KVM only when the guest architecture matches the host and that QEMU binary lists the accelerator. Otherwise it uses TCG. On this Apple Silicon Mac, x86 guests are TCG.
2. Copies the firmware variable store. The template file is never written.
3. Builds a per-run probe disk and QCOW2 overlays of the requested fixtures.
4. Boots headless, reads `SBM-LAB-MARKER:` lines from the serial console, and can capture a QMP PPM screenshot.
5. Re-hashes the firmware code, the variable template, and the fixture backing files. A change fails the run.

## Layout

- `crates/sbm-lab` — the CLI.
- `fixtures/efi-probe` — the UEFI probe and chainload payload. It is outside the default Cargo workspace.
- `profiles/` and `scenarios/` — machine and test definitions.
- `firmware/sources.toml` — pinned U-Boot source URL and SHA-256.
- `var/` — gitignored firmware, fixtures, and run state.

## License

Original code and documentation in this repository are dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). QEMU is invoked as a subprocess and is not linked.
