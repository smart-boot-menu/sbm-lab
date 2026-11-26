# Testing

Unit tests do not start QEMU:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

The UEFI probe is a separate package:

```bash
cargo build --manifest-path fixtures/efi-probe/Cargo.toml --release \
  --target x86_64-unknown-uefi --target aarch64-unknown-uefi
```

## Smoke

```bash
sbm-lab test --tier smoke
```

| Scenario | Pass condition |
| --- | --- |
| `x86_64-efi-launch` | Probe launches, GOP is ready, three EFI names are discovered, a key is received, and the QMP PPM is not a flat color. |
| `aarch64-efi-launch` | Probe launches, both fixture disks are identified, and either the QMP or the guest PPM has pixel variance. |
| `aarch64-chainload` | The payload prints `chainload-ok`. The fixture backing hash is checked again, which is the disk-reset check. |

## Product

```bash
sbm-lab test --tier product
sbm-lab test --id sbm-uefi-menu-x86_64
```

`sbm-uefi-menu-x86_64` and `sbm-uefi-menu-aarch64` boot the real SBM menu, require `menu_ready`, inject `c`, require `fixture_started` and `chainload_returned`, read the handoff JSON and `chainload-ok.txt` from the disposable ESP, and reset the machine until `menu_ready` appears again. The pass condition is those markers and files. The screenshot only has to be a non-blank PPM. The payload class in the report is `synthetic-fixture` unless a Core UKI was attached.

`sbm-uefi-menu-x86_64-online` is the same menu with a user-mode NIC. Policy keeps remote selection off, so the serial marker is `remote disabled`.

`sbm-core-x86_64`, `sbm-core-x86_64-offline`, and `sbm-core-aarch64-offline` run only when a PE UKI larger than 256 KiB whose name contains `core` or `uki` is found under `../sbm-core/image`, `../sbm-core/build`, or `var/artifacts`. They then expect `Linux version`, `SBM_UI_READY`, and `SBM_SMOKE_DONE`. The smoke script in sbm-core is what launches GParted. Until that UKI exists these three scenarios are skipped.

## Secure Boot

```bash
sbm-lab setup --secure-boot
sbm-lab test --tier secure
```

This tier is not part of `smoke` or `product`. It enrolls the lab development keys and checks three boots: the signed probe launches, the unsigned probe is denied, and a signed probe with one flipped byte is denied. The denial string observed on 2026-11-26 was `Access Denied`. Ubuntu OVMF can print that line without an `edk2-` banner. The scenario passes when `efi-launched` is forbidden and the serial contains `Access Denied` or `Security Violation`. The generic `guest did not emit efi-launched` result does not keep that scenario failed.

## Builder

```bash
sbm-lab setup --build-vm
sbm-lab test --id linux-dev-ready
```

The guest must print `SBM-LAB-MARKER:build-vm-ready`. The cloud image's hash is checked before and after.

## Full and fault

`sbm-lab test --tier full` covers Secure Boot observation, swtpm attachment, U-Boot and IA32 and SeaBIOS banners, virtio GPU, offline discovery, and USB attachment. Secure Boot, IA32, and SeaBIOS scenarios pass on safety plus a serial banner. They do not claim key enforcement or an IA32 lab probe.

`sbm-lab test --tier fault` kills the guest after `journal-begin`, injects virtio read errors, drops the NIC, delays the NIC, and boots the corrupt-config, missing-boot, broken-vars, and low-memory cases. The broken variable store is the per-run copy.

`scripts/smoke.sh` builds the release CLI and both probe targets, then runs the smoke tier.

## CI

GitHub Actions runs fmt, clippy, and unit tests, then three QEMU jobs on `ubuntu-latest`: smoke, product, and secure. Missing `/dev/kvm` is not a failure. x86 uses KVM when the device opens and TCG otherwise. aarch64 on an x86 runner is TCG and uses `-cpu cortex-a57`. Same-architecture TCG stays on `-cpu max`. A guest architecture that does not match the host gets a timeout of at least 720 seconds. The product job checks out `sbm-uefi` at `sbm-uefi-src` so it can boot the published EFI artifacts. A failed job uploads the serial log, QEMU stderr, and `result.json`.
