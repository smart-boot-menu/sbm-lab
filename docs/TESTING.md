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

## Full and fault

`sbm-lab test --tier full` covers Secure Boot observation, swtpm attachment, U-Boot and IA32 and SeaBIOS banners, virtio GPU, offline discovery, and USB attachment. Secure Boot, IA32, and SeaBIOS scenarios pass on safety plus a serial banner. They do not claim key enforcement or an IA32 lab probe.

`sbm-lab test --tier fault` kills the guest after `journal-begin`, injects virtio read errors, drops the NIC, delays the NIC, and boots the corrupt-config, missing-boot, broken-vars, and low-memory cases. The broken variable store is the per-run copy.

`scripts/smoke.sh` builds the release CLI and both probe targets, then runs the smoke tier.

## CI

The required GitHub job runs fmt, clippy, and unit tests, then a QEMU smoke on `ubuntu-latest`. Missing `/dev/kvm` is not a failure. x86 uses KVM when the device opens and TCG otherwise. aarch64 on an x86 runner is TCG. That job is the nested-virt fallback.
