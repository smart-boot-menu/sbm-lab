# `os-autoinst` Linux CI Prototype (Experimental)

This directory prototypes [`os-autoinst`](https://github.com/os-autoinst/os-autoinst) (`isotovideo:qemu-kvm`) in Linux CI as an evaluation candidate for replacing the custom QEMU/QMP test-orchestration logic in `sbm-lab` (`run.rs`, `qmp.rs`, `markers.rs`, `integration.rs`) per [ADR-010](https://github.com/smart-boot-menu/docs/blob/main/architecture-decisions/ADR-010-open-source-reuse-and-engineering-principles.md).

## Status

- **Experimental prototype only.** All existing `sbm-lab` tiers (`smoke`, `product`, `secure`, `integration`) remain preserved and authoritative until `os-autoinst` demonstrates equivalent or better coverage, reliability, and maintainability.
- **No full Linux image builds.** The prototype boots the tiny `fixtures/efi-probe` UEFI binary on a disposable 48 MiB GPT + FAT32 disk image under OVMF/KVM, asserts `SBM-LAB-MARKER:*` serial milestones via `wait_serial`, and captures a framebuffer screenshot via `save_screenshot`.
- **Offline by default.** `NICTYPE=none` ensures the guest boots with no virtual network interface.

## Layout

- `main.pm` — `os-autoinst` test schedule entry point.
- `tests/uefi_probe_smoke.pm` — UEFI/OVMF serial marker and screenshot check.
- `needles/` — Placeholder directory for future visual needle JSON/PNG assertions (e.g., SBM UEFI menu and `sbm-ui` screens).
- `.github/workflows/os-autoinst-prototype.yml` — Triggered manually (`workflow_dispatch`) or when files under `prototypes/os-autoinst/` change.
