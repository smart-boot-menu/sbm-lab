# Virtual Hardware, Benchmarks & Integration Testing (`sbm-lab`)

Automated QEMU (`x86_64` + `aarch64`), EDK2 OVMF/AAVMF, Das U-Boot `qemu_arm64`, and `swtpm` virtual hardware lab, golden QCOW2 disk fixtures, benchmarks, and fault-injection suites.

> **Project Status:** Phase 0 initialized — ready for dedicated engineering agent implementation targeting **SBM 0.1**.

## Scope & Responsibilities

- Reproducible Rust integration harness running `sbm-uefi`, `sbm-core`, `sbm-server`, `install`, and `sbm-agent` end-to-end across OVMF (standard + Secure Boot), AAVMF, and U-Boot `qemu_arm64`.
- Native-speed ARM64 virtualization (`-accel hvf` on M5 Mac; `-accel kvm` on Linux CI) + TCG fallback.
- Golden QCOW2 disk fixtures (Windows/BitLocker, multi-Linux BLS/UKI, Apple-protected guardrails, corrupt GPT).
- QMP `screendump` assertions, boot latency measurement harnesses, and power-cut/network/disk fault injection.

## Canonical Documentation & Contracts

- Central coordination & roadmap: [`smart-boot-menu/sbm`](https://github.com/smart-boot-menu/sbm)
- Normative specifications & ADRs: [`smart-boot-menu/docs`](https://github.com/smart-boot-menu/docs)
- Primary-source technical research: [`smart-boot-menu/research`](https://github.com/smart-boot-menu/research)
- Shared Rust types & JSON Schemas: [`smart-boot-menu/sbm-common`](https://github.com/smart-boot-menu/sbm-common)
- Agent guide: [AGENTS.md](AGENTS.md)

## License

Original code and documentation in this repository are dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), subject to third-party licensing requirements for bundled external components.
