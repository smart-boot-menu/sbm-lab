# AGENTS.md — `sbm-lab`

## Canonical Organization Policy (Read First)

Before designing or implementing changes, read the canonical organization-wide engineering rules in [`smart-boot-menu/.github/AGENTS.md`](https://github.com/smart-boot-menu/.github/blob/main/AGENTS.md) (local workspace: `../.github/AGENTS.md`), the operational checklists in [`.github/agent-reference.md`](https://github.com/smart-boot-menu/.github/blob/main/agent-reference.md) (`../.github/agent-reference.md`), and the **Open-Source Reuse & Engineering Principles** in [`ADR-010`](https://github.com/smart-boot-menu/docs/blob/main/architecture-decisions/ADR-010-open-source-reuse-and-engineering-principles.md) (`../docs/architecture-decisions/ADR-010-open-source-reuse-and-engineering-principles.md`).

> **Standalone / Single-Repo Agents:** If you were launched inside this repository alone and `../.github/AGENTS.md` is not present locally, fetch and follow the GitHub URLs above before proceeding. Do not recreate inferior versions of existing software; apply proportional build-versus-reuse evaluation for new components, major dependencies, architectural changes, or replacements.

## Assigned Repository & Role

- **Repository:** `smart-boot-menu/sbm-lab`
- **Primary Dependencies & Specs:** `sbm-common`, `docs/architecture-decisions/ADR-008`, `docs/testing/benchmarks.md`, `research/architecture/virtualization-and-testing.md`

## Responsibilities (What You Own)

- Reproducible Rust integration harness running `sbm-uefi`, `sbm-core`, `sbm-server`, `install`, and `sbm-agent` end-to-end across OVMF (standard + Secure Boot), AAVMF, and U-Boot `qemu_arm64`.
- Native-speed ARM64 virtualization (`-accel hvf` on M5 Mac; `-accel kvm` on Linux CI) + TCG fallback.
- Golden QCOW2 disk fixtures (Windows/BitLocker, multi-Linux BLS/UKI, Apple-protected guardrails, corrupt GPT).
- QMP `screendump` assertions, boot latency measurement harnesses, and power-cut/network/disk fault injection.

## Strict Boundaries (Do NOT Duplicate or Violate)

Do NOT put production runtime code here. NEVER touch physical host storage or macOS boot configuration.

## Engineering & Performance Targets

Fast smoke suite < 60 s on developer M5 Mac (HVF); deterministic reproducible fixtures.

*(Targets are goals, not claims; follow `../docs/testing/benchmarks.md` and archive real measurements in `../research/validation/evidence/`.)*

## Security, Testing & Interface Coordination

- Enforce all invariants in `../docs/threat-model/README.md` (offline-first, no secrets committed, bounded timeouts, safe storage plans).
- Run formatting, clippy, unit tests, and integration hooks before committing.
- Never silently diverge from `sbm-common` types or `docs/specifications/`; follow the Interface Change Protocol in `../.github/agent-reference.md`.
