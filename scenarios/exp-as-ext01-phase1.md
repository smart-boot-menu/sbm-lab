# EXP-AS-EXT01 phase 1

Run the Apple Silicon agent's U-Boot EFI probe. This scenario does not add a second harness and does not touch the host Mac's disk or boot policy.

```sh
./scripts/run-uboot-efi-probe.sh
```

The script calls `../sbm-as/scripts/uboot-efi-poc.sh`.

What a pass means: upstream U-Boot `v2026.10`, configured from `qemu_arm64_defconfig`, started `sbm-as-efi-probe` on QEMU `virt`, the probe filled a GOP rectangle, wrote `\EFI\sbm\boot-policy.json`, chainloaded `sbm-as-chain-target`, and found a marker file on a second disk attached as USB EHCI.

What a pass does not mean: an Apple Silicon boot. `virt` has no Apple NVMe, DART, or xHCI, and it does not run Boot ROM, LLB, or iBoot. On the 2026-11-26 host, HVF aborted and the passing accelerator was TCG. The log and the marker list live with the evidence note in `research/validation/evidence/sbm-as-uboot-efi-2026-11-26.md`.
