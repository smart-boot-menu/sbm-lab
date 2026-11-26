# Profiles

Profiles live in `profiles/*.toml`. Unknown keys are rejected. `sbm-lab list --profiles` prints the ids.

| Id | Machine | What it is for |
| --- | --- | --- |
| `x86_64-uefi` | q35 + OVMF | Default x86 UEFI guest. TCG on Apple Silicon. Attaches `multi-efi`. |
| `aarch64-uefi` | virt + AAVMF | HVF on Apple Silicon, KVM on a matching Linux host. Attaches `multi-efi` and `linux-bls`. Software framebuffer is `ramfb`. |
| `x86_64-uefi-secure-boot` | q35, SMM on | Secure Boot firmware. The bundled variable store is not key-enrolled. |
| `ia32-uefi` | q35 + IA32 OVMF | Firmware shell. The lab probe is not an IA32 PE. |
| `uboot-efi` | virt + U-Boot `-bios`, TCG | Needs `var/firmware/u-boot-qemu-arm64.bin`. HVF aborts in QEMU 11.1.3 before U-Boot prints a banner, so this profile forces TCG. |
| `legacy-bios` | pc + SeaBIOS | No pflash and no probe disk. Looks for a SeaBIOS banner. |
| `x86_64-uefi-tpm` | q35 + swtpm | TPM is attached. PCR values are not asserted. |
| `x86_64-lowmem` | q35, 512 MiB | Low-memory profile. Fault tests can lower it to 256 MiB. |
| `x86_64-multidisk` | q35 | `multi-efi` and `linux-bls`. |
| `x86_64-usb` | q35 | The last fixture is USB mass storage. |
| `x86_64-online` | q35 | User-mode NIC. The MAC is `52:54:00:12:34:56`, the QEMU OUI. |
| `x86_64-offline` | q35 | No NIC. |
| `x86_64-virtio-gpu` | q35 | `virtio-vga`. |
| `aarch64-virtio-gpu` | virt | `virtio-gpu-pci`. |
| `linux-dev` | virt, build-vm role | Shared Linux build VM. `setup --build-vm` downloads the image. `run linux-dev` does not boot it yet. |

Headless display is `-display none` plus an explicit VGA, ramfb, or virtio GPU device, because `-nodefaults` removes the default display. This QEMU build has no VNC backend. `--graphical` selects `cocoa`.

Every UEFI run gets its own variable-store copy. Secure Boot also passes `-global driver=cfi.pflash01,property=secure,value=on`.
