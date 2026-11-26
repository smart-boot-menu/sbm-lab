# Installer ISO boots

`sbm-lab` scenarios boot the lab probe, the SBM UEFI menu, and disposable qcow2 disks. They do not attach an operating-system installer ISO, and they do not accept a host disk path.

Verified Linux installer boots live in `sbm-catalog`. The command is:

```sh
../sbm-catalog/tools/boot-installer.sh ISO EXPECTED_SHA256 [SECONDS]
```

The script checks SHA-256, refuses a path under `/dev/`, copies the EDK2 variable store, and runs `qemu-system-aarch64 -machine virt,accel=hvf` with the ISO as a CD-ROM. There is no host disk argument. On this Apple Silicon Mac that guest is generic AArch64 UEFI, not an Apple Silicon boot chain.

Runs recorded on 2026-11-26, each a single boot log rather than a benchmark:

- Debian 13.8.0 arm64 netinst reached the GRUB install menu.
- openSUSE Leap 16.1 aarch64 online installer reached GRUB and then the guest kernel.
- Fedora 45 Server aarch64 netinst reached GRUB and then the installer kernel with `rd.live.check`.

The notes are in `smart-boot-menu/research` under `validation/evidence/`. Do not add a lab profile that passes a host block device through to these installers.
