# Disk fixtures

`sbm-lab setup --fixtures` writes `var/fixtures/<id>.raw`, `<id>.json`, and `<id>.qcow2`. A run creates a QCOW2 overlay of the qcow2 backing file and attaches the overlay. The backing hash is recorded and checked after the guest exits.

The probe disk is separate. It is a raw GPT+FAT32 image created for that run, with bootindex 0, so discovery does not depend on firmware boot order. Fixture disks are additional virtio disks. When `usb = true`, the last fixture is attached as `usb-storage` instead, using its own overlay.

| Id | Contents |
| --- | --- |
| `empty-gpt` | GPT, no partitions. |
| `empty-mbr` | MBR signature, no partition entries. |
| `one-esp` | One FAT32 ESP. |
| `multi-esp` | More than one ESP. |
| `multi-efi` | `alpha.efi`, `beta.efi`, and `gamma.efi` plus a manifest. |
| `linux-bls` | Two synthetic BLS type 1 entries and a synthetic UKI note. Not a Linux install. |
| `windows-like` | Layout that resembles a Windows disk. The image contains `THIS IS NOT WINDOWS.` It is not Windows. |
| `uki` | A synthetic UKI path. The EFI file is not a Linux UKI. |
| `filesystems` | FAT32 ESP plus ext4 (real `mkfs.ext4` when it is installed), and identifiable NTFS, Btrfs, and LUKS1 headers. |
| `missing-boot` | A manifest entry whose file is absent. |
| `corrupt-gpt` | Primary and backup GPT signatures are damaged. |
| `corrupt-config` | `EFI/sbm/policy.json` is not valid JSON. |
| `duplicate-entries` | Repeated BLS titles and catalog lines. |
| `apple-protected` | Names that resemble an Apple layout. The image says it is not an Apple disk. |

NTFS, Btrfs, and LUKS1 are synthetic headers, not filesystems produced by `mkfs.ntfs`, `mkfs.btrfs`, or `cryptsetup`. The LUKS header uses the LUKS1 magic and a SHA-1 checksum and is not unlockable. ext4 uses `mkfs.ext4` when `/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4` or `mkfs.ext4` on `PATH` works; otherwise the fixture writes the ext4 magic and a label.

`fixtures/corpus/invalid-command-envelope.json` is an intentionally incomplete command envelope. The lab checks that the required `sbm-common` fields are absent. It does not redefine that schema.
