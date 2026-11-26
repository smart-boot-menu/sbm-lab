#!/bin/sh
# Phase 1 of EXP-AS-EXT01. QEMU virt is not an Apple Silicon Mac.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/../../sbm-as/scripts/uboot-efi-poc.sh" "$@"
