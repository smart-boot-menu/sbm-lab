#!/bin/sh
# Build the release CLI and both UEFI probe targets, then run the smoke tier.
set -eu
cd "$(dirname "$0")/.."
cargo build --release
cargo build --manifest-path fixtures/efi-probe/Cargo.toml --release \
  --target x86_64-unknown-uefi --target aarch64-unknown-uefi
exec ./target/release/sbm-lab test --tier smoke
