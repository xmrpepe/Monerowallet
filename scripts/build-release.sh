#!/usr/bin/env bash
# Reproducible release build (docs/RELEASE.md).
# Output: dist/<target>/{kage-signer,zerotrace,SHA256SUMS}
#
# Reproducibility inputs, all pinned: rust-toolchain.toml (compiler), Cargo.lock
# (deps, with checksums), this script (flags), git commit (SOURCE_DATE_EPOCH).
# Absolute paths are remapped so the build directory does not leak into the
# binary. Static musl binaries are used: no dynamic loader, so LD_PRELOAD /
# LD_LIBRARY_PATH injection does not apply (T-SIGN-INJECT).
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=${TARGET:-x86_64-unknown-linux-musl}
ROOT=$(pwd -P)
CARGO_HOME_DIR=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
SYSROOT=$(rustc --print sysroot)

SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=${ROOT}=/zerotrace \
--remap-path-prefix=${CARGO_HOME_DIR}=/cargo \
--remap-path-prefix=${SYSROOT}=/rustc \
-C target-feature=+crt-static"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target/release-build}"

cargo build --release --locked --target "$TARGET" --bin kage-signer --bin zerotrace

OUT="dist/${TARGET}"
rm -rf "$OUT" && mkdir -p "$OUT"
for b in kage-signer zerotrace; do
  cp "${CARGO_TARGET_DIR}/${TARGET}/release/${b}" "$OUT/"
done
(cd "$OUT" && sha256sum kage-signer zerotrace > SHA256SUMS && cat SHA256SUMS)
