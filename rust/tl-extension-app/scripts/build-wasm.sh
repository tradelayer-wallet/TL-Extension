#!/usr/bin/env bash
# Build tl-extension-wasm for wasm32-unknown-unknown and copy the module to $1.
# Run inside WSL (Ubuntu 24.04, rustup toolchain 1.90.0 with the wasm32 target, clang for libsecp256k1):
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash <this file> <out dir>
set -euo pipefail
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
here="$(cd "$(dirname "$0")" && pwd)"
crate="$here/../wasm"
out="${1:?output directory}"
export CARGO_TARGET_DIR="$HOME/work/tl17-wasm/tl-extension-wasm"
cd "$crate"
cargo +1.90.0 build --locked --offline --release --target wasm32-unknown-unknown
mkdir -p "$out"
cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/tl_extension_wasm.wasm" "$out/tl_extension_wasm.wasm"
ls -l "$out/tl_extension_wasm.wasm"
