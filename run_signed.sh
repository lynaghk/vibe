#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$ROOT_DIR/target/debug/vibebox"
ENTITLEMENTS="$ROOT_DIR/entitlements.plist"

echo "[run_signed] Building (debug)..."
cargo build

echo "[run_signed] Signing with virtualization entitlement..."
codesign --entitlements "$ENTITLEMENTS" --force --sign - "$BINARY"

echo "[run_signed] Running..."
"$BINARY"
