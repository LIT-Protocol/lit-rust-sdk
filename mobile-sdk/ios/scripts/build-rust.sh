#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUST_FFI_DIR="$PROJECT_ROOT/rust-ffi"
TARGET_DIR="$PROJECT_ROOT/target"
XCFRAMEWORK_OUT="$PROJECT_ROOT/LitRustSDKFFI.xcframework"

TARGET_LIST="$(rustc --print target-list)"

DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGET_ARM64="aarch64-apple-ios-sim"
SIM_TARGET_X64="x86_64-apple-ios"

TARGETS=("$DEVICE_TARGET")

if echo "$TARGET_LIST" | grep -qx "$SIM_TARGET_ARM64"; then
    TARGETS+=("$SIM_TARGET_ARM64")
fi

if echo "$TARGET_LIST" | grep -qx "$SIM_TARGET_X64"; then
    TARGETS+=("$SIM_TARGET_X64")
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: cargo is not installed. Please install Rust: https://rustup.rs/" >&2
    exit 1
fi

for target in "${TARGETS[@]}"; do
    if ! echo "$TARGET_LIST" | grep -qx "$target"; then
        echo "Skipping target $target (not available in this toolchain)"
        continue
    fi
    rustup target add "$target" >/dev/null 2>&1 || true
done

export CARGO_TARGET_DIR="$TARGET_DIR"

cd "$RUST_FFI_DIR"
for target in "${TARGETS[@]}"; do
    echo "Building Rust FFI for $target..."
    cargo build --target "$target" --release
done

rm -rf "$XCFRAMEWORK_OUT"

LIB_ARGS=()

DEVICE_LIB="$TARGET_DIR/$DEVICE_TARGET/release/liblit_rust_sdk_ffi.a"
if [ -f "$DEVICE_LIB" ]; then
    LIB_ARGS+=(-library "$DEVICE_LIB" -headers "$RUST_FFI_DIR/include")
else
    echo "Device library not found: $DEVICE_LIB" >&2
    exit 1
fi

SIM_LIBS=()
SIM_LIB_ARM64="$TARGET_DIR/$SIM_TARGET_ARM64/release/liblit_rust_sdk_ffi.a"
SIM_LIB_X64="$TARGET_DIR/$SIM_TARGET_X64/release/liblit_rust_sdk_ffi.a"

if [ -f "$SIM_LIB_ARM64" ]; then
    SIM_LIBS+=("$SIM_LIB_ARM64")
fi
if [ -f "$SIM_LIB_X64" ]; then
    SIM_LIBS+=("$SIM_LIB_X64")
fi

if [ "${#SIM_LIBS[@]}" -eq 0 ]; then
    echo "No simulator libraries found; cannot create XCFramework" >&2
    exit 1
fi

SIM_FAT_DIR="$TARGET_DIR/ios-simulator/release"
SIM_FAT_LIB="$SIM_FAT_DIR/liblit_rust_sdk_ffi.a"
mkdir -p "$SIM_FAT_DIR"

if [ "${#SIM_LIBS[@]}" -eq 1 ]; then
    cp "${SIM_LIBS[0]}" "$SIM_FAT_LIB"
else
    xcrun lipo -create "${SIM_LIBS[@]}" -output "$SIM_FAT_LIB"
fi

LIB_ARGS+=(-library "$SIM_FAT_LIB" -headers "$RUST_FFI_DIR/include")

if [ "${#LIB_ARGS[@]}" -eq 0 ]; then
    echo "No static libraries found; cannot create XCFramework" >&2
    exit 1
fi

xcodebuild -create-xcframework "${LIB_ARGS[@]}" -output "$XCFRAMEWORK_OUT"

echo "Build complete."
echo "XCFramework: $XCFRAMEWORK_OUT"
