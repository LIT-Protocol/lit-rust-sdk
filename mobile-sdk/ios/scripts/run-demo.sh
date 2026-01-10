#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_DIR="$IOS_DIR/Examples/LitSDKDemo"
DERIVED_DIR="${IOS_DERIVED_DIR:-$IOS_DIR/.derived}"
SIM_NAME="${IOS_SIM_NAME:-iPhone 15}"
SIM_OS="${IOS_SIM_OS:-}"
SIM_ID="${IOS_SIM_ID:-}"

resolve_sim_id() {
    python3 - <<'PY'
import json
import os
import subprocess
import sys

name = os.environ.get("SIM_NAME", "iPhone 15")
osver = os.environ.get("SIM_OS", "17.0")

raw = subprocess.check_output(["xcrun", "simctl", "list", "devices", "available", "-j"])
data = json.loads(raw)

runtime_match = osver.replace(".", "-") if osver else None

for runtime, devices in data.get("devices", {}).items():
    if runtime_match and runtime_match not in runtime:
        continue
    for dev in devices:
        if dev.get("name") == name and dev.get("isAvailable", False):
            print(dev.get("udid", ""))
            sys.exit(0)

print("", end="")
sys.exit(0)
PY
}

if [ -z "$SIM_ID" ]; then
    SIM_ID=$(SIM_NAME="$SIM_NAME" SIM_OS="$SIM_OS" resolve_sim_id)
fi

if [ -z "$SIM_ID" ] && [ -n "$SIM_OS" ]; then
    SIM_ID=$(SIM_NAME="$SIM_NAME" SIM_OS="" resolve_sim_id)
fi

if [ -z "$SIM_ID" ]; then
    if [ -n "$SIM_OS" ]; then
        echo "No simulator found for name '$SIM_NAME' and OS '$SIM_OS'." >&2
    else
        echo "No simulator found for name '$SIM_NAME'." >&2
    fi
    echo "Available devices:" >&2
    xcrun simctl list devices available
    exit 1
fi

"$IOS_DIR/scripts/build-rust.sh"

xcrun simctl boot "$SIM_ID" >/dev/null 2>&1 || true
open -a Simulator --args -CurrentDeviceUDID "$SIM_ID" >/dev/null 2>&1 || true

xcodebuild \
    -project "$DEMO_DIR/LitSDKDemo.xcodeproj" \
    -scheme LitSDKDemo \
    -sdk iphonesimulator \
    -configuration Debug \
    -destination "id=$SIM_ID" \
    -derivedDataPath "$DERIVED_DIR" \
    build

APP_PATH="$DERIVED_DIR/Build/Products/Debug-iphonesimulator/LitSDKDemo.app"
if [ ! -d "$APP_PATH" ]; then
    echo "App bundle not found at $APP_PATH" >&2
    exit 1
fi

xcrun simctl install "$SIM_ID" "$APP_PATH"
xcrun simctl launch "$SIM_ID" com.litprotocol.LitSDKDemo

echo "LitSDKDemo launched on simulator $SIM_ID"
