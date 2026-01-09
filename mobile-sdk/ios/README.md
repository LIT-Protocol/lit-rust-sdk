# Lit Mobile SDK (iOS)

iOS Swift package that links against the Lit Rust SDK via a small Rust FFI layer.

## Prerequisites

- Xcode 14+
- iOS 15+ simulator or device
- Rust toolchain (rustup/cargo)

## Build Rust FFI

From the repo root:

```bash
cd mobile-sdk/ios
./scripts/build-rust.sh
```

This produces `LitRustSDKFFI.xcframework` in `mobile-sdk/ios/`.

## Run Tests on iOS Simulator

Set environment variables for the test run:

```bash
export LIT_RPC_URL=<YOUR_NAGA_RPC_URL>
export NETWORK=naga-dev
```

Then run XCTest on a simulator:

```bash
cd mobile-sdk/ios
xcodebuild test \
  -scheme LitSDK \
  -destination 'platform=iOS Simulator,name=iPhone 15,OS=latest'
```

If the scheme name differs in your Xcode version, run `xcodebuild -list` in
`mobile-sdk/ios` and use the scheme it prints (commonly `LitSDK-Package`).

If `LIT_RPC_URL` is not set, the network test will be skipped.

## Demo App (UI)

1) Build the XCFramework:

```bash
cd mobile-sdk/ios
./scripts/build-rust.sh
```

Or run everything from the repo root:

```bash
make ios
```

2) Open the demo app project in Xcode:

- `mobile-sdk/ios/Examples/LitSDKDemo/LitSDKDemo.xcodeproj`

3) Run the `LitSDKDemo` scheme on an iOS simulator.

In the app, set a `naga-*` network and RPC URL; the client connects automatically
and the demo flow mirrors the test cases.

The demo also lets you create an EOA auth context and sign with a PKP:
- Paste an EOA private key; the address and balances populate automatically.
- Use the faucet link (testnets only) once the address is derived.
- Use **Find PKPs** or **Mint PKP** to populate the PKP picker.
- Tap **Create Auth Context**.
- Enter a message and tap **Sign Message** to view the signature JSON.

You can override the simulator target for `make ios`:

```bash
IOS_SIM_NAME="iPhone 15" IOS_SIM_OS="17.0" make ios
```

RPC defaults:
- `naga` uses Lit Chain mainnet (`https://lit-chain-rpc.litprotocol.com`)
- All other `naga-*` networks use Chronicle Yellowstone testnet (`https://yellowstone-rpc.litprotocol.com/`)
- `naga-local` has no default
