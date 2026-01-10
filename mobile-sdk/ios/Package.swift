// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "LitSDK",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "LitSDK",
            targets: ["LitSDK"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "LitRustSDKFFI",
            path: "LitRustSDKFFI.xcframework"
        ),
        .target(
            name: "LitSDK",
            dependencies: ["LitRustSDKFFI"],
            path: "Sources/LitSDK"
        ),
        .testTarget(
            name: "LitSDKE2ETests",
            dependencies: ["LitSDK"],
            path: "Tests/LitSDKE2ETests"
        )
    ]
)
