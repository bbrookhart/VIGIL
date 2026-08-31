// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VigilMacSupport",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "VigilMacSupport", targets: ["VigilMacSupport"]),
    ],
    dependencies: [
        .package(path: "../../../extensions/network-filter"),
    ],
    targets: [
        .target(
            name: "VigilMacSupport",
            dependencies: [
                .product(name: "VigilNetworkAdapter", package: "network-filter"),
            ],
            linkerSettings: [.linkedFramework("SystemExtensions")]
        ),
        .testTarget(
            name: "VigilMacSupportTests",
            dependencies: ["VigilMacSupport"]
        ),
    ]
)
