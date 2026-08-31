// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VigilNetworkAdapter",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "VigilNetworkAdapter", targets: ["VigilNetworkAdapter"]),
    ],
    targets: [
        .target(
            name: "VigilNetworkAdapter",
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("NetworkExtension"),
            ]
        ),
        .testTarget(
            name: "VigilNetworkAdapterTests",
            dependencies: ["VigilNetworkAdapter"],
            resources: [.process("Resources")]
        ),
    ]
)
