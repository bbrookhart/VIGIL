// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VigilEndpointAdapter",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "VigilEndpointAdapter", targets: ["VigilEndpointAdapter"]),
    ],
    targets: [
        .target(
            name: "VigilEndpointAdapter",
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm"),
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "VigilEndpointAdapterTests",
            dependencies: ["VigilEndpointAdapter"],
            resources: [.process("Resources")]
        ),
    ]
)
