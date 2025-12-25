// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SoftEtherClient",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "SoftEtherClient",
            targets: ["SoftEtherClient"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.20.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "SoftEtherClient",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources"
        ),
        .testTarget(
            name: "SoftEtherClientTests",
            dependencies: ["SoftEtherClient"],
            path: "Tests"
        ),
    ]
)
