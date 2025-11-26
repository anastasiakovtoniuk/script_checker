// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "script_dependencies",
    platforms: [
        .macOS(.v14)
    ],
    dependencies: [
        .package(url: "https://github.com/grpc/grpc-swift-2.git", from: "2.2.0"),
        .package(url: "https://github.com/grpc/grpc-swift-nio-transport.git", from: "2.0.0")
    ],
    targets: [
        .executableTarget(
            name: "script_dependencies",
            dependencies: [
                .product(name: "GRPCCore", package: "grpc-swift-2"),
                .product(name: "GRPCNIOTransportHTTP2", package: "grpc-swift-nio-transport")
            ]
        )
    ]
)
