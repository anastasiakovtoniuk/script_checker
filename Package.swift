// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "script_checker",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "script_dependencies", targets: ["script_dependencies"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio-http2.git", exact: "1.37.0")
    ],
    targets: [
        .executableTarget(
            name: "script_dependencies",
            dependencies: [
                .product(name: "NIOHTTP2", package: "swift-nio-http2")
            ]
        )
    ]
)
