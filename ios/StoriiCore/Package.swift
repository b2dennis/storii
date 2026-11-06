// swift-tools-version: 6.0
// Everything that doesn't need UIKit/SwiftUI/AuthenticationServices lives here, so it builds and tests on Linux too.
import PackageDescription

let package = Package(
    name: "StoriiCore",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [.library(name: "StoriiCore", targets: ["StoriiCore"])],
    dependencies: [
        // CryptoKit's API for Linux. On Apple platforms CryptoKit itself is used and this is never linked.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"6.0.0"),
    ],
    targets: [
        // The Argon2 reference implementation (CC0), vendored: see Sources/CArgon2/VERSION.
        .target(name: "CArgon2", cSettings: [.define("ARGON2_NO_THREADS")]),
        .target(name: "StoriiCore", dependencies: [
            "CArgon2",
            .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
        ]),
        .testTarget(name: "StoriiCoreTests", dependencies: ["StoriiCore"]),
    ]
)
