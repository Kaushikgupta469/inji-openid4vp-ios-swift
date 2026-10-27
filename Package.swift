// swift-tools-version: 5.9.0

import PackageDescription

let package = Package(
    name: "OpenID4VP",
    platforms: [
        .iOS(.v14),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "OpenID4VP",
            targets: ["OpenID4VP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/beatt83/jose-swift.git", "4.0.2"..<"4.0.3"),
        .package(url: "https://github.com/Alamofire/Alamofire.git", "5.10.2"..<"5.10.3"),
        .package(url: "https://github.com/abhip2565/SwiftCBOR",  "0.5.0"..<"0.5.1"),
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", "2.1.7"..<"2.1.8"),
        .package(url: "https://github.com/ATProtoKit/MultiformatsKit.git", from: "0.3.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", "1.15.0"..<"1.15.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", "1.4.0"..<"1.4.1")
    ],
    targets: [
        .target(
            name: "OpenID4VP",
            dependencies: [
                "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift",
                .product(name: "MultiformatsKit", package: "multiformatskit"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        ),
        .testTarget(
            name: "OpenID4VPTests",
            dependencies: [
                "OpenID4VP", "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift",
                .product(name: "MultiformatsKit", package: "multiformatskit"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        )
    ]
)
