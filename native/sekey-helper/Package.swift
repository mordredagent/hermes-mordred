// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "mordred-hermes-sekey",
    platforms: [
        .macOS(.v13),
    ],
    targets: [
        .executableTarget(
            name: "mordred-hermes-sekey",
            path: "Sources/mordred-hermes-sekey",
            linkerSettings: [
                // Embed Info.plist into the __TEXT,__info_plist section so the
                // CLI carries a bundle identifier (io.intmax.mordred-hermes-sekey).
                // A bundle ID is required for the keychain-access-groups
                // entitlement to take effect under Developer ID signing.
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Resources/Info.plist",
                ]),
            ]
        ),
    ]
)
