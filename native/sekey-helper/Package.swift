// swift-tools-version:5.9
import PackageDescription

// The CryptoKit file-store design (SecureEnclave.P256 + dataRepresentation)
// needs no Keychain, no keychain-access-groups entitlement, no bundle ID, and
// no provisioning profile — so this is a plain executable target with no
// Info.plist embedding or unsafe linker flags. Ad-hoc signing (build.sh) is
// sufficient for Secure Enclave use.
let package = Package(
    name: "mordred-hermes-sekey",
    platforms: [
        .macOS(.v13),
    ],
    targets: [
        .executableTarget(
            name: "mordred-hermes-sekey",
            path: "Sources/mordred-hermes-sekey"
        ),
    ]
)
