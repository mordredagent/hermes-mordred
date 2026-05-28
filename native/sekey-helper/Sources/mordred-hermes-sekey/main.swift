// mordred-hermes-sekey — Secure Enclave helper CLI (CryptoKit file-store).
//
// One process invocation == one operation. Reads a single JSON request
// object from stdin, performs the Secure Enclave operation, writes a single
// JSON response object to stdout, and exits (0 on success, 1 on error).
//
// The Python side (`mordred_hermes.keyvault._seckey_helper`) spawns this
// binary once per `_SecKeyOps` method call. This binary is policy-free: it
// receives the application tag as hex bytes and uses it verbatim as the
// store filename, so the cleartext key_id never crosses the process boundary
// (the tag is a SHA-256 prefix computed Python-side).
//
// Requests (stdin):
//   {"cmd":"generate","tag_hex":"..","label":"..","unattended":false}
//   {"cmd":"public_key","tag_hex":".."}
//   {"cmd":"delete","tag_hex":".."}
//   {"cmd":"ecdh","tag_hex":"..","peer_pub_hex":".."}
//   {"cmd":"probe"}
//
// "unattended" (generate only, default false): when false the key is created
// with a Touch-ID/passcode-gated access control, so every ECDH prompts. When
// true the key carries only .privateKeyUsage — it stays Enclave-bound (cannot
// be exfiltrated to another machine) but ECDH runs WITHOUT a prompt as long as
// the session is unlocked, for autonomous use. The choice is baked into the
// key's dataRepresentation at generation time and cannot change afterward.
// Success (stdout, exit 0):
//   {"public_key_hex":"04.."}   {"shared_hex":".."}   {"ok":true}
// Failure (stdout, exit 1):
//   {"error":{"domain":"OSStatus","status":-25300,"message":".."}}
//
// Persistence model: each key is a CryptoKit `SecureEnclave.P256.KeyAgreement`
// private key. We store its `dataRepresentation` — an opaque blob that ONLY
// this device's Secure Enclave can decrypt and use — in a plain file at
// `<store>/<tag_hex>.bin`. No Keychain, no keychain-access-groups entitlement,
// no provisioning profile, no .app bundle: an ad-hoc-signed bare CLI works.
// The blob is useless without the originating Enclave, so the file at rest
// leaks nothing. ECDH triggers the Touch ID / passcode prompt because the key
// is generated with a `.biometryCurrentSet` access control; reading the public
// key does not.

import CryptoKit
import Foundation
import Security

// MARK: - OSStatus mirror
//
// We re-emit the same OSStatus ints the legacy Keychain path used so the
// Python `_translate_error` table keeps working unchanged across the boundary.

let errItemNotFound = -25300   // errSecItemNotFound
let errDuplicateItem = -25299  // errSecDuplicateItem
let errAuthFailed = -25293     // errSecAuthFailed

// MARK: - Wire types

struct Request: Decodable {
    let cmd: String
    let tag_hex: String?
    let label: String?
    let peer_pub_hex: String?
    let unattended: Bool?
}

struct HelperError: Error {
    let domain: String
    let status: Int
    let message: String
}

// MARK: - hex helpers

func hexDecode(_ s: String) -> Data? {
    guard s.count % 2 == 0 else { return nil }
    var out = Data(capacity: s.count / 2)
    var idx = s.startIndex
    while idx < s.endIndex {
        let next = s.index(idx, offsetBy: 2)
        guard let byte = UInt8(s[idx..<next], radix: 16) else { return nil }
        out.append(byte)
        idx = next
    }
    return out
}

func hexEncode(_ d: Data) -> String {
    d.map { String(format: "%02x", $0) }.joined()
}

// MARK: - Blob store
//
// Resolution order for the store directory:
//   1. MORDRED_SEKEY_STORE — explicit absolute directory (authoritative).
//   2. $HERMES_HOME/mordred/keyvault/sekey
//   3. ~/.hermes/mordred/keyvault/sekey
// This mirrors mordred_hermes._home.hermes_home so the SE blobs live under
// the same keyvault tree the Python side uses for everything else.

func storeDir() -> URL {
    let env = ProcessInfo.processInfo.environment
    if let explicit = env["MORDRED_SEKEY_STORE"], !explicit.isEmpty {
        return URL(fileURLWithPath: (explicit as NSString).expandingTildeInPath, isDirectory: true)
    }
    let base: URL
    if let hermesHome = env["HERMES_HOME"], !hermesHome.isEmpty {
        base = URL(fileURLWithPath: (hermesHome as NSString).expandingTildeInPath, isDirectory: true)
    } else {
        base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".hermes", isDirectory: true)
    }
    return base
        .appendingPathComponent("mordred", isDirectory: true)
        .appendingPathComponent("keyvault", isDirectory: true)
        .appendingPathComponent("sekey", isDirectory: true)
}

func blobURL(tagHex: String) -> URL {
    storeDir().appendingPathComponent("\(tagHex).bin", isDirectory: false)
}

func ensureStoreDir() throws {
    let dir = storeDir()
    do {
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    } catch {
        throw HelperError(domain: "helper", status: -1, message: "failed to create store dir: \(error.localizedDescription)")
    }
}

func writeBlob(_ blob: Data, tagHex: String) throws {
    try ensureStoreDir()
    let url = blobURL(tagHex: tagHex)
    do {
        try blob.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    } catch {
        throw HelperError(domain: "helper", status: -1, message: "failed to write blob: \(error.localizedDescription)")
    }
}

func readBlob(tagHex: String) throws -> Data {
    let url = blobURL(tagHex: tagHex)
    guard FileManager.default.fileExists(atPath: url.path) else {
        throw HelperError(domain: "OSStatus", status: errItemNotFound, message: "no key for tag")
    }
    do {
        return try Data(contentsOf: url)
    } catch {
        throw HelperError(domain: "helper", status: -1, message: "failed to read blob: \(error.localizedDescription)")
    }
}

// MARK: - Access control

func makeAccessControl(biometry: Bool) throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if biometry {
        // Biometry-preferred with a device-passcode fallback:
        // `.biometryCurrentSet` keeps the "key is invalidated when the
        // enrolled fingerprint set changes" defense (an attacker who enrolls
        // their own finger cannot use the key), while `.or, .devicePasscode`
        // lets the user fall back to the Mac password when Touch ID is
        // unavailable, flaky, or locked out — without it, a biometry lockout
        // makes the wrapping key permanently unusable until a screen unlock.
        flags.insert(.biometryCurrentSet)
        flags.insert(.or)
        flags.insert(.devicePasscode)
    }
    var acErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        flags,
        &acErr
    ) else {
        let message: String
        if let cf = acErr?.takeRetainedValue() {
            message = (cf as Error).localizedDescription
        } else {
            message = "SecAccessControlCreateWithFlags failed"
        }
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: message)
    }
    return access
}

// MARK: - Operations

func loadKey(tagHex: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    let blob = try readBlob(tagHex: tagHex)
    do {
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "failed to load enclave key: \(error.localizedDescription)")
    }
}

func generate(tagHex: String, unattended: Bool) throws -> Data {
    // Refuse to overwrite an existing key — mirrors errSecDuplicateItem so the
    // backend maps it to "already exists" rather than silently rotating.
    if FileManager.default.fileExists(atPath: blobURL(tagHex: tagHex).path) {
        throw HelperError(domain: "OSStatus", status: errDuplicateItem, message: "key already exists for tag")
    }
    // unattended → .privateKeyUsage only (no prompt); otherwise biometry-gated.
    let access = try makeAccessControl(biometry: !unattended)
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "SecureEnclave key generation failed: \(error.localizedDescription)")
    }
    try writeBlob(key.dataRepresentation, tagHex: tagHex)
    return key.publicKey.x963Representation
}

func publicKey(tagHex: String) throws -> Data {
    try loadKey(tagHex: tagHex).publicKey.x963Representation
}

func deleteKey(tagHex: String) throws {
    let url = blobURL(tagHex: tagHex)
    // Idempotent: a missing key is success, not an error.
    guard FileManager.default.fileExists(atPath: url.path) else { return }
    do {
        try FileManager.default.removeItem(at: url)
    } catch {
        // Lost a race with another deleter? Treat a now-absent file as success.
        if FileManager.default.fileExists(atPath: url.path) {
            throw HelperError(domain: "helper", status: -1, message: "failed to delete blob: \(error.localizedDescription)")
        }
    }
}

func ecdh(tagHex: String, peerPub: Data) throws -> Data {
    let key = try loadKey(tagHex: tagHex)
    let peer: P256.KeyAgreement.PublicKey
    do {
        peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPub)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "invalid peer public key: \(error.localizedDescription)")
    }
    let shared: SharedSecret
    do {
        // This is the authorization boundary — triggers the Touch ID /
        // passcode prompt because the key carries .biometryCurrentSet.
        shared = try key.sharedSecretFromKeyAgreement(with: peer)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "key agreement failed: \(error.localizedDescription)")
    }
    // Raw 32-byte X coordinate — identical to SecKeyCopyKeyExchangeResult
    // (.ecdhKeyExchangeStandard) and the software fallback, so wrap.py's HKDF
    // input is unchanged.
    return shared.withUnsafeBytes { Data($0) }
}

func probe() throws {
    guard SecureEnclave.isAvailable else {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "Secure Enclave not available")
    }
    // Generate a throwaway .privateKeyUsage-only key (no biometry → no prompt)
    // and never persist it. Success proves the hardware path works.
    let access = try makeAccessControl(biometry: false)
    do {
        _ = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "probe key generation failed: \(error.localizedDescription)")
    }
}

// MARK: - Output

func emit(_ obj: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: obj) else {
        FileHandle.standardOutput.write("{\"error\":{\"domain\":\"helper\",\"status\":-1,\"message\":\"failed to serialize response\"}}".data(using: .utf8)!)
        exit(1)
    }
    FileHandle.standardOutput.write(data)
}

func emitError(_ e: HelperError) -> Never {
    emit(["error": ["domain": e.domain, "status": e.status, "message": e.message]])
    exit(1)
}

func fail(_ message: String) -> Never {
    emitError(HelperError(domain: "helper", status: -1, message: message))
}

// MARK: - Main

let input = FileHandle.standardInput.readDataToEndOfFile()
guard let request = try? JSONDecoder().decode(Request.self, from: input) else {
    fail("invalid JSON request on stdin")
}

func requireTagHex(_ req: Request) -> String {
    guard let hex = req.tag_hex, hexDecode(hex) != nil else {
        fail("missing or invalid tag_hex")
    }
    return hex
}

do {
    switch request.cmd {
    case "generate":
        emit(["public_key_hex": hexEncode(try generate(tagHex: requireTagHex(request), unattended: request.unattended ?? false))])
    case "public_key":
        emit(["public_key_hex": hexEncode(try publicKey(tagHex: requireTagHex(request)))])
    case "delete":
        try deleteKey(tagHex: requireTagHex(request))
        emit(["ok": true])
    case "ecdh":
        guard let peerHex = request.peer_pub_hex, let peer = hexDecode(peerHex) else {
            fail("missing or invalid peer_pub_hex")
        }
        emit(["shared_hex": hexEncode(try ecdh(tagHex: requireTagHex(request), peerPub: peer))])
    case "probe":
        try probe()
        emit(["ok": true])
    default:
        fail("unknown cmd: \(request.cmd)")
    }
} catch let e as HelperError {
    emitError(e)
} catch {
    fail("unexpected error: \(error.localizedDescription)")
}
