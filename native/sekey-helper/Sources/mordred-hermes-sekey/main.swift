// mordred-hermes-sekey — Secure Enclave helper CLI.
//
// One process invocation == one operation. Reads a single JSON request
// object from stdin, performs the Security.framework call, writes a single
// JSON response object to stdout, and exits (0 on success, 1 on error).
//
// The Python side (`mordred_hermes.keyvault._seckey_helper`) spawns this
// binary once per `_SecKeyOps` method call. This binary is policy-free: it
// receives the Keychain application tag as hex bytes and uses it verbatim,
// so the cleartext key_id never crosses the process boundary (the tag is a
// SHA-256 prefix computed Python-side).
//
// Requests (stdin):
//   {"cmd":"generate","tag_hex":"..","label":".."}
//   {"cmd":"public_key","tag_hex":".."}
//   {"cmd":"delete","tag_hex":".."}
//   {"cmd":"ecdh","tag_hex":"..","peer_pub_hex":".."}
//   {"cmd":"probe"}
// Success (stdout, exit 0):
//   {"public_key_hex":"04.."}   {"shared_hex":".."}   {"ok":true}
// Failure (stdout, exit 1):
//   {"error":{"domain":"OSStatus","status":-25300,"message":".."}}

import Foundation
import Security

// NOTE: This helper deliberately uses the *legacy* file-based Keychain and
// carries NO keychain-access-groups entitlement. A Developer-ID-signed
// (non-App-Store) binary that requests keychain-access-groups without a
// provisioning profile is SIGKILLed by AMFI on launch. Secure Enclave keys
// persist fine in the legacy Keychain without that entitlement, so we match
// the in-process pyobjc path (_seckey_backend._keychain_query) exactly.

// MARK: - Wire types

struct Request: Decodable {
    let cmd: String
    let tag_hex: String?
    let label: String?
    let peer_pub_hex: String?
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

// MARK: - CFError extraction

func helperError(_ cfError: Unmanaged<CFError>?, _ fallbackMessage: String) -> HelperError {
    guard let cfError = cfError else {
        return HelperError(domain: "OSStatus", status: Int(errSecAuthFailed), message: fallbackMessage)
    }
    let err = cfError.takeRetainedValue() as Error as NSError
    return HelperError(domain: err.domain, status: err.code, message: err.localizedDescription)
}

// MARK: - Keychain query builders

func privateKeyQuery(tag: Data, returnRef: Bool) -> [String: Any] {
    var q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    ]
    if returnRef {
        q[kSecReturnRef as String] = true
    }
    return q
}

func lookupPrivateKey(tag: Data) throws -> SecKey {
    var ref: CFTypeRef?
    let status = SecItemCopyMatching(privateKeyQuery(tag: tag, returnRef: true) as CFDictionary, &ref)
    guard status == errSecSuccess, let item = ref else {
        throw HelperError(domain: "OSStatus", status: Int(status), message: "SecItemCopyMatching failed")
    }
    // Force-cast is safe: the query pins kSecClassKey + kSecReturnRef, so a
    // success status guarantees a SecKey ref.
    return (item as! SecKey)
}

func exportPublicKey(_ privateKey: SecKey) throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw HelperError(domain: "OSStatus", status: Int(errSecAuthFailed), message: "SecKeyCopyPublicKey failed")
    }
    var cfErr: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(publicKey, &cfErr) else {
        throw helperError(cfErr, "SecKeyCopyExternalRepresentation failed")
    }
    return data as Data
}

// MARK: - Operations

func createKey(tag: Data, label: String?, biometry: Bool) throws -> Data {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if biometry {
        flags.insert(.biometryCurrentSet)
    }
    var acErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        flags,
        &acErr
    ) else {
        throw helperError(acErr, "SecAccessControlCreateWithFlags failed")
    }

    var privateKeyAttrs: [String: Any] = [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access,
    ]
    if let label = label {
        privateKeyAttrs[kSecAttrLabel as String] = label
    }

    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: privateKeyAttrs,
    ]

    var cfErr: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &cfErr) else {
        throw helperError(cfErr, "SecKeyCreateRandomKey failed")
    }
    return try exportPublicKey(privateKey)
}

func deleteKey(tag: Data) throws {
    let status = SecItemDelete(privateKeyQuery(tag: tag, returnRef: false) as CFDictionary)
    // errSecItemNotFound is success — delete is contractually idempotent.
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw HelperError(domain: "OSStatus", status: Int(status), message: "SecItemDelete failed")
    }
}

func ecdh(tag: Data, peerPub: Data) throws -> Data {
    let privateKey = try lookupPrivateKey(tag: tag)
    let peerAttrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
    ]
    var cfErr: Unmanaged<CFError>?
    guard let peerKey = SecKeyCreateWithData(peerPub as CFData, peerAttrs as CFDictionary, &cfErr) else {
        throw helperError(cfErr, "SecKeyCreateWithData(peer) failed")
    }
    guard let shared = SecKeyCopyKeyExchangeResult(
        privateKey,
        .ecdhKeyExchangeStandard,
        peerKey,
        [:] as CFDictionary,
        &cfErr
    ) else {
        throw helperError(cfErr, "SecKeyCopyKeyExchangeResult failed")
    }
    return shared as Data
}

func probe() throws {
    // A throwaway .privateKeyUsage-only key (no biometry → no prompt). A
    // random suffix prevents concurrent probes from colliding on the tag.
    var suffix = Data(count: 8)
    _ = suffix.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 8, $0.baseAddress!) }
    let tag = "mordred-hermes.wrap.__probe__.".data(using: .utf8)! + suffix
    _ = try createKey(tag: tag, label: "Mordred capability probe", biometry: false)
    // Cleanup failure must not flip capability detection to false.
    try? deleteKey(tag: tag)
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

func requireTag(_ req: Request) -> Data {
    guard let hex = req.tag_hex, let tag = hexDecode(hex) else {
        fail("missing or invalid tag_hex")
    }
    return tag
}

do {
    switch request.cmd {
    case "generate":
        let pub = try createKey(tag: requireTag(request), label: request.label, biometry: true)
        emit(["public_key_hex": hexEncode(pub)])
    case "public_key":
        let privateKey = try lookupPrivateKey(tag: requireTag(request))
        emit(["public_key_hex": hexEncode(try exportPublicKey(privateKey))])
    case "delete":
        try deleteKey(tag: requireTag(request))
        emit(["ok": true])
    case "ecdh":
        guard let peerHex = request.peer_pub_hex, let peer = hexDecode(peerHex) else {
            fail("missing or invalid peer_pub_hex")
        }
        emit(["shared_hex": hexEncode(try ecdh(tag: requireTag(request), peerPub: peer))])
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
