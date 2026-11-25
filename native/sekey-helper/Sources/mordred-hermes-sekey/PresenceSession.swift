// Private parent-pipe presence sessions. No credential, key or ECDH cache.
import AppKit
import CoreGraphics
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication

func continuousSeconds() -> Double {
    var info = mach_timebase_info_data_t()
    mach_timebase_info(&info)
    return Double(mach_continuous_time()) * Double(info.numer) / Double(info.denom) / 1_000_000_000
}

// The clock/state machine is independent of authentication and pipe I/O so
// expiry and revocation never wait for a blocked OS prompt or stdout write.
final class PresenceLease {
    private let lock = NSLock()
    private let clock: () -> Double
    private let duration: Double
    private var deadline: Double?
    private var revoked = false

    init(seconds: Double, clock: @escaping () -> Double = continuousSeconds) {
        self.duration = seconds
        self.clock = clock
    }

    func authenticated() throws {
        lock.lock(); defer { lock.unlock() }
        guard !revoked else { throw refused() }
        if deadline == nil { deadline = clock() + duration }
    }

    func check() throws {
        lock.lock(); defer { lock.unlock() }
        guard !revoked, deadline.map({ clock() < $0 }) ?? true else { throw refused() }
    }

    func revoke() {
        lock.lock(); revoked = true; lock.unlock()
    }

    private func refused() -> HelperError {
        HelperError(domain: "OSStatus", status: errAuthFailed, message: "presence expired or revoked")
    }
}

// Called only by the session's serial ECDH queue. It caches just the
// authentication decision; every exchange closure still executes.
final class PresenceAuthorization {
    private let lease: PresenceLease
    private var authenticated = false

    init(lease: PresenceLease) { self.lease = lease }

    func perform<T>(authenticate: () throws -> Void, exchange: () throws -> T) throws -> T {
        do {
            try lease.check()
            if !authenticated {
                try authenticate()
                try lease.authenticated()
                authenticated = true
            }
            try lease.check()
            let result = try exchange()
            try lease.check()
            return result
        } catch {
            lease.revoke()
            throw error
        }
    }
}

// What a session is for: it picks the system prompt's text. The parent names
// it; the helper never infers a purpose from the keys it is asked to use.
enum PresencePurpose: String {
    case credentials, setup, startup

    var reason: String {
        switch self {
        case .credentials: return "Read Mordred Telegram or mail credentials"
        case .setup: return "Set up Mordred's keys and encryption"
        case .startup: return "Open Mordred's vault and databases"
        }
    }
}

// `--presence-session SECONDS [--max-keys N] [--purpose P] [--reason TEXT]`.
// Without the options a session is the original one: one key, the credentials
// text. `--reason` is the purpose's text in the user's language (the parent
// picks it); without it the English one above is shown.
struct PresenceOptions: Equatable {
    let seconds: Int
    let maxKeys: Int
    let purpose: PresencePurpose
    let reasonText: String?

    var reason: String { reasonText ?? purpose.reason }

    init?(arguments: [String]) {
        guard arguments.count >= 2, arguments[0] == "--presence-session", let seconds = Int(arguments[1]) else {
            return nil
        }
        var maxKeys = 1
        var purpose = PresencePurpose.credentials
        var reasonText: String?
        var rest = arguments.dropFirst(2)
        var seen = Set<String>()
        while let flag = rest.first {
            rest = rest.dropFirst()
            guard let value = rest.first, seen.insert(flag).inserted else { return nil }
            rest = rest.dropFirst()
            switch flag {
            case "--max-keys":
                guard let count = Int(value), (1...8).contains(count) else { return nil }
                maxKeys = count
            case "--purpose":
                guard let named = PresencePurpose(rawValue: value) else { return nil }
                purpose = named
            case "--reason":
                // One short line: what the Touch ID window says Mordred is doing.
                guard !value.isEmpty, value.utf8.count <= 240,
                      !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                    return nil
                }
                reasonText = value
            default:
                return nil
            }
        }
        self.seconds = seconds
        self.maxKeys = maxKeys
        self.purpose = purpose
        self.reasonText = reasonText
    }
}

// The keys one session may use: at most `limit` distinct keys (a store and a
// tag), each bound to the non-secret fingerprint of the key file it first saw.
// Only the serial ECDH queue calls it.
final class PresenceKeys {
    private let limit: Int
    private var bound: [String: SHA256.Digest] = [:]

    init(limit: Int) { self.limit = limit }

    func admit(tag: String, store: String? = nil, digest: SHA256.Digest) throws {
        let key = (store ?? "") + "\n" + tag
        if let known = bound[key] {
            guard known == digest else {
                throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "key changed")
            }
            return
        }
        guard bound.count < limit else {
            throw HelperError(domain: "helper", status: -1, message: "invalid presence request")
        }
        bound[key] = digest
    }
}

// The store an operation-window request names: an absolute directory path
// with no empty, `.` or `..` component (not NSString.standardizingPath, which
// also rewrites /private/tmp to /tmp). A one-key (credentials) session never
// takes one. The store itself is validated like any other (a real 0700
// directory, no symlinks).
func presenceStore(_ path: String?, maxKeys: Int) throws -> URL? {
    guard let path else { return nil }
    let components = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
    guard maxKeys > 1, path.hasPrefix("/"), path.count > 1, !path.contains("\0"),
          !components.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else {
        throw HelperError(domain: "helper", status: -1, message: "invalid presence request")
    }
    return URL(fileURLWithPath: path, isDirectory: true)
}

func presenceSession(seconds: Int, maxKeys: Int = 1, purpose: PresencePurpose = .credentials, reason: String? = nil) -> Never {
    guard (1...300).contains(seconds), isatty(STDIN_FILENO) == 0,
          isatty(STDOUT_FILENO) == 0, getppid() > 1 else {
        fail("presence session requires private parent pipes and 1...300 seconds")
    }
    // Refuse regular files, terminals and sockets: there is no discoverable
    // service endpoint, only the anonymous pipes inherited from the parent.
    var inputStat = stat(), outputStat = stat()
    guard fstat(STDIN_FILENO, &inputStat) == 0, fstat(STDOUT_FILENO, &outputStat) == 0,
          inputStat.st_mode & S_IFMT == S_IFIFO, outputStat.st_mode & S_IFMT == S_IFIFO else {
        fail("presence session requires anonymous pipes")
    }
    let parent = getppid()
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    let lease = PresenceLease(seconds: Double(seconds))
    let stop: () -> Void = {
        lease.revoke()
        context.invalidate()
        // Exit also drops queued requests and wakes every parent-side waiter.
        exit(1)
    }
    let workspace = NSWorkspace.shared.notificationCenter
    let sleepObserver = workspace.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: nil) { _ in stop() }
    let sessionObserver = workspace.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: nil) { _ in stop() }
    let center = DistributedNotificationCenter.default()
    let lockObserver = center.addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: nil) { _ in stop() }
    // Register notifications before checking current state, closing startup's
    // already-locked gap. Unknown session state does not authorize reuse.
    guard let session = CGSessionCopyCurrentDictionary() as? [String: Any],
          session[kCGSessionOnConsoleKey as String] as? Bool == true,
          session["CGSSessionScreenIsLocked"] as? Bool != true else { stop(); exit(1) }
    let monitor = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .userInitiated))
    monitor.schedule(deadline: .now(), repeating: .milliseconds(50))
    monitor.setEventHandler {
        guard getppid() == parent else { stop(); return }
        do { try lease.check() } catch { stop() }
    }
    monitor.resume()
    let worker = DispatchQueue(label: "mordred.presence.ecdh")
    let authorization = PresenceAuthorization(lease: lease)
    let authenticate: () throws -> Void = {
        let done = DispatchSemaphore(value: 0)
        var allowed = false
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason ?? purpose.reason) { success, _ in
            if success {
                do { try lease.authenticated(); allowed = true } catch { }
            }
            done.signal()
        }
        guard done.wait(timeout: .now() + 120) == .success, allowed else {
            throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "authentication denied or cancelled")
        }
    }
    let slots = DispatchSemaphore(value: 17)
    DispatchQueue.global(qos: .userInitiated).async {
        var frame = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        let keys = PresenceKeys(limit: maxKeys) // tags and fingerprints only; no SecKey retained
        while true {
            let count = read(STDIN_FILENO, &buffer, buffer.count)
            guard count > 0 else { stop(); return }
            for byte in buffer.prefix(count) {
                frame.append(byte)
                guard frame.count <= 65536 else { stop(); return }
                if byte != 10 { continue }
                guard slots.wait(timeout: .now()) == .success else { stop(); return }
                let requestData = frame
                frame.removeAll(keepingCapacity: true)
                let admitted = continuousSeconds()
                // Request timeout includes queueing and authentication.
                let timeout = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
                timeout.schedule(deadline: .now() + 120)
                timeout.setEventHandler(handler: stop)
                timeout.resume()
                worker.async {
                    defer { timeout.cancel(); slots.signal() }
                    do {
                        // An operation window may confirm presence before it uses any key, so
                        // a missed prompt stops the operation before it has changed anything.
                        if maxKeys > 1, let request = try? JSONDecoder().decode(Request.self, from: requestData),
                           request.cmd == "authenticate", request.tag_hex == nil, request.store == nil {
                            try authorization.perform(authenticate: authenticate, exchange: { () })
                            let reply = try JSONSerialization.data(withJSONObject: ["ok": true]) + Data([10])
                            try lease.check()
                            FileHandle.standardOutput.write(reply)
                            return
                        }
                        guard let request = try? JSONDecoder().decode(Request.self, from: requestData), request.cmd == "ecdh",
                              let tag = request.tag_hex, let tagData = hexDecode(tag), !tagData.isEmpty,
                              let peerHex = request.peer_pub_hex, let peer = hexDecode(peerHex) else {
                            throw HelperError(domain: "helper", status: -1, message: "invalid presence request")
                        }
                        presenceStoreOverride = try presenceStore(request.store, maxKeys: maxKeys)
                        defer { presenceStoreOverride = nil }
                        let blobDigest = SHA256.hash(data: try readBlob(tagHex: tag))
                        try keys.admit(tag: tag, store: request.store, digest: blobDigest)
                        let shared = try authorization.perform(authenticate: authenticate, exchange: {
                            // Reload the key and perform ECDH on every request.
                            try ecdh(tagHex: tag, peerPub: peer, authenticationContext: context, checkPresence: { try lease.check() })
                        })
                        guard SHA256.hash(data: try readBlob(tagHex: tag)) == blobDigest else {
                            throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "key changed during exchange")
                        }
                        guard continuousSeconds() - admitted < 120 else {
                            throw HelperError(domain: "helper", status: -1, message: "presence request timed out")
                        }
                        let reply = try JSONSerialization.data(withJSONObject: ["shared_hex": hexEncode(shared)]) + Data([10])
                        try lease.check()
                        FileHandle.standardOutput.write(reply)
                    } catch let error as HelperError {
                        lease.revoke()
                        context.invalidate()
                        emit(["error": ["domain": error.domain, "status": error.status, "message": error.message]])
                        FileHandle.standardOutput.write(Data([10]))
                        exit(1)
                    } catch {
                        // No retry after any authentication or ECDH failure.
                        stop()
                    }
                }
            }
        }
    }
    withExtendedLifetime((sleepObserver, sessionObserver, lockObserver, monitor)) {
        RunLoop.main.run()
    }
    stop()
    exit(1)
}
