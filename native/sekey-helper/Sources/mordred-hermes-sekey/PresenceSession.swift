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

func presenceSession(seconds: Int) -> Never {
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
    let slots = DispatchSemaphore(value: 17)
    DispatchQueue.global(qos: .userInitiated).async {
        var frame = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        var boundBlob: SHA256.Digest? // non-secret source fingerprint only
        var boundTag: String?      // one key per session; no SecKey retained
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
                        guard let request = try? JSONDecoder().decode(Request.self, from: requestData), request.cmd == "ecdh",
                              let tag = request.tag_hex, let tagData = hexDecode(tag), !tagData.isEmpty,
                              let peerHex = request.peer_pub_hex, let peer = hexDecode(peerHex),
                              boundTag == nil || boundTag == tag else {
                            throw HelperError(domain: "helper", status: -1, message: "invalid presence request")
                        }
                        boundTag = tag
                        let blobDigest = SHA256.hash(data: try readBlob(tagHex: tag))
                        guard boundBlob == nil || boundBlob == blobDigest else {
                            throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "key changed")
                        }
                        boundBlob = blobDigest
                        let shared = try authorization.perform(authenticate: {
                            let done = DispatchSemaphore(value: 0)
                            var allowed = false
                            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Read Mordred Telegram or mail credentials") { success, _ in
                                if success {
                                    do { try lease.authenticated(); allowed = true } catch { }
                                }
                                done.signal()
                            }
                            guard done.wait(timeout: .now() + 120) == .success, allowed else {
                                throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "authentication denied or cancelled")
                            }
                        }, exchange: {
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
