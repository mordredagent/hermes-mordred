import CryptoKit
import XCTest
@testable import mordred_hermes_sekey

final class PresenceTests: XCTestCase {
    func testDeadlineDoesNotSlideAndIncludesSleep() throws {
        var now = 100.0
        let lease = PresenceLease(seconds: 300, clock: { now })
        try lease.authenticated()
        now = 399
        try lease.check()
        try lease.authenticated()
        now = 400
        XCTAssertThrowsError(try lease.check())
    }

    func testRevocationBeforeAndAfterAuthentication() throws {
        let pending = PresenceLease(seconds: 300)
        pending.revoke()
        XCTAssertThrowsError(try pending.authenticated())
        let active = PresenceLease(seconds: 300)
        try active.authenticated()
        active.revoke()
        XCTAssertThrowsError(try active.check())
    }
}

final class PresenceOptionsTests: XCTestCase {
    func testDefaultsAreTheOriginalSingleKeyCredentialSession() {
        let options = PresenceOptions(arguments: ["--presence-session", "300"])
        XCTAssertEqual(options, PresenceOptions(arguments: ["--presence-session", "300", "--max-keys", "1", "--purpose", "credentials"]))
        XCTAssertEqual(options?.maxKeys, 1)
        XCTAssertEqual(options?.purpose, .credentials)
    }

    func testPurposeAndKeyCount() {
        let options = PresenceOptions(arguments: ["--presence-session", "60", "--purpose", "startup", "--max-keys", "4"])
        XCTAssertEqual(options?.seconds, 60)
        XCTAssertEqual(options?.maxKeys, 4)
        XCTAssertEqual(options?.purpose.reason, "Open Mordred's vault and databases")
    }

    func testMalformedOptionsAreRefused() {
        for arguments in [
            ["--presence-session"],
            ["--presence-session", "x"],
            ["--presence-session", "60", "--max-keys"],
            ["--presence-session", "60", "--max-keys", "0"],
            ["--presence-session", "60", "--max-keys", "9"],
            ["--presence-session", "60", "--purpose", "wallet"],
            ["--presence-session", "60", "--max-keys", "2", "--max-keys", "3"],
            ["--presence-session", "60", "--other", "1"],
            ["--sign", "60"],
        ] {
            XCTAssertNil(PresenceOptions(arguments: arguments), "\(arguments)")
        }
    }
}

final class PresenceKeysTests: XCTestCase {
    func testAtMostTheLimitAndEachKeyStaysBoundToItsFile() throws {
        let first = SHA256.hash(data: Data("one".utf8)), second = SHA256.hash(data: Data("two".utf8))
        let keys = PresenceKeys(limit: 2)
        try keys.admit(tag: "aa", digest: first)
        try keys.admit(tag: "aa", digest: first)
        try keys.admit(tag: "bb", digest: second)
        XCTAssertThrowsError(try keys.admit(tag: "cc", digest: first))
        XCTAssertThrowsError(try keys.admit(tag: "aa", digest: second))
        let single = PresenceKeys(limit: 1)
        try single.admit(tag: "aa", digest: first)
        XCTAssertThrowsError(try single.admit(tag: "bb", digest: second))
    }
}

final class AuthorizationTests: XCTestCase {
    func testOneAuthenticationAndEveryKeyAgreement() throws {
        var now = 0.0
        let lease = PresenceLease(seconds: 300, clock: { now })
        let state = PresenceAuthorization(lease: lease)
        var prompts = 0, exchanges = 0
        for moment in [0.0, 1.0, 299.0] {
            now = moment
            let value = try state.perform(authenticate: { prompts += 1 }, exchange: { exchanges += 1; return exchanges })
            XCTAssertEqual(value, exchanges)
        }
        XCTAssertEqual(prompts, 1)
        XCTAssertEqual(exchanges, 3)
        now = 300
        XCTAssertThrowsError(try state.perform(authenticate: { prompts += 1 }, exchange: { exchanges += 1 }))
        XCTAssertEqual(exchanges, 3)
    }

    func testCrossingDeadlineDiscardsExchangeResultAndDenialRevokes() throws {
        var now = 0.0
        let state = PresenceAuthorization(lease: PresenceLease(seconds: 300, clock: { now }))
        XCTAssertThrowsError(try state.perform(authenticate: {}, exchange: { now = 300; return "discard" }))
        XCTAssertThrowsError(try state.perform(authenticate: {}, exchange: { XCTFail("must not retry") }))
        let denied = PresenceAuthorization(lease: PresenceLease(seconds: 300))
        XCTAssertThrowsError(try denied.perform(authenticate: { throw NSError(domain: "denied", code: 1) }, exchange: { XCTFail("must not exchange") }))
        XCTAssertThrowsError(try denied.perform(authenticate: { XCTFail("must share denial") }, exchange: {}))
    }
}
