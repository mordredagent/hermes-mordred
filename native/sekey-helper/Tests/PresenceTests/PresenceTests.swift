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
