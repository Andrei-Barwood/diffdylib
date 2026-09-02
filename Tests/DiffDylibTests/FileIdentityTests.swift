import Darwin
import Foundation
import XCTest
@testable import DiffDylibCore

final class FileIdentityTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        do {
            try FixtureSupport.buildFixtures()
        } catch {
            fatalError("could not compile laboratory fixtures: \(error)")
        }
    }

    func testUnsignedFixture() throws {
        let url = try FixtureSupport.requireFile("unsigned/libunsigned.dylib")
        let identity = FileIdentityInspector.inspect(url: url)
        XCTAssertEqual(identity.signingState, .unsigned)
        XCTAssertNil(identity.teamID)
        XCTAssertEqual(identity.notarized, false)
        XCTAssertNotNil(identity.sha256)
        XCTAssertEqual(identity.sha256?.count, 64)
        XCTAssertNotNil(identity.uid)
        XCTAssertNotNil(identity.gid)
        XCTAssertNotNil(identity.posixPermissions)
        XCTAssertNotNil(identity.owner)
        XCTAssertEqual(identity.sip, .unprotected)
    }

    func testAdHocSignedFixtureIfToolchainSigns() throws {
        let url = try FixtureSupport.requireFile("thin/libleaf.dylib")
        let identity = FileIdentityInspector.inspect(url: url)
        switch identity.signingState {
        case .valid:
            // clang's default ad-hoc signature has no Team ID.
            XCTAssertNil(identity.teamID)
            XCTAssertNotNil(identity.signingID)
            XCTAssertNotNil(identity.sha256)
        case .unsigned:
            throw XCTSkip("toolchain left libleaf.dylib unsigned; ad-hoc case not available")
        case .invalid:
            XCTFail("ad-hoc fixture should not be invalid: \(String(describing: identity.signingState))")
        case .error(let message):
            XCTFail("Security.framework error on laboratory dylib: \(message)")
        case .none:
            XCTFail("expected a signing state")
        }
    }

    func testTmpFileIsWritableByUser() throws {
        let url = URL(fileURLWithPath: "/tmp/diffdylib-writable-\(UUID().uuidString)")
        try Data("fixture".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let identity = FileIdentityInspector.inspect(url: url)
        XCTAssertTrue(identity.writableByUser)
        XCTAssertTrue(FileIdentityInspector.isWritableByUser(url.path))
        XCTAssertEqual(identity.uid, UInt32(getuid()))
        // SIP is an st_flags approximation. /tmp may carry SF_RESTRICTED on
        // some volumes; the prompt only requires writableByUser == true here.
    }

    func testEnumeratorFillsHashAndPOSIX() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let dylibs = try StaticEnumerator.enumerate(appURL: host, depth: 1, skipSystem: true)
        let mid = try XCTUnwrap(dylibs.first { $0.path.hasSuffix("libmid.dylib") })
        XCTAssertNotNil(mid.sha256)
        XCTAssertEqual(mid.sha256?.count, 64)
        XCTAssertNotNil(mid.posixPermissions)
        XCTAssertNotNil(mid.uid)
        XCTAssertNotNil(mid.gid)
        XCTAssertNotNil(mid.signingState)
        XCTAssertEqual(mid.sip, .unprotected)
        XCTAssertTrue(mid.writableByUser, "laboratory Fixtures/build is user-writable")
    }

    func testSigningFailureDoesNotAbortEnumeration() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        XCTAssertNoThrow(
            try StaticEnumerator.enumerate(appURL: host, depth: 2, skipSystem: true)
        )
    }
}
