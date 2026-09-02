import Foundation
import XCTest
@testable import DiffDylibCore

final class BaselineStoreTests: XCTestCase {
    private var scratch: URL!

    override class func setUp() {
        super.setUp()
        do {
            try FixtureSupport.buildFixtures()
        } catch {
            fatalError("could not compile laboratory fixtures: \(error)")
        }
    }

    override func setUpWithError() throws {
        scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("diffdylib-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let scratch {
            try? FileManager.default.removeItem(at: scratch)
        }
    }

    func testCaptureWritesJSONBaseline() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let out = scratch.appendingPathComponent("hello.json")
        let result = try BaselineCapture.capture(appURL: host, outURL: out)

        XCTAssertTrue(FileManager.default.fileExists(atPath: out.path))
        XCTAssertEqual(result.baseline.schema, DiffDylibSchema.baselineV1)
        XCTAssertEqual(result.baseline.revision, 1)
        XCTAssertEqual(result.baseline.appPath, host.standardizedFileURL.path)
        XCTAssertNotNil(result.baseline.binarySHA256)
        XCTAssertEqual(result.baseline.binarySHA256?.count, 64)
        XCTAssertFalse(result.replaced)

        let loaded = try BaselineCapture.loadJSON(from: out)
        XCTAssertEqual(loaded.id, result.baseline.id)
        XCTAssertEqual(loaded.naturalKey, result.baseline.naturalKey)
        XCTAssertTrue(loaded.dylibs.contains { $0.path.hasSuffix("libmid.dylib") })
    }

    func testSQLiteCreatesRevisionsForSameKey() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let storeURL = scratch.appendingPathComponent("baselines.sqlite")
        let out1 = scratch.appendingPathComponent("r1.json")
        let out2 = scratch.appendingPathComponent("r2.json")

        let first = try BaselineCapture.capture(
            appURL: host,
            outURL: out1,
            storeURL: storeURL
        )
        let second = try BaselineCapture.capture(
            appURL: host,
            outURL: out2,
            storeURL: storeURL
        )

        XCTAssertEqual(first.baseline.revision, 1)
        XCTAssertEqual(second.baseline.revision, 2)
        XCTAssertEqual(first.baseline.naturalKey, second.baseline.naturalKey)
        XCTAssertNotEqual(first.baseline.id, second.baseline.id)
        XCTAssertFalse(second.replaced)
        XCTAssertTrue(
            second.baseline.notes.contains { $0.contains("revision 2") }
        )

        let store = try SQLiteBaselineStore(url: storeURL)
        defer { store.close() }
        let revisions = try store.allRevisions(for: first.baseline.naturalKey)
        XCTAssertEqual(revisions.map(\.revision), [1, 2])
        XCTAssertEqual(try store.latest(for: first.baseline.naturalKey)?.id, second.baseline.id)
    }

    func testReplaceOverwritesLatestRevision() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let storeURL = scratch.appendingPathComponent("baselines.sqlite")
        let out = scratch.appendingPathComponent("cap.json")

        let first = try BaselineCapture.capture(
            appURL: host,
            outURL: out,
            storeURL: storeURL
        )
        let replaced = try BaselineCapture.capture(
            appURL: host,
            outURL: out,
            storeURL: storeURL,
            replace: true
        )

        XCTAssertEqual(first.baseline.revision, 1)
        XCTAssertEqual(replaced.baseline.revision, 1)
        XCTAssertTrue(replaced.replaced)
        XCTAssertNotEqual(replaced.baseline.id, first.baseline.id)

        let store = try SQLiteBaselineStore(url: storeURL)
        defer { store.close() }
        let revisions = try store.allRevisions(for: first.baseline.naturalKey)
        XCTAssertEqual(revisions.count, 1)
        XCTAssertEqual(revisions.first?.id, replaced.baseline.id)
    }

    func testNaturalKeyUsesSigningIdPathAndHash() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let baseline = try BaselineCapture.make(appURL: host)
        let inspected = FileIdentityInspector.inspect(url: host)
        XCTAssertEqual(baseline.naturalKey.appPath, host.standardizedFileURL.path)
        XCTAssertEqual(baseline.naturalKey.binarySHA256, inspected.sha256)
        XCTAssertEqual(baseline.naturalKey.signingID, inspected.signingID ?? "")
    }

    func testShowFormatterMentionsAppAndDylibCount() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let baseline = try BaselineCapture.make(appURL: host)
        let text = BaselineFormatter.human(baseline)
        XCTAssertTrue(text.contains("DiffDylib baseline"))
        XCTAssertTrue(text.contains(host.lastPathComponent))
        XCTAssertTrue(text.contains("dylibs:"))
    }

    func testExpandTilde() {
        let expanded = BaselineCapture.expandPath("~/.diffdylib/baselines.sqlite")
        XCTAssertTrue(expanded.hasPrefix(FileManager.default.homeDirectoryForCurrentUser.path))
        XCTAssertTrue(expanded.hasSuffix(".diffdylib/baselines.sqlite"))
        XCTAssertFalse(expanded.contains("~"))
    }
}
