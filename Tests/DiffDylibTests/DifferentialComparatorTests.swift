import Foundation
import XCTest
@testable import DiffDylibCore

final class DifferentialComparatorTests: XCTestCase {
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
        scratch = URL(fileURLWithPath: "/tmp/diffdylib-compare-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let scratch {
            try? FileManager.default.removeItem(at: scratch)
        }
    }

    func testCleanCompareHasNoFindings() throws {
        let source = try FixtureSupport.requireFile("thin/hello_host").deletingLastPathComponent()
        let copy = scratch.appendingPathComponent("thin")
        try FileManager.default.copyItem(at: source, to: copy)
        let host = copy.appendingPathComponent("hello_host")
        let baseline = try BaselineCapture.make(appURL: host)
        let report = try DifferentialComparator.compare(baseline: baseline, appURL: host)
        XCTAssertTrue(report.findings.isEmpty, "\(report.findings.map(\.kind))")
        XCTAssertFalse(report.summary.hasMediumOrHigh)
    }

    func testPlantedRpathDylibIsAddedAndWritableUnexpected() throws {
        let source = FixtureSupport.file("rpath")
        let copy = scratch.appendingPathComponent("rpath")
        try FileManager.default.copyItem(at: source, to: copy)
        let host = copy.appendingPathComponent("host")
        let planted = copy.appendingPathComponent("r1/libcollide.dylib")
        try FileManager.default.removeItem(at: planted)

        let baseline = try BaselineCapture.make(appURL: host)
        XCTAssertFalse(baseline.dylibs.contains { $0.origin == .rpathCandidate })

        try FileManager.default.copyItem(
            at: copy.appendingPathComponent("r2/libcollide.dylib"),
            to: planted
        )

        let report = try DifferentialComparator.compare(baseline: baseline, appURL: host)
        let kinds = report.findings.map(\.kind)
        XCTAssertTrue(kinds.contains(.added), "expected added, got \(kinds)")
        XCTAssertTrue(kinds.contains(.rpathAmbiguous), "expected rpathAmbiguous, got \(kinds)")
        XCTAssertTrue(
            kinds.contains(.writableUnexpected),
            "planted dylib under /tmp should be writableUnexpected, got \(kinds)"
        )
        XCTAssertTrue(report.summary.hasMediumOrHigh)
        XCTAssertTrue(
            report.findings.contains { $0.kind == .added && ($0.observed?.resolvedPath?.contains("/r1/") ?? false) }
        )
    }

    func testHashChangedOnOverwrittenDylib() throws {
        let source = try FixtureSupport.requireFile("thin/hello_host").deletingLastPathComponent()
        let copy = scratch.appendingPathComponent("thin-hash")
        try FileManager.default.copyItem(at: source, to: copy)
        let host = copy.appendingPathComponent("hello_host")
        let baseline = try BaselineCapture.make(appURL: host)

        let libmid = copy.appendingPathComponent("libmid.dylib")
        var bytes = try Data(contentsOf: libmid)
        bytes.append(0xFF)
        try bytes.write(to: libmid)

        let report = try DifferentialComparator.compare(baseline: baseline, appURL: host)
        let kinds = report.findings.map(\.kind)
        XCTAssertTrue(kinds.contains(.hashChanged), "expected hashChanged, got \(kinds)")
        XCTAssertTrue(kinds.contains(.writableUnexpected), "expected writableUnexpected, got \(kinds)")
        XCTAssertEqual(
            report.findings.first { $0.kind == .writableUnexpected }?.scoreHint,
            .medium
        )
    }

    func testRemovedWhenDepthDrops() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let baseline = try BaselineCapture.make(appURL: host, depth: 2)
        XCTAssertTrue(baseline.dylibs.contains { $0.path.hasSuffix("libleaf.dylib") })
        let report = try DifferentialComparator.compare(
            baseline: baseline,
            appURL: host,
            depth: 1
        )
        XCTAssertTrue(report.findings.contains { $0.kind == .removed })
        XCTAssertEqual(report.findings.first { $0.kind == .removed }?.scoreHint, .info)
        XCTAssertFalse(
            report.findings.filter { $0.kind == .removed }.contains { $0.scoreHint >= .medium }
        )
    }

    func testAddedSystemPathIsLowAndNotBlocking() throws {
        let host = try FixtureSupport.requireFile("libz_host")
        let baseline = try BaselineCapture.make(appURL: host, skipSystem: true)
        let report = try DifferentialComparator.compare(
            baseline: baseline,
            appURL: host,
            skipSystem: false
        )
        let added = report.findings.filter { $0.kind == .added }
        XCTAssertFalse(added.isEmpty)
        XCTAssertTrue(added.allSatisfy { $0.scoreHint == .low })
        XCTAssertFalse(report.summary.hasMediumOrHigh)
    }

    func testWritableUnexpectedPlusTeamChangedIsHigh() {
        let expected = DylibIdentity(
            path: "@rpath/libx.dylib",
            resolvedPath: "/tmp/libx.dylib",
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            teamID: "TEAMAAAA",
            writableByUser: true,
            origin: .staticDependency
        )
        let observed = DylibIdentity(
            path: "@rpath/libx.dylib",
            resolvedPath: "/tmp/libx.dylib",
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            teamID: "TEAMBBBB",
            writableByUser: true,
            origin: .staticDependency
        )
        let baseline = AppBaseline(appPath: "/tmp/host", dylibs: [expected])
        let enumeration = StaticEnumerationResult(
            appPath: "/tmp/host",
            executablePath: "/tmp/host",
            depth: 1,
            skipSystem: true,
            dylibs: [observed],
            findings: []
        )
        let report = DifferentialComparator.compare(
            baseline: baseline,
            observed: enumeration,
            executableURL: URL(fileURLWithPath: "/tmp/host")
        )
        let unexpected = report.findings.first { $0.kind == .writableUnexpected }
        XCTAssertEqual(unexpected?.scoreHint, .high)
        XCTAssertTrue(report.summary.hasMediumOrHigh)
    }
}
