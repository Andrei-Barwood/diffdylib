import Darwin
import Foundation
import XCTest
@testable import DiffDylibCore

final class RuntimeEnumeratorTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        do {
            try FixtureSupport.buildFixtures()
        } catch {
            fatalError("could not compile laboratory fixtures: \(error)")
        }
    }

    func testListExecutableMappingsIncludesHostAndLinkedDylib() throws {
        let host = try FixtureSupport.requireFile("thin/linger_host")
        let process = try spawnLinger(host)
        defer { terminate(process) }

        let pid = process.processIdentifier
        let mappings = try RuntimeEnumerator.listExecutableMappings(pid: pid)
        let paths = mappings.map { URL(fileURLWithPath: $0.resolvedPath ?? $0.path).standardizedFileURL.path }

        let hostPath = host.standardizedFileURL.path
        XCTAssertTrue(
            paths.contains(hostPath),
            "main executable missing from mappings: \(paths)"
        )
        XCTAssertTrue(
            paths.contains { $0.hasSuffix("/libmid.dylib") },
            "linked libmid.dylib missing from mappings: \(paths)"
        )
        XCTAssertTrue(mappings.allSatisfy { $0.origin == .runtimeMapping })
        XCTAssertTrue(mappings.contains { $0.sha256 != nil && ($0.resolvedPath ?? "").hasSuffix("libmid.dylib") })
    }

    func testProcessPathMatchesSpawnedHost() throws {
        let host = try FixtureSupport.requireFile("thin/linger_host")
        let process = try spawnLinger(host)
        defer { terminate(process) }
        let path = try RuntimeEnumerator.processPath(pid: process.processIdentifier)
        XCTAssertEqual(path.standardizedFileURL, host.standardizedFileURL)
    }

    func testMissingPidThrows() {
        XCTAssertThrowsError(try RuntimeEnumerator.listExecutableMappings(pid: 999_999_999)) { error in
            guard let typed = error as? RuntimeEnumerationError else {
                return XCTFail("expected RuntimeEnumerationError, got \(error)")
            }
            XCTAssertEqual(typed, .processNotFound(999_999_999))
        }
    }

    func testRuntimeCompareFlagsBasenameCollision() throws {
        let baselineLib = DylibIdentity(
            path: "@rpath/libtbb.12.6.dylib",
            resolvedPath: "/tmp/Photoshop.app/Contents/Frameworks/libtbb.12.6.dylib",
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            teamID: "ADOBE",
            origin: .staticDependency
        )
        let hijacker = DylibIdentity(
            path: "/tmp/Photoshop.app/Contents/MacOS/libtbb.12.6.dylib",
            resolvedPath: "/tmp/Photoshop.app/Contents/MacOS/libtbb.12.6.dylib",
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            teamID: nil,
            writableByUser: true,
            origin: .runtimeMapping
        )
        let legit = DylibIdentity(
            path: "/tmp/Photoshop.app/Contents/Frameworks/libtbb.12.6.dylib",
            resolvedPath: "/tmp/Photoshop.app/Contents/Frameworks/libtbb.12.6.dylib",
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            teamID: "ADOBE",
            origin: .runtimeMapping
        )
        let baseline = AppBaseline(
            appPath: "/tmp/Photoshop.app/Contents/MacOS/Photoshop",
            dylibs: [baselineLib]
        )
        let report = DifferentialComparator.compareRuntime(
            baseline: baseline,
            mappings: [hijacker, legit],
            executableURL: URL(fileURLWithPath: "/tmp/Photoshop.app/Contents/MacOS/Photoshop"),
            skipSystem: true
        )
        let kinds = report.findings.map(\.kind)
        XCTAssertTrue(kinds.contains(.added), "hijacker should be Δ added, got \(kinds)")
        XCTAssertTrue(kinds.contains(.pathChanged), "same basename different path, got \(kinds)")
        XCTAssertFalse(kinds.contains(.removed))
    }

    func testRuntimeCompareAgainstLiveFixture() throws {
        let host = try FixtureSupport.requireFile("thin/linger_host")
        let baseline = try BaselineCapture.make(appURL: host, depth: 2, skipSystem: true)
        let process = try spawnLinger(host)
        defer { terminate(process) }

        let report = try DifferentialComparator.compare(
            baseline: baseline,
            pid: process.processIdentifier,
            skipSystem: true
        )
        XCTAssertEqual(report.baselineId, baseline.id)
        XCTAssertFalse(
            report.findings.contains { $0.kind == .removed && ($0.expected?.path.hasSuffix("libmid.dylib") ?? false) },
            "libmid should be present at runtime: \(report.findings.map(\.kind))"
        )
    }

    private func spawnLinger(_ url: URL) throws -> Process {
        let process = Process()
        process.executableURL = url
        process.currentDirectoryURL = url.deletingLastPathComponent()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        var alive = false
        for _ in 0..<50 {
            if kill(process.processIdentifier, 0) == 0 {
                alive = true
                break
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertTrue(alive, "linger_host did not start")
        Thread.sleep(forTimeInterval: 0.05)
        return process
    }

    private func terminate(_ process: Process) {
        process.terminate()
        process.waitUntilExit()
    }
}
