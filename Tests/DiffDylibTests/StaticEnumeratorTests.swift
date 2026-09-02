import Darwin
import Foundation
import XCTest
@testable import DiffDylibCore

final class StaticEnumeratorTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        do {
            try FixtureSupport.buildFixtures()
        } catch {
            fatalError("could not compile laboratory fixtures: \(error)")
        }
    }

    func testThinHostListsFirstLevelOwnDylibAndSkipsLibSystem() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let result = try StaticEnumerator.enumerateDetailed(
            appURL: host,
            depth: 1,
            skipSystem: true
        )

        XCTAssertTrue(result.findings.isEmpty)
        let names = result.dylibs.map(\.path)
        XCTAssertTrue(
            names.contains { $0.hasSuffix("libmid.dylib") },
            "expected @rpath/libmid.dylib, got \(names)"
        )
        XCTAssertFalse(names.contains { $0.hasSuffix("libleaf.dylib") })
        XCTAssertFalse(result.dylibs.contains { identity in
            (identity.resolvedPath.map { StaticEnumerator.isSystemPath($0) } ?? false)
                || StaticEnumerator.isSystemPath(identity.path)
        })
        XCTAssertEqual(
            result.dylibs.filter { $0.path.hasSuffix("libmid.dylib") }.first?.origin,
            .staticDependency
        )
    }

    func testDepthTwoWalksIntoLibmid() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let result = try StaticEnumerator.enumerateDetailed(
            appURL: host,
            depth: 2,
            skipSystem: true
        )
        let names = result.dylibs.map(\.path)
        XCTAssertTrue(names.contains { $0.hasSuffix("libmid.dylib") })
        XCTAssertTrue(
            names.contains { $0.hasSuffix("libleaf.dylib") },
            "depth 2 should reach libleaf, got \(names)"
        )
    }

    func testFatAndThinDeclareTheSameDependencies() throws {
        let thin = try FixtureSupport.requireFile("thin/hello_host")
        let fat = FixtureSupport.file("fat/hello_host")
        if !FileManager.default.fileExists(atPath: fat.path) {
            throw XCTSkip("fat fixture not built by this toolchain")
        }

        let fatHeader = try Data(contentsOf: fat)
        XCTAssertGreaterThanOrEqual(fatHeader.count, 4)
        var magic: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &magic) { dest in
            fatHeader.copyBytes(to: dest, from: 0..<4)
        }
        XCTAssertTrue(
            magic == MachOParser.fatCigam
                || magic == MachOParser.fatMagic
                || magic == MachOParser.fatCigam64
                || magic == MachOParser.fatMagic64,
            "fat fixture magic was \(String(magic, radix: 16))"
        )

        let thinNames = Set(
            try StaticEnumerator.enumerate(appURL: thin, depth: 1, skipSystem: true).map(\.path)
        )
        let fatNames = Set(
            try StaticEnumerator.enumerate(appURL: fat, depth: 1, skipSystem: true).map(\.path)
        )
        XCTAssertEqual(thinNames, fatNames)
    }

    func testSkipSystemOmitsLibZ() throws {
        let host = try FixtureSupport.requireFile("libz_host")
        let skipped = try StaticEnumerator.enumerate(appURL: host, depth: 1, skipSystem: true)
        XCTAssertFalse(
            skipped.contains { ($0.resolvedPath ?? $0.path).contains("libz") },
            "skip-system should drop libz, got \(skipped.map(\.path))"
        )

        let included = try StaticEnumerator.enumerate(appURL: host, depth: 1, skipSystem: false)
        XCTAssertTrue(
            included.contains { pathHasLibZ($0) },
            "skipSystem=false should list libz, got \(included.map { $0.resolvedPath ?? $0.path })"
        )
        XCTAssertTrue(
            included.contains { identity in
                if let resolved = identity.resolvedPath {
                    return StaticEnumerator.isSystemPath(resolved)
                }
                return StaticEnumerator.isSystemPath(identity.path)
            }
        )
    }

    func testRpathAmbiguousSynthetic() throws {
        let host = try FixtureSupport.requireFile("rpath/host")
        let result = try StaticEnumerator.enumerateDetailed(
            appURL: host,
            depth: 1,
            skipSystem: true
        )

        let ambiguous = result.findings.filter { $0.kind == .rpathAmbiguous }
        XCTAssertFalse(ambiguous.isEmpty, "expected rpathAmbiguous finding")
        XCTAssertEqual(ambiguous.first?.scoreHint, .medium)

        let candidates = result.dylibs.filter { $0.origin == .rpathCandidate }
        let resolved = Set(candidates.compactMap(\.resolvedPath))
        XCTAssertGreaterThanOrEqual(resolved.count, 2)

        let r1 = FixtureSupport.buildRoot.appendingPathComponent("rpath/r1/libcollide.dylib").path
        let r2 = FixtureSupport.buildRoot.appendingPathComponent("rpath/r2/libcollide.dylib").path
        XCTAssertTrue(resolved.contains(URL(fileURLWithPath: r1).standardizedFileURL.path))
        XCTAssertTrue(resolved.contains(URL(fileURLWithPath: r2).standardizedFileURL.path))
        XCTAssertEqual(candidates.first?.path, "@rpath/libcollide.dylib")
    }

    func testNotMachO() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("diffdylib-not-macho-\(UUID().uuidString).txt")
        try Data("hello".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertThrowsError(try StaticEnumerator.enumerate(appURL: url)) { error in
            guard let typed = error as? StaticEnumerationError else {
                return XCTFail("expected StaticEnumerationError, got \(error)")
            }
            XCTAssertEqual(typed, .notMachO(url.standardizedFileURL))
        }
    }

    func testTruncatedMachO() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("diffdylib-truncated-\(UUID().uuidString).bin")
        // MH_MAGIC_64 little-endian bytes, far too short for a header.
        var magic = MachOParser.mhMagic64
        let data = Data(bytes: &magic, count: 4)
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertThrowsError(try StaticEnumerator.enumerate(appURL: url)) { error in
            guard let typed = error as? StaticEnumerationError else {
                return XCTFail("expected StaticEnumerationError, got \(error)")
            }
            XCTAssertEqual(typed, .truncated(url.standardizedFileURL))
        }
    }

    func testPermissionDenied() throws {
        if getuid() == 0 {
            throw XCTSkip("root can read chmod 000 files")
        }
        let source = try FixtureSupport.requireFile("thin/hello_host")
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("diffdylib-noperm-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: source, to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: url.path)
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertThrowsError(try StaticEnumerator.enumerate(appURL: url)) { error in
            guard let typed = error as? StaticEnumerationError else {
                return XCTFail("expected StaticEnumerationError, got \(error)")
            }
            XCTAssertEqual(typed, .permissionDenied(url.standardizedFileURL))
        }
    }

    func testEnumerateAPIMatchesDetailedDylibs() throws {
        let host = try FixtureSupport.requireFile("thin/hello_host")
        let listed = try StaticEnumerator.enumerate(appURL: host, depth: 1, skipSystem: true)
        let detailed = try StaticEnumerator.enumerateDetailed(
            appURL: host,
            depth: 1,
            skipSystem: true
        )
        XCTAssertEqual(listed, detailed.dylibs)
    }

    func testDoesNotReferenceThirdPartyApplications() {
        // Guardrail: this suite must stay inside Fixtures/ + temp dirs.
        XCTAssertTrue(FixtureSupport.buildRoot.path.contains("Fixtures"))
        XCTAssertFalse(FixtureSupport.buildRoot.path.hasPrefix("/Applications"))
    }

    private func pathHasLibZ(_ identity: DylibIdentity) -> Bool {
        let haystack = (identity.resolvedPath ?? identity.path).lowercased()
        return haystack.contains("libz")
    }
}
