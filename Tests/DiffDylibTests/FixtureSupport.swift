import Foundation
import XCTest

enum FixtureSupport {
    static var packageRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // Tests/DiffDylibTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // package root
    }

    static var fixturesRoot: URL {
        packageRoot.appendingPathComponent("Fixtures")
    }

    static var buildRoot: URL {
        fixturesRoot.appendingPathComponent("build")
    }

    static func buildFixtures() throws {
        let script = fixturesRoot.appendingPathComponent("build-fixtures.sh")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: script.path),
            "missing \(script.path)"
        )
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [script.path]
        process.currentDirectoryURL = fixturesRoot
        let err = Pipe()
        process.standardError = err
        process.standardOutput = Pipe()
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus != 0 {
            let message = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw NSError(
                domain: "FixtureSupport",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "build-fixtures.sh failed: \(message)"]
            )
        }
    }

    static func file(_ relative: String) -> URL {
        buildRoot.appendingPathComponent(relative)
    }

    static func requireFile(_ relative: String) throws -> URL {
        let url = file(relative)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw NSError(
                domain: "FixtureSupport",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing required fixture \(relative)"]
            )
        }
        return url
    }
}
