import Foundation
import XCTest
@testable import DiffDylibCore

final class ModelSerializationTests: XCTestCase {
    func testDylibIdentityRoundTrip() throws {
        let identity = DylibIdentity(
            path: "@rpath/libfixture.dylib",
            resolvedPath: "/tmp/DiffDylibLab/libfixture.dylib",
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            teamID: nil,
            signingID: nil,
            posixPermissions: 0o100644,
            owner: "tester:staff",
            writableByUser: true,
            origin: .rpathCandidate
        )

        let data = try DiffDylibJSON.encode(identity)
        let decoded = try DiffDylibJSON.decode(DylibIdentity.self, from: data)

        XCTAssertEqual(decoded, identity)

        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(object?["resolved_path"] as? String, identity.resolvedPath)
        XCTAssertEqual(object?["team_id"] as? String, nil)
        XCTAssertEqual(object?["writable_by_user"] as? Bool, true)
        XCTAssertEqual(object?["origin"] as? String, "rpathCandidate")
    }

    func testAppBaselineRoundTrip() throws {
        let capturedAt = DiffDylibJSON.iso8601Date(from: "2026-09-02T12:00:00.250Z")!
        let baseline = AppBaseline(
            id: "baseline-fixture-1",
            appPath: "/tmp/DiffDylibLab/HelloHost",
            signingID: "com.dyld87.hellohost",
            teamID: nil,
            capturedAt: capturedAt,
            dylibs: [
                DylibIdentity(
                    path: "@executable_path/libLegitA.dylib",
                    resolvedPath: "/tmp/DiffDylibLab/libLegitA.dylib",
                    writableByUser: false,
                    origin: .staticDependency
                ),
            ],
            notes: ["laboratory fixture, not a production app"]
        )

        let data = try DiffDylibJSON.encode(baseline)
        let decoded = try DiffDylibJSON.decode(AppBaseline.self, from: data)

        XCTAssertEqual(decoded.schema, DiffDylibSchema.baselineV1)
        XCTAssertEqual(decoded.id, baseline.id)
        XCTAssertEqual(decoded.appPath, baseline.appPath)
        XCTAssertEqual(decoded.signingID, baseline.signingID)
        XCTAssertEqual(decoded.dylibs, baseline.dylibs)
        XCTAssertEqual(decoded.notes, baseline.notes)
        XCTAssertEqual(
            DiffDylibJSON.iso8601String(from: decoded.capturedAt),
            DiffDylibJSON.iso8601String(from: capturedAt)
        )

        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(object?["schema"] as? String, "dyld87.baseline.v1")
        XCTAssertEqual(object?["app_path"] as? String, baseline.appPath)
        XCTAssertEqual(object?["captured_at"] as? String, "2026-09-02T12:00:00.250Z")
    }

    func testDiffReportRoundTrip() throws {
        let expected = DylibIdentity(
            path: "/usr/lib/libz.1.dylib",
            resolvedPath: "/usr/lib/libz.1.dylib",
            teamID: nil,
            writableByUser: false,
            origin: .staticDependency
        )
        let observed = DylibIdentity(
            path: "/tmp/libz.1.dylib",
            resolvedPath: "/tmp/libz.1.dylib",
            writableByUser: true,
            origin: .rpathCandidate
        )
        let finding = DiffFinding(
            kind: .writableUnexpected,
            expected: expected,
            observed: observed,
            scoreHint: .medium
        )
        let report = DiffReport(
            app: AppRef(
                path: "/tmp/DiffDylibLab/HelloHost",
                signingID: "com.dyld87.hellohost",
                teamID: nil
            ),
            baselineId: "baseline-fixture-1",
            findings: [
                finding,
                DiffFinding(kind: .added, observed: observed, scoreHint: .medium),
                DiffFinding(kind: .removed, expected: expected, scoreHint: .info),
            ],
            summary: DiffSummary(
                expectedCount: 1,
                observedCount: 1,
                added: 1,
                removed: 1,
                hashChanged: 0,
                teamChanged: 0,
                pathChanged: 1,
                writableUnexpected: 1,
                highestScoreHint: .medium
            )
        )

        let data = try DiffDylibJSON.encode(report)
        let decoded = try DiffDylibJSON.decode(DiffReport.self, from: data)

        XCTAssertEqual(decoded, report)
        XCTAssertEqual(decoded.schema, DiffDylibSchema.diffReportV1)
        XCTAssertEqual(decoded.findings.map(\.kind), [.writableUnexpected, .added, .removed])
        XCTAssertEqual(decoded.summary.highestScoreHint, .medium)

        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(object?["schema"] as? String, "dyld87.diff-report.v1")
        XCTAssertEqual(object?["baseline_id"] as? String, "baseline-fixture-1")
        let summary = object?["summary"] as? [String: Any]
        XCTAssertEqual(summary?["writable_unexpected"] as? Int, 1)
        XCTAssertEqual(summary?["highest_score_hint"] as? String, "medium")
    }

    func testScoreHintOrdering() {
        XCTAssertLessThan(ScoreHint.info, ScoreHint.low)
        XCTAssertLessThan(ScoreHint.low, ScoreHint.medium)
        XCTAssertLessThan(ScoreHint.medium, ScoreHint.high)
    }

    func testFindingKindsAndOriginsAreStableStrings() throws {
        let kinds: [DiffFindingKind] = [
            .added, .removed, .hashChanged, .teamChanged, .pathChanged, .writableUnexpected,
            .rpathAmbiguous,
        ]
        let encodedKinds = try kinds.map { kind -> String in
            let data = try DiffDylibJSON.encode(kind)
            return String(decoding: data, as: UTF8.self).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        }
        XCTAssertEqual(
            encodedKinds,
            [
                "added", "removed", "hashChanged", "teamChanged", "pathChanged",
                "writableUnexpected", "rpathAmbiguous",
            ]
        )

        let origins: [DylibOrigin] = [.staticDependency, .rpathCandidate, .runtimeMapping]
        let encodedOrigins = try origins.map { origin -> String in
            let data = try DiffDylibJSON.encode(origin)
            return String(decoding: data, as: UTF8.self).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        }
        XCTAssertEqual(
            encodedOrigins,
            ["staticDependency", "rpathCandidate", "runtimeMapping"]
        )
    }
}
