import Foundation

/// Expected (baseline) vs observed (another static walk of the same binary).
/// Findings are differential conditions, not malware verdicts.
public enum DifferentialComparator {
    public static func compare(
        baseline: AppBaseline,
        appURL: URL,
        depth: Int = 1,
        skipSystem: Bool = true
    ) throws -> DiffReport {
        let observed = try StaticEnumerator.enumerateDetailed(
            appURL: appURL,
            depth: depth,
            skipSystem: skipSystem
        )
        let executable = try StaticEnumerator.resolveExecutableURL(appURL)
        return compare(
            baseline: baseline,
            observed: observed,
            executableURL: executable
        )
    }

    /// Δ = runtime executable mappings − baseline static set.
    /// Also flags mappings that share a basename but not a path (two `libtbb`).
    public static func compare(
        baseline: AppBaseline,
        pid: pid_t,
        skipSystem: Bool = true
    ) throws -> DiffReport {
        let mappings = try RuntimeEnumerator.listExecutableMappings(pid: pid)
        let executable = try RuntimeEnumerator.processPath(pid: pid)
        return compareRuntime(
            baseline: baseline,
            mappings: mappings,
            executableURL: executable,
            skipSystem: skipSystem
        )
    }

    public static func compareRuntime(
        baseline: AppBaseline,
        mappings: [DylibIdentity],
        executableURL: URL,
        skipSystem: Bool = true
    ) -> DiffReport {
        let bundleDirectory = executableURL.deletingLastPathComponent().path
        let hostPath = executableURL.standardizedFileURL.path
        let runtime = mappings.filter { dylib in
            let path = dylib.resolvedPath ?? dylib.path
            if URL(fileURLWithPath: path).standardizedFileURL.path == hostPath {
                return false
            }
            if skipSystem, systemOwned(dylib) {
                return false
            }
            return true
        }

        var expectedByResolved: [String: DylibIdentity] = [:]
        var expectedByBasename: [String: [DylibIdentity]] = [:]
        for dylib in baseline.dylibs {
            if skipSystem, systemOwned(dylib) { continue }
            if let resolved = standardized(dylib.resolvedPath) {
                expectedByResolved[resolved] = dylib
                expectedByBasename[basename(resolved), default: []].append(dylib)
            } else {
                expectedByBasename[basename(dylib.path), default: []].append(dylib)
            }
        }

        var findings: [DiffFinding] = []
        var addedKeys: Set<String> = []
        var hashChangedKeys: Set<String> = []
        var teamChangedKeys: Set<String> = []
        var seenRuntime = Set<String>()

        for observed in runtime {
            guard let path = standardized(observed.resolvedPath ?? observed.path) else { continue }
            guard seenRuntime.insert(path).inserted else { continue }
            let name = basename(path)

            if let expected = expectedByResolved[path] {
                if hashDiffers(expected.sha256, observed.sha256) {
                    hashChangedKeys.insert(path)
                    findings.append(
                        DiffFinding(
                            kind: .hashChanged,
                            expected: expected,
                            observed: observed,
                            scoreHint: .medium
                        )
                    )
                }
                if expected.teamID != observed.teamID {
                    teamChangedKeys.insert(path)
                    findings.append(
                        DiffFinding(
                            kind: .teamChanged,
                            expected: expected,
                            observed: observed,
                            scoreHint: .medium
                        )
                    )
                }
                continue
            }

            addedKeys.insert(path)
            let score: ScoreHint = systemOwned(observed) ? .low : .medium
            findings.append(DiffFinding(kind: .added, observed: observed, scoreHint: score))

            let collisions = (expectedByBasename[name] ?? []).filter { candidate in
                standardized(candidate.resolvedPath) != path
            }
            if let other = collisions.first {
                findings.append(
                    DiffFinding(
                        kind: .pathChanged,
                        expected: other,
                        observed: observed,
                        scoreHint: .medium
                    )
                )
            }
        }

        let runtimeResolved = seenRuntime
        for dylib in baseline.dylibs {
            if skipSystem, systemOwned(dylib) { continue }
            guard let path = standardized(dylib.resolvedPath) else { continue }
            if !runtimeResolved.contains(path) {
                findings.append(
                    DiffFinding(kind: .removed, expected: dylib, scoreHint: .info)
                )
            }
        }

        for key in addedKeys.union(hashChangedKeys).sorted() {
            guard let observed = runtime.first(where: {
                standardized($0.resolvedPath ?? $0.path) == key
            }) else { continue }
            guard observed.writableByUser else { continue }
            let location = observed.resolvedPath ?? observed.path
            guard isSensitiveLocation(location, bundleDirectory: bundleDirectory) else {
                continue
            }
            let score: ScoreHint = teamChangedKeys.contains(key) ? .high : .medium
            findings.append(
                DiffFinding(
                    kind: .writableUnexpected,
                    expected: expectedByResolved[key],
                    observed: observed,
                    scoreHint: score
                )
            )
        }

        let summary = summarize(
            expectedCount: baseline.dylibs.count,
            observedCount: runtime.count,
            findings: findings
        )
        let host = FileIdentityInspector.inspect(url: executableURL)
        return DiffReport(
            app: AppRef(
                path: executableURL.path,
                signingID: host.signingID ?? baseline.signingID,
                teamID: host.teamID ?? baseline.teamID
            ),
            baselineId: baseline.id,
            findings: findings,
            summary: summary
        )
    }

    private static func standardized(_ path: String?) -> String? {
        guard let path, !path.isEmpty else { return nil }
        return URL(fileURLWithPath: path).standardizedFileURL.path
    }

    private static func basename(_ path: String) -> String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    public static func compare(
        baseline: AppBaseline,
        observed: StaticEnumerationResult,
        executableURL: URL
    ) -> DiffReport {
        let bundleDirectory = executableURL.deletingLastPathComponent().path
        let expected = Dictionary(
            baseline.dylibs.map { (matchKey($0), $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let actual = Dictionary(
            observed.dylibs.map { (matchKey($0), $0) },
            uniquingKeysWith: { first, _ in first }
        )

        var findings: [DiffFinding] = []
        var addedKeys: Set<String> = []
        var hashChangedKeys: Set<String> = []
        var teamChangedKeys: Set<String> = []

        // 1. added
        for (key, dylib) in actual.sorted(by: { $0.key < $1.key }) where expected[key] == nil {
            addedKeys.insert(key)
            let score: ScoreHint = systemOwned(dylib) ? .low : .medium
            findings.append(
                DiffFinding(kind: .added, observed: dylib, scoreHint: score)
            )
        }

        // 2. removed
        for (key, dylib) in expected.sorted(by: { $0.key < $1.key }) where actual[key] == nil {
            findings.append(
                DiffFinding(kind: .removed, expected: dylib, scoreHint: .info)
            )
        }

        // 3–4. hashChanged / teamChanged
        for (key, observedDylib) in actual.sorted(by: { $0.key < $1.key }) {
            guard let expectedDylib = expected[key] else { continue }
            if hashDiffers(expectedDylib.sha256, observedDylib.sha256) {
                hashChangedKeys.insert(key)
                findings.append(
                    DiffFinding(
                        kind: .hashChanged,
                        expected: expectedDylib,
                        observed: observedDylib,
                        scoreHint: .medium
                    )
                )
            }
            if expectedDylib.teamID != observedDylib.teamID {
                teamChangedKeys.insert(key)
                findings.append(
                    DiffFinding(
                        kind: .teamChanged,
                        expected: expectedDylib,
                        observed: observedDylib,
                        scoreHint: .medium
                    )
                )
            }
        }

        // 5. writableUnexpected: added OR hashChanged, writable, sensitive location
        let unexpectedKeys = addedKeys.union(hashChangedKeys)
        for key in unexpectedKeys.sorted() {
            guard let observedDylib = actual[key] else { continue }
            guard observedDylib.writableByUser else { continue }
            let location = observedDylib.resolvedPath ?? observedDylib.path
            guard isSensitiveLocation(location, bundleDirectory: bundleDirectory) else {
                continue
            }
            let score: ScoreHint = teamChangedKeys.contains(key) ? .high : .medium
            findings.append(
                DiffFinding(
                    kind: .writableUnexpected,
                    expected: expected[key],
                    observed: observedDylib,
                    scoreHint: score
                )
            )
        }

        // 6. rpathAmbiguous
        findings.append(contentsOf: rpathAmbiguousFindings(from: observed.dylibs))

        let summary = summarize(
            expectedCount: baseline.dylibs.count,
            observedCount: observed.dylibs.count,
            findings: findings
        )
        let host = FileIdentityInspector.inspect(url: executableURL)
        return DiffReport(
            app: AppRef(
                path: executableURL.path,
                signingID: host.signingID ?? baseline.signingID,
                teamID: host.teamID ?? baseline.teamID
            ),
            baselineId: baseline.id,
            findings: findings,
            summary: summary
        )
    }

    /// Static dependencies match by install name so a planted @rpath hit
    /// does not look like a removed load command. Rpath candidates match
    /// by install name + resolved path (each on-disk hit is its own load).
    static func matchKey(_ dylib: DylibIdentity) -> String {
        let install = dylib.path
        switch dylib.origin {
        case .staticDependency:
            return "static:\(install)"
        case .rpathCandidate:
            return "rpath:\(install)|\(dylib.resolvedPath ?? "")"
        case .runtimeMapping:
            return "runtime:\(dylib.resolvedPath ?? install)"
        }
    }

    static func isSensitiveLocation(_ path: String, bundleDirectory: String?) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let prefixes = [
            "/tmp",
            "/private/tmp",
            "/var/tmp",
            "/private/var/tmp",
            (home as NSString).appendingPathComponent("Library"),
            "/Users",
        ]
        for prefix in prefixes {
            if standardized == prefix || standardized.hasPrefix(prefix + "/") {
                return true
            }
        }
        if let bundleDirectory {
            let bundle = URL(fileURLWithPath: bundleDirectory).standardizedFileURL.path
            if standardized == bundle || standardized.hasPrefix(bundle + "/") {
                return true
            }
        }
        return false
    }

    public static func formatHuman(_ report: DiffReport) -> String {
        var lines: [String] = []
        lines.append("DiffDylib compare (\(report.schema))")
        lines.append("  app:         \(report.app.path)")
        lines.append("  baseline_id: \(report.baselineId)")
        lines.append("  expected:    \(report.summary.expectedCount)")
        lines.append("  observed:    \(report.summary.observedCount)")
        lines.append("  findings:    \(report.findings.count)")
        lines.append("  highest:     \(report.summary.highestScoreHint?.rawValue ?? "none")")
        for finding in report.findings {
            let name = finding.observed?.path ?? finding.expected?.path ?? "(unknown)"
            lines.append("    [\(finding.scoreHint.rawValue)] \(finding.kind.rawValue)  \(name)")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func hashDiffers(_ expected: String?, _ observed: String?) -> Bool {
        guard expected != nil || observed != nil else { return false }
        return expected != observed
    }

    private static func systemOwned(_ dylib: DylibIdentity) -> Bool {
        if let resolved = dylib.resolvedPath, StaticEnumerator.isSystemPath(resolved) {
            return true
        }
        return StaticEnumerator.isSystemPath(dylib.path)
    }

    private static func rpathAmbiguousFindings(from dylibs: [DylibIdentity]) -> [DiffFinding] {
        var grouped: [String: [DylibIdentity]] = [:]
        for dylib in dylibs where dylib.origin == .rpathCandidate {
            grouped[dylib.path, default: []].append(dylib)
        }
        var findings: [DiffFinding] = []
        for installName in grouped.keys.sorted() {
            let hits = grouped[installName] ?? []
            let unique = Array(Set(hits.compactMap(\.resolvedPath))).sorted()
            guard unique.count >= 2 else { continue }
            let first = hits.first { $0.resolvedPath == unique[0] }
            let second = hits.first { $0.resolvedPath == unique[1] }
            findings.append(
                DiffFinding(
                    kind: .rpathAmbiguous,
                    expected: first,
                    observed: second,
                    scoreHint: .medium
                )
            )
        }
        return findings
    }

    private static func summarize(
        expectedCount: Int,
        observedCount: Int,
        findings: [DiffFinding]
    ) -> DiffSummary {
        var summary = DiffSummary(expectedCount: expectedCount, observedCount: observedCount)
        for finding in findings {
            switch finding.kind {
            case .added: summary.added += 1
            case .removed: summary.removed += 1
            case .hashChanged: summary.hashChanged += 1
            case .teamChanged: summary.teamChanged += 1
            case .pathChanged: summary.pathChanged += 1
            case .writableUnexpected: summary.writableUnexpected += 1
            case .rpathAmbiguous: summary.rpathAmbiguous += 1
            }
            if summary.highestScoreHint == nil || finding.scoreHint > summary.highestScoreHint! {
                summary.highestScoreHint = finding.scoreHint
            }
        }
        return summary
    }
}
