import Foundation

/// How a dylib was observed. Capture/compare layers fill this in later;
/// the skeleton only needs a stable, serializable tag.
public enum DylibOrigin: String, Codable, Equatable, Sendable {
    /// Declared via Mach-O load commands (`LC_LOAD_DYLIB`, weak loads).
    case staticDependency
    /// Candidate that satisfies an `@rpath` search directory.
    case rpathCandidate
    /// File-backed executable mapping seen at runtime.
    case runtimeMapping
}

/// Severity hint for a differential finding. Not a malware verdict.
public enum ScoreHint: String, Codable, Equatable, Sendable, Comparable {
    case info
    case low
    case medium
    case high

    private var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        }
    }

    public static func < (lhs: ScoreHint, rhs: ScoreHint) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// Kind of mismatch between expected (baseline) and observed state.
public enum DiffFindingKind: String, Codable, Equatable, Sendable {
    case added
    case removed
    case hashChanged
    case teamChanged
    case pathChanged
    case writableUnexpected
    /// Same `@rpath` dependency exists in more than one run-path directory.
    /// Dylib Hijack Scanner heuristic. Anomaly, not a malware label.
    case rpathAmbiguous
}

/// Identity of one dynamic library as far as DiffDylib is concerned.
///
/// This is a *nameplate*, not a verdict: path, hash, Team ID, POSIX
/// metadata. Fields stay optional until a later prompt fills them in
/// (hashing, code signing, Mach-O resolution).
public struct DylibIdentity: Codable, Equatable, Sendable {
    /// Install name or observed path (may still contain `@rpath`).
    public var path: String
    /// Absolute path after conservative resolution, if known.
    public var resolvedPath: String?
    /// Hex SHA-256 of the on-disk file, if hashed.
    public var sha256: String?
    /// Code-signing Team ID, if present.
    public var teamID: String?
    /// Code-signing identifier, if present.
    public var signingID: String?
    /// `st_mode` bits (e.g. `0o100755`).
    public var posixPermissions: UInt16?
    /// File owner as `user:group` or username, if known.
    public var owner: String?
    /// True when the effective user can write the file or its parent directory.
    public var writableByUser: Bool
    /// Which enumeration layer produced this identity.
    public var origin: DylibOrigin

    public init(
        path: String,
        resolvedPath: String? = nil,
        sha256: String? = nil,
        teamID: String? = nil,
        signingID: String? = nil,
        posixPermissions: UInt16? = nil,
        owner: String? = nil,
        writableByUser: Bool = false,
        origin: DylibOrigin
    ) {
        self.path = path
        self.resolvedPath = resolvedPath
        self.sha256 = sha256
        self.teamID = teamID
        self.signingID = signingID
        self.posixPermissions = posixPermissions
        self.owner = owner
        self.writableByUser = writableByUser
        self.origin = origin
    }

    enum CodingKeys: String, CodingKey {
        case path
        case resolvedPath = "resolved_path"
        case sha256
        case teamID = "team_id"
        case signingID = "signing_id"
        case posixPermissions = "posix_permissions"
        case owner
        case writableByUser = "writable_by_user"
        case origin
    }
}

/// Expected operating state of an application: the "restraining order"
/// of a differential relay. One capture, one snapshot.
public struct AppBaseline: Codable, Equatable, Sendable {
    /// Document type. Always `dyld87.baseline.v1` for this schema.
    public var schema: String
    /// Stable identifier referenced by `DiffReport.baselineId`.
    public var id: String
    /// Path of the host application or main executable.
    public var appPath: String
    /// Host signing identifier, if known.
    public var signingID: String?
    /// Host Team ID, if known.
    public var teamID: String?
    /// When this baseline was captured.
    public var capturedAt: Date
    /// Dylibs that constitute the expected connected load.
    public var dylibs: [DylibIdentity]
    /// Free-form operator notes (not findings).
    public var notes: [String]

    public init(
        schema: String = DiffDylibSchema.baselineV1,
        id: String = UUID().uuidString,
        appPath: String,
        signingID: String? = nil,
        teamID: String? = nil,
        capturedAt: Date = Date(),
        dylibs: [DylibIdentity] = [],
        notes: [String] = []
    ) {
        self.schema = schema
        self.id = id
        self.appPath = appPath
        self.signingID = signingID
        self.teamID = teamID
        self.capturedAt = capturedAt
        self.dylibs = dylibs
        self.notes = notes
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case id
        case appPath = "app_path"
        case signingID = "signing_id"
        case teamID = "team_id"
        case capturedAt = "captured_at"
        case dylibs
        case notes
    }
}

/// One differential condition: expected vs observed nameplate.
/// Absence of `expected` or `observed` is meaningful (added / removed).
public struct DiffFinding: Codable, Equatable, Sendable {
    public var kind: DiffFindingKind
    public var expected: DylibIdentity?
    public var observed: DylibIdentity?
    /// Hint only. Never a malware classification.
    public var scoreHint: ScoreHint

    public init(
        kind: DiffFindingKind,
        expected: DylibIdentity? = nil,
        observed: DylibIdentity? = nil,
        scoreHint: ScoreHint
    ) {
        self.kind = kind
        self.expected = expected
        self.observed = observed
        self.scoreHint = scoreHint
    }

    enum CodingKeys: String, CodingKey {
        case kind
        case expected
        case observed
        case scoreHint = "score_hint"
    }
}

/// Application identity as cited by a report (may be thinner than a baseline).
public struct AppRef: Codable, Equatable, Sendable {
    public var path: String
    public var signingID: String?
    public var teamID: String?

    public init(path: String, signingID: String? = nil, teamID: String? = nil) {
        self.path = path
        self.signingID = signingID
        self.teamID = teamID
    }

    enum CodingKeys: String, CodingKey {
        case path
        case signingID = "signing_id"
        case teamID = "team_id"
    }
}

/// Counts for a compare run. `expectedCount` / `observedCount` are the
/// sizes of the two library sets, not the number of findings.
public struct DiffSummary: Codable, Equatable, Sendable {
    public var expectedCount: Int
    public var observedCount: Int
    public var added: Int
    public var removed: Int
    public var hashChanged: Int
    public var teamChanged: Int
    public var pathChanged: Int
    public var writableUnexpected: Int
    public var highestScoreHint: ScoreHint?

    public init(
        expectedCount: Int = 0,
        observedCount: Int = 0,
        added: Int = 0,
        removed: Int = 0,
        hashChanged: Int = 0,
        teamChanged: Int = 0,
        pathChanged: Int = 0,
        writableUnexpected: Int = 0,
        highestScoreHint: ScoreHint? = nil
    ) {
        self.expectedCount = expectedCount
        self.observedCount = observedCount
        self.added = added
        self.removed = removed
        self.hashChanged = hashChanged
        self.teamChanged = teamChanged
        self.pathChanged = pathChanged
        self.writableUnexpected = writableUnexpected
        self.highestScoreHint = highestScoreHint
    }

    enum CodingKeys: String, CodingKey {
        case expectedCount = "expected_count"
        case observedCount = "observed_count"
        case added
        case removed
        case hashChanged = "hash_changed"
        case teamChanged = "team_changed"
        case pathChanged = "path_changed"
        case writableUnexpected = "writable_unexpected"
        case highestScoreHint = "highest_score_hint"
    }
}

/// Result of comparing expected state (baseline) with observed state.
/// A non-empty `findings` array is an anomaly, not a malware detection.
public struct DiffReport: Codable, Equatable, Sendable {
    /// Document type. Always `dyld87.diff-report.v1` for this schema.
    public var schema: String
    public var app: AppRef
    public var baselineId: String
    public var findings: [DiffFinding]
    public var summary: DiffSummary

    public init(
        schema: String = DiffDylibSchema.diffReportV1,
        app: AppRef,
        baselineId: String,
        findings: [DiffFinding] = [],
        summary: DiffSummary = DiffSummary()
    ) {
        self.schema = schema
        self.app = app
        self.baselineId = baselineId
        self.findings = findings
        self.summary = summary
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case app
        case baselineId = "baseline_id"
        case findings
        case summary
    }
}
