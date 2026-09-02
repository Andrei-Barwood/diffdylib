import Foundation

/// Result of a static walk of Mach-O load commands.
/// `findings` only carries `rpathAmbiguous` in this prompt — a DHS-style
/// condition, not a malware classification.
public struct StaticEnumerationResult: Codable, Equatable, Sendable {
    public var schema: String
    public var appPath: String
    public var executablePath: String
    public var depth: Int
    public var skipSystem: Bool
    public var dylibs: [DylibIdentity]
    public var findings: [DiffFinding]

    public init(
        schema: String = DiffDylibSchema.staticEnumV1,
        appPath: String,
        executablePath: String,
        depth: Int,
        skipSystem: Bool,
        dylibs: [DylibIdentity],
        findings: [DiffFinding]
    ) {
        self.schema = schema
        self.appPath = appPath
        self.executablePath = executablePath
        self.depth = depth
        self.skipSystem = skipSystem
        self.dylibs = dylibs
        self.findings = findings
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case appPath = "app_path"
        case executablePath = "executable_path"
        case depth
        case skipSystem = "skip_system"
        case dylibs
        case findings
    }
}

/// Static (on-disk) enumeration of dylib dependencies.
///
/// Walks `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` / `LC_RPATH` / `LC_ID_DYLIB`.
/// Enriches each resolved path with hash / POSIX / Security.framework.
/// Does not inspect process memory or Endpoint Security.
public enum StaticEnumerator {
    public static let maxDepth = 3

    /// Path prefixes treated as platform / dyld-shared-cache adjacent.
    /// `/usr/lib/system` is listed for documentation; it is already under `/usr/lib`.
    public static let systemPrefixes = [
        "/usr/lib",
        "/System",
        "/Library/Apple",
        "/usr/lib/system",
    ]

    /// First-level dependencies always. `depth` 2–3 recurse into resolved
    /// non-system dylibs. Values outside `1...maxDepth` are clamped.
    public static func enumerate(
        appURL: URL,
        depth: Int = 1,
        skipSystem: Bool = true
    ) throws -> [DylibIdentity] {
        try enumerateDetailed(appURL: appURL, depth: depth, skipSystem: skipSystem).dylibs
    }

    public static func enumerateDetailed(
        appURL: URL,
        depth: Int = 1,
        skipSystem: Bool = true
    ) throws -> StaticEnumerationResult {
        let clampedDepth = min(max(depth, 1), maxDepth)
        let executable = try resolveExecutableURL(appURL)
        let executableDir = executable.deletingLastPathComponent().path

        var identities: [DylibIdentity] = []
        var findings: [DiffFinding] = []
        var visited: Set<String> = []

        try walk(
            binary: executable,
            executableDir: executableDir,
            remainingDepth: clampedDepth,
            skipSystem: skipSystem,
            identities: &identities,
            findings: &findings,
            visited: &visited
        )

        return StaticEnumerationResult(
            appPath: appURL.standardizedFileURL.path,
            executablePath: executable.path,
            depth: clampedDepth,
            skipSystem: skipSystem,
            dylibs: identities,
            findings: findings
        )
    }

    public static func isSystemPath(_ path: String) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        for prefix in systemPrefixes {
            if standardized == prefix || standardized.hasPrefix(prefix + "/") {
                return true
            }
        }
        return false
    }

    /// `.app` bundle → `Contents/MacOS/<CFBundleExecutable>`. Otherwise the URL itself.
    public static func resolveExecutableURL(_ appURL: URL) throws -> URL {
        let url = appURL.standardizedFileURL
        if url.hasDirectoryPath || url.pathExtension == "app" {
            let info = url.appendingPathComponent("Contents/Info.plist")
            let macos = url.appendingPathComponent("Contents/MacOS")
            if let executableName = bundleExecutableName(at: info) {
                let candidate = macos.appendingPathComponent(executableName)
                if FileManager.default.isReadableFile(atPath: candidate.path) {
                    return candidate
                }
            }
            if let fallback = firstExecutable(in: macos) {
                return fallback
            }
            throw StaticEnumerationError.notMachO(url)
        }
        return url
    }

    // MARK: - Walk

    private static func walk(
        binary: URL,
        executableDir: String,
        remainingDepth: Int,
        skipSystem: Bool,
        identities: inout [DylibIdentity],
        findings: inout [DiffFinding],
        visited: inout Set<String>
    ) throws {
        let canonical = binary.standardizedFileURL.path
        guard visited.insert(canonical).inserted else { return }
        guard remainingDepth >= 1 else { return }

        let image = try MachOParser.parseFile(at: binary)
        let loaderDir = binary.deletingLastPathComponent().path
        let resolvedRpaths = image.rpaths.map {
            expandTokens($0, executableDir: executableDir, loaderDir: loaderDir)
        }

        var recurseTargets: [URL] = []

        for load in image.loadDylibs {
            let resolved = resolveDependency(
                load.name,
                executableDir: executableDir,
                loaderDir: loaderDir,
                rpaths: resolvedRpaths
            )

            if load.name.hasPrefix("@rpath") {
                let existing = resolved.rpathHits.filter { FileManager.default.fileExists(atPath: $0) }
                // DHS: two on-disk hits for the same @rpath name is a hijack-shaped
                // condition. Reported as rpathAmbiguous, never as "malware".
                if existing.count >= 2 {
                    let first = identity(
                        installName: load.name,
                        resolvedPath: existing[0],
                        origin: .rpathCandidate
                    )
                    let second = identity(
                        installName: load.name,
                        resolvedPath: existing[1],
                        origin: .rpathCandidate
                    )
                    findings.append(
                        DiffFinding(
                            kind: .rpathAmbiguous,
                            expected: first,
                            observed: second,
                            scoreHint: .medium
                        )
                    )
                    for hit in existing {
                        let item = identity(
                            installName: load.name,
                            resolvedPath: hit,
                            origin: .rpathCandidate
                        )
                        if shouldEmit(item, skipSystem: skipSystem) {
                            appendUnique(&identities, item)
                        }
                    }
                }
            }

            let primaryPath = resolved.primary
            let staticItem = identity(
                installName: load.name,
                resolvedPath: primaryPath,
                origin: .staticDependency
            )
            if shouldEmit(staticItem, skipSystem: skipSystem) {
                appendUnique(&identities, staticItem)
                if remainingDepth > 1, let path = primaryPath, !isSystemPath(path) {
                    let url = URL(fileURLWithPath: path)
                    if FileManager.default.isReadableFile(atPath: url.path) {
                        recurseTargets.append(url)
                    }
                }
            }
        }

        for target in recurseTargets {
            try walk(
                binary: target,
                executableDir: executableDir,
                remainingDepth: remainingDepth - 1,
                skipSystem: skipSystem,
                identities: &identities,
                findings: &findings,
                visited: &visited
            )
        }
    }

    private static func shouldEmit(_ item: DylibIdentity, skipSystem: Bool) -> Bool {
        guard skipSystem else { return true }
        if let resolved = item.resolvedPath, isSystemPath(resolved) {
            return false
        }
        if item.resolvedPath == nil, isSystemPath(item.path) {
            return false
        }
        return true
    }

    private static func appendUnique(_ list: inout [DylibIdentity], _ item: DylibIdentity) {
        if !list.contains(item) {
            list.append(item)
        }
    }

    private static func identity(
        installName: String,
        resolvedPath: String?,
        origin: DylibOrigin
    ) -> DylibIdentity {
        FileIdentityInspector.enrich(
            DylibIdentity(
                path: installName,
                resolvedPath: resolvedPath,
                origin: origin
            )
        )
    }

    static func isWritableByUser(_ path: String) -> Bool {
        FileIdentityInspector.isWritableByUser(path)
    }

    // MARK: - Path tokens

    struct ResolvedDependency {
        /// First existing candidate, else the first constructed path, else nil.
        var primary: String?
        /// Every `@rpath` concatenation that was attempted (may not exist).
        var rpathHits: [String]
    }

    static func resolveDependency(
        _ installName: String,
        executableDir: String,
        loaderDir: String,
        rpaths: [String]
    ) -> ResolvedDependency {
        if installName.hasPrefix("@rpath") {
            let suffix = rpathSuffix(installName)
            var hits: [String] = []
            var firstExisting: String?
            var firstConstructed: String?
            for rpath in rpaths {
                let expanded = expandTokens(rpath, executableDir: executableDir, loaderDir: loaderDir)
                let combined = join(directory: expanded, suffix: suffix)
                let standardized = URL(fileURLWithPath: combined).standardizedFileURL.path
                hits.append(standardized)
                if firstConstructed == nil { firstConstructed = standardized }
                if firstExisting == nil, FileManager.default.fileExists(atPath: standardized) {
                    firstExisting = standardized
                }
            }
            return ResolvedDependency(
                primary: firstExisting ?? firstConstructed,
                rpathHits: hits
            )
        }

        let expanded = expandTokens(installName, executableDir: executableDir, loaderDir: loaderDir)
        let standardized = URL(fileURLWithPath: expanded).standardizedFileURL.path
        return ResolvedDependency(primary: standardized, rpathHits: [])
    }

    static func expandTokens(_ path: String, executableDir: String, loaderDir: String) -> String {
        if path.hasPrefix("@executable_path") {
            let rest = String(path.dropFirst("@executable_path".count))
            return join(directory: executableDir, suffix: rest)
        }
        if path.hasPrefix("@loader_path") {
            let rest = String(path.dropFirst("@loader_path".count))
            return join(directory: loaderDir, suffix: rest)
        }
        return path
    }

    private static func rpathSuffix(_ installName: String) -> String {
        String(installName.dropFirst("@rpath".count))
    }

    private static func join(directory: String, suffix: String) -> String {
        if suffix.isEmpty { return directory }
        if suffix.hasPrefix("/") {
            return (directory as NSString).appendingPathComponent(String(suffix.dropFirst()))
        }
        return (directory as NSString).appendingPathComponent(suffix)
    }

    private static func bundleExecutableName(at infoPlist: URL) -> String? {
        guard let data = try? Data(contentsOf: infoPlist) else { return nil }
        let plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
        guard let dict = plist as? [String: Any] else { return nil }
        return dict["CFBundleExecutable"] as? String
    }

    private static func firstExecutable(in macosDir: URL) -> URL? {
        guard let items = try? FileManager.default.contentsOfDirectory(
            at: macosDir,
            includingPropertiesForKeys: nil
        ) else { return nil }
        return items.sorted { $0.lastPathComponent < $1.lastPathComponent }.first
    }
}
