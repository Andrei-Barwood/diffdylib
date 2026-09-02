import Foundation
import SQLite3

public enum BaselineStoreError: Error, Equatable, CustomStringConvertible {
    case io(String)
    case sqlite(String)
    case invalidJSON(String)

    public var description: String {
        switch self {
        case .io(let message), .sqlite(let message), .invalidJSON(let message):
            return message
        }
    }
}

public struct BaselineCaptureResult: Equatable, Sendable {
    public var baseline: AppBaseline
    public var jsonURL: URL
    public var storeURL: URL?
    public var replaced: Bool
}

/// Builds and persists `dyld87.baseline.v1` documents.
/// JSON is the portable export. SQLite is the optional revisioned store.
public enum BaselineCapture {
    public static let defaultStorePath = "~/.diffdylib/baselines.sqlite"

    public static func make(
        appURL: URL,
        depth: Int = 1,
        skipSystem: Bool = true
    ) throws -> AppBaseline {
        let executable = try StaticEnumerator.resolveExecutableURL(appURL)
        let host = FileIdentityInspector.inspect(url: executable)
        let dylibs = try StaticEnumerator.enumerate(
            appURL: appURL,
            depth: depth,
            skipSystem: skipSystem
        )
        return AppBaseline(
            appPath: executable.standardizedFileURL.path,
            signingID: host.signingID,
            teamID: host.teamID,
            binarySHA256: host.sha256,
            revision: 1,
            dylibs: dylibs
        )
    }

    public static func capture(
        appURL: URL,
        outURL: URL,
        storeURL: URL? = nil,
        replace: Bool = false,
        depth: Int = 1,
        skipSystem: Bool = true
    ) throws -> BaselineCaptureResult {
        var baseline = try make(appURL: appURL, depth: depth, skipSystem: skipSystem)
        var replaced = false

        if let storeURL {
            let store = try SQLiteBaselineStore(url: storeURL)
            defer { store.close() }
            let saved = try store.save(baseline, replace: replace)
            baseline = saved.baseline
            replaced = saved.replaced
        }

        try writeJSON(baseline, to: outURL)
        return BaselineCaptureResult(
            baseline: baseline,
            jsonURL: outURL,
            storeURL: storeURL,
            replaced: replaced
        )
    }

    public static func writeJSON(_ baseline: AppBaseline, to url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try DiffDylibJSON.encode(baseline)
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            throw BaselineStoreError.io("could not write \(url.path): \(error.localizedDescription)")
        }
    }

    public static func loadJSON(from url: URL) throws -> AppBaseline {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw BaselineStoreError.io("could not read \(url.path): \(error.localizedDescription)")
        }
        do {
            return try DiffDylibJSON.decode(AppBaseline.self, from: data)
        } catch {
            throw BaselineStoreError.invalidJSON("\(url.path): \(error.localizedDescription)")
        }
    }

    public static func expandPath(_ path: String) -> String {
        if path == "~" {
            return FileManager.default.homeDirectoryForCurrentUser.path
        }
        if path.hasPrefix("~/") {
            return (FileManager.default.homeDirectoryForCurrentUser.path as NSString)
                .appendingPathComponent(String(path.dropFirst(2)))
        }
        return path
    }
}

/// Human-readable dump of a baseline. Not a verdict.
public enum BaselineFormatter {
    public static func human(_ baseline: AppBaseline) -> String {
        var lines: [String] = []
        lines.append("DiffDylib baseline (\(baseline.schema))")
        lines.append("  id:          \(baseline.id)")
        lines.append("  revision:    \(baseline.revision)")
        lines.append("  app_path:    \(baseline.appPath)")
        lines.append("  signing_id:  \(baseline.signingID ?? "(unsigned / none)")")
        lines.append("  team_id:     \(baseline.teamID ?? "(none)")")
        lines.append("  binary_sha:  \(baseline.binarySHA256 ?? "(unknown)")")
        lines.append("  captured_at: \(DiffDylibJSON.iso8601String(from: baseline.capturedAt))")
        lines.append("  dylibs:      \(baseline.dylibs.count)")
        for dylib in baseline.dylibs {
            let resolved = dylib.resolvedPath ?? "(unresolved)"
            let state: String
            switch dylib.signingState {
            case .unsigned: state = "unsigned"
            case .valid: state = "valid"
            case .invalid: state = "invalid"
            case .error(let message): state = "error(\(message))"
            case .none: state = "uninspected"
            }
            lines.append("    [\(dylib.origin.rawValue)] \(dylib.path)")
            lines.append("      resolved: \(resolved)")
            lines.append("      sha256:   \(dylib.sha256 ?? "(none)")")
            lines.append("      signing:  \(state) team=\(dylib.teamID ?? "-") writable=\(dylib.writableByUser)")
        }
        if !baseline.notes.isEmpty {
            lines.append("  notes:")
            for note in baseline.notes {
                lines.append("    - \(note)")
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

/// Revisioned SQLite store keyed by `(signing_id, app_path, binary_sha256)`.
public final class SQLiteBaselineStore {
    private var db: OpaquePointer?

    public init(url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var handle: OpaquePointer?
        let status = sqlite3_open_v2(
            url.path,
            &handle,
            SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard status == SQLITE_OK, let handle else {
            sqlite3_close(handle)
            throw BaselineStoreError.sqlite("could not open \(url.path)")
        }
        db = handle
        try exec("PRAGMA foreign_keys = ON;")
        try exec("""
            CREATE TABLE IF NOT EXISTS baselines (
                id TEXT PRIMARY KEY,
                signing_id TEXT NOT NULL,
                app_path TEXT NOT NULL,
                binary_sha256 TEXT NOT NULL,
                revision INTEGER NOT NULL,
                captured_at TEXT NOT NULL,
                json TEXT NOT NULL,
                UNIQUE (signing_id, app_path, binary_sha256, revision)
            );
            """)
        try exec("""
            CREATE INDEX IF NOT EXISTS idx_baselines_key
            ON baselines (signing_id, app_path, binary_sha256);
            """)
    }

    deinit {
        close()
    }

    public func close() {
        if let db {
            sqlite3_close(db)
            self.db = nil
        }
    }

    public struct SaveOutcome: Equatable {
        public var baseline: AppBaseline
        public var replaced: Bool
    }

    public func save(_ baseline: AppBaseline, replace: Bool) throws -> SaveOutcome {
        let key = baseline.naturalKey
        if replace {
            if let latest = try latestRevisionNumber(for: key) {
                var updated = baseline
                updated.revision = latest
                try replaceRevision(updated)
                return SaveOutcome(baseline: updated, replaced: true)
            }
        }
        var inserted = baseline
        let next = (try latestRevisionNumber(for: key) ?? 0) + 1
        inserted.revision = next
        if next > 1 {
            inserted.notes.append(
                "revision \(next) created because key already existed (signing_id, app_path, binary_sha256)"
            )
        }
        try insert(inserted)
        return SaveOutcome(baseline: inserted, replaced: false)
    }

    public func latest(for key: BaselineKey) throws -> AppBaseline? {
        try allRevisions(for: key).last
    }

    public func allRevisions(for key: BaselineKey) throws -> [AppBaseline] {
        let sql = """
            SELECT json FROM baselines
            WHERE signing_id = ? AND app_path = ? AND binary_sha256 = ?
            ORDER BY revision ASC;
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        bindText(statement, 1, key.signingID)
        bindText(statement, 2, key.appPath)
        bindText(statement, 3, key.binarySHA256)

        var rows: [AppBaseline] = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { break }
            guard step == SQLITE_ROW else {
                throw sqliteError("step")
            }
            guard let cString = sqlite3_column_text(statement, 0) else { continue }
            let json = String(cString: cString)
            guard let data = json.data(using: .utf8) else { continue }
            rows.append(try DiffDylibJSON.decode(AppBaseline.self, from: data))
        }
        return rows
    }

    private func latestRevisionNumber(for key: BaselineKey) throws -> Int? {
        let sql = """
            SELECT MAX(revision) FROM baselines
            WHERE signing_id = ? AND app_path = ? AND binary_sha256 = ?;
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        bindText(statement, 1, key.signingID)
        bindText(statement, 2, key.appPath)
        bindText(statement, 3, key.binarySHA256)
        let step = sqlite3_step(statement)
        guard step == SQLITE_ROW else { throw sqliteError("max revision") }
        if sqlite3_column_type(statement, 0) == SQLITE_NULL {
            return nil
        }
        return Int(sqlite3_column_int64(statement, 0))
    }

    private func insert(_ baseline: AppBaseline) throws {
        let sql = """
            INSERT INTO baselines
            (id, signing_id, app_path, binary_sha256, revision, captured_at, json)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        let key = baseline.naturalKey
        let json = String(data: try DiffDylibJSON.encode(baseline), encoding: .utf8) ?? "{}"
        bindText(statement, 1, baseline.id)
        bindText(statement, 2, key.signingID)
        bindText(statement, 3, key.appPath)
        bindText(statement, 4, key.binarySHA256)
        sqlite3_bind_int64(statement, 5, Int64(baseline.revision))
        bindText(statement, 6, DiffDylibJSON.iso8601String(from: baseline.capturedAt))
        bindText(statement, 7, json)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError("insert")
        }
    }

    private func replaceRevision(_ baseline: AppBaseline) throws {
        let sql = """
            UPDATE baselines
            SET id = ?, captured_at = ?, json = ?
            WHERE signing_id = ? AND app_path = ? AND binary_sha256 = ? AND revision = ?;
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        let key = baseline.naturalKey
        let json = String(data: try DiffDylibJSON.encode(baseline), encoding: .utf8) ?? "{}"
        bindText(statement, 1, baseline.id)
        bindText(statement, 2, DiffDylibJSON.iso8601String(from: baseline.capturedAt))
        bindText(statement, 3, json)
        bindText(statement, 4, key.signingID)
        bindText(statement, 5, key.appPath)
        bindText(statement, 6, key.binarySHA256)
        sqlite3_bind_int64(statement, 7, Int64(baseline.revision))
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError("replace")
        }
        if sqlite3_changes(db) == 0 {
            try insert(baseline)
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw sqliteError("prepare")
        }
        return statement
    }

    private func exec(_ sql: String) throws {
        var errmsg: UnsafeMutablePointer<CChar>?
        let status = sqlite3_exec(db, sql, nil, nil, &errmsg)
        let message = errmsg.map { String(cString: $0) }
        sqlite3_free(errmsg)
        guard status == SQLITE_OK else {
            throw BaselineStoreError.sqlite(message ?? "sqlite exec failed")
        }
    }

    private func bindText(_ statement: OpaquePointer, _ index: Int32, _ value: String) {
        _ = value.withCString { pointer in
            sqlite3_bind_text(statement, index, pointer, -1, sqliteTransientDestructor)
        }
    }

    private func sqliteError(_ what: String) -> BaselineStoreError {
        if let db, let cString = sqlite3_errmsg(db) {
            return .sqlite("\(what): \(String(cString: cString))")
        }
        return .sqlite(what)
    }
}

private let sqliteTransientDestructor = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
