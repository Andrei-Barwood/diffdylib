import Darwin
import DiffDylibProc
import Foundation

public enum RuntimeEnumerationError: Error, Equatable, CustomStringConvertible {
    case processNotFound(pid_t)
    case permissionDenied(pid_t)
    case walkFailed(pid_t, Int32)

    public var description: String {
        switch self {
        case .processNotFound(let pid):
            return "process not found: \(pid)"
        case .permissionDenied(let pid):
            return "permission denied walking mappings of pid \(pid)"
        case .walkFailed(let pid, let code):
            return "proc_pidinfo failed for pid \(pid) (errno \(code))"
        }
    }
}

/// Runtime view of a process: file-backed executable mappings via
/// `proc_pidinfo` + `PROC_PIDREGIONPATHINFO` (Wardle).
///
/// This does **not** call `task_for_pid` and does **not** read the
/// target's address space. The kernel reports region metadata only.
///
/// Limitations (must not be papered over):
/// - Mappings from the **dyld shared cache** often have no per-dylib
///   path, so they will not appear.
/// - The on-disk file at a returned path may no longer match the pages
///   that are mapped (**TOCTOU** disk vs memory).
public enum RuntimeEnumerator {
    public static func listExecutableMappings(pid: pid_t) throws -> [DylibIdentity] {
        try ensureAlive(pid)
        let capacity = Int(DIFFDYLIB_MAX_MAPPINGS)
        let buffer = UnsafeMutablePointer<diffdylib_mapping_t>.allocate(capacity: capacity)
        defer { buffer.deallocate() }
        memset(buffer, 0, MemoryLayout<diffdylib_mapping_t>.stride * capacity)

        let count = diffdylib_list_executable_mappings(pid, buffer, Int32(capacity))
        if count < 0 {
            throw mapErrno(pid: pid, errnoValue: errno)
        }

        var seen = Set<String>()
        var identities: [DylibIdentity] = []
        for index in 0..<Int(count) {
            let raw = withUnsafeBytes(of: buffer[index].path) { bytes -> String in
                bytes.bindMemory(to: CChar.self).baseAddress.map { String(cString: $0) } ?? ""
            }
            guard !raw.isEmpty else { continue }
            let path = URL(fileURLWithPath: raw).standardizedFileURL.path
            guard seen.insert(path).inserted else { continue }
            identities.append(
                FileIdentityInspector.enrich(
                    DylibIdentity(
                        path: path,
                        resolvedPath: path,
                        origin: .runtimeMapping
                    )
                )
            )
        }
        return identities
    }

    public static func processPath(pid: pid_t) throws -> URL {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let written = buffer.withUnsafeMutableBufferPointer { pointer in
            diffdylib_pid_path(pid, pointer.baseAddress, UInt32(pointer.count))
        }
        if written <= 0 {
            throw mapErrno(pid: pid, errnoValue: errno)
        }
        return URL(fileURLWithPath: String(cString: buffer)).standardizedFileURL
    }

    private static func ensureAlive(_ pid: pid_t) throws {
        if kill(pid, 0) == 0 { return }
        if errno == ESRCH {
            throw RuntimeEnumerationError.processNotFound(pid)
        }
        if errno == EPERM {
            // Process exists; we may still be allowed to query proc_pidinfo.
            return
        }
        throw RuntimeEnumerationError.walkFailed(pid, errno)
    }

    private static func mapErrno(pid: pid_t, errnoValue: Int32) -> RuntimeEnumerationError {
        switch errnoValue {
        case ESRCH:
            return .processNotFound(pid)
        case EPERM, EACCES:
            return .permissionDenied(pid)
        default:
            return .walkFailed(pid, errnoValue)
        }
    }
}

public struct RuntimeProcessSnapshot: Codable, Equatable, Sendable {
    public var schema: String
    public var pid: Int32
    public var processPath: String
    public var dylibs: [DylibIdentity]
    public var notes: [String]

    public init(
        schema: String = DiffDylibSchema.runtimePsV1,
        pid: pid_t,
        processPath: String,
        dylibs: [DylibIdentity],
        notes: [String] = RuntimeProcessSnapshot.defaultNotes
    ) {
        self.schema = schema
        self.pid = pid
        self.processPath = processPath
        self.dylibs = dylibs
        self.notes = notes
    }

    public static let defaultNotes = [
        "proc_pidinfo does not enumerate dyld shared cache dylibs well",
        "on-disk file at a mapping path may not match mapped pages (TOCTOU)",
        "no task_for_pid; no remote memory reads",
    ]

    enum CodingKeys: String, CodingKey {
        case schema
        case pid
        case processPath = "process_path"
        case dylibs
        case notes
    }
}
