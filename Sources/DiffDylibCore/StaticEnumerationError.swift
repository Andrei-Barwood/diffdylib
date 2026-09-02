import Foundation

/// Typed failures for static Mach-O enumeration.
/// Missing files and unreadable blobs map to these three cases; nothing
/// here is a malware verdict.
public enum StaticEnumerationError: Error, Equatable, CustomStringConvertible {
    /// Magic number is not Mach-O or a well-formed fat wrapper.
    case notMachO(URL)
    /// Header, fat slice, or load commands extend past the file.
    case truncated(URL)
    /// The process cannot read the file (EACCES / EPERM / Cocoa no-permission).
    case permissionDenied(URL)

    public var description: String {
        switch self {
        case .notMachO(let url):
            return "not a Mach-O file: \(url.path)"
        case .truncated(let url):
            return "truncated Mach-O: \(url.path)"
        case .permissionDenied(let url):
            return "permission denied: \(url.path)"
        }
    }

    public var url: URL {
        switch self {
        case .notMachO(let url), .truncated(let url), .permissionDenied(let url):
            return url
        }
    }
}
