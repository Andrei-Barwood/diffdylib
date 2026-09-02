import CryptoKit
import Darwin
import Foundation
import Security

/// On-disk nameplate for a path: digest, POSIX metadata, SIP flags, and
/// Security.framework code signing. Failures never abort the caller.
public enum FileIdentityInspector {
    /// Restricted user/system flags used by SIP-protected files.
    /// Public `lstat` / `st_flags` — not a private rootless API.
    private static let restrictedFlag: UInt32 = 0x00080000 // UF_RESTRICTED / SF_RESTRICTED

    public static func enrich(_ identity: DylibIdentity) -> DylibIdentity {
        guard let path = identity.resolvedPath else { return identity }
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.fileExists(atPath: url.path) else {
            var missing = identity
            if missing.sip == nil { missing.sip = .unknown }
            if missing.signingState == nil { missing.signingState = .error("missing on-disk file") }
            return missing
        }
        let snapshot = inspect(url: url)
        var updated = identity
        updated.sha256 = snapshot.sha256
        updated.teamID = snapshot.teamID
        updated.signingID = snapshot.signingID
        updated.authority = snapshot.authority
        updated.notarized = snapshot.notarized
        updated.signingState = snapshot.signingState
        updated.posixPermissions = snapshot.posixPermissions
        updated.uid = snapshot.uid
        updated.gid = snapshot.gid
        updated.owner = snapshot.owner
        updated.writableByUser = snapshot.writableByUser
        updated.sip = snapshot.sip
        return updated
    }

    public static func inspect(url: URL) -> DylibIdentity {
        var identity = DylibIdentity(
            path: url.path,
            resolvedPath: url.standardizedFileURL.path,
            origin: .staticDependency
        )
        fillPOSIX(url: url, into: &identity)
        identity.sha256 = sha256Hex(of: url)
        fillSigning(url: url, into: &identity)
        return identity
    }

    // MARK: - POSIX / SIP

    static func isWritableByUser(_ path: String) -> Bool {
        if access(path, W_OK) == 0 { return true }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        return access(parent, W_OK) == 0
    }

    private static func fillPOSIX(url: URL, into identity: inout DylibIdentity) {
        var info = stat()
        let path = url.path
        identity.writableByUser = isWritableByUser(path)

        guard lstat(path, &info) == 0 else {
            identity.sip = .unknown
            return
        }

        identity.posixPermissions = UInt16(truncatingIfNeeded: info.st_mode)
        identity.uid = UInt32(info.st_uid)
        identity.gid = UInt32(info.st_gid)
        identity.owner = ownerString(uid: info.st_uid, gid: info.st_gid)

        let flags = UInt32(info.st_flags)
        identity.sip = (flags & restrictedFlag) != 0 ? .protected : .unprotected
    }

    private static func ownerString(uid: uid_t, gid: gid_t) -> String {
        "\(userName(uid)):\(groupName(gid))"
    }

    private static func userName(_ uid: uid_t) -> String {
        var pwd = passwd()
        var buffer = [CChar](repeating: 0, count: 4096)
        var result: UnsafeMutablePointer<passwd>?
        let status = getpwuid_r(uid, &pwd, &buffer, buffer.count, &result)
        if status == 0, result != nil {
            return String(cString: pwd.pw_name)
        }
        return "\(uid)"
    }

    private static func groupName(_ gid: gid_t) -> String {
        var grp = group()
        var buffer = [CChar](repeating: 0, count: 4096)
        var result: UnsafeMutablePointer<group>?
        let status = getgrgid_r(gid, &grp, &buffer, buffer.count, &result)
        if status == 0, result != nil {
            return String(cString: grp.gr_name)
        }
        return "\(gid)"
    }

    // MARK: - SHA-256

    static func sha256Hex(of url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk: Data
            do {
                chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            } catch {
                return nil
            }
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Security.framework

    private static func fillSigning(url: URL, into identity: inout DylibIdentity) {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode)
        guard createStatus == errSecSuccess, let staticCode else {
            identity.signingState = .error(secMessage(createStatus))
            return
        }

        let validity = SecStaticCodeCheckValidity(staticCode, SecCSFlags(), nil)
        if validity == errSecCSUnsigned {
            identity.signingState = .unsigned
            identity.notarized = false
            return
        }

        var information: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        if infoStatus == errSecSuccess, let information {
            applySigningInformation(information as NSDictionary, into: &identity)
        }

        if validity == errSecSuccess {
            identity.signingState = .valid
        } else {
            identity.signingState = .invalid
        }
    }

    private static func applySigningInformation(_ info: NSDictionary, into identity: inout DylibIdentity) {
        identity.teamID = stringValue(info[kSecCodeInfoTeamIdentifier])
        identity.signingID = stringValue(info[kSecCodeInfoIdentifier])

        if let certificates = info[kSecCodeInfoCertificates] as? [SecCertificate],
           let leaf = certificates.first {
            identity.authority = SecCertificateCopySubjectSummary(leaf) as String?
        }

        // Cheap / offline only. Do not call into syspolicyd or the network.
        // Keys are looked up by string so a missing SDK symbol is not a compile break.
        if info["notarization-date"] != nil || info["notarization"] != nil {
            identity.notarized = true
        }
    }

    private static func stringValue(_ value: Any?) -> String? {
        if let string = value as? String, !string.isEmpty { return string }
        if let cf = value as? NSString { return cf as String }
        return nil
    }

    private static func secMessage(_ status: OSStatus) -> String {
        if let cf = SecCopyErrorMessageString(status, nil) {
            return cf as String
        }
        return "OSStatus \(status)"
    }
}
