import Foundation

/// Load-command facts extracted from one Mach-O image (one thin file or
/// one slice of a fat binary). No code signing, no hashing.
struct MachOImageInfo: Equatable {
    var magic: UInt32
    var is64Bit: Bool
    var cpuType: Int32
    var fileType: UInt32
    /// `LC_ID_DYLIB` install name, if this image is a dylib.
    var installName: String?
    var loadDylibs: [MachOLoadDylib]
    var rpaths: [String]
}

struct MachOLoadDylib: Equatable {
    var name: String
    var isWeak: Bool
}

enum MachOParseFailure: Error {
    case notMachO
    case truncated
}

enum MachOParser {
    static let mhMagic: UInt32 = 0xfeedface
    static let mhCigam: UInt32 = 0xcefaedfe
    static let mhMagic64: UInt32 = 0xfeedfacf
    static let mhCigam64: UInt32 = 0xcffaedfe
    static let fatMagic: UInt32 = 0xcafebabe
    static let fatCigam: UInt32 = 0xbebafeca
    static let fatMagic64: UInt32 = 0xcafebabf
    static let fatCigam64: UInt32 = 0xbfbafeca

    static let lcLoadDylib: UInt32 = 0x0c
    static let lcIdDylib: UInt32 = 0x0d
    static let lcLoadWeakDylib: UInt32 = 0x18 | 0x8000_0000
    static let lcRpath: UInt32 = 0x1c | 0x8000_0000

    static let cpuTypeX86_64: Int32 = 0x01000007
    static let cpuTypeArm64: Int32 = 0x0100000c

    static func parseFile(at url: URL) throws -> MachOImageInfo {
        let data: Data
        do {
            data = try Data(contentsOf: url, options: [.mappedIfSafe])
        } catch {
            throw mapReadError(error, url: url)
        }
        do {
            return try parse(data: data)
        } catch MachOParseFailure.notMachO {
            throw StaticEnumerationError.notMachO(url)
        } catch MachOParseFailure.truncated {
            throw StaticEnumerationError.truncated(url)
        }
    }

    static func parse(data: Data) throws -> MachOImageInfo {
        guard data.count >= 4 else { throw MachOParseFailure.truncated }
        let magic = readUInt32(data, at: 0, swapped: false)
        if isFatMagic(magic) {
            let slice = try selectFatSlice(data, magic: magic)
            return try parseThin(slice)
        }
        return try parseThin(data)
    }

    static func mapReadError(_ error: Error, url: URL) -> StaticEnumerationError {
        let ns = error as NSError
        if ns.domain == NSPOSIXErrorDomain && (ns.code == Int(EACCES) || ns.code == Int(EPERM)) {
            return .permissionDenied(url)
        }
        if ns.domain == NSCocoaErrorDomain && ns.code == NSFileReadNoPermissionError {
            return .permissionDenied(url)
        }
        // Missing file is not a Mach-O we can parse.
        if ns.domain == NSPOSIXErrorDomain && ns.code == Int(ENOENT) {
            return .notMachO(url)
        }
        if ns.domain == NSCocoaErrorDomain && ns.code == NSFileReadNoSuchFileError {
            return .notMachO(url)
        }
        return .notMachO(url)
    }

    private static func isFatMagic(_ magic: UInt32) -> Bool {
        magic == fatMagic || magic == fatCigam || magic == fatMagic64 || magic == fatCigam64
    }

    private static func isThinMagic(_ magic: UInt32) -> Bool {
        magic == mhMagic || magic == mhCigam || magic == mhMagic64 || magic == mhCigam64
    }

    private static func selectFatSlice(_ data: Data, magic: UInt32) throws -> Data {
        let swapped = (magic == fatCigam || magic == fatCigam64)
        let is64 = (magic == fatMagic64 || magic == fatCigam64)
        guard data.count >= 8 else { throw MachOParseFailure.truncated }
        let nfat = Int(readUInt32(data, at: 4, swapped: swapped))
        // Java class files also start with 0xcafebabe; reject implausible tables.
        guard nfat > 0, nfat <= 64 else { throw MachOParseFailure.notMachO }

        let headerSize = 8
        let archSize = is64 ? 32 : 20
        let tableEnd = headerSize + nfat * archSize
        guard data.count >= tableEnd else { throw MachOParseFailure.truncated }

        var slices: [(cpuType: Int32, offset: UInt64, size: UInt64)] = []
        slices.reserveCapacity(nfat)
        for index in 0..<nfat {
            let base = headerSize + index * archSize
            let cpuType = Int32(bitPattern: readUInt32(data, at: base, swapped: swapped))
            let offset: UInt64
            let size: UInt64
            if is64 {
                offset = readUInt64(data, at: base + 8, swapped: swapped)
                size = readUInt64(data, at: base + 16, swapped: swapped)
            } else {
                offset = UInt64(readUInt32(data, at: base + 8, swapped: swapped))
                size = UInt64(readUInt32(data, at: base + 12, swapped: swapped))
            }
            let end = offset.addingReportingOverflow(size)
            guard !end.overflow, end.partialValue <= UInt64(data.count) else {
                throw MachOParseFailure.truncated
            }
            slices.append((cpuType, offset, size))
        }

        let preferred = preferredCPUType()
        let chosen = slices.first(where: { $0.cpuType == preferred }) ?? slices[0]
        let start = Int(chosen.offset)
        let end = start + Int(chosen.size)
        guard start >= 0, end <= data.count, start < end else {
            throw MachOParseFailure.truncated
        }
        return data.subdata(in: start..<end)
    }

    private static func preferredCPUType() -> Int32 {
        #if arch(arm64)
        return cpuTypeArm64
        #elseif arch(x86_64)
        return cpuTypeX86_64
        #else
        return cpuTypeArm64
        #endif
    }

    private static func parseThin(_ data: Data) throws -> MachOImageInfo {
        guard data.count >= 4 else { throw MachOParseFailure.truncated }
        let rawMagic = readUInt32(data, at: 0, swapped: false)
        guard isThinMagic(rawMagic) else { throw MachOParseFailure.notMachO }

        let swapped = (rawMagic == mhCigam || rawMagic == mhCigam64)
        let is64 = (rawMagic == mhMagic64 || rawMagic == mhCigam64)
        let headerSize = is64 ? 32 : 28
        guard data.count >= headerSize else { throw MachOParseFailure.truncated }

        let cpuType = Int32(bitPattern: readUInt32(data, at: 4, swapped: swapped))
        let fileType = readUInt32(data, at: 12, swapped: swapped)
        let ncmds = Int(readUInt32(data, at: 16, swapped: swapped))
        let sizeofcmds = Int(readUInt32(data, at: 20, swapped: swapped))

        guard ncmds >= 0, ncmds <= 65_536 else { throw MachOParseFailure.truncated }
        let commandsEnd = headerSize + sizeofcmds
        guard sizeofcmds >= 0, commandsEnd <= data.count else { throw MachOParseFailure.truncated }

        var offset = headerSize
        var installName: String?
        var loadDylibs: [MachOLoadDylib] = []
        var rpaths: [String] = []

        for _ in 0..<ncmds {
            guard offset + 8 <= commandsEnd else { throw MachOParseFailure.truncated }
            let cmd = readUInt32(data, at: offset, swapped: swapped)
            let cmdsize = Int(readUInt32(data, at: offset + 4, swapped: swapped))
            guard cmdsize >= 8, offset + cmdsize <= commandsEnd else {
                throw MachOParseFailure.truncated
            }

            switch cmd {
            case lcLoadDylib, lcLoadWeakDylib:
                let name = try readLoadCommandString(data, commandOffset: offset, cmdsize: cmdsize, swapped: swapped)
                loadDylibs.append(MachOLoadDylib(name: name, isWeak: cmd == lcLoadWeakDylib))
            case lcIdDylib:
                installName = try readLoadCommandString(data, commandOffset: offset, cmdsize: cmdsize, swapped: swapped)
            case lcRpath:
                let path = try readLoadCommandString(data, commandOffset: offset, cmdsize: cmdsize, swapped: swapped)
                rpaths.append(path)
            default:
                break
            }

            offset += cmdsize
        }

        return MachOImageInfo(
            magic: rawMagic,
            is64Bit: is64,
            cpuType: cpuType,
            fileType: fileType,
            installName: installName,
            loadDylibs: loadDylibs,
            rpaths: rpaths
        )
    }

    /// `lc_str` offset lives at byte 8 of dylib_command / rpath_command.
    private static func readLoadCommandString(
        _ data: Data,
        commandOffset: Int,
        cmdsize: Int,
        swapped: Bool
    ) throws -> String {
        let strOff = Int(readUInt32(data, at: commandOffset + 8, swapped: swapped))
        guard strOff >= 8, strOff < cmdsize else { throw MachOParseFailure.truncated }
        let start = commandOffset + strOff
        let limit = commandOffset + cmdsize
        guard start < limit else { throw MachOParseFailure.truncated }

        var end = start
        while end < limit, data[end] != 0 {
            end += 1
        }
        if end == limit && (start == limit || data[limit - 1] != 0) {
            // Missing NUL: take the remainder of the command.
        }
        let bytes = data[start..<end]
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func readUInt32(_ data: Data, at offset: Int, swapped: Bool) -> UInt32 {
        var value: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &value) { dest in
            data.copyBytes(to: dest, from: offset..<(offset + 4))
        }
        return swapped ? value.byteSwapped : value
    }

    private static func readUInt64(_ data: Data, at offset: Int, swapped: Bool) -> UInt64 {
        var value: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &value) { dest in
            data.copyBytes(to: dest, from: offset..<(offset + 8))
        }
        return swapped ? value.byteSwapped : value
    }
}
