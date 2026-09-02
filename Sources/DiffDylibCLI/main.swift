import Foundation
import DiffDylibCore

/// DiffDylib CLI.
/// Static enumerate / capture / show / compare. No libproc, no Endpoint Security.

enum CLIExit {
    static let findings = 1
    static let failure = 1
    static let usage = 2
}

struct CLIError: Error, CustomStringConvertible {
    let message: String
    let exitCode: Int

    var description: String { message }
}

@main
struct DiffDylibCLI {
    static func main() {
        do {
            try run(arguments: Array(CommandLine.arguments.dropFirst()))
        } catch let error as CLIError {
            fputs("error: \(error.message)\n", stderr)
            Foundation.exit(Int32(error.exitCode))
        } catch let error as StaticEnumerationError {
            fputs("error: \(error.description)\n", stderr)
            Foundation.exit(Int32(CLIExit.failure))
        } catch let error as BaselineStoreError {
            fputs("error: \(error.description)\n", stderr)
            Foundation.exit(Int32(CLIExit.failure))
        } catch {
            fputs("error: \(error)\n", stderr)
            Foundation.exit(Int32(CLIExit.failure))
        }
    }

    static func run(arguments: [String]) throws {
        guard let command = arguments.first else {
            printUsage()
            throw CLIError(message: "missing command", exitCode: CLIExit.usage)
        }

        switch command {
        case "enumerate":
            let options = try parseEnumerate(Array(arguments.dropFirst()))
            guard let options else { return }
            try runEnumerate(options)
        case "capture":
            let options = try parseCapture(Array(arguments.dropFirst()))
            guard let options else { return }
            try runCapture(options)
        case "compare":
            let options = try parseCompare(Array(arguments.dropFirst()))
            guard let options else { return }
            try runCompare(options)
        case "show":
            let options = try parseShow(Array(arguments.dropFirst()))
            guard let options else { return }
            try runShow(options)
        case "-h", "--help", "help":
            printUsage()
        default:
            printUsage()
            throw CLIError(
                message: "unknown command '\(command)'",
                exitCode: CLIExit.usage
            )
        }
    }

    private struct EnumerateOptions {
        var app: String
        var depth: Int
        var skipSystem: Bool
    }

    /// Returns `nil` when help was printed.
    private static func parseEnumerate(_ args: [String]) throws -> EnumerateOptions? {
        var app: String?
        var depth = 1
        var skipSystem = true
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--app":
                app = try requireValue("--app", args: args, index: &i)
            case "--depth":
                let raw = try requireValue("--depth", args: args, index: &i)
                guard let value = Int(raw), value >= 1, value <= StaticEnumerator.maxDepth else {
                    throw CLIError(
                        message: "--depth must be an integer 1...\(StaticEnumerator.maxDepth)",
                        exitCode: CLIExit.usage
                    )
                }
                depth = value
            case "--skip-system":
                skipSystem = true
            case "--no-skip-system":
                skipSystem = false
            case "-h", "--help":
                printEnumerateUsage()
                return nil
            default:
                throw CLIError(
                    message: "unknown option '\(args[i])' for enumerate",
                    exitCode: CLIExit.usage
                )
            }
            i += 1
        }
        guard let app else {
            printEnumerateUsage()
            throw CLIError(
                message: "enumerate requires --app <path>",
                exitCode: CLIExit.usage
            )
        }
        return EnumerateOptions(app: app, depth: depth, skipSystem: skipSystem)
    }

    private static func runEnumerate(_ options: EnumerateOptions) throws {
        let url = URL(fileURLWithPath: options.app)
        let result = try StaticEnumerator.enumerateDetailed(
            appURL: url,
            depth: options.depth,
            skipSystem: options.skipSystem
        )
        let data = try DiffDylibJSON.encode(result)
        FileHandle.standardOutput.write(data)
        if data.last != UInt8(ascii: "\n") {
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }

    private struct CaptureOptions {
        var app: String
        var out: String
        var store: String?
        var replace: Bool
        var depth: Int
        var skipSystem: Bool
    }

    /// Returns `nil` when help was printed.
    private static func parseCapture(_ args: [String]) throws -> CaptureOptions? {
        var app: String?
        var out: String?
        var store: String?
        var replace = false
        var depth = 1
        var skipSystem = true
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--app":
                app = try requireValue("--app", args: args, index: &i)
            case "--out":
                out = try requireValue("--out", args: args, index: &i)
            case "--store":
                if i + 1 < args.count, !args[i + 1].hasPrefix("-") {
                    store = try requireValue("--store", args: args, index: &i)
                } else {
                    store = BaselineCapture.defaultStorePath
                }
            case "--replace":
                replace = true
            case "--depth":
                let raw = try requireValue("--depth", args: args, index: &i)
                guard let value = Int(raw), value >= 1, value <= StaticEnumerator.maxDepth else {
                    throw CLIError(
                        message: "--depth must be an integer 1...\(StaticEnumerator.maxDepth)",
                        exitCode: CLIExit.usage
                    )
                }
                depth = value
            case "--skip-system":
                skipSystem = true
            case "--no-skip-system":
                skipSystem = false
            case "-h", "--help":
                printCaptureUsage()
                return nil
            default:
                throw CLIError(
                    message: "unknown option '\(args[i])' for capture",
                    exitCode: CLIExit.usage
                )
            }
            i += 1
        }
        guard let app, let out else {
            printCaptureUsage()
            throw CLIError(
                message: "capture requires --app <path> and --out <file>",
                exitCode: CLIExit.usage
            )
        }
        return CaptureOptions(
            app: app,
            out: out,
            store: store,
            replace: replace,
            depth: depth,
            skipSystem: skipSystem
        )
    }

    private static func runCapture(_ options: CaptureOptions) throws {
        let storeURL = options.store.map {
            URL(fileURLWithPath: BaselineCapture.expandPath($0))
        }
        let result = try BaselineCapture.capture(
            appURL: URL(fileURLWithPath: options.app),
            outURL: URL(fileURLWithPath: BaselineCapture.expandPath(options.out)),
            storeURL: storeURL,
            replace: options.replace,
            depth: options.depth,
            skipSystem: options.skipSystem
        )
        var summary = "captured revision \(result.baseline.revision) → \(result.jsonURL.path)"
        if result.replaced {
            summary += " (replaced)"
        }
        if let store = result.storeURL {
            summary += "\nstore \(store.path)"
        }
        fputs(summary + "\n", stderr)
        let data = try DiffDylibJSON.encode(result.baseline)
        FileHandle.standardOutput.write(data)
        if data.last != UInt8(ascii: "\n") {
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }

    private struct CompareOptions {
        var baseline: String
        var app: String
        var jsonOnly: Bool
        var depth: Int
        var skipSystem: Bool
    }

    /// Returns `nil` when help was printed.
    private static func parseCompare(_ args: [String]) throws -> CompareOptions? {
        var baseline: String?
        var app: String?
        var jsonOnly = false
        var depth = 1
        var skipSystem = true
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--baseline":
                baseline = try requireValue("--baseline", args: args, index: &i)
            case "--app":
                app = try requireValue("--app", args: args, index: &i)
            case "--json":
                jsonOnly = true
            case "--depth":
                let raw = try requireValue("--depth", args: args, index: &i)
                guard let value = Int(raw), value >= 1, value <= StaticEnumerator.maxDepth else {
                    throw CLIError(
                        message: "--depth must be an integer 1...\(StaticEnumerator.maxDepth)",
                        exitCode: CLIExit.usage
                    )
                }
                depth = value
            case "--skip-system":
                skipSystem = true
            case "--no-skip-system":
                skipSystem = false
            case "-h", "--help":
                printCompareUsage()
                return nil
            default:
                throw CLIError(
                    message: "unknown option '\(args[i])' for compare",
                    exitCode: CLIExit.usage
                )
            }
            i += 1
        }
        guard let baseline, let app else {
            printCompareUsage()
            throw CLIError(
                message: "compare requires --baseline <file> and --app <path>",
                exitCode: CLIExit.usage
            )
        }
        return CompareOptions(
            baseline: baseline,
            app: app,
            jsonOnly: jsonOnly,
            depth: depth,
            skipSystem: skipSystem
        )
    }

    private static func runCompare(_ options: CompareOptions) throws {
        let baseline = try BaselineCapture.loadJSON(
            from: URL(fileURLWithPath: BaselineCapture.expandPath(options.baseline))
        )
        let report = try DifferentialComparator.compare(
            baseline: baseline,
            appURL: URL(fileURLWithPath: options.app),
            depth: options.depth,
            skipSystem: options.skipSystem
        )
        let json = try DiffDylibJSON.encode(report)
        if !options.jsonOnly {
            fputs(DifferentialComparator.formatHuman(report), stdout)
            fputs("--- json ---\n", stdout)
        }
        FileHandle.standardOutput.write(json)
        if json.last != UInt8(ascii: "\n") {
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
        if report.summary.hasMediumOrHigh {
            Foundation.exit(1)
        }
    }

    private struct ShowOptions {
        var baseline: String
        var jsonOnly: Bool
    }

    /// Returns `nil` when help was printed.
    private static func parseShow(_ args: [String]) throws -> ShowOptions? {
        var baseline: String?
        var jsonOnly = false
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--baseline":
                baseline = try requireValue("--baseline", args: args, index: &i)
            case "--json":
                jsonOnly = true
            case "-h", "--help":
                printShowUsage()
                return nil
            default:
                throw CLIError(
                    message: "unknown option '\(args[i])' for show",
                    exitCode: CLIExit.usage
                )
            }
            i += 1
        }
        guard let baseline else {
            printShowUsage()
            throw CLIError(
                message: "show requires --baseline <file>",
                exitCode: CLIExit.usage
            )
        }
        return ShowOptions(baseline: baseline, jsonOnly: jsonOnly)
    }

    private static func runShow(_ options: ShowOptions) throws {
        let url = URL(fileURLWithPath: BaselineCapture.expandPath(options.baseline))
        let baseline = try BaselineCapture.loadJSON(from: url)
        let json = try DiffDylibJSON.encode(baseline)
        if options.jsonOnly {
            FileHandle.standardOutput.write(json)
            if json.last != UInt8(ascii: "\n") {
                FileHandle.standardOutput.write(Data("\n".utf8))
            }
            return
        }
        fputs(BaselineFormatter.human(baseline), stdout)
        fputs("--- json ---\n", stdout)
        FileHandle.standardOutput.write(json)
        if json.last != UInt8(ascii: "\n") {
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }

    private static func requireValue(
        _ flag: String,
        args: [String],
        index i: inout Int
    ) throws -> String {
        let next = i + 1
        guard next < args.count else {
            throw CLIError(message: "\(flag) requires a value", exitCode: CLIExit.usage)
        }
        i = next
        return args[i]
    }

    private static func printUsage() {
        let text = """
        diffdylib — Differential Dylib Protection (Dyld87 module)

        Usage:
          diffdylib enumerate --app <path> [--depth 1] [--skip-system|--no-skip-system]
          diffdylib capture --app <path> --out <file> [--store [file]] [--replace]
                           [--depth 1] [--skip-system|--no-skip-system]
          diffdylib compare --baseline <file> --app <path> [--json]
                           [--depth 1] [--skip-system|--no-skip-system]
          diffdylib show --baseline <file> [--json]

        enumerate walks LC_LOAD_DYLIB / LC_RPATH (static only).
        capture writes baseline.v1 JSON and optional SQLite revisions.
        compare diffs baseline vs a fresh static walk (not runtime).
        Exit 0 = no medium/high findings; 1 = medium/high; 2 = usage.
        show prints a human dump and JSON.
        No libproc. No Endpoint Security.

        """
        fputs(text, stdout)
    }

    private static func printEnumerateUsage() {
        fputs(
            "usage: diffdylib enumerate --app <path> [--depth 1] [--skip-system|--no-skip-system]\n",
            stdout
        )
    }

    private static func printCaptureUsage() {
        fputs(
            """
            usage: diffdylib capture --app <path> --out <file> [--store [file]] [--replace]
                                 [--depth 1] [--skip-system|--no-skip-system]
            default --store path: \(BaselineCapture.defaultStorePath)

            """,
            stdout
        )
    }

    private static func printCompareUsage() {
        fputs(
            """
            usage: diffdylib compare --baseline <file> --app <path> [--json]
                                 [--depth 1] [--skip-system|--no-skip-system]
            exit 0 = no medium/high findings; 1 = medium/high; 2 = usage

            """,
            stdout
        )
    }

    private static func printShowUsage() {
        fputs("usage: diffdylib show --baseline <file> [--json]\n", stdout)
    }
}
