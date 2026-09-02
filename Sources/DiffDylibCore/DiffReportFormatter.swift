import Foundation

/// Markdown + compact human rendering of a differential report.
/// Not a malware verdict: the table is ΣI ≠ 0, not a family name.
public enum DiffReportFormatter {
    public static func markdown(_ report: DiffReport) -> String {
        let s = report.summary
        var lines: [String] = []
        lines.append("# DiffDylib report")
        lines.append("")
        lines.append("Schema: `\(report.schema)`. Findings are differential conditions, not malware labels.")
        lines.append("")
        lines.append("| expected | observed | Δ added | Δ removed | hashΔ | teamΔ | pathΔ | writable unexpected | rpath ambiguous | highest |")
        lines.append("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
        lines.append(
            "| \(s.expectedCount) | \(s.observedCount) | \(s.added) | \(s.removed) | \(s.hashChanged) | \(s.teamChanged) | \(s.pathChanged) | \(s.writableUnexpected) | \(s.rpathAmbiguous) | \(s.highestScoreHint?.rawValue ?? "none") |"
        )
        lines.append("")
        lines.append("- App: `\(report.app.path)`")
        lines.append("- Baseline: `\(report.baselineId)`")
        lines.append("- Signing id: \(report.app.signingID ?? "(none)")")
        lines.append("- Team id: \(report.app.teamID ?? "(none)")")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        if report.findings.isEmpty {
            lines.append("No differential conditions. The observed set matches the baseline under this walk.")
        } else {
            lines.append("| score | kind | path |")
            lines.append("| --- | --- | --- |")
            for finding in report.findings {
                let path = finding.observed?.resolvedPath
                    ?? finding.observed?.path
                    ?? finding.expected?.resolvedPath
                    ?? finding.expected?.path
                    ?? "(unknown)"
                lines.append("| \(finding.scoreHint.rawValue) | `\(finding.kind.rawValue)` | `\(path)` |")
            }
        }
        lines.append("")
        lines.append("## How to read this")
        lines.append("")
        lines.append("- `added` / `removed` are set difference, not attribution of an attacker.")
        lines.append("- `writableUnexpected` means an added or hash-changed library sits on a user-writable path.")
        lines.append("- `rpathAmbiguous` is the Dylib Hijack Scanner heuristic: two on-disk hits for one `@rpath`.")
        lines.append("- Plugins, JIT, and updaters produce false positives; see README.")
        lines.append("")
        return lines.joined(separator: "\n")
    }

    public static func write(_ report: DiffReport, to prefix: URL) throws {
        let stem: URL
        if prefix.pathExtension.lowercased() == "json" || prefix.pathExtension.lowercased() == "md" {
            stem = prefix.deletingPathExtension()
        } else {
            stem = prefix
        }
        let jsonURL = stem.appendingPathExtension("json")
        let mdURL = stem.appendingPathExtension("md")
        let directory = stem.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try DiffDylibJSON.encode(report).write(to: jsonURL, options: .atomic)
        try markdown(report).data(using: .utf8)?.write(to: mdURL, options: .atomic)
    }
}

extension DifferentialComparator {
    public static func formatMarkdown(_ report: DiffReport) -> String {
        DiffReportFormatter.markdown(report)
    }
}
