import Foundation

/// Schema identifiers for versioned DiffDylib JSON documents.
public enum DiffDylibSchema {
    public static let baselineV1 = "dyld87.baseline.v1"
    public static let diffReportV1 = "dyld87.diff-report.v1"
    public static let staticEnumV1 = "dyld87.static-enum.v1"
}

/// Shared JSON coding for baselines and reports.
/// Dates are ISO-8601 with fractional seconds (RFC 3339).
public enum DiffDylibJSON {
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(iso8601String(from: date))
        }
        return encoder
    }

    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let string = try container.decode(String.self)
            guard let date = iso8601Date(from: string) else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Invalid RFC 3339 timestamp: \(string)"
                )
            }
            return date
        }
        return decoder
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try encoder().encode(value)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder().decode(type, from: data)
    }

    public static func iso8601String(from date: Date) -> String {
        iso8601Fractional.string(from: date)
    }

    public static func iso8601Date(from string: String) -> Date? {
        if let date = iso8601Fractional.date(from: string) {
            return date
        }
        return iso8601Plain.date(from: string)
    }

    private static let iso8601Fractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let iso8601Plain: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}
