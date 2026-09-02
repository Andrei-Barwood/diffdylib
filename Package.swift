// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DiffDylib",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .library(name: "DiffDylibCore", targets: ["DiffDylibCore"]),
        .executable(name: "diffdylib", targets: ["DiffDylibCLI"]),
    ],
    targets: [
        .target(
            name: "DiffDylibProc",
            publicHeadersPath: "include"
        ),
        .target(
            name: "DiffDylibCore",
            dependencies: ["DiffDylibProc"],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedLibrary("sqlite3"),
            ]
        ),
        .executableTarget(
            name: "DiffDylibCLI",
            dependencies: ["DiffDylibCore"]
        ),
        .testTarget(
            name: "DiffDylibTests",
            dependencies: ["DiffDylibCore"]
        ),
    ]
)
