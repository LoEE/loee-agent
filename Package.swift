// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "loee-agent",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "SSHAgentLib",
            path: "Sources/SSHAgentLib"
        ),
        .executableTarget(
            name: "loee-agent",
            dependencies: ["SSHAgentLib"],
            path: "Sources/SSHAgent",
            linkerSettings: [
                .linkedFramework("AppKit"),
            ]
        ),
        .executableTarget(
            name: "loee-agent-ctl",
            dependencies: ["SSHAgentLib"],
            path: "Sources/SSHAgentCtl"
        ),
        .testTarget(
            name: "SSHAgentLibTests",
            dependencies: ["SSHAgentLib"]
        ),
    ]
)
