// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ssh-agent",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "SSHAgentLib",
            path: "Sources/SSHAgentLib"
        ),
        .executableTarget(
            name: "ssh-agent",
            dependencies: ["SSHAgentLib"],
            path: "Sources/SSHAgent",
            linkerSettings: [
                .linkedFramework("AppKit"),
            ]
        ),
        .executableTarget(
            name: "ssh-agent-ctl",
            dependencies: ["SSHAgentLib"],
            path: "Sources/SSHAgentCtl"
        ),
        .testTarget(
            name: "SSHAgentLibTests",
            dependencies: ["SSHAgentLib"]
        ),
    ]
)
