import AppKit
import Foundation
import SSHAgentLib

// Set up as an accessory app (no dock icon, no menu bar)
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let keyStore = KeyStore()

// Load known_hosts for host key verification
let knownHosts = KnownHostsStore()
try? knownHosts.loadDefault()

// Determine socket paths
let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
let sshDir = homeDir + "/.ssh"
let localSocketPath = sshDir + "/loee-agent-local.sock"
let forwardedSocketPath = sshDir + "/loee-agent-forwarded.sock"

// Ensure ~/.ssh exists
try? FileManager.default.createDirectory(atPath: sshDir, withIntermediateDirectories: true)

// Capture upstream agent before we override SSH_AUTH_SOCK
let upstreamAgent: UpstreamAgent?
if let upstreamPath = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"],
   upstreamPath != localSocketPath,
   upstreamPath != forwardedSocketPath {
    upstreamAgent = UpstreamAgent(socketPath: upstreamPath)
} else {
    upstreamAgent = nil
}

// Local socket: auto-approve all signing requests
let localHandler = AgentRequestHandler(keyStore: keyStore, knownHosts: knownHosts, approvalHandler: nil)
let localServer = AgentServer(
    socketPath: localSocketPath,
    socketType: .local,
    requestHandler: localHandler
)

// Forwarded socket: prompt user via native macOS alert before signing
let forwardedHandler = AgentRequestHandler(keyStore: keyStore, knownHosts: knownHosts) { key, info, hostContext in
    await requestUserApproval(for: key, info: info, hostContext: hostContext)
}
let forwardedServer = AgentServer(
    socketPath: forwardedSocketPath,
    socketType: .forwarded,
    requestHandler: forwardedHandler
)

// Wire up upstream agent
localHandler.upstreamAgent = upstreamAgent
forwardedHandler.upstreamAgent = upstreamAgent

// Install signal handlers for cleanup
func cleanup() {
    localServer.stop()
    forwardedServer.stop()
}

signal(SIGTERM) { _ in
    cleanup()
    exit(0)
}
signal(SIGINT) { _ in
    cleanup()
    exit(0)
}

// Start servers on a background queue
DispatchQueue.global().async {
    do {
        try localServer.start()
        try forwardedServer.start()

        NSLog("SSH agent started")
        NSLog("  Local socket:     ~/.ssh/loee-agent-local.sock")
        NSLog("  Forwarded socket: ~/.ssh/loee-agent-forwarded.sock")
        if let upstreamAgent {
            NSLog("  Upstream agent:   %@", upstreamAgent.socketPath)
        } else {
            NSLog("  Upstream agent:   none")
        }
        NSLog("")
        NSLog("Run 'loee-agent-ctl setup' for one-time SSH config setup.")
    } catch {
        NSLog("Failed to start SSH agent: \(error)")
        exit(1)
    }
}

// Run the main event loop (required for NSAlert)
app.run()
