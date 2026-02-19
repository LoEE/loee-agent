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
let localSocketPath = sshDir + "/agent-local.sock"
let forwardedSocketPath = sshDir + "/agent-forwarded.sock"

// Ensure ~/.ssh exists
try? FileManager.default.createDirectory(atPath: sshDir, withIntermediateDirectories: true)

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
        NSLog("  Local socket:     \(localSocketPath)")
        NSLog("  Forwarded socket: \(forwardedSocketPath)")
        NSLog("")
        NSLog("Usage:")
        NSLog("  export SSH_AUTH_SOCK=\"\(localSocketPath)\"")
        NSLog("")
        NSLog("SSH config for forwarding:")
        NSLog("  Host myserver")
        NSLog("    RemoteForward /run/user/%%i/agent.sock \(forwardedSocketPath)")
    } catch {
        NSLog("Failed to start SSH agent: \(error)")
        exit(1)
    }
}

// Run the main event loop (required for NSAlert)
app.run()
