import AppKit
import SSHAgentLib

@MainActor
public func requestUserApproval(
    for key: any SSHKey,
    info: SignRequestInfo?,
    hostContext: VerifiedHostContext?
) async -> Bool {
    NSApp.activate(ignoringOtherApps: true)

    let alert = NSAlert()

    // Build the message based on what we know
    var title: String
    var details = ""

    if let hostContext {
        switch hostContext.verification {
        case .verified(let hostname):
            title = "SSH: Authenticate to \(hostname)?"
            details += "Host: \(hostname) (verified via known_hosts)\n"

        case .mismatch(let hostname):
            title = "WARNING: Host key mismatch for \(hostname)!"
            details += "Host: \(hostname)\n"
            details += "WARNING: The host key does NOT match known_hosts!\n"
            details += "This could indicate a man-in-the-middle attack.\n\n"
            alert.alertStyle = .critical

        case .unknown(let hostname):
            title = "SSH: Authenticate to \(hostname)?"
            details += "Host: \(hostname) (not in known_hosts)\n"
        }
    } else {
        title = "SSH Signing Request (Remote)"
        details += "Target host: unknown (client did not send host info)\n"
    }

    if let info {
        details += "Username: \(info.username)\n"
    }
    details += "Key: \(key.algorithm.sshName)\n"
    details += "Fingerprint: \(key.fingerprint)\n"
    details += "Comment: \(key.comment)\n"

    if hostContext?.verification != .mismatch(hostContext?.hostname ?? "") {
        details += "\nAllow this signing operation?"
        alert.alertStyle = .warning
    }

    alert.messageText = title
    alert.informativeText = details
    alert.icon = NSImage(
        systemSymbolName: hostContext?.verification == .verified(hostContext?.hostname ?? "")
            ? "lock.shield" : "exclamationmark.shield",
        accessibilityDescription: "SSH signing request"
    )

    alert.addButton(withTitle: "Allow")
    alert.addButton(withTitle: "Deny")

    let response = alert.runModal()
    return response == .alertFirstButtonReturn
}
