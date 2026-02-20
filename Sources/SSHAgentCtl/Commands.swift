import Foundation
import SSHAgentLib
import CryptoKit

func commandGenerate(args: [String]) throws {
    let keyType = parseArg("--type", from: args) ?? "ed25519"
    let comment = parseArg("--comment", from: args) ?? "\(NSUserName())@\(Host.current().localizedName ?? "mac")"

    let keyStore = KeyStore()

    let identifier: KeyIdentifier
    switch keyType {
    case "ed25519":
        identifier = try keyStore.generateEd25519Key(comment: comment)
        printStderr("Generated Ed25519 key: \(identifier.id)")

    case "ecdsa-p256", "ecdsa":
        if SecureEnclave.isAvailable {
            identifier = try keyStore.generateSecureEnclaveKey(comment: comment)
            printStderr("Generated Secure Enclave P-256 key: \(identifier.id)")
        } else {
            printStderr("Error: Secure Enclave is not available on this Mac.")
            printStderr("Tip: Use --type ed25519 for a software-backed key.")
            exit(1)
        }

    default:
        printStderr("Unknown key type: \(keyType)")
        printStderr("Supported types: ed25519, ecdsa-p256")
        exit(1)
    }

    // Print public key
    let key = try keyStore.loadKey(identifier)
    let pubLine = authorizedKeysLine(key: key)
    print(pubLine)
    printStderr("Fingerprint: \(key.fingerprint)")
}

func commandList(args: [String]) throws {
    let keyStore = KeyStore()
    let keys = try keyStore.loadAllKeys()

    if keys.isEmpty {
        printStderr("No keys found. Use 'ssh-agent-ctl generate' to create one.")
        return
    }

    for key in keys {
        print("\(key.fingerprint) \(key.algorithm.sshName) \(key.comment)")
    }
}

func commandExport(args: [String]) throws {
    guard let id = parseArg("--id", from: args) else {
        printStderr("Usage: ssh-agent-ctl export --id <key-id>")
        printStderr("Use 'ssh-agent-ctl list' to see available keys.")
        exit(1)
    }

    let keyStore = KeyStore()
    let identifiers = try keyStore.listKeys()

    // Match by full ID or prefix
    guard let identifier = identifiers.first(where: { $0.id == id || $0.id.hasPrefix(id) }) else {
        printStderr("Key not found: \(id)")
        exit(1)
    }

    let key = try keyStore.loadKey(identifier)
    print(authorizedKeysLine(key: key))
}

func commandDelete(args: [String]) throws {
    guard let id = parseArg("--id", from: args) else {
        printStderr("Usage: ssh-agent-ctl delete --id <key-id>")
        exit(1)
    }

    let keyStore = KeyStore()
    let identifiers = try keyStore.listKeys()

    guard let identifier = identifiers.first(where: { $0.id == id || $0.id.hasPrefix(id) }) else {
        printStderr("Key not found: \(id)")
        exit(1)
    }

    try keyStore.deleteKey(identifier)
    printStderr("Deleted key: \(identifier.id) (\(identifier.comment))")
}

func commandSetup(args: [String]) throws {
    let fm = FileManager.default
    let homeDir = fm.homeDirectoryForCurrentUser.path
    let sshDir = homeDir + "/.ssh"
    let confPath = sshDir + "/loee-agent.conf"
    let sshConfigPath = sshDir + "/config"

    // Ensure ~/.ssh exists
    try? fm.createDirectory(atPath: sshDir, withIntermediateDirectories: true)

    // Write loee-agent.conf
    let confContent = """
        # SSH agent configuration (pl.loee)
        Host *
            IdentityAgent ~/.ssh/loee-agent-local.sock
            ForwardAgent ~/.ssh/loee-agent-forwarded.sock
        """
    try confContent.write(toFile: confPath, atomically: true, encoding: .utf8)
    printStderr("Wrote \(confPath)")

    // Check if ~/.ssh/config already includes loee-agent.conf
    let includeLine = "Include loee-agent.conf"
    var existingConfig = ""
    if fm.fileExists(atPath: sshConfigPath) {
        existingConfig = try String(contentsOfFile: sshConfigPath, encoding: .utf8)
        if existingConfig.contains(includeLine) {
            printStderr("SSH config already includes \(includeLine)")
            return
        }
    }

    // Prompt user for confirmation
    printStderr("")
    printStderr("Add '\(includeLine)' to ~/.ssh/config?")
    printStderr("This must be at the top of the file to take effect.")
    printStderr("")
    print("Proceed? [y/N] ", terminator: "")
    guard let answer = readLine(), answer.lowercased() == "y" else {
        printStderr("Skipped. You can manually add '\(includeLine)' to ~/.ssh/config")
        return
    }

    // Prepend Include to config
    let newConfig = includeLine + "\n\n" + existingConfig
    try newConfig.write(toFile: sshConfigPath, atomically: true, encoding: .utf8)
    printStderr("Updated \(sshConfigPath)")
}

// MARK: - Helpers

func parseArg(_ name: String, from args: [String]) -> String? {
    guard let idx = args.firstIndex(of: name), idx + 1 < args.count else {
        return nil
    }
    return args[idx + 1]
}

func printStderr(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

func printUsage() {
    let usage = """
        Usage: ssh-agent-ctl <command> [options]

        Commands:
          setup       Configure SSH to use the agent (one-time)

          generate    Generate a new SSH key
            --type <ed25519|ecdsa-p256>  Key type (default: ed25519)
            --comment <text>             Key comment

          list        List all stored keys

          export      Export public key in authorized_keys format
            --id <key-id>                Key ID (or prefix)

          delete      Delete a stored key
            --id <key-id>                Key ID (or prefix)
        """
    printStderr(usage)
}
