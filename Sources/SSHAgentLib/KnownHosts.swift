import Foundation
import CryptoKit

/// Represents an entry in ~/.ssh/known_hosts.
public struct KnownHostEntry {
    public let hostnames: [String]   // plaintext hostnames (empty if hashed)
    public let hashedHost: HashedHost?
    public let keyType: String       // e.g. "ssh-ed25519", "ecdsa-sha2-nistp256"
    public let keyBlob: Data         // raw public key blob

    public struct HashedHost {
        public let salt: Data
        public let hash: Data
    }
}

/// Parses and queries ~/.ssh/known_hosts for host key verification.
public final class KnownHostsStore {
    private var entries: [KnownHostEntry] = []

    public init() {}

    /// Loads known_hosts from the default path (~/.ssh/known_hosts).
    public func loadDefault() throws {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/known_hosts").path
        try load(from: path)
    }

    /// Loads known_hosts from a specific file path.
    public func load(from path: String) throws {
        guard let content = FileManager.default.contents(atPath: path),
              let text = String(data: content, encoding: .utf8) else {
            return
        }
        entries = text
            .split(separator: "\n", omittingEmptySubsequences: true)
            .compactMap { parseEntry(String($0)) }
    }

    /// Looks up a hostname and verifies that the given host key matches.
    /// Returns .verified if the hostname is found and the key matches,
    /// .mismatch if the hostname is found but with a different key,
    /// .unknown if the hostname is not in known_hosts.
    public func verify(hostname: String, port: Int = 22, keyBlob: Data) -> HostVerification {
        let lookupNames = hostLookupNames(hostname: hostname, port: port)

        var foundHostname = false
        for entry in entries {
            let hostnameMatches: Bool
            if let hashed = entry.hashedHost {
                hostnameMatches = lookupNames.contains { name in
                    verifyHashedHost(name: name, salt: hashed.salt, expectedHash: hashed.hash)
                }
            } else {
                hostnameMatches = entry.hostnames.contains { entryHost in
                    lookupNames.contains { entryHost == $0 }
                }
            }

            guard hostnameMatches else { continue }
            foundHostname = true

            if entry.keyBlob == keyBlob {
                return .verified(hostname)
            }
        }

        return foundHostname ? .mismatch(hostname) : .unknown(hostname)
    }

    /// Looks up a host key blob and returns all matching hostnames.
    /// For hashed entries, this cannot reverse-lookup — only plaintext entries are returned.
    public func hostnamesForKey(_ keyBlob: Data) -> [String] {
        entries
            .filter { $0.keyBlob == keyBlob }
            .flatMap { $0.hostnames }
    }

    // MARK: - Parsing

    private func parseEntry(_ line: String) -> KnownHostEntry? {
        let line = line.trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty, !line.hasPrefix("#") else { return nil }

        // Format: hostname[,hostname2,...] keytype base64-key [comment]
        // Hashed: |1|base64-salt|base64-hash keytype base64-key [comment]
        let parts = line.split(separator: " ", maxSplits: 3).map(String.init)
        guard parts.count >= 3 else { return nil }

        let hostField = parts[0]
        let keyType = parts[1]
        guard let keyBlob = Data(base64Encoded: parts[2]) else { return nil }

        // Check if this is a hashed entry
        if hostField.hasPrefix("|1|") {
            let hashParts = hostField.dropFirst(3).split(separator: "|").map(String.init)
            guard hashParts.count == 2,
                  let salt = Data(base64Encoded: hashParts[0]),
                  let hash = Data(base64Encoded: hashParts[1]) else {
                return nil
            }
            return KnownHostEntry(
                hostnames: [],
                hashedHost: .init(salt: salt, hash: hash),
                keyType: keyType,
                keyBlob: keyBlob
            )
        }

        // Plaintext hostnames (comma-separated, may include [host]:port)
        let hostnames = hostField.split(separator: ",").map(String.init)
        return KnownHostEntry(
            hostnames: hostnames,
            hashedHost: nil,
            keyType: keyType,
            keyBlob: keyBlob
        )
    }

    /// Returns the names to look up for a given hostname and port.
    /// Standard port 22 uses just the hostname; non-standard uses [host]:port.
    private func hostLookupNames(hostname: String, port: Int) -> [String] {
        if port == 22 {
            return [hostname]
        }
        return [hostname, "[\(hostname)]:\(port)"]
    }

    /// Verifies a hashed known_hosts entry using HMAC-SHA1.
    private func verifyHashedHost(name: String, salt: Data, expectedHash: Data) -> Bool {
        let key = SymmetricKey(data: salt)
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(name.utf8), using: key)
        return Data(mac) == expectedHash
    }
}

public enum HostVerification: Equatable {
    case verified(String)    // hostname found in known_hosts and key matches
    case mismatch(String)    // hostname found but key doesn't match (possible MITM)
    case unknown(String)     // hostname not in known_hosts
}
