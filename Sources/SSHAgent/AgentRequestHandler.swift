import Foundation
import SSHAgentLib

/// Context about the remote host, verified via the session-bind extension.
public struct VerifiedHostContext {
    public let hostname: String
    public let verification: HostVerification
    public let isForwarded: Bool
}

/// Handles SSH agent requests by dispatching to the key store.
/// For forwarded socket requests, invokes the approval callback before signing.
public final class AgentRequestHandler {
    private let keyStore: KeyStore
    private let knownHosts: KnownHostsStore
    private let approvalHandler: ((any SSHKey, SignRequestInfo?, VerifiedHostContext?) async -> Bool)?

    /// Upstream ssh-agent to proxy requests to (e.g. system ssh-agent).
    public var upstreamAgent: UpstreamAgent?

    /// Session bindings: maps session_id → verified host context.
    /// Populated by session-bind@pl.loee extensions, consumed by sign requests.
    private var sessionBindings = [Data: VerifiedHostContext]()
    private let bindingsLock = NSLock()

    public init(
        keyStore: KeyStore,
        knownHosts: KnownHostsStore,
        approvalHandler: ((any SSHKey, SignRequestInfo?, VerifiedHostContext?) async -> Bool)? = nil
    ) {
        self.keyStore = keyStore
        self.knownHosts = knownHosts
        self.approvalHandler = approvalHandler
    }

    public func handle(request: AgentRequest, socketType: SocketType) async -> AgentResponse {
        switch request {
        case .requestIdentities:
            return handleRequestIdentities()

        case .signRequest(let keyBlob, let data, let flags):
            return await handleSignRequest(keyBlob: keyBlob, data: data, flags: flags, socketType: socketType)

        case .sessionBind(let info):
            return handleSessionBind(info)

        case .unknown:
            return .failure
        }
    }

    private func handleRequestIdentities() -> AgentResponse {
        var identities = allKeys().map { key in
            AgentIdentity(keyBlob: key.sshPublicKeyBlob, comment: key.comment)
        }
        if let upstream = upstreamAgent {
            identities += upstream.requestIdentities()
        }
        return .identitiesAnswer(identities)
    }

    private func allKeys() -> [any SSHKey] {
        (try? keyStore.loadAllKeys()) ?? []
    }

    private func handleSessionBind(_ info: SessionBindInfo) -> AgentResponse {
        // Verify the host key signature proves a real key exchange
        let sigValid = HostKeyVerifier.verify(
            hostKeyBlob: info.hostKeyBlob,
            sessionId: info.sessionId,
            signature: info.hostKeySignature
        )

        guard sigValid else {
            NSLog("[session-bind] Host key signature verification failed for %@", info.hostname)
            return .failure
        }

        // Verify hostname against known_hosts
        let verification = knownHosts.verify(hostname: info.hostname, keyBlob: info.hostKeyBlob)

        let context = VerifiedHostContext(
            hostname: info.hostname,
            verification: verification,
            isForwarded: info.isForwarded
        )

        // Store binding keyed by session_id
        bindingsLock.lock()
        sessionBindings[info.sessionId] = context
        bindingsLock.unlock()

        NSLog("[session-bind] Bound session to %@ (%@)", info.hostname, String(describing: verification))
        return .success
    }

    private func handleSignRequest(keyBlob: Data, data: Data, flags: UInt32, socketType: SocketType) async -> AgentResponse {
        let key = allKeys().first(where: { $0.sshPublicKeyBlob == keyBlob })
        let isUpstreamKey = key == nil

        // Parse sign data to get session ID and username
        let info = parseSignRequestData(data)

        // Look up verified host context from session binding
        let hostContext: VerifiedHostContext?
        if let sid = info?.sessionId {
            hostContext = lookupBinding(sid)
        } else {
            hostContext = nil
        }

        // For forwarded socket, require user approval (for both our keys and upstream keys)
        if socketType == .forwarded, let approve = approvalHandler {
            // For upstream keys, we don't have an SSHKey object — create a minimal description
            // We still require approval before forwarding to upstream
            if let key {
                let approved = await approve(key, info, hostContext)
                guard approved else {
                    NSLog("[forwarded] User denied signing as %@ to %@ with key: %@",
                          info?.username ?? "unknown",
                          hostContext?.hostname ?? "unknown host",
                          key.fingerprint)
                    return .failure
                }
                NSLog("[forwarded] User approved signing as %@ to %@ with key: %@",
                      info?.username ?? "unknown",
                      hostContext?.hostname ?? "unknown host",
                      key.fingerprint)
            } else if isUpstreamKey {
                // For upstream keys on forwarded socket, create a proxy key for approval
                let proxyKey = UpstreamProxyKey(sshPublicKeyBlob: keyBlob)
                let approved = await approve(proxyKey, info, hostContext)
                guard approved else {
                    NSLog("[forwarded] User denied upstream signing as %@ to %@ with key: %@",
                          info?.username ?? "unknown",
                          hostContext?.hostname ?? "unknown host",
                          proxyKey.fingerprint)
                    return .failure
                }
                NSLog("[forwarded] User approved upstream signing as %@ to %@ with key: %@",
                      info?.username ?? "unknown",
                      hostContext?.hostname ?? "unknown host",
                      proxyKey.fingerprint)
            }
        }

        // Try our own keys first
        if let key {
            do {
                let signature = try key.sign(data: data)
                return .signResponse(signature)
            } catch {
                NSLog("Signing failed: \(error)")
                return .failure
            }
        }

        // Forward to upstream agent
        if let upstream = upstreamAgent,
           let signature = upstream.signRequest(keyBlob: keyBlob, data: data, flags: flags) {
            return .signResponse(signature)
        }

        return .failure
    }

    private nonisolated func lookupBinding(_ sessionId: Data) -> VerifiedHostContext? {
        bindingsLock.lock()
        defer { bindingsLock.unlock() }
        return sessionBindings[sessionId]
    }
}

/// Minimal SSHKey stand-in for upstream agent keys, used only for the approval UI.
private struct UpstreamProxyKey: SSHKey {
    let sshPublicKeyBlob: Data

    var algorithm: KeyAlgorithm {
        // Parse algorithm name from key blob
        var buf = SSHReadBuffer(sshPublicKeyBlob)
        if let name = try? buf.readStringAsString() {
            switch name {
            case "ssh-ed25519": return .ed25519
            case "ecdsa-sha2-nistp256": return .ecdsaP256
            default: return .ed25519
            }
        }
        return .ed25519
    }

    var comment: String { "upstream-agent" }

    var fingerprint: String {
        sshFingerprint(keyBlob: sshPublicKeyBlob)
    }

    func sign(data: Data) throws -> Data {
        fatalError("UpstreamProxyKey cannot sign — signing is handled by the upstream agent")
    }
}
