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

        case .signRequest(let keyBlob, let data, _):
            return await handleSignRequest(keyBlob: keyBlob, data: data, socketType: socketType)

        case .sessionBind(let info):
            return handleSessionBind(info)

        case .unknown:
            return .failure
        }
    }

    private func handleRequestIdentities() -> AgentResponse {
        guard let keys = try? keyStore.loadAllKeys() else {
            return .identitiesAnswer([])
        }
        let identities = keys.map { key in
            AgentIdentity(keyBlob: key.sshPublicKeyBlob, comment: key.comment)
        }
        return .identitiesAnswer(identities)
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

    private func handleSignRequest(keyBlob: Data, data: Data, socketType: SocketType) async -> AgentResponse {
        guard let keys = try? keyStore.loadAllKeys(),
              let key = keys.first(where: { $0.sshPublicKeyBlob == keyBlob }) else {
            return .failure
        }

        // Parse sign data to get session ID and username
        let info = parseSignRequestData(data)

        // Look up verified host context from session binding
        let hostContext: VerifiedHostContext?
        if let sid = info?.sessionId {
            hostContext = lookupBinding(sid)
        } else {
            hostContext = nil
        }

        // For forwarded socket, require user approval
        if socketType == .forwarded, let approve = approvalHandler {
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
        }

        do {
            let signature = try key.sign(data: data)
            return .signResponse(signature)
        } catch {
            NSLog("Signing failed: \(error)")
            return .failure
        }
    }

    private nonisolated func lookupBinding(_ sessionId: Data) -> VerifiedHostContext? {
        bindingsLock.lock()
        defer { bindingsLock.unlock() }
        return sessionBindings[sessionId]
    }
}
