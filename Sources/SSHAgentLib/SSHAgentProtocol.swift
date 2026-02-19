import Foundation

// MARK: - Message Types

public enum SSHAgentMessageType: UInt8 {
    case failure = 5
    case success = 6
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case addIdentity = 17
    case removeIdentity = 18
    case removeAllIdentities = 19
    case lock = 22
    case unlock = 23
    case extension_ = 27
}

// MARK: - Request / Response

public struct AgentIdentity {
    public let keyBlob: Data
    public let comment: String

    public init(keyBlob: Data, comment: String) {
        self.keyBlob = keyBlob
        self.comment = comment
    }
}

/// Information from a session-bind@pl.loee extension.
public struct SessionBindInfo {
    public let hostname: String
    public let hostKeyBlob: Data
    public let sessionId: Data
    public let hostKeySignature: Data
    public let isForwarded: Bool
}

public enum AgentRequest {
    case requestIdentities
    case signRequest(keyBlob: Data, data: Data, flags: UInt32)
    case sessionBind(SessionBindInfo)
    case unknown(type: UInt8)
}

public enum AgentResponse {
    case failure
    case success
    case identitiesAnswer([AgentIdentity])
    case signResponse(Data)
}

// MARK: - Parsing

public func parseAgentRequest(from messageData: Data) throws -> AgentRequest {
    var buf = SSHReadBuffer(messageData)
    let typeByte = try buf.readByte()

    guard let type = SSHAgentMessageType(rawValue: typeByte) else {
        return .unknown(type: typeByte)
    }

    switch type {
    case .requestIdentities:
        return .requestIdentities

    case .signRequest:
        let keyBlob = try buf.readString()
        let data = try buf.readString()
        let flags = try buf.readUInt32()
        return .signRequest(keyBlob: keyBlob, data: data, flags: flags)

    case .extension_:
        return try parseExtension(&buf)

    default:
        return .unknown(type: typeByte)
    }
}

private func parseExtension(_ buf: inout SSHReadBuffer) throws -> AgentRequest {
    let name = try buf.readStringAsString()

    switch name {
    case "session-bind@pl.loee":
        let hostname = try buf.readStringAsString()
        let hostKeyBlob = try buf.readString()
        let sessionId = try buf.readString()
        let signature = try buf.readString()
        let forwarded = try buf.readBoolean()
        return .sessionBind(SessionBindInfo(
            hostname: hostname,
            hostKeyBlob: hostKeyBlob,
            sessionId: sessionId,
            hostKeySignature: signature,
            isForwarded: forwarded
        ))

    default:
        return .unknown(type: SSHAgentMessageType.extension_.rawValue)
    }
}

// MARK: - Sign Data Parsing

/// Information extracted from the data field of a SIGN_REQUEST.
public struct SignRequestInfo {
    public let sessionId: Data
    public let username: String
    public let serviceName: String
    public let algorithm: String
}

/// Attempts to parse the sign request data to extract the session ID, username, etc.
public func parseSignRequestData(_ data: Data) -> SignRequestInfo? {
    var buf = SSHReadBuffer(data)
    do {
        let sessionId = try buf.readString()
        let msgType = try buf.readByte()
        guard msgType == 50 else { return nil }
        let username = try buf.readStringAsString()
        let serviceName = try buf.readStringAsString()
        let method = try buf.readStringAsString()
        guard method == "publickey" else { return nil }
        _ = try buf.readBoolean()
        let algorithm = try buf.readStringAsString()
        return SignRequestInfo(
            sessionId: sessionId,
            username: username,
            serviceName: serviceName,
            algorithm: algorithm
        )
    } catch {
        return nil
    }
}

// MARK: - Serialization

public func serializeAgentResponse(_ response: AgentResponse) -> Data {
    var payload = SSHWriteBuffer()

    switch response {
    case .failure:
        payload.writeByte(SSHAgentMessageType.failure.rawValue)

    case .success:
        payload.writeByte(SSHAgentMessageType.success.rawValue)

    case .identitiesAnswer(let identities):
        payload.writeByte(SSHAgentMessageType.identitiesAnswer.rawValue)
        payload.writeUInt32(UInt32(identities.count))
        for identity in identities {
            payload.writeString(identity.keyBlob)
            payload.writeString(identity.comment)
        }

    case .signResponse(let signature):
        payload.writeByte(SSHAgentMessageType.signResponse.rawValue)
        payload.writeString(signature)
    }

    var framed = SSHWriteBuffer()
    framed.writeUInt32(UInt32(payload.data.count))
    framed.writeBytes(payload.data)
    return framed.data
}
