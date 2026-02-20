import Foundation
import SSHAgentLib

#if canImport(Darwin)
import Darwin
#endif

/// Client that connects to an upstream ssh-agent Unix socket to proxy requests.
/// Used to merge system ssh-agent keys with our Keychain-managed keys.
public final class UpstreamAgent {
    public let socketPath: String

    public init(socketPath: String) {
        self.socketPath = socketPath
    }

    /// Queries the upstream agent for its identities.
    public func requestIdentities() -> [AgentIdentity] {
        var request = SSHWriteBuffer()
        request.writeByte(SSHAgentMessageType.requestIdentities.rawValue)

        guard let responseBody = sendMessage(request.data) else {
            return []
        }

        do {
            var buf = SSHReadBuffer(responseBody)
            let typeByte = try buf.readByte()
            guard typeByte == SSHAgentMessageType.identitiesAnswer.rawValue else {
                return []
            }
            let count = try buf.readUInt32()
            var identities = [AgentIdentity]()
            for _ in 0 ..< count {
                let keyBlob = try buf.readString()
                let comment = try buf.readStringAsString()
                identities.append(AgentIdentity(keyBlob: keyBlob, comment: comment))
            }
            return identities
        } catch {
            NSLog("[upstream] Failed to parse identities response: \(error)")
            return []
        }
    }

    /// Forwards a sign request to the upstream agent.
    /// Returns the signature Data on success, nil on failure.
    public func signRequest(keyBlob: Data, data: Data, flags: UInt32) -> Data? {
        var request = SSHWriteBuffer()
        request.writeByte(SSHAgentMessageType.signRequest.rawValue)
        request.writeString(keyBlob)
        request.writeString(data)
        request.writeUInt32(flags)

        guard let responseBody = sendMessage(request.data) else {
            return nil
        }

        do {
            var buf = SSHReadBuffer(responseBody)
            let typeByte = try buf.readByte()
            guard typeByte == SSHAgentMessageType.signResponse.rawValue else {
                return nil
            }
            return try buf.readString()
        } catch {
            NSLog("[upstream] Failed to parse sign response: \(error)")
            return nil
        }
    }

    /// Sends a message to the upstream agent and reads the response.
    /// Returns the response message body (without length prefix), or nil on error.
    private func sendMessage(_ messageBody: Data) -> Data? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            NSLog("[upstream] Failed to create socket: \(String(cString: strerror(errno)))")
            return nil
        }
        defer { close(fd) }

        // Connect to upstream socket
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            NSLog("[upstream] Socket path too long: \(socketPath)")
            return nil
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dest in
                pathBytes.withUnsafeBufferPointer { src in
                    _ = memcpy(dest, src.baseAddress!, src.count)
                }
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            NSLog("[upstream] Failed to connect to %@: %@", socketPath, String(cString: strerror(errno)))
            return nil
        }

        // Write length-prefixed message
        var framed = SSHWriteBuffer()
        framed.writeUInt32(UInt32(messageBody.count))
        framed.writeBytes(messageBody)

        let writeOk = framed.data.withUnsafeBytes { ptr -> Bool in
            var remaining = framed.data.count
            var offset = 0
            while remaining > 0 {
                let written = write(fd, ptr.baseAddress! + offset, remaining)
                if written <= 0 { return false }
                offset += written
                remaining -= written
            }
            return true
        }
        guard writeOk else {
            NSLog("[upstream] Failed to write request")
            return nil
        }

        // Read 4-byte length prefix
        var lengthBuf = [UInt8](repeating: 0, count: 4)
        guard readFully(fd, &lengthBuf, 4) else {
            NSLog("[upstream] Failed to read response length")
            return nil
        }
        let length = Int(lengthBuf[0]) << 24 | Int(lengthBuf[1]) << 16 | Int(lengthBuf[2]) << 8 | Int(lengthBuf[3])

        guard length > 0, length <= 256 * 1024 else {
            NSLog("[upstream] Response length out of range: \(length)")
            return nil
        }

        // Read message body
        var bodyBuf = [UInt8](repeating: 0, count: length)
        guard readFully(fd, &bodyBuf, length) else {
            NSLog("[upstream] Failed to read response body")
            return nil
        }

        return Data(bodyBuf)
    }

    /// Reads exactly `count` bytes from a file descriptor.
    private func readFully(_ fd: Int32, _ buffer: inout [UInt8], _ count: Int) -> Bool {
        var offset = 0
        while offset < count {
            let n = buffer.withUnsafeMutableBytes { ptr in
                read(fd, ptr.baseAddress! + offset, count - offset)
            }
            if n <= 0 { return false }
            offset += n
        }
        return true
    }
}
