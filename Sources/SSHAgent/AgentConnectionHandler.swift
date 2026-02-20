import Foundation
import SSHAgentLib

#if canImport(Darwin)
import Darwin
#endif

/// Handles a single client connection to the SSH agent.
/// Reads SSH agent protocol messages, dispatches to the request handler, and writes responses.
public final class AgentConnectionHandler {
    private let clientFD: Int32
    private let socketType: SocketType
    private let requestHandler: AgentRequestHandler
    private var readSource: DispatchSourceRead?
    private var buffer = [UInt8]()
    private let queue: DispatchQueue
    private let onClose: (AgentConnectionHandler) -> Void

    public init(
        clientFD: Int32,
        socketType: SocketType,
        requestHandler: AgentRequestHandler,
        onClose: @escaping (AgentConnectionHandler) -> Void
    ) {
        self.clientFD = clientFD
        self.socketType = socketType
        self.requestHandler = requestHandler
        self.queue = DispatchQueue(label: "pl.loee.loee-agent.conn.\(clientFD)")
        self.onClose = onClose
    }

    public func start() {
        readSource = DispatchSource.makeReadSource(fileDescriptor: clientFD, queue: queue)
        readSource?.setEventHandler { [weak self] in
            self?.handleReadEvent()
        }
        readSource?.setCancelHandler { [weak self] in
            guard let self else { return }
            close(self.clientFD)
            self.onClose(self)
        }
        readSource?.resume()
    }

    private func handleReadEvent() {
        var readBuf = [UInt8](repeating: 0, count: 4096)
        let bytesRead = read(clientFD, &readBuf, readBuf.count)

        if bytesRead <= 0 {
            readSource?.cancel()
            return
        }

        buffer.append(contentsOf: readBuf[0 ..< bytesRead])
        processBuffer()
    }

    private func processBuffer() {
        while buffer.count >= 4 {
            let length = Int(buffer[0]) << 24 | Int(buffer[1]) << 16 | Int(buffer[2]) << 8 | Int(buffer[3])

            let totalNeeded = 4 + length
            guard buffer.count >= totalNeeded else {
                break
            }

            let messageData = Data(buffer[4 ..< totalNeeded])
            buffer.removeFirst(totalNeeded)

            processMessage(messageData)
        }
    }

    private func processMessage(_ messageData: Data) {
        do {
            let request = try parseAgentRequest(from: messageData)

            Task {
                let response = await self.requestHandler.handle(
                    request: request,
                    socketType: self.socketType
                )
                let responseData = serializeAgentResponse(response)
                self.writeResponse(responseData)
            }
        } catch {
            let response = serializeAgentResponse(.failure)
            writeResponse(response)
        }
    }

    private func writeResponse(_ data: Data) {
        data.withUnsafeBytes { ptr in
            var remaining = data.count
            var offset = 0
            while remaining > 0 {
                let written = write(clientFD, ptr.baseAddress! + offset, remaining)
                if written <= 0 {
                    readSource?.cancel()
                    return
                }
                offset += written
                remaining -= written
            }
        }
    }
}
