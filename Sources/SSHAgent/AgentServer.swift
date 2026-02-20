import Foundation
import SSHAgentLib

#if canImport(Darwin)
import Darwin
#endif

public enum SocketType {
    case local
    case forwarded
}

public final class AgentServer {
    public let socketPath: String
    public let socketType: SocketType
    public let requestHandler: AgentRequestHandler
    private var listenFD: Int32 = -1
    private var listenSource: DispatchSourceRead?
    private let queue = DispatchQueue(label: "pl.loee.loee-agent.server", attributes: .concurrent)

    /// Active connections — the server retains handlers for their lifetime.
    private var connections = Set<ObjectIdentifier>()
    private var connectionHandlers = [ObjectIdentifier: AgentConnectionHandler]()
    private let connectionsLock = NSLock()

    public init(socketPath: String, socketType: SocketType, requestHandler: AgentRequestHandler) {
        self.socketPath = socketPath
        self.socketType = socketType
        self.requestHandler = requestHandler
    }

    public func start() throws {
        // Remove existing socket file
        unlink(socketPath)

        // Create socket
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenFD >= 0 else {
            throw AgentServerError.socketCreationFailed(errno)
        }

        // Bind
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            close(listenFD)
            throw AgentServerError.pathTooLong(socketPath)
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dest in
                pathBytes.withUnsafeBufferPointer { src in
                    _ = memcpy(dest, src.baseAddress!, src.count)
                }
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(listenFD, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            close(listenFD)
            throw AgentServerError.bindFailed(errno)
        }

        // Set permissions to 0600
        chmod(socketPath, 0o600)

        // Listen
        guard Darwin.listen(listenFD, 5) == 0 else {
            close(listenFD)
            unlink(socketPath)
            throw AgentServerError.listenFailed(errno)
        }

        NSLog("[\(socketType)] Listening on \(socketPath)")

        // Accept loop via GCD
        listenSource = DispatchSource.makeReadSource(fileDescriptor: listenFD, queue: queue)
        listenSource?.setEventHandler { [weak self] in
            self?.acceptConnection()
        }
        listenSource?.setCancelHandler { [weak self] in
            if let fd = self?.listenFD, fd >= 0 {
                close(fd)
            }
        }
        listenSource?.resume()
    }

    public func stop() {
        listenSource?.cancel()
        listenSource = nil
        if listenFD >= 0 {
            close(listenFD)
            listenFD = -1
        }
        unlink(socketPath)
    }

    private func acceptConnection() {
        let clientFD = accept(listenFD, nil, nil)
        guard clientFD >= 0 else { return }

        let handler = AgentConnectionHandler(
            clientFD: clientFD,
            socketType: socketType,
            requestHandler: requestHandler,
            onClose: { [weak self] handler in
                self?.removeConnection(handler)
            }
        )

        let id = ObjectIdentifier(handler)
        connectionsLock.lock()
        connectionHandlers[id] = handler
        connectionsLock.unlock()

        handler.start()
    }

    private func removeConnection(_ handler: AgentConnectionHandler) {
        let id = ObjectIdentifier(handler)
        connectionsLock.lock()
        connectionHandlers.removeValue(forKey: id)
        connectionsLock.unlock()
    }
}

public enum AgentServerError: Error, CustomStringConvertible {
    case socketCreationFailed(Int32)
    case pathTooLong(String)
    case bindFailed(Int32)
    case listenFailed(Int32)

    public var description: String {
        switch self {
        case .socketCreationFailed(let e): return "Failed to create socket: \(String(cString: strerror(e)))"
        case .pathTooLong(let p): return "Socket path too long: \(p)"
        case .bindFailed(let e): return "Failed to bind socket: \(String(cString: strerror(e)))"
        case .listenFailed(let e): return "Failed to listen on socket: \(String(cString: strerror(e)))"
        }
    }
}
