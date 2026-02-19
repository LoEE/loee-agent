import Foundation

public enum SSHWireError: Error {
    case insufficientData
    case invalidFormat(String)
}

// MARK: - Write Buffer

public struct SSHWriteBuffer {
    public private(set) var data = Data()

    public init() {}

    public mutating func writeUInt32(_ value: UInt32) {
        var big = value.bigEndian
        data.append(Data(bytes: &big, count: 4))
    }

    public mutating func writeByte(_ value: UInt8) {
        data.append(value)
    }

    public mutating func writeBytes(_ bytes: Data) {
        data.append(bytes)
    }

    /// Writes an SSH string: uint32 length followed by raw bytes.
    public mutating func writeString(_ value: Data) {
        writeUInt32(UInt32(value.count))
        data.append(value)
    }

    /// Writes an SSH string from a Swift string (UTF-8 encoded).
    public mutating func writeString(_ value: String) {
        writeString(Data(value.utf8))
    }

    /// Writes an SSH mpint (multiple precision integer).
    /// The value is unsigned and represented as big-endian bytes.
    /// Leading zero bytes are stripped, and a 0x00 is prepended if the high bit is set.
    public mutating func writeMPInt(_ value: Data) {
        // Strip leading zeros
        var bytes = Array(value)
        while bytes.count > 1 && bytes[0] == 0 {
            bytes.removeFirst()
        }

        // Handle zero value
        if bytes.count == 1 && bytes[0] == 0 {
            writeUInt32(0)
            return
        }

        // Prepend 0x00 if high bit is set (to indicate positive)
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }

        writeString(Data(bytes))
    }

    public mutating func writeBoolean(_ value: Bool) {
        writeByte(value ? 1 : 0)
    }

    /// Writes a composite value as a length-prefixed string.
    /// The closure builds the inner content, which is then wrapped with a length prefix.
    public mutating func writeComposite(_ build: (inout SSHWriteBuffer) -> Void) {
        var inner = SSHWriteBuffer()
        build(&inner)
        writeString(inner.data)
    }
}

// MARK: - Read Buffer

public struct SSHReadBuffer {
    private let data: Data
    public private(set) var offset: Int

    public init(_ data: Data) {
        self.data = data
        self.offset = 0
    }

    public var remaining: Int { data.count - offset }

    public var isAtEnd: Bool { offset >= data.count }

    public mutating func readByte() throws -> UInt8 {
        guard remaining >= 1 else { throw SSHWireError.insufficientData }
        let value = data[data.startIndex + offset]
        offset += 1
        return value
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else { throw SSHWireError.insufficientData }
        let i = data.startIndex + offset
        let value = UInt32(data[i]) << 24 | UInt32(data[i+1]) << 16 | UInt32(data[i+2]) << 8 | UInt32(data[i+3])
        offset += 4
        return value
    }

    /// Reads an SSH string: uint32 length followed by that many bytes.
    public mutating func readString() throws -> Data {
        let length = try readUInt32()
        guard remaining >= Int(length) else { throw SSHWireError.insufficientData }
        let start = data.startIndex + offset
        let value = data[start ..< start + Int(length)]
        offset += Int(length)
        return Data(value)
    }

    /// Reads an SSH string and interprets it as UTF-8.
    public mutating func readStringAsString() throws -> String {
        let bytes = try readString()
        guard let s = String(data: bytes, encoding: .utf8) else {
            throw SSHWireError.invalidFormat("Invalid UTF-8 in string")
        }
        return s
    }

    /// Reads an SSH mpint.
    public mutating func readMPInt() throws -> Data {
        return try readString()
    }

    public mutating func readBoolean() throws -> Bool {
        let b = try readByte()
        return b != 0
    }

    /// Reads a specific number of bytes without a length prefix.
    public mutating func readBytes(_ count: Int) throws -> Data {
        guard remaining >= count else { throw SSHWireError.insufficientData }
        let start = data.startIndex + offset
        let value = data[start ..< start + count]
        offset += count
        return Data(value)
    }

    public mutating func readRemainingData() -> Data {
        let start = data.startIndex + offset
        let value = data[start...]
        offset = data.count
        return Data(value)
    }
}
