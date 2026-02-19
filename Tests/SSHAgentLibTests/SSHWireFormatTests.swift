import Testing
import Foundation
@testable import SSHAgentLib

@Suite("SSHWriteBuffer")
struct SSHWriteBufferTests {
    @Test func writeUInt32() {
        var buf = SSHWriteBuffer()
        buf.writeUInt32(0x01020304)
        #expect(buf.data == Data([0x01, 0x02, 0x03, 0x04]))
    }

    @Test func writeUInt32Zero() {
        var buf = SSHWriteBuffer()
        buf.writeUInt32(0)
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x00]))
    }

    @Test func writeByte() {
        var buf = SSHWriteBuffer()
        buf.writeByte(0xFF)
        #expect(buf.data == Data([0xFF]))
    }

    @Test func writeStringData() {
        var buf = SSHWriteBuffer()
        buf.writeString(Data([0x41, 0x42, 0x43]))
        // length = 3, then "ABC"
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x03, 0x41, 0x42, 0x43]))
    }

    @Test func writeStringText() {
        var buf = SSHWriteBuffer()
        buf.writeString("ssh-ed25519")
        let expected = Data([0x00, 0x00, 0x00, 0x0B]) + Data("ssh-ed25519".utf8)
        #expect(buf.data == expected)
    }

    @Test func writeEmptyString() {
        var buf = SSHWriteBuffer()
        buf.writeString(Data())
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x00]))
    }

    @Test func writeMPIntZero() {
        var buf = SSHWriteBuffer()
        buf.writeMPInt(Data([0x00]))
        // Zero mpint has length 0
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x00]))
    }

    @Test func writeMPIntPositiveNoHighBit() {
        var buf = SSHWriteBuffer()
        buf.writeMPInt(Data([0x7F, 0x01]))
        // No high bit set, length 2
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x02, 0x7F, 0x01]))
    }

    @Test func writeMPIntPositiveWithHighBit() {
        var buf = SSHWriteBuffer()
        buf.writeMPInt(Data([0x80, 0x01]))
        // High bit set, prepend 0x00, length 3
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x01]))
    }

    @Test func writeMPIntStripsLeadingZeros() {
        var buf = SSHWriteBuffer()
        buf.writeMPInt(Data([0x00, 0x00, 0x7F, 0x01]))
        // Strips leading zeros, length 2
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x02, 0x7F, 0x01]))
    }

    @Test func writeMPIntStripsLeadingZerosThenAddsBack() {
        var buf = SSHWriteBuffer()
        buf.writeMPInt(Data([0x00, 0x00, 0x80, 0x01]))
        // Strip leading zeros → [0x80, 0x01], high bit set → prepend 0x00 → [0x00, 0x80, 0x01]
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x01]))
    }

    @Test func writeComposite() {
        var buf = SSHWriteBuffer()
        buf.writeComposite { inner in
            inner.writeByte(0x01)
            inner.writeByte(0x02)
        }
        // length 2, then bytes
        #expect(buf.data == Data([0x00, 0x00, 0x00, 0x02, 0x01, 0x02]))
    }
}

@Suite("SSHReadBuffer")
struct SSHReadBufferTests {
    @Test func readUInt32() throws {
        var buf = SSHReadBuffer(Data([0x01, 0x02, 0x03, 0x04]))
        let value = try buf.readUInt32()
        #expect(value == 0x01020304)
        #expect(buf.isAtEnd)
    }

    @Test func readByte() throws {
        var buf = SSHReadBuffer(Data([0xFF]))
        let value = try buf.readByte()
        #expect(value == 0xFF)
    }

    @Test func readString() throws {
        var buf = SSHReadBuffer(Data([0x00, 0x00, 0x00, 0x03, 0x41, 0x42, 0x43]))
        let value = try buf.readString()
        #expect(value == Data([0x41, 0x42, 0x43]))
    }

    @Test func readStringAsString() throws {
        let input = Data([0x00, 0x00, 0x00, 0x0B]) + Data("ssh-ed25519".utf8)
        var buf = SSHReadBuffer(input)
        let value = try buf.readStringAsString()
        #expect(value == "ssh-ed25519")
    }

    @Test func readInsufficientDataThrows() {
        var buf = SSHReadBuffer(Data([0x01, 0x02]))
        #expect(throws: SSHWireError.self) {
            _ = try buf.readUInt32()
        }
    }

    @Test func readStringInsufficientDataThrows() {
        // Claims length 10 but only has 3 bytes
        var buf = SSHReadBuffer(Data([0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03]))
        #expect(throws: SSHWireError.self) {
            _ = try buf.readString()
        }
    }

    @Test func roundTripUInt32() throws {
        var write = SSHWriteBuffer()
        write.writeUInt32(0xDEADBEEF)
        var read = SSHReadBuffer(write.data)
        let value = try read.readUInt32()
        #expect(value == 0xDEADBEEF)
    }

    @Test func roundTripString() throws {
        let original = Data("hello, world!".utf8)
        var write = SSHWriteBuffer()
        write.writeString(original)
        var read = SSHReadBuffer(write.data)
        let value = try read.readString()
        #expect(value == original)
    }

    @Test func readMultipleValues() throws {
        var write = SSHWriteBuffer()
        write.writeUInt32(42)
        write.writeString("test")
        write.writeByte(0xFF)

        var read = SSHReadBuffer(write.data)
        #expect(try read.readUInt32() == 42)
        #expect(try read.readStringAsString() == "test")
        #expect(try read.readByte() == 0xFF)
        #expect(read.isAtEnd)
    }
}
