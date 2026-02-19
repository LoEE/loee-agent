import Testing
import Foundation
@testable import SSHAgentLib

@Suite("Agent Protocol Parsing")
struct AgentProtocolParsingTests {
    @Test func parseRequestIdentities() throws {
        // Type 11, no payload
        let data = Data([0x0B])
        let request = try parseAgentRequest(from: data)
        guard case .requestIdentities = request else {
            Issue.record("Expected requestIdentities, got \(request)")
            return
        }
    }

    @Test func parseSignRequest() throws {
        // Build a sign request message body
        var msg = SSHWriteBuffer()
        msg.writeByte(0x0D) // type 13
        msg.writeString(Data([0x01, 0x02, 0x03])) // key blob
        msg.writeString(Data([0x04, 0x05])) // data
        msg.writeUInt32(0) // flags

        let request = try parseAgentRequest(from: msg.data)
        guard case .signRequest(let keyBlob, let signData, let flags) = request else {
            Issue.record("Expected signRequest, got \(request)")
            return
        }
        #expect(keyBlob == Data([0x01, 0x02, 0x03]))
        #expect(signData == Data([0x04, 0x05]))
        #expect(flags == 0)
    }

    @Test func parseUnknownType() throws {
        let data = Data([0x63]) // type 99
        let request = try parseAgentRequest(from: data)
        guard case .unknown(let t) = request else {
            Issue.record("Expected unknown, got \(request)")
            return
        }
        #expect(t == 0x63)
    }
}

@Suite("Agent Protocol Serialization")
struct AgentProtocolSerializationTests {
    @Test func serializeFailure() {
        let data = serializeAgentResponse(.failure)
        // length=1, type=5
        #expect(data == Data([0x00, 0x00, 0x00, 0x01, 0x05]))
    }

    @Test func serializeSuccess() {
        let data = serializeAgentResponse(.success)
        #expect(data == Data([0x00, 0x00, 0x00, 0x01, 0x06]))
    }

    @Test func serializeEmptyIdentitiesAnswer() {
        let data = serializeAgentResponse(.identitiesAnswer([]))
        // length = 1 (type) + 4 (nkeys=0) = 5
        #expect(data == Data([0x00, 0x00, 0x00, 0x05, 0x0C, 0x00, 0x00, 0x00, 0x00]))
    }

    @Test func serializeIdentitiesAnswer() {
        let identities = [
            AgentIdentity(keyBlob: Data([0xAA, 0xBB]), comment: "test"),
        ]
        let data = serializeAgentResponse(.identitiesAnswer(identities))

        var buf = SSHReadBuffer(data)
        let length = try! buf.readUInt32()
        let typeByte = try! buf.readByte()
        let nkeys = try! buf.readUInt32()
        let blob = try! buf.readString()
        let comment = try! buf.readStringAsString()

        #expect(typeByte == 0x0C) // identitiesAnswer
        #expect(nkeys == 1)
        #expect(blob == Data([0xAA, 0xBB]))
        #expect(comment == "test")
        #expect(Int(length) == data.count - 4)
    }

    @Test func serializeSignResponse() {
        let sig = Data([0x01, 0x02, 0x03])
        let data = serializeAgentResponse(.signResponse(sig))

        var buf = SSHReadBuffer(data)
        let length = try! buf.readUInt32()
        let typeByte = try! buf.readByte()
        let sigBlob = try! buf.readString()

        #expect(typeByte == 0x0E) // signResponse
        #expect(sigBlob == sig)
        #expect(Int(length) == data.count - 4)
    }
}
