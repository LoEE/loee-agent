import Testing
import Foundation
import CryptoKit
@testable import SSHAgentLib

@Suite("KnownHosts")
struct KnownHostsTests {
    @Test func parsePlaintextEntry() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        // Generate a real Ed25519 key and create a known_hosts entry
        let key = Curve25519.Signing.PrivateKey()
        let blob = encodeEd25519PublicKeyBlob(publicKey: key.publicKey)
        let b64 = blob.base64EncodedString()

        let knownHostsPath = tmpDir.appendingPathComponent("known_hosts").path
        let content = "github.com,192.30.255.113 ssh-ed25519 \(b64)\n"
        FileManager.default.createFile(atPath: knownHostsPath, contents: Data(content.utf8))

        let store = KnownHostsStore()
        try store.load(from: knownHostsPath)

        // Verify matching key
        let result = store.verify(hostname: "github.com", keyBlob: blob)
        #expect(result == .verified("github.com"))

        // Verify by alternate hostname
        let result2 = store.verify(hostname: "192.30.255.113", keyBlob: blob)
        #expect(result2 == .verified("192.30.255.113"))

        // Verify unknown hostname
        let result3 = store.verify(hostname: "example.com", keyBlob: blob)
        #expect(result3 == .unknown("example.com"))

        // Verify mismatched key
        let otherKey = Curve25519.Signing.PrivateKey()
        let otherBlob = encodeEd25519PublicKeyBlob(publicKey: otherKey.publicKey)
        let result4 = store.verify(hostname: "github.com", keyBlob: otherBlob)
        #expect(result4 == .mismatch("github.com"))
    }

    @Test func parseHashedEntry() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        // Create a hashed known_hosts entry
        let key = Curve25519.Signing.PrivateKey()
        let blob = encodeEd25519PublicKeyBlob(publicKey: key.publicKey)
        let b64 = blob.base64EncodedString()

        // Generate HMAC-SHA1 hash like OpenSSH does
        let hostname = "myserver.example.com"
        let salt = Data((0..<20).map { _ in UInt8.random(in: 0...255) })
        let symmetricKey = SymmetricKey(data: salt)
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(hostname.utf8), using: symmetricKey)

        let saltB64 = salt.base64EncodedString()
        let hashB64 = Data(mac).base64EncodedString()
        let line = "|1|\(saltB64)|\(hashB64) ssh-ed25519 \(b64)\n"

        let knownHostsPath = tmpDir.appendingPathComponent("known_hosts").path
        FileManager.default.createFile(atPath: knownHostsPath, contents: Data(line.utf8))

        let store = KnownHostsStore()
        try store.load(from: knownHostsPath)

        // Should verify the correct hostname
        let result = store.verify(hostname: hostname, keyBlob: blob)
        #expect(result == .verified(hostname))

        // Should not verify a different hostname
        let result2 = store.verify(hostname: "other.example.com", keyBlob: blob)
        #expect(result2 == .unknown("other.example.com"))
    }

    @Test func hostnamesForKey() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let key = Curve25519.Signing.PrivateKey()
        let blob = encodeEd25519PublicKeyBlob(publicKey: key.publicKey)
        let b64 = blob.base64EncodedString()

        let content = """
        host1.example.com ssh-ed25519 \(b64)
        host2.example.com ssh-ed25519 \(b64)
        """
        let knownHostsPath = tmpDir.appendingPathComponent("known_hosts").path
        FileManager.default.createFile(atPath: knownHostsPath, contents: Data(content.utf8))

        let store = KnownHostsStore()
        try store.load(from: knownHostsPath)

        let names = store.hostnamesForKey(blob)
        #expect(names.contains("host1.example.com"))
        #expect(names.contains("host2.example.com"))
    }

    @Test func nonStandardPort() throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let key = Curve25519.Signing.PrivateKey()
        let blob = encodeEd25519PublicKeyBlob(publicKey: key.publicKey)
        let b64 = blob.base64EncodedString()

        let content = "[myhost.com]:2222 ssh-ed25519 \(b64)\n"
        let knownHostsPath = tmpDir.appendingPathComponent("known_hosts").path
        FileManager.default.createFile(atPath: knownHostsPath, contents: Data(content.utf8))

        let store = KnownHostsStore()
        try store.load(from: knownHostsPath)

        let result = store.verify(hostname: "myhost.com", port: 2222, keyBlob: blob)
        #expect(result == .verified("myhost.com"))
    }
}

@Suite("SessionBind Parsing")
struct SessionBindParsingTests {
    @Test func parseSessionBindExtension() throws {
        var msg = SSHWriteBuffer()
        msg.writeByte(27) // SSH_AGENTC_EXTENSION
        msg.writeString("session-bind@pl.loee")
        msg.writeString("myhost.example.com")
        msg.writeString(Data([0x01, 0x02, 0x03])) // host key blob
        msg.writeString(Data([0x04, 0x05])) // session id
        msg.writeString(Data([0x06, 0x07])) // signature
        msg.writeByte(1) // is_forwarded

        let request = try parseAgentRequest(from: msg.data)
        guard case .sessionBind(let info) = request else {
            Issue.record("Expected sessionBind, got \(request)")
            return
        }
        #expect(info.hostname == "myhost.example.com")
        #expect(info.hostKeyBlob == Data([0x01, 0x02, 0x03]))
        #expect(info.sessionId == Data([0x04, 0x05]))
        #expect(info.hostKeySignature == Data([0x06, 0x07]))
        #expect(info.isForwarded == true)
    }

    @Test func unknownExtensionReturnedAsUnknown() throws {
        var msg = SSHWriteBuffer()
        msg.writeByte(27)
        msg.writeString("something-else@example.com")

        let request = try parseAgentRequest(from: msg.data)
        guard case .unknown = request else {
            Issue.record("Expected unknown, got \(request)")
            return
        }
    }
}

@Suite("HostKeyVerifier")
struct HostKeyVerifierTests {
    @Test func ed25519HostKeyVerification() throws {
        // Simulate a host key exchange
        let hostKey = Curve25519.Signing.PrivateKey()
        let hostKeyBlob = encodeEd25519PublicKeyBlob(publicKey: hostKey.publicKey)
        let sessionId = Data("fake-session-id-for-test".utf8)

        // Host signs the session ID
        let signature = try hostKey.signature(for: sessionId)

        // Wrap in SSH signature format
        var sigBuf = SSHWriteBuffer()
        sigBuf.writeString("ssh-ed25519")
        sigBuf.writeString(Data(signature))

        let result = HostKeyVerifier.verify(
            hostKeyBlob: hostKeyBlob,
            sessionId: sessionId,
            signature: sigBuf.data
        )
        #expect(result == true)
    }

    @Test func ed25519HostKeyWrongSignature() throws {
        let hostKey = Curve25519.Signing.PrivateKey()
        let hostKeyBlob = encodeEd25519PublicKeyBlob(publicKey: hostKey.publicKey)
        let sessionId = Data("fake-session-id".utf8)

        // Sign different data
        let wrongSig = try hostKey.signature(for: Data("wrong-data".utf8))
        var sigBuf = SSHWriteBuffer()
        sigBuf.writeString("ssh-ed25519")
        sigBuf.writeString(Data(wrongSig))

        let result = HostKeyVerifier.verify(
            hostKeyBlob: hostKeyBlob,
            sessionId: sessionId,
            signature: sigBuf.data
        )
        #expect(result == false)
    }

    @Test func signRequestDataParsing() {
        // Build a mock SSH_MSG_USERAUTH_REQUEST
        var data = SSHWriteBuffer()
        data.writeString(Data("session-id-here".utf8)) // session_id
        data.writeByte(50) // SSH_MSG_USERAUTH_REQUEST
        data.writeString("deploy") // username
        data.writeString("ssh-connection") // service
        data.writeString("publickey") // method
        data.writeBoolean(true)
        data.writeString("ssh-ed25519") // algorithm
        data.writeString(Data([0x01, 0x02])) // pubkey blob

        let info = parseSignRequestData(data.data)
        #expect(info != nil)
        #expect(info?.username == "deploy")
        #expect(info?.sessionId == Data("session-id-here".utf8))
        #expect(info?.algorithm == "ssh-ed25519")
    }
}
