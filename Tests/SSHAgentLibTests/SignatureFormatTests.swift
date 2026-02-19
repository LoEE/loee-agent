import Testing
import Foundation
import CryptoKit
@testable import SSHAgentLib

@Suite("Signature Formats")
struct SignatureFormatTests {
    @Test func ed25519SignatureFormat() {
        let rawSig = Data(repeating: 0xAA, count: 64)
        let sshSig = ed25519SignatureToSSH(rawSignature: rawSig)

        var buf = SSHReadBuffer(sshSig)
        let alg = try! buf.readStringAsString()
        let sig = try! buf.readString()

        #expect(alg == "ssh-ed25519")
        #expect(sig == rawSig)
        #expect(sig.count == 64)
    }

    @Test func ecdsaSignatureFormat() throws {
        // Create a known 64-byte raw representation: r(32) || s(32)
        // Fill with non-zero values to avoid leading-zero stripping confusion
        var raw = Data(repeating: 0x01, count: 64)
        raw[0] = 0x7F  // r starts with 0x7F (no 0x00 padding needed)
        raw[32] = 0x80 // s starts with 0x80 (needs 0x00 padding)

        let sshSig = try ecdsaSignatureToSSH(rawRepresentation: raw)

        var buf = SSHReadBuffer(sshSig)
        let alg = try buf.readStringAsString()
        #expect(alg == "ecdsa-sha2-nistp256")

        let innerBlob = try buf.readString()
        var inner = SSHReadBuffer(innerBlob)

        // r: 32 bytes starting with 0x7F — no leading zeros, no 0x00 padding needed
        let r = try inner.readString()
        #expect(r.count == 32)
        #expect(r.first! == 0x7F)

        // s: 32 bytes starting with 0x80 — needs 0x00 prefix since high bit set
        let s = try inner.readString()
        #expect(s.count == 33) // 0x00 + 32 bytes
        #expect(s.first! == 0x00)
        #expect(s[1] == 0x80)
    }

    @Test func ecdsaSignatureRejectsWrongLength() {
        #expect(throws: SSHWireError.self) {
            _ = try ecdsaSignatureToSSH(rawRepresentation: Data(count: 32))
        }
    }

    @Test func realEd25519SignAndVerify() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let data = Data("test data to sign".utf8)
        let sig = try privateKey.signature(for: data)

        let sshSig = ed25519SignatureToSSH(rawSignature: sig)

        // Parse it back
        var buf = SSHReadBuffer(sshSig)
        let alg = try buf.readStringAsString()
        let rawSig = try buf.readString()

        #expect(alg == "ssh-ed25519")
        #expect(rawSig.count == 64)

        // Verify the raw signature still works
        #expect(privateKey.publicKey.isValidSignature(rawSig, for: data))
    }

    @Test func realP256SignatureConversion() throws {
        let privateKey = P256.Signing.PrivateKey()
        let data = Data("test data to sign".utf8)
        let sig = try privateKey.signature(for: SHA256.hash(data: data))

        let sshSig = try ecdsaSignatureToSSH(rawRepresentation: sig.rawRepresentation)

        // Parse it back
        var buf = SSHReadBuffer(sshSig)
        let alg = try buf.readStringAsString()
        #expect(alg == "ecdsa-sha2-nistp256")

        let innerBlob = try buf.readString()
        var inner = SSHReadBuffer(innerBlob)
        let r = try inner.readMPInt()
        let s = try inner.readMPInt()

        // r and s should be non-empty
        #expect(!r.isEmpty)
        #expect(!s.isEmpty)
    }
}

@Suite("Public Key Formats")
struct PublicKeyFormatTests {
    @Test func ed25519PublicKeyBlob() {
        let privateKey = Curve25519.Signing.PrivateKey()
        let blob = encodeEd25519PublicKeyBlob(publicKey: privateKey.publicKey)

        var buf = SSHReadBuffer(blob)
        let alg = try! buf.readStringAsString()
        let pubBytes = try! buf.readString()

        #expect(alg == "ssh-ed25519")
        #expect(pubBytes.count == 32)
        #expect(pubBytes == privateKey.publicKey.rawRepresentation)
    }

    @Test func ecdsaP256PublicKeyBlob() {
        let privateKey = P256.Signing.PrivateKey()
        let blob = encodeECDSAP256PublicKeyBlob(publicKey: privateKey.publicKey)

        var buf = SSHReadBuffer(blob)
        let alg = try! buf.readStringAsString()
        let curve = try! buf.readStringAsString()
        let point = try! buf.readString()

        #expect(alg == "ecdsa-sha2-nistp256")
        #expect(curve == "nistp256")
        #expect(point.count == 65)
        #expect(point[0] == 0x04) // uncompressed point
        #expect(point == privateKey.publicKey.x963Representation)
    }

    @Test func sshFingerprintFormat() {
        let blob = Data("test key blob".utf8)
        let fp = sshFingerprint(keyBlob: blob)
        #expect(fp.hasPrefix("SHA256:"))
        #expect(!fp.contains("="))
    }

    @Test func authorizedKeysLineFormat() {
        let privateKey = Curve25519.Signing.PrivateKey()
        let key = Ed25519SSHKey(privateKey: privateKey, comment: "test@host")
        let line = authorizedKeysLine(key: key)

        #expect(line.hasPrefix("ssh-ed25519 "))
        #expect(line.hasSuffix(" test@host"))

        // The middle part should be valid base64
        let parts = line.split(separator: " ")
        #expect(parts.count == 3)
        let b64 = String(parts[1])
        #expect(Data(base64Encoded: b64) != nil)
    }
}
