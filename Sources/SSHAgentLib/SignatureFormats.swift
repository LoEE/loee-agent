import Foundation

/// Encodes an Ed25519 signature in SSH wire format.
/// Input: 64-byte raw signature from CryptoKit.
/// Output: string("ssh-ed25519") || string(64-byte-signature)
public func ed25519SignatureToSSH(rawSignature: Data) -> Data {
    var buf = SSHWriteBuffer()
    buf.writeString("ssh-ed25519")
    buf.writeString(rawSignature)
    return buf.data
}

/// Converts a CryptoKit P-256 ECDSA signature (raw representation) to SSH wire format.
/// Input: 64-byte raw representation (r[32] || s[32]) from ECDSASignature.rawRepresentation.
/// Output: string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))
public func ecdsaSignatureToSSH(rawRepresentation: Data) throws -> Data {
    guard rawRepresentation.count == 64 else {
        throw SSHWireError.invalidFormat("ECDSA raw representation must be 64 bytes, got \(rawRepresentation.count)")
    }

    let r = rawRepresentation.prefix(32)
    let s = rawRepresentation.suffix(32)

    var buf = SSHWriteBuffer()
    buf.writeString("ecdsa-sha2-nistp256")

    // Inner blob: mpint(r) || mpint(s)
    buf.writeComposite { inner in
        inner.writeMPInt(r)
        inner.writeMPInt(s)
    }

    return buf.data
}
