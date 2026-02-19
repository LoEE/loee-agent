import Foundation
import CryptoKit

/// Encodes an Ed25519 public key as an SSH key blob.
/// Format: string("ssh-ed25519") || string(32-byte-public-key)
public func encodeEd25519PublicKeyBlob(publicKey: Curve25519.Signing.PublicKey) -> Data {
    var buf = SSHWriteBuffer()
    buf.writeString("ssh-ed25519")
    buf.writeString(publicKey.rawRepresentation)
    return buf.data
}

/// Encodes a P-256 public key as an SSH key blob.
/// Format: string("ecdsa-sha2-nistp256") || string("nistp256") || string(uncompressed-point)
public func encodeECDSAP256PublicKeyBlob(publicKey: P256.Signing.PublicKey) -> Data {
    var buf = SSHWriteBuffer()
    buf.writeString("ecdsa-sha2-nistp256")
    buf.writeString("nistp256")
    buf.writeString(publicKey.x963Representation)
    return buf.data
}

/// Computes an SSH fingerprint: "SHA256:<base64-no-padding>"
public func sshFingerprint(keyBlob: Data) -> String {
    let hash = SHA256.hash(data: keyBlob)
    let b64 = Data(hash).base64EncodedString()
    // Remove trailing '=' padding to match OpenSSH format
    let trimmed = b64.replacingOccurrences(of: "=", with: "")
    return "SHA256:\(trimmed)"
}

/// Formats a key for authorized_keys: "<algorithm> <base64-blob> <comment>"
public func authorizedKeysLine(key: any SSHKey) -> String {
    let b64 = key.sshPublicKeyBlob.base64EncodedString()
    return "\(key.algorithm.sshName) \(b64) \(key.comment)"
}
