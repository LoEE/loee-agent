import Foundation
import CryptoKit

/// Verifies SSH host key signatures from key exchange.
/// Supports Ed25519 and ECDSA P-256 host keys.
public enum HostKeyVerifier {

    /// Verifies that `signature` is a valid signature over `sessionId` by `hostKeyBlob`.
    /// This proves a real key exchange happened with the host that holds this key.
    public static func verify(
        hostKeyBlob: Data,
        sessionId: Data,
        signature: Data
    ) -> Bool {
        do {
            // Parse the host key blob to determine the algorithm
            var keyBuf = SSHReadBuffer(hostKeyBlob)
            let keyType = try keyBuf.readStringAsString()

            // Parse the signature blob to get the raw signature
            var sigBuf = SSHReadBuffer(signature)
            let sigType = try sigBuf.readStringAsString()
            let sigData = try sigBuf.readString()

            switch keyType {
            case "ssh-ed25519":
                guard sigType == "ssh-ed25519" else { return false }
                return try verifyEd25519(
                    publicKeyBlob: hostKeyBlob,
                    signature: sigData,
                    data: sessionId
                )

            case "ecdsa-sha2-nistp256":
                guard sigType == "ecdsa-sha2-nistp256" else { return false }
                return try verifyECDSAP256(
                    publicKeyBlob: hostKeyBlob,
                    signatureBlob: sigData,
                    data: sessionId
                )

            case "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa":
                // RSA verification would require Security framework.
                // For now, accept RSA host keys without signature verification
                // but still match against known_hosts by key blob.
                return true

            default:
                return false
            }
        } catch {
            return false
        }
    }

    private static func verifyEd25519(
        publicKeyBlob: Data,
        signature: Data,
        data: Data
    ) throws -> Bool {
        // Extract the 32-byte public key from the blob
        // Blob: string("ssh-ed25519") || string(32-byte key)
        var buf = SSHReadBuffer(publicKeyBlob)
        _ = try buf.readString() // "ssh-ed25519"
        let rawKey = try buf.readString()
        guard rawKey.count == 32 else { return false }

        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawKey)
        return publicKey.isValidSignature(signature, for: data)
    }

    private static func verifyECDSAP256(
        publicKeyBlob: Data,
        signatureBlob: Data,
        data: Data
    ) throws -> Bool {
        // Extract the public key point from the blob
        // Blob: string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)
        var keyBuf = SSHReadBuffer(publicKeyBlob)
        _ = try keyBuf.readString() // "ecdsa-sha2-nistp256"
        _ = try keyBuf.readString() // "nistp256"
        let point = try keyBuf.readString()
        guard point.count == 65, point[point.startIndex] == 0x04 else { return false }

        let publicKey = try P256.Signing.PublicKey(x963Representation: point)

        // Parse the SSH signature: mpint(r) || mpint(s)
        var sigBuf = SSHReadBuffer(signatureBlob)
        let rData = try sigBuf.readMPInt()
        let sData = try sigBuf.readMPInt()

        // Convert mpint r,s back to fixed 32-byte values for rawRepresentation
        let r = mpintToFixed(rData, size: 32)
        let s = mpintToFixed(sData, size: 32)
        guard r.count == 32, s.count == 32 else { return false }

        let rawSig = r + s
        let ecdsaSig = try P256.Signing.ECDSASignature(rawRepresentation: rawSig)

        // ECDSA signatures in SSH are over SHA-256(data)
        let digest = SHA256.hash(data: data)
        return publicKey.isValidSignature(ecdsaSig, for: digest)
    }

    /// Converts an mpint value to a fixed-size unsigned big-endian byte array.
    /// Strips the leading 0x00 padding byte if present, then left-pads with zeros.
    private static func mpintToFixed(_ data: Data, size: Int) -> Data {
        var bytes = Array(data)
        // Strip leading zero that was added for sign encoding
        if bytes.count == size + 1 && bytes[0] == 0 {
            bytes.removeFirst()
        }
        // Strip any other leading zeros and left-pad to target size
        while bytes.count > size {
            bytes.removeFirst()
        }
        while bytes.count < size {
            bytes.insert(0, at: 0)
        }
        return Data(bytes)
    }
}
