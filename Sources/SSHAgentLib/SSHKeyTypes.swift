import Foundation
import CryptoKit

public enum KeyAlgorithm: String, Codable {
    case ed25519
    case ecdsaP256

    public var sshName: String {
        switch self {
        case .ed25519: return "ssh-ed25519"
        case .ecdsaP256: return "ecdsa-sha2-nistp256"
        }
    }
}

public struct KeyIdentifier: Codable, Hashable {
    public let id: String
    public let keyType: KeyAlgorithm
    public let comment: String
    public let createdAt: Date

    public init(id: String, keyType: KeyAlgorithm, comment: String, createdAt: Date = Date()) {
        self.id = id
        self.keyType = keyType
        self.comment = comment
        self.createdAt = createdAt
    }
}

/// Unified interface for SSH keys (both SE and software-backed).
public protocol SSHKey {
    var algorithm: KeyAlgorithm { get }
    var sshPublicKeyBlob: Data { get }
    var comment: String { get }
    var fingerprint: String { get }
    func sign(data: Data) throws -> Data
}

// MARK: - Ed25519 Key

public final class Ed25519SSHKey: SSHKey {
    public let algorithm = KeyAlgorithm.ed25519
    public let comment: String
    private let privateKey: Curve25519.Signing.PrivateKey

    public init(privateKey: Curve25519.Signing.PrivateKey, comment: String) {
        self.privateKey = privateKey
        self.comment = comment
    }

    public var sshPublicKeyBlob: Data {
        encodeEd25519PublicKeyBlob(publicKey: privateKey.publicKey)
    }

    public var fingerprint: String {
        sshFingerprint(keyBlob: sshPublicKeyBlob)
    }

    public func sign(data: Data) throws -> Data {
        let sig = try privateKey.signature(for: data)
        return ed25519SignatureToSSH(rawSignature: sig)
    }
}

// MARK: - Secure Enclave P-256 Key

public final class SecureEnclaveSSHKey: SSHKey {
    public let algorithm = KeyAlgorithm.ecdsaP256
    public let comment: String
    private let privateKey: SecureEnclave.P256.Signing.PrivateKey

    public init(privateKey: SecureEnclave.P256.Signing.PrivateKey, comment: String) {
        self.privateKey = privateKey
        self.comment = comment
    }

    public var sshPublicKeyBlob: Data {
        encodeECDSAP256PublicKeyBlob(publicKey: privateKey.publicKey)
    }

    public var fingerprint: String {
        sshFingerprint(keyBlob: sshPublicKeyBlob)
    }

    public func sign(data: Data) throws -> Data {
        let sig = try privateKey.signature(for: data)
        return try ecdsaSignatureToSSH(rawRepresentation: sig.rawRepresentation)
    }
}

// MARK: - Software P-256 Key (fallback when SE is unavailable)

public final class SoftwareP256SSHKey: SSHKey {
    public let algorithm = KeyAlgorithm.ecdsaP256
    public let comment: String
    private let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey, comment: String) {
        self.privateKey = privateKey
        self.comment = comment
    }

    public var sshPublicKeyBlob: Data {
        encodeECDSAP256PublicKeyBlob(publicKey: privateKey.publicKey)
    }

    public var fingerprint: String {
        sshFingerprint(keyBlob: sshPublicKeyBlob)
    }

    public func sign(data: Data) throws -> Data {
        let sig = try privateKey.signature(for: data)
        return try ecdsaSignatureToSSH(rawRepresentation: sig.rawRepresentation)
    }
}
