import Foundation
import CryptoKit
import Security

public enum KeyStoreError: Error, CustomStringConvertible {
    case keychainError(OSStatus)
    case keyNotFound(String)
    case secureEnclaveUnavailable
    case corruptedKeyData
    case metadataCorrupted

    public var description: String {
        switch self {
        case .keychainError(let status):
            return "Keychain error: \(status) (\(SecCopyErrorMessageString(status, nil) as String? ?? "unknown"))"
        case .keyNotFound(let id):
            return "Key not found: \(id)"
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available on this Mac"
        case .corruptedKeyData:
            return "Key data in Keychain is corrupted"
        case .metadataCorrupted:
            return "Key metadata in Keychain is corrupted"
        }
    }
}

public final class KeyStore {
    public static let serviceIdentifier = "pl.loee.ssh-agent"

    public init() {}

    // MARK: - Key Generation

    public func generateEd25519Key(comment: String) throws -> KeyIdentifier {
        let privateKey = Curve25519.Signing.PrivateKey()
        let id = UUID().uuidString
        let identifier = KeyIdentifier(id: id, keyType: .ed25519, comment: comment)

        try storeKeyData(privateKey.rawRepresentation, identifier: identifier)
        return identifier
    }

    public func generateSecureEnclaveKey(comment: String) throws -> KeyIdentifier {
        guard SecureEnclave.isAvailable else {
            throw KeyStoreError.secureEnclaveUnavailable
        }

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
        let id = UUID().uuidString
        let identifier = KeyIdentifier(id: id, keyType: .ecdsaP256, comment: comment)

        try storeKeyData(privateKey.dataRepresentation, identifier: identifier)
        return identifier
    }

    // MARK: - Key Listing

    public func listKeys() throws -> [KeyIdentifier] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceIdentifier,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeyStoreError.keychainError(status)
        }

        guard let items = result as? [[String: Any]] else {
            return []
        }

        return items.compactMap { item -> KeyIdentifier? in
            guard
                let account = item[kSecAttrAccount as String] as? String,
                account.hasPrefix(Self.serviceIdentifier + ".keys."),
                let label = item[kSecAttrLabel as String] as? String,
                let typeStr = item[kSecAttrDescription as String] as? String,
                let keyType = KeyAlgorithm(rawValue: typeStr),
                let created = item[kSecAttrCreationDate as String] as? Date
            else {
                return nil
            }
            let id = String(account.dropFirst((Self.serviceIdentifier + ".keys.").count))
            return KeyIdentifier(id: id, keyType: keyType, comment: label, createdAt: created)
        }
    }

    // MARK: - Key Loading

    public func loadKey(_ identifier: KeyIdentifier) throws -> any SSHKey {
        let keyData = try loadKeyData(identifier)

        switch identifier.keyType {
        case .ed25519:
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
            return Ed25519SSHKey(privateKey: privateKey, comment: identifier.comment)

        case .ecdsaP256:
            if SecureEnclave.isAvailable {
                let privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)
                return SecureEnclaveSSHKey(privateKey: privateKey, comment: identifier.comment)
            } else {
                // Fallback: try loading as software P-256 key
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: keyData)
                return SoftwareP256SSHKey(privateKey: privateKey, comment: identifier.comment)
            }
        }
    }

    public func loadAllKeys() throws -> [any SSHKey] {
        let identifiers = try listKeys()
        return identifiers.compactMap { id in
            try? loadKey(id)
        }
    }

    // MARK: - Key Deletion

    public func deleteKey(_ identifier: KeyIdentifier) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceIdentifier,
            kSecAttrAccount as String: Self.serviceIdentifier + ".keys." + identifier.id,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyStoreError.keychainError(status)
        }
    }

    // MARK: - Private Keychain Helpers

    private func storeKeyData(_ data: Data, identifier: KeyIdentifier) throws {
        let account = Self.serviceIdentifier + ".keys." + identifier.id

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceIdentifier,
            kSecAttrAccount as String: account,
            kSecAttrLabel as String: identifier.comment,
            kSecAttrDescription as String: identifier.keyType.rawValue,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyStoreError.keychainError(status)
        }
    }

    private func loadKeyData(_ identifier: KeyIdentifier) throws -> Data {
        let account = Self.serviceIdentifier + ".keys." + identifier.id

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.serviceIdentifier,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeyStoreError.keyNotFound(identifier.id)
            }
            throw KeyStoreError.keychainError(status)
        }

        guard let data = result as? Data else {
            throw KeyStoreError.corruptedKeyData
        }

        return data
    }
}
