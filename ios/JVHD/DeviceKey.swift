/*
 * DeviceKey.swift
 * Khoá thiết bị ECDSA P-256:
 *   - Tạo trong Secure Enclave (nếu máy hỗ trợ), dự phòng: Keychain thường.
 *   - Khoá riêng KHÔNG BAO GIỜ rời khỏi thiết bị và không bị đưa vào WebView.
 *   - d0() = base64(0x04 || X || Y)   ·   e0(data) = ECDSA(SHA-256(data)) DER/base64
 *
 * Tương đương `src/crypto-bridge.js` + libbtcore.so của bản Android/Windows.
 */

import Foundation
import Security

final class DeviceKey {

    static let shared = DeviceKey()

    private let applicationTag = "vn.jvhd.ios.devicekey".data(using: .utf8)!
    private let lock = NSLock()
    private var cachedKey: SecKey?

    private init() {}

    // MARK: - Khoá riêng

    /// Trả về khoá riêng P-256 lưu trong Secure Enclave/Keychain (tạo lần đầu nếu chưa có).
    func privateKey() -> SecKey? {
        lock.lock()
        defer { lock.unlock() }
        if let cached = cachedKey { return cached }
        let key = loadKey() ?? createKey()
        cachedKey = key
        return key
    }

    private func baseQuery() -> [String: Any] {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
    }

    private func loadKey() -> SecKey? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(baseQuery() as CFDictionary, &result)
        guard status == errSecSuccess, let result = result else { return nil }
        // CFTypeRef của một key item phải ép về SecKey.
        return (result as! SecKey)
    }

    private func createKey() -> SecKey? {
        // Thử Secure Enclave trước (chỉ có trên máy thật).
        if let secureEnclaveKey = createSecureEnclaveKey() { return secureEnclaveKey }
        // Dự phòng: khoá Keychain thường (chạy được cả trên Simulator).
        return createKeychainKey()
    }

    private func createSecureEnclaveKey() -> SecKey? {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else { return nil }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrIsPermanent as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    }

    private func createKeychainKey() -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrIsPermanent as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag
            ]
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    }

    // MARK: - d0(): khoá công khai

    /// base64( 0x04 || X(32) || Y(32) ) — đúng định dạng `pubKeyFormat = "raw-uncompressed-b64"`.
    func publicKeyBase64() -> String {
        guard let privateKey = privateKey(),
              let publicKey = SecKeyCopyPublicKey(privateKey) else { return "" }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) else { return "" }
        return (raw as Data).base64EncodedString()
    }

    // MARK: - e0(): chữ ký

    /// Ký dữ liệu thô (đã decode base64) bằng SHA-256 + ECDSA, trả về DER/base64.
    func signBase64(message: Data) -> String {
        guard let key = privateKey() else { return "" }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) else {
            NSLog("[JVHD][DeviceKey] ký thất bại: %@", String(describing: error?.takeRetainedValue()))
            return ""
        }
        return (signature as Data).base64EncodedString()
    }
}
